"""Exercise the real entrypoint with bounded local Redis and worker peers."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "ark-api/deploy")]
from smoke import http
import ark_api_entrypoint_benchmark as benchmark


from entrypoint_peers import entrypoint_factory


@pytest.fixture
def entrypoint(entrypoint_factory):
    node = entrypoint_factory()
    return node["url"], node["active"], node["peaks"]


def submit(url, body=b"valid"):
    status, payload = http(url, "/v1/scan", "test-key", body, "text/plain")
    assert status == 202, payload
    return payload["jobs"][0]["status_url"]


def completed(url, path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status, result = http(url, path, "test-key")
        assert status == 200
        if result["status"] in {"completed", "failed"}:
            return result
        time.sleep(0.01)
    pytest.fail("job never terminated")


def test_first_free_worker_and_plaintext_rejections(entrypoint):
    url, active, peaks = entrypoint
    # Plaintext worker errors must not remove healthy workers from the pool.
    for _ in range(3):
        assert http(url, "/v1/scan", "test-key", b"invalid", "text/plain")[0] == 400
    initial = [submit(url) for _ in range(3)]
    next_job = submit(url)
    result = completed(url, next_job)
    assert result["worker"] == "worker-2", "next job must use the worker that finished first"
    assert result["timings"]["l2_ms"] == 7.25
    assert result["timings"]["worker_ms"] > 7.25
    assert all(completed(url, path)["status"] == "completed" for path in initial)
    assert peaks == {0:1,1:1,2:1}, "no worker may receive overlapping submissions"
    assert active == {0:0,1:0,2:0}


def test_interrupted_worker_job_fails_and_other_workers_continue(entrypoint):
    url, _, _ = entrypoint
    failed = completed(url, submit(url, b"disconnect"))
    assert failed["status"] == "failed"
    assert failed["decision"] == "review"
    assert failed["completion"]["state"] == "failed"
    for _ in range(3):
        result = completed(url, submit(url))
        assert result["status"] == "completed"
        assert result["worker"] != failed["worker"]


def test_shared_store_serves_jobs_across_entrypoints_and_after_origin_stops(entrypoint_factory):
    first, second = entrypoint_factory(), entrypoint_factory()
    first_path = submit(first["url"])
    second_path = submit(second["url"])
    assert first_path != second_path
    assert http(second["url"], first_path, "wrong-key")[0] == 401
    first_result = completed(second["url"], first_path)
    second_result = completed(first["url"], second_path)
    assert first_result["completion"]["state"] == second_result["completion"]["state"] == "complete"
    assert first_result == http(first["url"], first_path, "test-key")[1]
    assert second_result == http(second["url"], second_path, "test-key")[1]
    first["process"].terminate()
    first["process"].wait(timeout=5)
    assert http(second["url"], first_path, "test-key") == (200, first_result)
    assert completed(second["url"], submit(second["url"]))["status"] == "completed"


def wait_status(url, expected):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if http(url, "/readyz")[0] == expected:
            return
        time.sleep(0.025)
    pytest.fail(f"readiness did not become {expected}")


def test_quarantined_workers_require_proven_idle_and_recover_without_restart(entrypoint_factory):
    node = entrypoint_factory()
    url = node["url"]
    paths = [submit(url, b"disconnect") for _ in range(3)]
    # Busy workers still count as service capacity; unfinished inference is
    # subsequently quarantined once its event stream disconnects.
    assert http(url, "/readyz")[0] == 200
    assert all(completed(url, path)["status"] == "failed" for path in paths)
    wait_status(url, 503)
    time.sleep(1.1)
    assert http(url, "/readyz")[0] == 503
    with node["lock"]:
        assert node["active"] == {0: 1, 1: 1, 2: 1}
        node["active"][1] = 0
    wait_status(url, 200)
    result = completed(url, submit(url))
    assert result["worker"] == "worker-2"
    assert node["process"].poll() is None
    assert node["peaks"] == {0: 1, 1: 1, 2: 1}


def test_readiness_tracks_worker_health_without_treating_alive_http_as_ready(entrypoint_factory):
    node = entrypoint_factory()
    with node["lock"]:
        for control in node["controls"]:
            control["ready"] = False
    wait_status(node["url"], 503)
    assert http(node["url"], "/healthz")[0] == 200
    with node["lock"]:
        node["controls"][0]["ready"] = True
    wait_status(node["url"], 200)
    assert completed(node["url"], submit(node["url"]))["worker"] == "worker-1"


@pytest.mark.parametrize("l2_ms", [None, 2.5])
def test_benchmark_keeps_original_text_and_accepts_absent_l2(monkeypatch, l2_ms):
    cases = benchmark.validation_case_texts()
    assert len(cases) == 42 and sum(len(text.encode()) for _, text in cases) == 19664
    case = cases[0]
    def fake_http(url, path, key=None, data=None, content_type=None):
        if data is not None:
            assert ("\r\n\r\n" + case[1] + "\r\n--").encode() in data
            return 202, {"jobs":[{"job_id":"job_test","status_url":"/v1/scan/job_test"}]}
        return 200, {"status":"completed","completion":{"state":"complete"},"decision":"allow","worker":"worker-1",
                     "timings":{"l2_ms":l2_ms,"queue_wait_ms":0.0,"worker_ms":5.0,"total_ms":5.0},
                     "categories":{name:{"category":name,"class_name":"benign","confidence":0.99,"model":"test","level":"L2"} for name in benchmark.THROUGHPUT_CATEGORIES}}
    monkeypatch.setattr(benchmark, "http", fake_http)
    result = benchmark.scan("http://test", "test-key", case)
    assert result["passed"] is True
    assert result["bytes"] == len(case[1].encode())
    assert result["timings"]["l2_ms"] == l2_ms


def test_benchmark_reuses_prepared_clients_without_proxy_or_redirect(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    redirected = []
    built = []
    original_build = benchmark.urllib.request.build_opener

    def build(*args, **kwargs):
        built.append(threading.get_ident())
        return original_build(*args, **kwargs)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == "/forwarded":
                redirected.append(self.headers.get("Authorization"))
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "/forwarded")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    monkeypatch.setattr(benchmark.urllib.request, "build_opener", build)
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    ready = threading.Barrier(3, timeout=10)

    def requests():
        assert benchmark.http(url, "/readyz")[0] == 200
        ready.wait()
        for _ in range(4):
            assert benchmark.http(url, "/healthz")[0] == 200
        assert benchmark.http(url, "/redirect", "test-key")[0] == 302

    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(requests) for _ in range(3)]
            for future in futures:
                future.result()
        assert len(built) == len(set(built)) == 3
        assert redirected == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
