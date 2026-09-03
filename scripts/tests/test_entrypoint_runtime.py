"""Exercise the real entrypoint with bounded local Redis and worker peers."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socketserver
import subprocess
import sys
import threading
import time
import uuid

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "ark-api/deploy")]
from smoke import http
import ark_api_entrypoint_benchmark as benchmark


@pytest.fixture
def entrypoint(tmp_path):
    servers = []
    threads = []
    store = {}
    state_lock = threading.Lock()
    active = {i: 0 for i in range(3)}
    peaks = {i: 0 for i in range(3)}

    def start(server):
        servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
        return server.server_address[1]

    class Redis(socketserver.StreamRequestHandler):
        def handle(self):
            while line := self.rfile.readline():
                count = int(line[1:])
                args = []
                for _ in range(count):
                    size = int(self.rfile.readline()[1:])
                    args.append(self.rfile.read(size))
                    self.rfile.read(2)
                command = args[0].upper()
                if command == b"GET":
                    with state_lock:
                        value = store.get(args[1])
                    reply = b"$-1\r\n" if value is None else b"$%d\r\n%s\r\n" % (len(value), value)
                elif command == b"SETEX":
                    with state_lock:
                        store[args[1]] = args[3]
                    reply = b"+OK\r\n"
                elif command == b"PING":
                    reply = b"+PONG\r\n"
                else:
                    reply = b"+OK\r\n"
                self.wfile.write(reply)
                self.wfile.flush()

    redis_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Redis)
    redis_server.daemon_threads = True
    redis_port = start(redis_server)

    def worker_handler(index):
        jobs = {}
        class Worker(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, body, content_type="application/json"):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if body == b"invalid":
                    return self.reply(400, b"Invalid multipart boundary", "text/plain")
                request_id = uuid.uuid4().hex
                with state_lock:
                    active[index] += 1
                    peaks[index] = max(peaks[index], active[index])
                    jobs[request_id] = (time.monotonic(), body)
                self.reply(202, json.dumps({"jobs":[{"request_id":request_id,"source":"text"}]}).encode())

            def do_GET(self):
                request_id = self.path.split("/")[-2]
                started, body = jobs[request_id]
                time.sleep(max(0, (0.7, 0.08, 0.9)[index] - (time.monotonic() - started)))
                with state_lock:
                    active[index] -= 1
                if body == b"disconnect":
                    return self.reply(200, b"", "text/event-stream")
                result = {"category":"injection", "level":"L2", "model":"test", "class_name":"benign",
                          "confidence":0.99, "duration_ms":9.5, "layers":[
                              {"layer_type":"ntdb_l2","duration_ms":7.25,"details":{"decision_cache_hit":False}}]}
                events = f'event: provisional\ndata: {json.dumps(result)}\n\n'
                events += f'event: result\ndata: {json.dumps(result)}\n\n'
                events += 'event: finished\ndata: {"completion":{"state":"complete"}}\n\n'
                self.reply(200, events.encode(), "text/event-stream")
        return Worker

    worker_ports = [start(ThreadingHTTPServer(("127.0.0.1", 0), worker_handler(i))) for i in range(3)]
    config = tmp_path / "entrypoint.yaml"
    # Ask the OS for an unused port, then let the entrypoint bind it.
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config.write_text(yaml.safe_dump({
        "server":{"bind":f"127.0.0.1:{port}"},
        "auth":{"keys":[{"key_hash":hashlib.sha256(b"test-key").hexdigest()}]},
        "gateway":{"redis_url":f"redis://127.0.0.1:{redis_port}", "worker_token":"test-worker-key",
                   "max_waiting_requests":3, "workers":[{"name":f"worker-{i+1}","url":f"http://127.0.0.1:{p}"} for i,p in enumerate(worker_ports)]},
    }))
    binary = ROOT / "target/debug/ark-api-entrypoint"
    assert binary.is_file(), "Build cargo build --locked -p ark-api --bin ark-api-entrypoint before this test"
    process = subprocess.Popen([str(binary), "--config", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if http(url, "/readyz")[0] == 200:
                    break
            except OSError:
                pass
            assert process.poll() is None, "entrypoint exited before readiness"
            time.sleep(0.02)
        else:
            pytest.fail("entrypoint did not become ready")
        yield url, active, peaks
    finally:
        process.terminate()
        process.wait(timeout=5)
        for server in reversed(servers):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


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
