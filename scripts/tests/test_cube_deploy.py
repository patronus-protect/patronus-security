"""Exercise the downloadable acceptance client against an HTTP entrypoint peer."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "ark-api" / "deploy"
spec = importlib.util.spec_from_file_location("cube_smoke", DEPLOY / "smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


@pytest.fixture
def entrypoint_peer():
    jobs = {}
    lock = threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, data=None):
            self.send_response(status)
            self.end_headers()
            if data is not None:
                self.wfile.write(json.dumps(data).encode())

        def do_GET(self):
            if self.path in {"/healthz", "/readyz"}:
                return self.reply(200)
            if self.headers.get("Authorization") != "Bearer test-key":
                return self.reply(401)
            self.reply(200, jobs[self.path])

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"])).decode()
            if self.headers.get("Authorization") != "Bearer test-key":
                return self.reply(401)
            with lock:
                index = len(jobs)
                job_id = f"job_{index}"
                path = f"/v1/scan/{job_id}"
                categories = smoke.CATEGORIES if '"dynamic-pii"' in body else {"injection"}
                risky = smoke.INJECTION in body
                jobs[path] = {
                    "job_id": job_id, "status": "completed", "completion": {"state": "complete"},
                    "decision": "block" if risky else "allow", "worker": f"worker-{index % 3 + 1}",
                    "categories": {category: {"category": category, "confidence": 0.99,
                        "class_name": "instruction_override" if risky else "benign", "model": "test"}
                        for category in categories},
                }
            self.reply(202, {"jobs": [{"job_id": job_id, "status_url": path}]})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


def test_complete_smoke_lifecycle_and_redacted_report(entrypoint_peer, tmp_path):
    key = tmp_path / "key"
    key.write_text("test-key\n")
    result = subprocess.run([sys.executable, str(DEPLOY / "smoke.py"), "--url", entrypoint_peer,
                             "--key-file", str(key)], capture_output=True, text=True, check=True)
    report = json.loads(result.stdout)
    assert report["passed"] is True
    assert report["requests"] == 9
    assert report["workers"] == ["worker-1", "worker-2", "worker-3"]
    assert "test-key" not in result.stdout
    assert smoke.BENIGN not in result.stdout
    assert smoke.INJECTION not in result.stdout


@pytest.mark.parametrize("field,value", [
    ("status", "failed"), ("completion", {"state": "partial"}),
    ("categories", {}), ("worker", "unknown"), ("decision", "unknown"),
])
def test_rejects_invalid_final_results(field, value):
    result = {"status": "completed", "completion": {"state": "complete"}, "decision": "allow",
              "worker": "worker-1", "categories": {"injection": {
                  "category": "injection", "confidence": 0.9, "class_name": "benign", "model": "test"}}}
    result[field] = value
    with pytest.raises(RuntimeError):
        smoke.check_result(result, {"injection"})


def test_no_auth_forwarding_to_redirect(entrypoint_peer):
    class Redirect(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", entrypoint_peer + "/healthz")
            self.end_headers()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert smoke.http(f"http://127.0.0.1:{server.server_port}", "/", "test-key")[0] == 302
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_compose_isolates_internal_services_and_uses_registry_images():
    config = yaml.safe_load((DEPLOY / "compose.yaml").read_text())
    services = config["services"]
    assert set(services) == {"worker-1", "worker-2", "worker-3", "redis", "entrypoint"}
    for name, service in services.items():
        assert "build" not in service
        assert service["image"].startswith("${")
        assert "privileged" not in service
        assert service["read_only"] is True
        if name != "entrypoint":
            assert "ports" not in service
            assert all(config["networks"][network]["internal"] for network in service["networks"])
    for name in ("worker-1", "worker-2", "worker-3"):
        assert services[name]["cpus"] == 2.5
        assert "/readyz" in str(services[name]["healthcheck"])
    assert all("0.0.0.0" not in port for port in services["entrypoint"]["ports"])


def test_bootstrap_help_does_not_touch_host():
    result = subprocess.run(["bash", str(DEPLOY / "bootstrap.sh"), "--help"],
                            text=True, capture_output=True, check=True)
    assert "Two reboots are mandatory" in result.stdout
