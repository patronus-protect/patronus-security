"""Local RESP and fenced-worker peers for exercising compiled entrypoints."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socketserver
import subprocess
import threading
import time
import uuid

import pytest
import yaml
from smoke import http

ROOT = Path(__file__).resolve().parents[2]

@pytest.fixture
def entrypoint_factory(tmp_path):
    servers = []
    threads = []
    store = {}
    state_lock = threading.Lock()
    processes = []
    redis_available = threading.Event()
    redis_available.set()

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
                if not redis_available.is_set():
                    return
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

    def worker_handler(index, active, peaks, control):
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
                if self.path == "/internal/recover":
                    if self.headers.get("Authorization") != "Bearer test-worker-key":
                        return self.reply(401, b"{}")
                    with state_lock:
                        if not control["ready"] or active[index]:
                            return self.reply(409, b"{}")
                        control["epoch"] += 1
                        return self.reply(200, json.dumps({**control, "active_jobs": 0, "active_submissions": 0}).encode())
                if self.headers.get("Authorization") != "Bearer test-worker-key":
                    return self.reply(401, b"{}")
                expected_instance = self.headers.get("x-ark-worker-instance")
                expected_epoch = self.headers.get("x-ark-worker-epoch")
                with state_lock:
                    if expected_instance != control["instance_id"] or expected_epoch != str(control["epoch"]):
                        return self.reply(409, b"{}")
                request_id = uuid.uuid4().hex
                with state_lock:
                    active[index] += 1
                    peaks[index] = max(peaks[index], active[index])
                    jobs[request_id] = (time.monotonic(), body)
                self.reply(202, json.dumps({"jobs":[{"request_id":request_id,"source":"text"}]}).encode())

            def do_GET(self):
                if self.path == "/internal/status":
                    if self.headers.get("Authorization") != "Bearer test-worker-key":
                        return self.reply(401, b"{}")
                    with state_lock:
                        return self.reply(200 if control["ready"] else 503, json.dumps({
                            **control, "active_jobs": active[index], "active_submissions": 0,
                        }).encode())
                request_id = self.path.split("/")[-2]
                started, body = jobs[request_id]
                time.sleep(max(0, (0.7, 0.08, 0.9)[index] - (time.monotonic() - started)))
                if body == b"disconnect":
                    # Losing SSE does not imply inference stopped. Keep active until
                    # the test explicitly completes the uncertain worker job.
                    return self.reply(200, b"", "text/event-stream")
                with state_lock:
                    active[index] -= 1
                result = {"category":"injection", "level":"L2", "model":"test", "class_name":"benign",
                          "confidence":0.99, "duration_ms":9.5, "layers":[
                              {"layer_type":"ntdb_l2","duration_ms":7.25,"details":{"decision_cache_hit":False}}]}
                events = f'event: provisional\ndata: {json.dumps(result)}\n\n'
                events += f'event: result\ndata: {json.dumps(result)}\n\n'
                events += 'event: finished\ndata: {"completion":{"state":"complete"}}\n\n'
                self.reply(200, events.encode(), "text/event-stream")
        return Worker

    def create():
        active = {i: 0 for i in range(3)}
        peaks = {i: 0 for i in range(3)}
        controls = [{"ready": True, "instance_id": uuid.uuid4().hex, "epoch": 0} for _ in range(3)]
        worker_ports = [start(ThreadingHTTPServer(("127.0.0.1", 0), worker_handler(i, active, peaks, controls[i]))) for i in range(3)]
        config = tmp_path / f"entrypoint-{len(processes)}.yaml"
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
        processes.append(process)
        url = f"http://127.0.0.1:{port}"
        for _ in range(150):
            try:
                if http(url, "/readyz")[0] == 200:
                    break
            except OSError:
                pass
            assert process.poll() is None, "entrypoint exited before readiness"
            time.sleep(0.02)
        else:
            pytest.fail("entrypoint did not become ready")
        return {"url": url, "active": active, "peaks": peaks, "controls": controls,
                "lock": state_lock, "process": process, "store": store,
                "redis_available": redis_available}

    try:
        yield create
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        for server in reversed(servers):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
