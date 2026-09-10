#!/usr/bin/env python3
"""Measure the 42 unchanged validation texts through an ARK entrypoint."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from ark_api_http_benchmark import multipart
from ark_api_throughput_benchmark import THROUGHPUT_CATEGORIES, timing_summary, validation_case_texts

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ark-api" / "deploy"))
from smoke import check_result


_transport = threading.local()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http(url, path, key=None, data=None, content_type=None):
    # Building an opener creates a TLS context, even for HTTP. Reuse it per
    # thread and initialize it before measuring; never use ambient proxies.
    if not hasattr(_transport, "opener"):
        _transport.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    headers = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url + path, data=data, headers=headers)
    try:
        response = _transport.opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise RuntimeError("Unexpectedly large API response")
        return response.code, json.loads(raw) if raw else None


def run_cases(url, key, cases, concurrency):
    ready = threading.Barrier(concurrency + 1, timeout=60)

    def prepare():
        try:
            if http(url, "/readyz")[0] != 200:
                raise RuntimeError("Entrypoint is not ready")
            ready.wait()
        except Exception:
            ready.abort()
            raise

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        prepared = [pool.submit(prepare) for _ in range(concurrency)]
        ready.wait()
        for future in prepared:
            future.result()
        started = time.monotonic()
        rows = list(pool.map(lambda case: scan(url, key, case), cases))
        elapsed = time.monotonic() - started
    return rows, elapsed


def scan(url, key, case):
    name, content = case
    # Preserve the source text byte for byte. Server gates define the profile.
    body, boundary = multipart(content, {
        "categories": THROUGHPUT_CATEGORIES, "max_level": "L3",
        "ntdb_operating_point": "best_promote",
    })
    row = {"case": name, "bytes": len(content.encode()),
           "sha256": hashlib.sha256(content.encode()).hexdigest()}
    started = time.monotonic()
    poll_count = 0
    poll_http_ms = 0.0
    poll_sleep_ms = 0.0
    try:
        status, payload = http(url, "/v1/scan", key, body, f"multipart/form-data; boundary={boundary}")
        row["submit_http_ms"] = (time.monotonic() - started) * 1000
        if status != 202 or len(payload.get("jobs", [])) != 1:
            raise RuntimeError(f"submit HTTP {status}")
        job = payload["jobs"][0]
        row["job_id"] = job["job_id"]
        if job.get("status_url") != "/v1/scan/" + row["job_id"]:
            raise RuntimeError("invalid status URL")
        while time.monotonic() - started < 120:
            poll_started = time.monotonic()
            status, result = http(url, job["status_url"], key)
            poll_http_ms += (time.monotonic() - poll_started) * 1000
            poll_count += 1
            if status != 200:
                raise RuntimeError(f"poll HTTP {status}")
            if result.get("status") in {"completed", "failed"}:
                check_result(result, set(THROUGHPUT_CATEGORIES))
                timings = result.get("timings", {})
                for field in ("queue_wait_ms", "worker_ms", "total_ms"):
                    value = timings.get(field)
                    if not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
                        raise RuntimeError(f"missing or invalid timing: {field}")
                l2 = timings.get("l2_ms")
                if l2 is not None and (not isinstance(l2, (float, int)) or not math.isfinite(l2) or l2 < 0):
                    raise RuntimeError("invalid L2 timing")
                row.update(passed=True, worker=result["worker"], decision=result["decision"],
                           timings=timings, categories={category: {
                               field: value.get(field) for field in ("class_name", "level", "model")
                           } for category, value in result["categories"].items()})
                break
            sleep_started = time.monotonic()
            time.sleep(0.01)
            poll_sleep_ms += (time.monotonic() - sleep_started) * 1000
        else:
            raise TimeoutError("job exceeded 120 seconds")
    except Exception as error:
        row.update(passed=False, error=f"{type(error).__name__}: {error}")
    row["client_total_ms"] = (time.monotonic() - started) * 1000
    row.update(poll_count=poll_count, poll_http_ms=poll_http_ms, poll_sleep_ms=poll_sleep_ms)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=6,
                        help="Three workers plus three waiting requests keep the server supplied.")
    args = parser.parse_args()
    url = args.url.rstrip("/")
    origin = urllib.parse.urlsplit(url)
    if origin.scheme not in {"http", "https"} or not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment:
        parser.error("Use an HTTP(S) origin without credentials, path or query")
    if not 1 <= args.concurrency <= 12:
        parser.error("concurrency must be between 1 and 12")
    key = args.key_file.read_text().strip()
    cases = validation_case_texts()
    assert len(cases) == 42 and len({text for _, text in cases}) == 42
    assert http(url, "/readyz")[0] == 200
    timestamp = datetime.now(timezone.utc).isoformat()
    rows, elapsed = run_cases(url, key, cases, args.concurrency)
    completed = [r for r in rows if r["passed"]]
    sizes = [r["bytes"] for r in rows]
    report = {
        "timestamp": timestamp, "endpoint": url,
        "workload": "42 original validation_case_texts; no padding, repetition or added markers",
        "categories": THROUGHPUT_CATEGORIES, "threat_max_level": "L2", "dynamic_pii": False,
        "requests": len(rows), "completed": len(completed), "errors": len(rows) - len(completed),
        "client_concurrency": args.concurrency, "passes": 1,
        "cache": "Existing deployed caches retained. l2_cache_hit=true means all observed L2 heads cached; false means at least one head scored, and may include partial model cache hits.",
        "bytes": {"total": sum(sizes), "mean": statistics.mean(sizes),
                  "median": statistics.median(sizes), "min": min(sizes), "max": max(sizes)},
        "duration_s": elapsed, "completed_rps": len(completed) / elapsed,
        "completed_mib_s": sum(r["bytes"] for r in completed) / (1024 * 1024) / elapsed,
        "latency_ms": {
            "l2_uncached": timing_summary([r["timings"]["l2_ms"] for r in completed if r["timings"].get("l2_ms") is not None and r["timings"].get("l2_cache_hit") is False]),
            "l2_cached": timing_summary([r["timings"]["l2_ms"] for r in completed if r["timings"].get("l2_ms") is not None and r["timings"].get("l2_cache_hit") is True]),
            "worker_total": timing_summary([r["timings"]["worker_ms"] for r in completed]),
            "entrypoint_total": timing_summary([r["timings"]["total_ms"] for r in completed]),
            "queue_wait": timing_summary([r["timings"]["queue_wait_ms"] for r in completed]),
            "client_total": timing_summary([r["client_total_ms"] for r in completed]),
            "client_minus_entrypoint": timing_summary([r["client_total_ms"] - r["timings"]["total_ms"] for r in completed]),
            "submit_http": timing_summary([r["submit_http_ms"] for r in completed]),
            "poll_http_sum": timing_summary([r["poll_http_ms"] for r in completed]),
            "poll_sleep_sum": timing_summary([r["poll_sleep_ms"] for r in completed]),
        },
        "timing_definitions": {
            "l2_uncached": "Shared NTDB L2 scoring duration when at least one head scored without cache; counted once across heads; excludes L1/L3 and HTTP",
            "l2_cached": "Cache lookup duration; not model inference",
            "worker_total": "Entrypoint dispatch through worker finished event, excluding admission wait",
            "entrypoint_total": "Entrypoint admission through finished event, including wait for free worker",
            "client_total": "Client POST through final status retrieval, including transport and 10ms polling",
            "client_minus_entrypoint": "Per-request client time minus server total; not subtraction of unrelated percentiles",
            "measurement_window": "First scan submission through last result; excludes per-thread HTTP client initialization, readiness and output; no inference warmup",
        },
        "l2_cache_hits": sum(r["timings"].get("l2_cache_hit") is True for r in completed),
        "l2_measurements": sum(r["timings"].get("l2_ms") is not None for r in completed),
        "workers": dict(Counter(r["worker"] for r in completed)),
        "requests_with_l3_final": sum(any(c["level"] == "L3" for c in r["categories"].values()) for r in completed),
        "results": rows,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))
    return 0 if len(completed) == 42 else 1


if __name__ == "__main__":
    raise SystemExit(main())
