#!/usr/bin/env python3
"""Benchmark one or more Ark API containers with the canonical mixed workload."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import math
import queue
import random
import statistics
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from ark_api_profile import execution_gates
from ark_api_throughput_benchmark import (
    MIB,
    THROUGHPUT_CATEGORIES,
    UNIFIED_MODEL,
)

SIZE_BUCKETS = {
    "short": (0, 2 * 1024),
    "medium": (2 * 1024 + 1, 8 * 1024),
    "long": (8 * 1024 + 1, math.inf),
}


def validation_workload(path: Path, per_bucket: int = 14, seed: int = 42) -> list[tuple[str, str]]:
    pools = {bucket: [] for bucket in SIZE_BUCKETS}
    with path.open(newline="", encoding="utf-8") as handle:
        for index, row in enumerate(csv.DictReader(handle)):
            text = row.get("text", "")
            if not text:
                continue
            size = len(text.encode())
            for bucket, (minimum, maximum) in SIZE_BUCKETS.items():
                if minimum <= size <= maximum:
                    pools[bucket].append((f"{bucket}-{index}-{row.get('label', 'unknown')}", text))
                    break
    rng = random.Random(seed)
    selected = []
    for bucket, pool in pools.items():
        if len(pool) < per_bucket:
            raise ValueError(f"validation CSV has only {len(pool)} {bucket} rows")
        selected.extend(rng.sample(pool, per_bucket))
    rng.shuffle(selected)
    return selected


def request_config(categories: list[str], ntdb_operating_point: str) -> dict:
    gates = execution_gates()
    levels = gates.pop("levels")
    gates.update(levels)
    gates["models"]["gliner_small-v2.5-edge"] = False
    gates["models"]["routing"] = False
    gates["models"]["unified-v3-routing"] = False
    gates["policy"] = {
        "clustering": "representative",
        "representatives_per_cluster": 1,
    }
    gates.pop("l3", None)
    gates["conditional"] = []
    return {
        "categories": categories,
        "max_level": "L3",
        "ntdb_operating_point": ntdb_operating_point,
        "gates": gates,
    }


def multipart(content: str, config: dict) -> tuple[bytes, str]:
    boundary = f"ark-benchmark-{uuid.uuid4().hex}"
    parts = []
    for name, value in (("config", json.dumps(config)), ("content", content)):
        parts.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
            value.encode(), b"\r\n",
        ])
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), boundary


def open_request(request: urllib.request.Request, timeout: float):
    return urllib.request.urlopen(request, timeout=timeout)


def l3_run_timing(result: dict) -> tuple[float, float, int] | None:
    for layer in result.get("layers", []):
        details = layer.get("details", {})
        if "l3_worker_wall_ms" not in details:
            continue
        return (
            float(details["l3_queue_wait_ms"]),
            float(details["l3_worker_wall_ms"]),
            int(details.get("chunk_count", 0)),
        )
    return None


def submit(base_url: str, token: str, name: str, content: str, config: dict, timeout: float) -> dict:
    body, boundary = multipart(content, config)
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/scan", data=body, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    try:
        with open_request(request, timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(error.read().decode("utf-8", errors="replace")) from error
    return {"name": name, "request_id": payload["jobs"][0]["request_id"], "base_url": base_url}


def consume(job: dict, token: str, timeout: float) -> dict:
    request = urllib.request.Request(
        f"{job['base_url'].rstrip('/')}/v1/scan/{job['request_id']}/events",
        headers={"Authorization": f"Bearer {token}", "Accept": "text/event-stream"},
    )
    event_name = None
    data_lines = []
    models, l3_models, pipelines, levels, failures = set(), set(), set(), set(), []
    l2_promoted_categories = set()
    l3_categories = set()
    l3_runs = set()
    l2_chunk_spans = {}
    promoted_chunk_spans = {}
    with open_request(request, timeout) as response:
        for raw in response:
            line = raw.decode("utf-8").rstrip("\r\n")
            if line.startswith("event:"):
                event_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif not line and event_name:
                data = json.loads("\n".join(data_lines)) if data_lines else {}
                if event_name in {"result", "provisional"}:
                    models.add(data["model"])
                    pipelines.add(data["category"])
                    levels.add(data["level"])
                    for layer in data.get("layers", []):
                        for chunk in layer.get("details", {}).get("l2_chunk_outputs", []):
                            span = chunk.get("span", {})
                            key = (span.get("start"), span.get("end"))
                            if None in key:
                                continue
                            l2_chunk_spans.setdefault(data["category"], set()).add(key)
                            if chunk.get("promoted") is True:
                                promoted_chunk_spans.setdefault(data["category"], set()).add(key)
                    if any(
                        layer.get("level") == "L2"
                        and layer.get("details", {}).get("route_to_l3") is True
                        for layer in data.get("layers", [])
                    ):
                        l2_promoted_categories.add(data["category"])
                    if data["level"] == "L3":
                        l3_models.add(data["model"])
                        if event_name == "result" and (timing := l3_run_timing(data)) is not None:
                            l3_categories.add(data["category"])
                            l3_runs.add(timing)
                elif event_name == "finished":
                    completion = data["completion"]
                    failures.extend(completion.get("failures", []))
                    return {
                        **job, "models": models, "l3_models": l3_models,
                        "pipelines": pipelines, "levels": levels, "failures": failures,
                        "l2_promoted_categories": l2_promoted_categories,
                        "l3_categories": l3_categories,
                        "l3_runs": l3_runs,
                        "l2_chunk_spans": l2_chunk_spans,
                        "promoted_chunk_spans": promoted_chunk_spans,
                        "completion": completion["state"],
                    }
                event_name, data_lines = None, []
    raise RuntimeError(f"SSE ended before finished for {job['request_id']}")


def run_batch(
    base_urls: list[str], token: str, requests: list[tuple[str, str]], timeout: float,
    categories: list[str], ntdb_operating_point: str, concurrency: int | None = None,
    endpoint_offset: int = 0,
) -> dict:
    config = request_config(categories, ntdb_operating_point)
    started = time.monotonic()
    submitted_at = {}
    completed = {}
    requests_by_container = {base_url: 0 for base_url in base_urls}
    pending = queue.Queue()
    available_endpoints = queue.Queue()
    for request_item in requests:
        pending.put(request_item)
    for index in range(len(base_urls)):
        available_endpoints.put(base_urls[(endpoint_offset + index) % len(base_urls)])
    lock = threading.Lock()

    def client_worker() -> None:
        while True:
            try:
                name, content = pending.get_nowait()
            except queue.Empty:
                return
            request_started = time.monotonic()
            base_url = available_endpoints.get()
            with lock:
                submitted_at[name] = request_started
                requests_by_container[base_url] += 1
            try:
                job = submit(base_url, token, name, content, config, timeout)
                result = consume(job, token, timeout)
                with lock:
                    completed[name] = (time.monotonic(), result)
            finally:
                available_endpoints.put(base_url)

    client_count = concurrency or len(base_urls)
    if concurrency is None:
        def container_worker(base_url: str) -> None:
            while True:
                try:
                    name, content = pending.get_nowait()
                except queue.Empty:
                    return
                request_started = time.monotonic()
                with lock:
                    submitted_at[name] = request_started
                    requests_by_container[base_url] += 1
                job = submit(base_url, token, name, content, config, timeout)
                result = consume(job, token, timeout)
                with lock:
                    completed[name] = (time.monotonic(), result)

        worker_targets = [(container_worker, base_url) for base_url in base_urls]
    else:
        worker_targets = [(client_worker,) for _ in range(client_count)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=client_count) as pool:
        futures = [pool.submit(*target) for target in worker_targets]
        for future in futures:
            future.result()
    elapsed = time.monotonic() - started
    total_bytes = sum(len(content.encode()) for _, content in requests)
    request_sizes = [len(content.encode()) for _, content in requests]
    results = [item[1] for item in completed.values()]
    models = set().union(*(result["models"] for result in results))
    l3_models = set().union(*(result["l3_models"] for result in results))
    pipelines = set().union(*(result["pipelines"] for result in results))
    levels = set().union(*(result["levels"] for result in results))
    failures = [failure for result in results for failure in result["failures"]]
    requests_with_l3 = sum(bool(result["l3_models"]) for result in results)
    promotion_cases = [
        {
            "name": result["name"],
            "l2_categories": sorted(result.get("l2_promoted_categories", set())),
            "l3_categories": sorted(result.get("l3_categories", set())),
        }
        for result in results
        if result.get("l2_promoted_categories") or result.get("l3_categories")
    ]
    l2_promotions_by_category = {
        category: sum(
            category in result.get("l2_promoted_categories", set())
            for result in results
        )
        for category in categories
    }
    l3_runs = set().union(*(result["l3_runs"] for result in results))
    latencies = [finished - submitted_at[name] for name, (finished, _) in completed.items()]
    errors = []
    if failures:
        errors.append(f"received {len(failures)} pipeline failures")
    if UNIFIED_MODEL not in l3_models:
        errors.append("unified L3 model was not observed")
    if l3_models - {UNIFIED_MODEL}:
        errors.append(f"dedicated L3 models observed: {sorted(l3_models - {UNIFIED_MODEL})}")
    if set(categories) - pipelines:
        errors.append(f"missing pipelines: {sorted(set(categories) - pipelines)}")
    return {
        "ok": not errors, "containers": len(base_urls), "concurrency": client_count,
        "base_urls": base_urls,
        "requests": len(requests), "input_mib": round(total_bytes / MIB, 3),
        "request_bytes": {
            "min": min(request_sizes),
            "median": round(statistics.median(request_sizes), 1),
            "p95": sorted(request_sizes)[min(math.ceil(len(request_sizes) * .95) - 1, len(request_sizes) - 1)],
            "max": max(request_sizes),
        },
        "size_buckets": {
            bucket: sum(minimum <= size <= maximum for size in request_sizes)
            for bucket, (minimum, maximum) in SIZE_BUCKETS.items()
        },
        "elapsed_seconds": round(elapsed, 3),
        "mib_per_second": round(total_bytes / MIB / elapsed, 3),
        "rps": round(len(requests) / elapsed, 3),
        "latency_seconds": {
            "p50": round(statistics.median(latencies), 3),
            "p95": round(sorted(latencies)[min(math.ceil(len(latencies) * .95) - 1, len(latencies) - 1)], 3),
            "p99": round(sorted(latencies)[min(math.ceil(len(latencies) * .99) - 1, len(latencies) - 1)], 3),
            "max": round(max(latencies), 3),
        },
        "models": sorted(models), "l3_models": sorted(l3_models),
        "pipelines": sorted(pipelines), "levels": sorted(levels),
        "categories": categories, "ntdb_operating_point": ntdb_operating_point,
        "requests_with_l3": requests_with_l3,
        "chunk_promotion": summarize_chunk_promotion(results, categories),
        "requests_promoted_by_category": l2_promotions_by_category,
        "promotion_cases": promotion_cases,
        "requests_by_container": requests_by_container,
        "failure_count": len(failures), "failures": failures[:10], "errors": errors,
        "l3_stage": summarize_l3_runs(l3_runs),
        "_latencies": latencies,
        "_l3_runs": list(l3_runs),
    }


def summarize_values(values: list[float]) -> dict:
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "p50": round(statistics.median(values), 3),
        "p95": round(ordered[min(math.ceil(len(values) * .95) - 1, len(values) - 1)], 3),
        "p99": round(ordered[min(math.ceil(len(values) * .99) - 1, len(values) - 1)], 3),
        "max": round(max(values), 3),
    }


def summarize_chunk_promotion(results: list[dict], categories: list[str]) -> dict:
    by_category = {}
    for category in categories:
        total = sum(len(result.get("l2_chunk_spans", {}).get(category, set())) for result in results)
        promoted = sum(
            len(result.get("promoted_chunk_spans", {}).get(category, set()))
            for result in results
        )
        by_category[category] = {
            "total_chunks": total,
            "promoted_chunks": promoted,
            "rate": round(promoted / total, 4) if total else None,
        }
    union_total = 0
    union_promoted = 0
    for result in results:
        total_spans = set().union(*result.get("l2_chunk_spans", {}).values()) \
            if result.get("l2_chunk_spans") else set()
        promoted_spans = set().union(*result.get("promoted_chunk_spans", {}).values()) \
            if result.get("promoted_chunk_spans") else set()
        union_total += len(total_spans)
        union_promoted += len(promoted_spans)
    return {
        "by_category": by_category,
        "union": {
            "total_chunks": union_total,
            "promoted_chunks": union_promoted,
            "rate": round(union_promoted / union_total, 4) if union_total else None,
        },
    }


def summarize_l3_runs(runs) -> dict:
    runs = list(runs)
    return {
        "runs": len(runs),
        "queue_wait_ms": summarize_values([run[0] for run in runs]),
        "worker_wall_ms": summarize_values([run[1] for run in runs]),
        "chunks": summarize_values([float(run[2]) for run in runs]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", action="append", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--validation-csv", type=Path, required=True)
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--per-bucket", type=int, default=14)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument(
        "--categories", default=",".join(THROUGHPUT_CATEGORIES),
        help="comma-separated pipeline categories",
    )
    parser.add_argument(
        "--ntdb-operating-point", default="best_fpr_in_f1",
        choices=("best_fpr_in_f1", "best_f1", "best_promote"),
    )
    args = parser.parse_args()
    categories = [value.strip() for value in args.categories.split(",") if value.strip()]
    if not categories:
        parser.error("--categories must contain at least one category")
    report = run_batch(
        args.base_url, args.token,
        validation_workload(args.validation_csv, args.per_bucket, args.seed),
        args.timeout_seconds, categories, args.ntdb_operating_point, args.concurrency,
    )
    report.pop("_latencies", None)
    report.pop("_l3_runs", None)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
