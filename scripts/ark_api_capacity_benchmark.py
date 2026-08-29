#!/usr/bin/env python3
"""Capacity benchmark with unique validation texts and exact-cover book packets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import time
from collections import Counter
from pathlib import Path

from ark_api_http_benchmark import MIB, SIZE_BUCKETS, run_batch, summarize_values


def stratified_workload(path: Path, total: int = 600, seed: int = 20260828):
    bucket_shares = {"short": 0.60, "medium": 0.30, "long": 0.10}
    pools = {(bucket, label): [] for bucket in SIZE_BUCKETS for label in ("0", "1")}
    seen = set()
    with path.open(newline="", encoding="utf-8") as handle:
        for index, row in enumerate(csv.DictReader(handle)):
            text = row.get("text", "")
            digest = hashlib.sha256(text.encode()).digest()
            label = row.get("label", "")
            if not text or digest in seen or label not in {"0", "1"}:
                continue
            seen.add(digest)
            size = len(text.encode())
            bucket = next(
                name for name, (minimum, maximum) in SIZE_BUCKETS.items()
                if minimum <= size <= maximum
            )
            pools[(bucket, label)].append((f"{bucket}-{index}-{label}", text))

    rng = random.Random(seed)
    selected = []
    for bucket, share in bucket_shares.items():
        bucket_total = round(total * share)
        positive = round(bucket_total * 0.25)
        for label, count in (("0", bucket_total - positive), ("1", positive)):
            pool = pools[(bucket, label)]
            if len(pool) < count:
                raise ValueError(f"need {count} rows for {bucket}/label={label}, found {len(pool)}")
            selected.extend(rng.sample(pool, count))
    rng.shuffle(selected)
    return selected


def triangular_batches(total: int, seed: int = 20260828) -> list[int]:
    """Bounded API-burst profile: modal concurrency 3, right tail through 10."""
    rng = random.Random(seed)
    values = list(range(1, 11))
    weights = [0.05, 0.15, 0.30, 0.15, 0.10, 0.08, 0.06, 0.05, 0.04, 0.02]
    batches = []
    remaining = total
    while remaining:
        concurrency = rng.choices(values, weights=weights, k=1)[0]
        concurrency = min(concurrency, remaining)
        batches.append(concurrency)
        remaining -= concurrency
    return batches


def exact_packets(text: str, count: int) -> list[tuple[str, str]]:
    return [
        (
            f"moby-{count}-{index}",
            text[index * len(text) // count:(index + 1) * len(text) // count],
        )
        for index in range(count)
    ]


def compact(report: dict) -> dict:
    return {
        key: report[key]
        for key in (
            "requests", "input_mib", "elapsed_seconds", "mib_per_second", "rps",
            "latency_seconds", "requests_with_l3", "chunk_promotion",
            "requests_promoted_by_category", "requests_by_container", "failure_count",
            "l3_stage", "ok", "errors",
            "failures",
        )
    }


def dynamic_dataset(args, requests, batches=None):
    batches = batches or triangular_batches(len(requests), args.seed)
    reports = []
    offset = 0
    endpoint_offset = 0
    started = time.monotonic()
    for concurrency in batches:
        wave = requests[offset:offset + concurrency]
        reports.append(run_batch(
            args.base_url, args.token, wave, args.timeout_seconds,
            args.categories, args.ntdb_operating_point, concurrency, endpoint_offset,
        ))
        offset += concurrency
        endpoint_offset += len(wave)
    elapsed = time.monotonic() - started
    latencies = [value for report in reports for value in report["_latencies"]]
    l3_runs = [value for report in reports for value in report["_l3_runs"]]
    total_bytes = sum(len(text.encode()) for _, text in requests)
    requests_with_l3 = sum(report["requests_with_l3"] for report in reports)
    request_promotions = {
        category: sum(report["requests_promoted_by_category"][category] for report in reports)
        for category in args.categories
    }
    chunk_by_category = {}
    for category in args.categories:
        total = sum(
            report["chunk_promotion"]["by_category"][category]["total_chunks"]
            for report in reports
        )
        promoted = sum(
            report["chunk_promotion"]["by_category"][category]["promoted_chunks"]
            for report in reports
        )
        chunk_by_category[category] = {
            "total_chunks": total,
            "promoted_chunks": promoted,
            "rate": round(promoted / total, 4) if total else None,
        }
    union_total = sum(report["chunk_promotion"]["union"]["total_chunks"] for report in reports)
    union_promoted = sum(
        report["chunk_promotion"]["union"]["promoted_chunks"] for report in reports
    )
    by_container = Counter()
    for report in reports:
        by_container.update(report["requests_by_container"])
    failures = sum(report["failure_count"] for report in reports)
    failure_samples = [
        failure for report in reports for failure in report.get("failures", [])
    ][:20]
    return {
        "kind": "dynamic_dataset", "requests": len(requests),
        "input_mib": round(total_bytes / MIB, 3), "elapsed_seconds": round(elapsed, 3),
        "rps": round(len(requests) / elapsed, 3),
        "mib_per_second": round(total_bytes / MIB / elapsed, 3),
        "latency_seconds": summarize_values(latencies),
        "concurrency_distribution": dict(sorted(Counter(batches).items())),
        "concurrency_mean": round(statistics.mean(batches), 3),
        "requests_with_l3": requests_with_l3,
        "requests_promoted_by_category": request_promotions,
        "chunk_promotion": {
            "by_category": chunk_by_category,
            "union": {
                "total_chunks": union_total,
                "promoted_chunks": union_promoted,
                "rate": round(union_promoted / union_total, 4) if union_total else None,
            },
        },
        "requests_by_container": dict(by_container), "failure_count": failures,
        "failures": failure_samples,
        "l3_stage": {
            "runs": len(l3_runs),
            "queue_wait_ms": summarize_values([run[0] for run in l3_runs]),
            "worker_wall_ms": summarize_values([run[1] for run in l3_runs]),
            "chunks": summarize_values([float(run[2]) for run in l3_runs]),
        },
        "ok": failures == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", action="append", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--validation-csv", type=Path, required=True)
    parser.add_argument("--moby-dick", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--seed", type=int, default=20260828)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--ntdb-operating-point", default="best_promote")
    args = parser.parse_args()
    args.categories = ["injection", "dlp", "threat"]

    requests = stratified_workload(args.validation_csv, seed=args.seed)
    report = {"dataset": dynamic_dataset(args, requests), "moby_dick": {}}
    book = args.moby_dick.read_text(encoding="utf-8-sig")
    for packet_count in (1, 2, 4, 8, 13, 20):
        result = run_batch(
            args.base_url, args.token, exact_packets(book, packet_count),
            args.timeout_seconds, args.categories, args.ntdb_operating_point,
            min(10, packet_count),
        )
        report["moby_dick"][str(packet_count)] = compact(result)
    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    return 0 if report["dataset"]["ok"] and all(
        value["ok"] for value in report["moby_dick"].values()
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
