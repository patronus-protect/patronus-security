#!/usr/bin/env python3
"""Build and run the token-sized Ark API agent-readiness workload."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import time
from collections import Counter
from pathlib import Path

from ark_api_capacity_benchmark import dynamic_dataset
import ark_api_http_benchmark as http


TARGET_TOKENS = (5_000, 10_000, 20_000, 50_000)
KINDS = ("benign", "injection", "threat", "sensitive")
SEPARATOR = "\n\n--- next distinct source excerpt ---\n\n"


def agent_batches(total: int, seed: int) -> list[int]:
    rng = random.Random(seed)
    values = list(range(1, 7))
    weights = [0.08, 0.18, 0.32, 0.20, 0.14, 0.08]
    batches = []
    remaining = total
    while remaining:
        value = min(rng.choices(values, weights=weights, k=1)[0], remaining)
        batches.append(value)
        remaining -= value
    return batches


def csv_rows(path: Path, predicate=lambda _row: True) -> list[str]:
    rows = []
    seen = set()
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            text = row.get("text", "").strip()
            digest = hashlib.sha256(text.encode()).digest()
            if text and digest not in seen and predicate(row):
                seen.add(digest)
                rows.append(text)
    return rows


def token_count(tokenizer, text: str) -> int:
    return len(tokenizer.encode(text, add_special_tokens=False).ids)


def fit_document(tokenizer, header: str, seed_text: str, fillers: list[str], target: int) -> str:
    pieces = [header, seed_text]
    approximate = sum(token_count(tokenizer, piece) for piece in pieces)
    while approximate < target:
        if not fillers:
            raise ValueError("not enough distinct benign source text for requested fixtures")
        piece = fillers.pop()
        pieces.append(piece)
        approximate += token_count(tokenizer, SEPARATOR + piece)

    text = SEPARATOR.join(pieces)
    actual = token_count(tokenizer, text)
    while actual < target:
        if not fillers:
            raise ValueError("not enough distinct benign source text for requested fixtures")
        pieces.append(fillers.pop())
        text = SEPARATOR.join(pieces)
        actual = token_count(tokenizer, text)

    if actual > target:
        tail = pieces.pop()
        prefix = SEPARATOR.join(pieces) + SEPARATOR
        low, high = 0, len(tail)
        while low < high:
            middle = (low + high + 1) // 2
            if token_count(tokenizer, prefix + tail[:middle]) <= target:
                low = middle
            else:
                high = middle - 1
        text = prefix + tail[:low]
    return text


def build_fixtures(args) -> list[dict]:
    from tokenizers import Tokenizer

    tokenizer = Tokenizer.from_file(str(args.tokenizer))
    rng = random.Random(args.seed)
    benign = csv_rows(args.injection_csv, lambda row: row.get("label") == "0")
    seeds = {
        "benign": benign[:],
        "injection": csv_rows(args.injection_csv, lambda row: row.get("label") == "1"),
        "threat": csv_rows(args.threat_csv, lambda row: row.get("label") != "6"),
        "sensitive": csv_rows(args.sensitive_csv),
    }
    for pool in seeds.values():
        rng.shuffle(pool)
    rng.shuffle(benign)

    fixtures = []
    per_kind = args.per_size // len(KINDS)
    if per_kind * len(KINDS) != args.per_size:
        raise ValueError("--per-size must be divisible by four")
    for target in TARGET_TOKENS:
        kinds = [kind for kind in KINDS for _ in range(per_kind)]
        rng.shuffle(kinds)
        for index, kind in enumerate(kinds):
            if not seeds[kind]:
                raise ValueError(f"not enough distinct {kind} seed rows")
            name = f"agent-{target // 1000}k-{index:03d}-{kind}"
            header = f"agent-readiness fixture {name}; source excerpts follow"
            text = fit_document(tokenizer, header, seeds[kind].pop(), benign, target)
            fixtures.append({
                "name": name,
                "target_tokens": target,
                "token_count": token_count(tokenizer, text),
                "kind": kind,
                "text": text,
            })
    return fixtures


def threat_l2_only_config(categories, operating_point):
    config = ORIGINAL_REQUEST_CONFIG(categories, operating_point)
    config["gates"]["conditional"] = [{
        "level": "L3",
        "pipeline": "threat",
        "when": {
            "metadata": {
                "path": "__benchmark_enable_threat_l3",
                "equals": True,
            },
        },
    }]
    return config


ORIGINAL_REQUEST_CONFIG = http.request_config


def run(args) -> dict:
    fixtures = [json.loads(line) for line in args.fixtures.read_text().splitlines() if line]
    http.request_config = threat_l2_only_config
    reports = {}
    overall_started = time.monotonic()
    for target in TARGET_TOKENS:
        selected = [fixture for fixture in fixtures if fixture["target_tokens"] == target]
        requests = [(fixture["name"], fixture["text"]) for fixture in selected]
        report = dynamic_dataset(args, requests, agent_batches(len(requests), args.seed + target))
        total_tokens = sum(fixture["token_count"] for fixture in selected)
        report.update({
            "target_tokens": target,
            "total_tokens": total_tokens,
            "average_tokens": round(total_tokens / len(selected), 1),
            "tokens_per_second": round(total_tokens / report["elapsed_seconds"], 1),
            "content_mix": dict(Counter(fixture["kind"] for fixture in selected)),
        })
        reports[str(target)] = report
    return {
        "profile": "agent_readiness_threat_l2_only",
        "elapsed_seconds": round(time.monotonic() - overall_started, 3),
        "by_target_tokens": reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-fixtures")
    build.add_argument("--tokenizer", type=Path, required=True)
    build.add_argument("--injection-csv", type=Path, required=True)
    build.add_argument("--threat-csv", type=Path, required=True)
    build.add_argument("--sensitive-csv", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--per-size", type=int, default=60)
    build.add_argument("--seed", type=int, default=20260828)

    execute = subparsers.add_parser("run")
    execute.add_argument("--base-url", action="append", required=True)
    execute.add_argument("--token", required=True)
    execute.add_argument("--fixtures", type=Path, required=True)
    execute.add_argument("--output", type=Path)
    execute.add_argument("--timeout-seconds", type=float, default=300.0)
    execute.add_argument("--seed", type=int, default=20260828)
    execute.add_argument("--ntdb-operating-point", default="best_promote")
    execute.set_defaults(categories=["injection", "dlp", "threat"])
    args = parser.parse_args()

    if args.command == "build-fixtures":
        fixtures = build_fixtures(args)
        args.output.write_text(
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in fixtures),
            encoding="utf-8",
        )
        print(json.dumps({
            "fixtures": len(fixtures),
            "bytes": args.output.stat().st_size,
            "token_counts": dict(Counter(item["target_tokens"] for item in fixtures)),
        }, indent=2))
        return 0

    report = run(args)
    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    return 0 if all(item["ok"] for item in report["by_target_tokens"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
