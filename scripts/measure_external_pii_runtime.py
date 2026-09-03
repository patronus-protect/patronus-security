#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure Ark PII-L1 or GLiNER on one frozen external-PII selection."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

from patronus_ark import SecurityGateway
from patronus_ark.external_pii_eval import ARK_OUTPUT_MAP, ark_entity_id, read_jsonl
from patronus_ark.gliner_category_map import GLINER_LABEL_THRESHOLDS


L1_METRICS = set(ARK_OUTPUT_MAP.values())
GLINER_CORE_LABELS = ["person", "organization", "date", "city", "country", "street_address"]
GLINER_PAIRWISE_LABELS = [
    "date_of_birth",
    "employee_identifier",
    "username",
    "passport_number",
    "driver_license_number",
]
GLINER_METRIC_MAP = {
    "person": "entity.person_name",
    "organization": "entity.organization",
    "date": "entity.date",
    "city": "entity.location",
    "country": "entity.location",
    "street_address": "entity.street_address",
    "date_of_birth": "pii.date_of_birth",
    "employee_identifier": "pii.employee_id",
    "username": "pii.username",
    "passport_number": "entity.passport_number",
    "driver_license_number": "entity.driver_license_number",
}


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[math.ceil(fraction * len(ordered)) - 1]


def score(gold: set[tuple[int, int]], predicted: set[tuple[int, int]], *, overlap: bool) -> dict:
    remaining = set(gold)
    true_positives = 0
    for candidate in sorted(predicted):
        match = next(
            (
                expected
                for expected in sorted(remaining)
                if candidate == expected
                or (overlap and candidate[0] < expected[1] and expected[0] < candidate[1])
            ),
            None,
        )
        if match is not None:
            remaining.remove(match)
            true_positives += 1
    precision = true_positives / len(predicted) if predicted else 0.0
    recall = true_positives / len(gold) if gold else 0.0
    return {
        "gold": len(gold),
        "predicted": len(predicted),
        "true_positives": true_positives,
        "false_positives": len(predicted) - true_positives,
        "false_negatives": len(gold) - true_positives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0,
    }


def combined_score(items: list[tuple[set[tuple[int, int]], set[tuple[int, int]]]], *, overlap: bool) -> dict:
    totals = defaultdict(int)
    for gold, predicted in items:
        measured = score(gold, predicted, overlap=overlap)
        for key in ("gold", "predicted", "true_positives", "false_positives", "false_negatives"):
            totals[key] += measured[key]
    precision = totals["true_positives"] / totals["predicted"] if totals["predicted"] else 0.0
    recall = totals["true_positives"] / totals["gold"] if totals["gold"] else 0.0
    return {
        **totals,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--arm", choices=("l1", "gliner-core", "gliner-pairwise"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-dir")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = {row["id"]: row for row in read_jsonl(args.gold)}
    selection = json.loads(args.selection.read_text(encoding="utf-8"))
    if args.arm == "l1":
        labels = []
        metrics = L1_METRICS
        gateway = SecurityGateway(categories=["pii"], max_level="l1", download_files=False)
        category = "pii"
    else:
        labels = GLINER_CORE_LABELS if args.arm == "gliner-core" else GLINER_PAIRWISE_LABELS
        metrics = {GLINER_METRIC_MAP[label] for label in labels}
        config = {
            "labels": labels,
            "threshold": 0.5,
            "label_thresholds": {
                label: GLINER_LABEL_THRESHOLDS[label]
                for label in labels
                if label in GLINER_LABEL_THRESHOLDS
            },
            "execution_gate": {"type": "always"},
            "conditional_labels": [],
        }
        gateway = SecurityGateway(
            categories=["dynamic-pii"],
            max_level="l3",
            download_files=False,
            dynamic_pii_config=config,
            **({"model_dir": args.model_dir} if args.model_dir else {}),
        )
        gateway.warmup()
        category = "dynamic-pii"

    chosen = {
        item["metric_id"]: item
        for item in selection["selections"]
        if item["metric_id"] in metrics
    }
    document_ids = sorted({identifier for item in chosen.values() for identifier in item["selected_document_ids"]})
    missing = set(document_ids) - rows.keys()
    if missing:
        raise ValueError(f"selection contains {len(missing)} unknown document ids")

    predictions: dict[str, set[tuple[str, int, int]]] = {}
    latencies = []
    text_bytes = []
    for index, identifier in enumerate(document_ids, 1):
        text = rows[identifier]["text"]
        started = time.perf_counter()
        results = gateway.scan_category(category, text)
        latencies.append((time.perf_counter() - started) * 1000)
        text_bytes.append(len(text.encode("utf-8")))
        found = set()
        for result in results:
            for span in result.get("evidence_spans", []):
                raw_label = str(span.get("label", ""))
                metric = (
                    ARK_OUTPUT_MAP.get(raw_label, ark_entity_id(raw_label))
                    if args.arm == "l1"
                    else GLINER_METRIC_MAP.get(raw_label)
                )
                if metric in metrics:
                    found.add((metric, int(span["start_char"]), int(span["end_char"])))
        predictions[identifier] = found
        if index % 50 == 0 or index == len(document_ids):
            print(f"{args.arm}: {index}/{len(document_ids)} documents", file=sys.stderr, flush=True)

    report_metrics = {}
    overall_exact = []
    overall_overlap = []
    for metric, item in sorted(chosen.items()):
        selected_gold = defaultdict(set)
        for span in item["selected_spans"]:
            selected_gold[span["id"]].add((int(span["start"]), int(span["end"])))
        per_document = []
        per_language = defaultdict(list)
        for identifier in item["selected_document_ids"]:
            gold = selected_gold[identifier]
            predicted = {
                (start, end)
                for predicted_metric, start, end in predictions[identifier]
                if predicted_metric == metric
            }
            pair = (gold, predicted)
            per_document.append(pair)
            per_language[rows[identifier]["language"]].append(pair)
        exact = combined_score(per_document, overlap=False)
        relaxed = combined_score(per_document, overlap=True)
        report_metrics[metric] = {
            "documents": len(item["selected_document_ids"]),
            "exact": exact,
            "overlap": relaxed,
            "per_language": {
                language: {
                    "exact": combined_score(pairs, overlap=False),
                    "overlap": combined_score(pairs, overlap=True),
                }
                for language, pairs in sorted(per_language.items())
            },
        }
        overall_exact.extend(per_document)
        overall_overlap.extend(per_document)

    output = {
        "schema": "ark-external-pii-runtime-measurement-v1",
        "arm": args.arm,
        "corpus": selection["corpus"],
        "revision": selection["revision"],
        "selection_seed": selection["seed"],
        "labels": labels,
        "label_thresholds": {
            label: GLINER_LABEL_THRESHOLDS[label]
            for label in labels
            if label in GLINER_LABEL_THRESHOLDS
        },
        "documents": len(document_ids),
        "text_bytes": {
            "total": sum(text_bytes),
            "median": round(statistics.median(text_bytes), 1) if text_bytes else 0.0,
            "p95": round(percentile(text_bytes, 0.95), 1),
            "max": max(text_bytes, default=0),
        },
        "latency_ms": {
            "total": round(sum(latencies), 1),
            "mean": round(statistics.mean(latencies), 1) if latencies else 0.0,
            "median": round(statistics.median(latencies), 1) if latencies else 0.0,
            "p95": round(percentile(latencies, 0.95), 1),
            "max": round(max(latencies), 1) if latencies else 0.0,
        },
        "overall": {
            "exact": combined_score(overall_exact, overlap=False),
            "overlap": combined_score(overall_overlap, overlap=True),
        },
        "metrics": report_metrics,
    }
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
