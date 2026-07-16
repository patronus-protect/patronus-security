#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Measure exact-span GLiNER quality across confidence thresholds.

The fixture intentionally contains one target entity per positive row plus a
shared set of hard negatives. Each label is inferred once at the lowest
threshold; higher thresholds are evaluated from the returned scores so the
sweep does not repeatedly execute the model.
"""

import argparse
import json
from pathlib import Path

from patronus_security import SecurityGateway


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path(__file__).parents[1]
        / "python/patronus_security/benchmark_data/dynamic_pii_threshold_sweep.jsonl",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--thresholds",
        type=float,
        nargs="+",
        default=(
            0.05,
            0.1,
            0.15,
            0.2,
            0.25,
            0.3,
            0.35,
            0.4,
            0.45,
            0.5,
            0.55,
            0.6,
            0.65,
            0.7,
            0.75,
            0.8,
        ),
    )
    return parser.parse_args()


def load_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def exact_key(entity):
    return (
        entity["label"],
        entity.get("start", entity.get("start_char")),
        entity.get("end", entity.get("end_char")),
    )


def metrics(rows, threshold):
    gold = predicted = true_positives = 0
    for row in rows:
        expected = {exact_key(entity) for entity in row["expected"]}
        actual = {
            exact_key(entity)
            for entity in row["predicted"]
            if entity.get("score", 0.0) >= threshold
        }
        gold += len(expected)
        predicted += len(actual)
        true_positives += len(expected & actual)
    precision = true_positives / predicted if predicted else 0.0
    recall = true_positives / gold if gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": threshold,
        "gold": gold,
        "predicted": predicted,
        "true_positives": true_positives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main():
    args = parse_args()
    rows = load_rows(args.fixture)
    labels = sorted({row["label"] for row in rows if row["label"] != "negative"})
    negatives = [row for row in rows if row["label"] == "negative"]
    gateway = SecurityGateway(
        categories=["dynamic-pii"],
        max_level="l3",
        model_dir=args.model_dir,
        download_files=False,
    )
    gateway.warmup()

    results = {}
    for label in labels:
        evaluation_rows = [row for row in rows if row["label"] == label] + negatives
        gateway.set_dynamic_pii_config(
            {
                "labels": [label],
                "threshold": min(args.thresholds),
                "execution_gate": {"type": "always"},
                "conditional_labels": [],
            }
        )
        measured = []
        for row in evaluation_rows:
            text = row["text"]
            expected = []
            if row["label"] == label:
                entity_text = row["entity"]
                start = text.index(entity_text)
                expected.append(
                    {
                        "label": label,
                        "start": start,
                        "end": start + len(entity_text),
                    }
                )
            scan = gateway.scan_category("dynamic-pii", text)
            dynamic = next((item for item in scan if item["category"] == "dynamic-pii"), None)
            measured.append(
                {
                    "id": row["id"],
                    "expected": expected,
                    "predicted": dynamic["evidence_spans"] if dynamic else [],
                }
            )
        sweep = [metrics(measured, threshold) for threshold in args.thresholds]
        best = max(
            sweep,
            key=lambda item: (
                item["f1"],
                item["precision"],
                item["recall"],
                item["threshold"],
            ),
        )
        results[label] = {"best": best, "sweep": sweep, "rows": measured}
        print(label, best, flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
