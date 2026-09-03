#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure Ark against the augmented PII/DLP live-demo Golden set."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GOLD = ROOT / "python/patronus_ark/benchmark_data/demo_pii_dlp.jsonl"
BLIND_GOLDENS = (
    ROOT / "python/patronus_ark/benchmark_data/demo_pii_dlp_blind_de.jsonl",
    ROOT / "python/patronus_ark/benchmark_data/demo_pii_dlp_blind_en_tech.jsonl",
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def entity_span(row: dict, entity: dict) -> tuple[int, int]:
    value = entity["text"]
    start = row["text"].find(value)
    if start < 0 or row["text"].find(value, start + 1) >= 0:
        raise ValueError(f"{row['id']}: entity text must occur exactly once: {value!r}")
    return start, start + len(value)


def validate_rows(rows: list[dict]) -> None:
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("demo Golden IDs must be unique")
    for row in rows:
        if row["suite"] != "demo_pii_dlp":
            raise ValueError(f"{row['id']}: unexpected suite")
        if row["scenario"] not in {"customer_data", "source_code", "personnel_record"}:
            raise ValueError(f"{row['id']}: unexpected scenario")
        if row["language"] not in {"de", "en"}:
            raise ValueError(f"{row['id']}: unexpected language")
        if row["case_type"] not in {"live_demo", "augmented", "hard_negative"}:
            raise ValueError(f"{row['id']}: unexpected case type")
        for entity in row["entities"]:
            if entity["pipeline"] not in {"pii", "dlp", "dynamic-pii"}:
                raise ValueError(f"{row['id']}: unexpected entity pipeline")
            entity_span(row, entity)


def expected_spans(rows: list[dict], pipelines: set[str]) -> set[tuple[str, str, int, int]]:
    expected = set()
    for row in rows:
        for entity in row["entities"]:
            if entity["pipeline"] in pipelines:
                start, end = entity_span(row, entity)
                expected.add((row["id"], entity["label"], start, end))
    return expected


def score(
    gold: set[tuple[str, str, int, int]],
    predicted: set[tuple[str, str, int, int]],
    *,
    overlap: bool,
) -> dict:
    remaining = set(gold)
    true_positives = 0
    for candidate in sorted(predicted):
        row_id, label, start, end = candidate
        match = next(
            (
                expected
                for expected in sorted(remaining)
                if expected[0] == row_id
                and expected[1] == label
                and (
                    (expected[2], expected[3]) == (start, end)
                    or (overlap and start < expected[3] and expected[2] < end)
                )
            ),
            None,
        )
        if match is not None:
            remaining.remove(match)
            true_positives += 1
    false_positives = len(predicted) - true_positives
    false_negatives = len(gold) - true_positives
    precision = true_positives / len(predicted) if predicted else 0.0
    recall = true_positives / len(gold) if gold else 0.0
    return {
        "gold": len(gold),
        "predicted": len(predicted),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0,
    }


def score_report(
    rows: list[dict],
    pipelines: set[str],
    predicted: set[tuple[str, str, int, int]],
    *,
    target_labels: set[str] | None = None,
) -> dict:
    gold = expected_spans(rows, pipelines)
    labels = sorted(target_labels or {span[1] for span in gold})
    target_predictions = {span for span in predicted if span[1] in labels}
    unexpected = Counter(span[1] for span in predicted if span[1] not in labels)
    text_by_id = {row["id"]: row["text"] for row in rows}
    return {
        "exact": score(gold, target_predictions, overlap=False),
        "overlap": score(gold, target_predictions, overlap=True),
        "per_label_exact": {
            label: score(
                {span for span in gold if span[1] == label},
                {span for span in target_predictions if span[1] == label},
                overlap=False,
            )
            for label in labels
        },
        "unexpected_predictions": dict(sorted(unexpected.items())),
        "missed_exact": [
            {"id": row_id, "label": label, "text": text_by_id[row_id][start:end]}
            for row_id, label, start, end in sorted(gold - target_predictions)
        ],
        "false_positive_exact": [
            {"id": row_id, "label": label, "text": text_by_id[row_id][start:end]}
            for row_id, label, start, end in sorted(target_predictions - gold)
        ],
    }


def score_with_slices(
    rows: list[dict],
    pipelines: set[str],
    predicted: set[tuple[str, str, int, int]],
) -> dict:
    report = score_report(rows, pipelines, predicted)
    target_labels = {span[1] for span in expected_spans(rows, pipelines)}
    for field in ("case_type", "scenario"):
        values = sorted({row[field] for row in rows})
        report[f"by_{field}"] = {}
        for value in values:
            selected = [row for row in rows if row[field] == value]
            selected_ids = {row["id"] for row in selected}
            selected_predictions = {span for span in predicted if span[0] in selected_ids}
            report[f"by_{field}"][value] = score_report(
                selected,
                pipelines,
                selected_predictions,
                target_labels=target_labels,
            )["exact"]
    return report


def collect_predictions(gateway, rows: list[dict], categories: tuple[str, ...]) -> set[tuple[str, str, int, int]]:
    predictions = set()
    for row in rows:
        for category in categories:
            for result in gateway.scan_category(category, row["text"]):
                predictions.update(
                    (row["id"], span["label"], int(span["start_char"]), int(span["end_char"]))
                    for span in result["evidence_spans"]
                )
    return predictions


def measure_l1(rows: list[dict]) -> dict:
    from patronus_ark import SecurityGateway

    gateway = SecurityGateway(categories=["pii", "dlp"], max_level="l1", download_files=False)
    # This benchmark measures the full detector inventory, not the default profile.
    source = (ROOT / "rust/src/detectors/dlp/dlp.rs").read_text()
    gateway.set_execution_gates({"rules": {
        rule_id: True for rule_id in re.findall(r'name: "(dlp_[^"]+)"', source)
    }})
    predictions = collect_predictions(gateway, rows, ("pii", "dlp"))
    return score_with_slices(rows, {"pii", "dlp"}, predictions)


def measure_gliner(rows: list[dict], model_dir: str | None) -> dict:
    from patronus_ark import SecurityGateway

    gateway = SecurityGateway(
        categories=["dynamic-pii"],
        max_level="l3",
        download_files=False,
        **({"model_dir": model_dir} if model_dir else {}),
    )
    gateway.warmup()
    predictions = collect_predictions(gateway, rows, ("dynamic-pii",))
    return score_with_slices(rows, {"dynamic-pii"}, predictions)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    parser.add_argument(
        "--include-blind-goldens",
        action="store_true",
        help="Include the implementation-blind DE and EN/Tech demo extensions.",
    )
    parser.add_argument("--arm", choices=("l1", "gliner", "all"), default="all")
    parser.add_argument("--model-dir")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    paths = [args.gold, *BLIND_GOLDENS] if args.include_blind_goldens else [args.gold]
    rows = [row for path in paths for row in read_jsonl(path)]
    validate_rows(rows)
    report = {
        "schema": "ark-demo-pii-dlp-measurement-v1",
        "gold": {
            "documents": len(rows),
            "entities": sum(len(row["entities"]) for row in rows),
            "scenarios": dict(sorted(Counter(row["scenario"] for row in rows).items())),
            "languages": dict(sorted(Counter(row["language"] for row in rows).items())),
            "case_types": dict(sorted(Counter(row["case_type"] for row in rows).items())),
        },
    }
    if args.arm in {"l1", "all"}:
        report["l1"] = measure_l1(rows)
    if args.arm in {"gliner", "all"}:
        report["gliner"] = measure_gliner(rows, args.model_dir)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
