#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure Ark DLP-L1 on the frozen external source-code and SQL goldens."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable


SOURCE_LABEL = "dlp.content.source_code"
SQL_LABEL = "dlp.content.sql"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def score_source_documents(rows: Iterable[dict], detected_ids: set[str]) -> dict:
    totals = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for row in rows:
        positive = row.get("document_label") == SOURCE_LABEL
        detected = row["id"] in detected_ids
        bucket = "tp" if positive and detected else "fn" if positive else "fp" if detected else "tn"
        totals[bucket] += 1
    positives = totals["tp"] + totals["fn"]
    negatives = totals["fp"] + totals["tn"]
    return {
        **totals,
        "recall": totals["tp"] / positives if positives else 0.0,
        "negative_document_fpr": totals["fp"] / negatives if negatives else 0.0,
    }


def score_sql_spans(rows: Iterable[dict], predictions: dict[str, set[tuple[int, int]]]) -> dict:
    gold: dict[str, set[tuple[int, int]]] = defaultdict(set)
    for row in rows:
        for entity in row.get("entities", []):
            if entity["entity_type"] == SQL_LABEL:
                gold[row["source_path"]].add((int(entity["start"]), int(entity["end"])))

    exact_hits = 0
    overlap_hits = 0
    for source_path, expected in gold.items():
        predicted = predictions.get(source_path, set())
        exact_hits += len(expected & predicted)
        overlap_hits += sum(
            any(start < predicted_end and predicted_start < end for predicted_start, predicted_end in predicted)
            for start, end in expected
        )
    total = sum(len(spans) for spans in gold.values())
    return {
        "documents": len(gold),
        "gold": total,
        "predicted_unscoped": sum(len(spans) for spans in predictions.values()),
        "exact_hits": exact_hits,
        "overlap_hits": overlap_hits,
        "exact_recall": exact_hits / total if total else 0.0,
        "overlap_recall": overlap_hits / total if total else 0.0,
        "precision": "not_reported_incomplete_gold_after_cap",
    }


def measure(gitleaks_rows: list[dict], schemapile_rows: list[dict]) -> dict:
    from patronus_ark import SecurityGateway

    gateway = SecurityGateway(categories=["dlp"], max_level="l1", download_files=False)
    detected_source_ids = set()
    for row in gitleaks_rows:
        results = gateway.scan_category("dlp", row["text"])
        if any(
            span["label"] == SOURCE_LABEL
            for result in results
            for span in result["evidence_spans"]
        ):
            detected_source_ids.add(row["id"])

    documents = {}
    for row in schemapile_rows:
        documents.setdefault(row["source_path"], row["text"])
    sql_predictions = {}
    for source_path, text in documents.items():
        results = gateway.scan_category("dlp", text)
        sql_predictions[source_path] = {
            (int(span["start_char"]), int(span["end_char"]))
            for result in results
            for span in result["evidence_spans"]
            if span["label"] == SQL_LABEL
        }

    return {
        "schema": "ark-external-dlp-runtime-measurement-v1",
        "source_code": {
            "corpus": gitleaks_rows[0]["corpus"] if gitleaks_rows else None,
            "task": "derived_source_code_document",
            **score_source_documents(gitleaks_rows, detected_source_ids),
        },
        "sql": {
            "corpus": schemapile_rows[0]["corpus"] if schemapile_rows else None,
            "task": "derived_sql_statement_boundaries",
            **score_sql_spans(schemapile_rows, sql_predictions),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", type=Path, required=True)
    parser.add_argument("--schemapile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = measure(read_jsonl(args.gitleaks), read_jsonl(args.schemapile))
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
