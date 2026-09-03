#!/usr/bin/env python3
"""Evaluate private, human-verified PII span sidecars without exporting text.

This tool deliberately does not read document-class labels.  Gold annotations
and detector predictions are separate JSONL files keyed by an opaque document
id.  The annotation file stays in the controlled dataset location; reports
contain counts and metrics only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


REQUIRED_ANNOTATION_KINDS = {"verified_span", "verified_no_pii"}


def jsonl_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"{path}:{line_number}: invalid JSON") from error


def span_key(span: dict[str, Any]) -> tuple[str, int, int]:
    label = span.get("label")
    start = span.get("start", span.get("start_char"))
    end = span.get("end", span.get("end_char"))
    if not isinstance(label, str) or not isinstance(start, int) or not isinstance(end, int):
        raise ValueError("each entity needs string label and integer character start/end")
    if start < 0 or end <= start:
        raise ValueError("entity offsets must be a non-empty half-open interval")
    return label, start, end


def validate_gold(row: dict[str, Any]) -> None:
    forbidden = {"text", "expected_class", "document_label", "sensitive_label"} & row.keys()
    if forbidden:
        raise ValueError(f"gold row {row.get('id')!r} contains forbidden fields: {sorted(forbidden)}")
    if row.get("annotation_kind") not in REQUIRED_ANNOTATION_KINDS:
        raise ValueError("gold rows require annotation_kind=verified_span or verified_no_pii")
    for field in ("id", "corpus", "language", "document_sha256"):
        if not isinstance(row.get(field), str) or not row[field]:
            raise ValueError(f"gold row needs non-empty {field}")
    if len(row["document_sha256"]) != 64:
        raise ValueError("document_sha256 must be a SHA-256 hex digest")
    try:
        int(row["document_sha256"], 16)
    except ValueError as error:
        raise ValueError("document_sha256 must be a SHA-256 hex digest") from error
    entities = row.get("entities")
    if not isinstance(entities, list):
        raise ValueError("gold rows require entities list")
    if row["annotation_kind"] == "verified_no_pii" and entities:
        raise ValueError("verified_no_pii rows must contain no entities")
    if row["annotation_kind"] == "verified_span" and not entities:
        raise ValueError("empty span gold must be explicitly verified_no_pii")
    if len({span_key(entity) for entity in entities}) != len(entities):
        raise ValueError("gold row contains duplicate entities")


def metrics(gold: set[tuple[str, int, int]], predicted: set[tuple[str, int, int]]) -> dict[str, Any]:
    true_positives = len(gold & predicted)
    false_positives = len(predicted - gold)
    false_negatives = len(gold - predicted)
    precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 0.0
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 0.0
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0,
    }


def evaluate(gold_rows: Iterable[dict[str, Any]], prediction_rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    gold_by_id: dict[str, dict[str, Any]] = {}
    for row in gold_rows:
        validate_gold(row)
        if row["id"] in gold_by_id:
            raise ValueError(f"duplicate gold id {row['id']!r}")
        gold_by_id[row["id"]] = row

    predictions: dict[str, set[tuple[str, int, int]]] = {}
    for row in prediction_rows:
        identifier = row.get("id")
        if identifier not in gold_by_id:
            raise ValueError(f"prediction has unknown id {identifier!r}")
        if identifier in predictions:
            raise ValueError(f"duplicate prediction id {identifier!r}")
        entities = row.get("entities", row.get("evidence_spans"))
        if not isinstance(entities, list):
            raise ValueError("prediction rows require entities or evidence_spans list")
        predictions[identifier] = {span_key(entity) for entity in entities}

    if set(predictions) != set(gold_by_id):
        missing = sorted(set(gold_by_id) - set(predictions))
        raise ValueError(f"predictions missing {len(missing)} gold ids")

    buckets: dict[tuple[str, ...], list[set[tuple[str, int, int]]]] = defaultdict(lambda: [set(), set()])
    for identifier, row in gold_by_id.items():
        gold = {span_key(entity) for entity in row["entities"]}
        predicted = predictions[identifier]
        dimensions = [
            ("overall",),
            ("corpus", row["corpus"]),
            ("language", row["language"]),
        ]
        for label in {item[0] for item in gold | predicted}:
            dimensions.append(("entity", label))
            dimensions.append(("corpus_entity", row["corpus"], label))
            dimensions.append(("language_entity", row["language"], label))
        for key in dimensions:
            if key[0] in {"entity", "corpus_entity", "language_entity"}:
                label = key[-1]
                expected = {item for item in gold if item[0] == label}
                actual = {item for item in predicted if item[0] == label}
            else:
                expected, actual = gold, predicted
            buckets[key][0].update((identifier, *item) for item in expected)
            buckets[key][1].update((identifier, *item) for item in actual)

    report = {"schema_version": 1, "metric": "exact_label_and_unicode_code_point_span"}
    report["rows"] = len(gold_by_id)
    report["slices"] = {
        "/".join(key): metrics(set(items[0]), set(items[1]))
        for key, items in sorted(buckets.items())
    }
    return report


def sample_manifest(source: Path, output: Path, corpus: str, limit: int, seed: str, text_field: str) -> dict[str, Any]:
    """Create a text-free review manifest; this is discovery, never span gold."""
    candidates = []
    identifiers = set()
    for index, row in enumerate(jsonl_rows(source)):
        text = row.get(text_field)
        if not isinstance(text, str) or not text:
            continue
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        identifier = str(row.get("id", f"line-{index + 1}"))
        if identifier in identifiers:
            raise ValueError(f"source contains duplicate id {identifier!r}")
        identifiers.add(identifier)
        rank = hashlib.sha256(f"{seed}:{identifier}:{digest}".encode()).hexdigest()
        candidates.append((rank, identifier, digest))
    selected = sorted(candidates)[:limit]
    rows = [
        {
            "id": identifier,
            "corpus": corpus,
            "document_sha256": digest,
            "review_role": "requires_human_span_annotation",
            "not_gold_until": "annotation_kind is verified_span or verified_no_pii",
        }
        for _, identifier, digest in selected
    ]
    output.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + ("\n" if rows else ""), encoding="utf-8")
    return {"candidates": len(candidates), "sampled": len(rows), "output": str(output)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = commands.add_parser("evaluate")
    evaluate_parser.add_argument("--gold", type=Path, required=True)
    evaluate_parser.add_argument("--predictions", type=Path, required=True)
    evaluate_parser.add_argument("--output", type=Path, required=True)
    sample_parser = commands.add_parser("sample")
    sample_parser.add_argument("--source", type=Path, required=True)
    sample_parser.add_argument("--output", type=Path, required=True)
    sample_parser.add_argument("--corpus", required=True)
    sample_parser.add_argument("--limit", type=int, required=True)
    sample_parser.add_argument("--seed", default="ark-internal-pii-v1")
    sample_parser.add_argument("--text-field", default="text")
    args = parser.parse_args()
    if args.command == "sample" and args.limit < 1:
        parser.error("sample --limit must be positive")
    if args.command == "evaluate":
        report = evaluate(jsonl_rows(args.gold), jsonl_rows(args.predictions))
    else:
        report = sample_manifest(args.source, args.output, args.corpus, args.limit, args.seed, args.text_field)
    if args.command == "evaluate":
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
