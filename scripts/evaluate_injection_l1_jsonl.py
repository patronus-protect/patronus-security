#!/usr/bin/env python3
"""Evaluate the public native Injection-L1 decision on labeled JSONL corpora."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from patronus_ark import SecurityGateway


def read_texts(path: Path) -> list[str]:
    texts = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            text = row.get("text")
            if not isinstance(text, str):
                raise ValueError(f"{path}:{line_number}: missing string field 'text'")
            texts.append(text)
    return texts


def scan_corpus(gateway: SecurityGateway, texts: list[str]) -> dict[str, int]:
    candidate_documents = 0
    accepted_documents = 0
    for text in texts:
        results = gateway.scan_category("injection", text)
        native = [result for result in results if result["model"] == "native:injection_l1"]
        if len(native) != 1:
            raise RuntimeError(f"expected one native Injection L1 result, got {len(native)}")
        result = native[0]
        candidates = result["layers"][0]["details"].get("l1_candidates", [])
        candidate_documents += bool(candidates)
        accepted_documents += result["class_name"] != "safe"
    return {
        "documents": len(texts),
        "candidate_documents": candidate_documents,
        "accepted_documents": accepted_documents,
    }


def metrics(positive: dict[str, int], negative: dict[str, int]) -> dict[str, float | int]:
    tp = positive["accepted_documents"]
    fn = positive["documents"] - tp
    fp = negative["accepted_documents"]
    tn = negative["documents"] - fp
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--positive", type=Path, required=True)
    parser.add_argument("--negative", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--min-recall", type=float)
    parser.add_argument("--max-false-positives", type=int)
    args = parser.parse_args()
    if args.output and args.output.exists():
        parser.error(f"refusing to overwrite {args.output}")

    gateway = SecurityGateway(categories=["injection"], max_level="l1", download_files=False)
    gateway.warmup()
    positive = scan_corpus(gateway, read_texts(args.positive))
    negative = scan_corpus(gateway, read_texts(args.negative))
    report = {
        "model": "native:injection_l1",
        "positive": positive,
        "negative": negative,
        "metrics": metrics(positive, negative),
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.min_recall is not None and report["metrics"]["recall"] < args.min_recall:
        raise SystemExit("minimum recall gate failed")
    if (
        args.max_false_positives is not None
        and report["metrics"]["fp"] > args.max_false_positives
    ):
        raise SystemExit("maximum false-positive gate failed")


if __name__ == "__main__":
    main()
