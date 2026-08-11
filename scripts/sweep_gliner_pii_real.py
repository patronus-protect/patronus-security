#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Calibrate GLiNER ``dynamic-pii`` thresholds on a real PII corpus.

Unlike ``sweep_gliner_pii.py`` (small synthetic fixtures with exact-span
matching), this sweep runs against a real, human/agent-realistic PII dataset
such as ``Ai4Privacy/pii-masking-300k``. Records are ``{"source_text", ...,
"privacy_mask": [{"value", "start", "end", "label"}, ...]}`` with character
offsets.

The dataset is *not* redistributed with this repository (its upstream license
is restrictive); point ``--fixture`` at a locally downloaded split, e.g. the
English validation JSONL from the Hugging Face cache.

Real-corpus span boundaries follow the dataset's own annotation conventions,
which rarely coincide exactly with GLiNER word boundaries (e.g. GLiNER may emit
``"Barcelona"`` where the gold span is ``"Barcelona city"``). Selecting a
threshold on *exact*-span F1 would therefore penalise correct detections for
boundary style alone. This sweep selects on **relaxed** (label-matched span
overlap) F1 and additionally reports exact-span F1 for reference.

Each of our canonical labels is mapped to one or more dataset labels. For a
target label the positives are rows containing at least one mapped gold span;
the negatives are rows that contain other PII but none of the mapped spans
(hard negatives). Each label is inferred once at the lowest threshold; higher
thresholds are evaluated from the returned scores without re-running the model.
"""

import argparse
import json
import random
from pathlib import Path

from patronus_ark import SecurityGateway

# Canonical dynamic-pii label -> dataset (Ai4Privacy) source labels it maps to.
# Only labels with clean, single-span gold annotations in the corpus are listed;
# labels the deterministic native-L1 layer already owns (email, ip, phone, iban,
# card) are intentionally excluded from GLiNER calibration.
DEFAULT_LABEL_MAP = {
    # New semantic-gap labels.
    "first_name": ["GIVENNAME1", "GIVENNAME2"],
    "last_name": ["LASTNAME1", "LASTNAME2", "LASTNAME3"],
    "date_of_birth": ["BOD"],
    "city": ["CITY"],
    "state_or_region": ["STATE"],
    "postal_code": ["POSTCODE"],
    "country": ["COUNTRY"],
    "national_id_number": ["IDCARD", "SOCIALNUMBER"],
    "password": ["PASS"],
    # Existing labels re-calibrated on real data.
    "username": ["USERNAME"],
    "passport_number": ["PASSPORT"],
    "driver_license_number": ["DRIVERLICENSE"],
    "date": ["DATE"],
    "street_address": ["STREET"],
}

DEFAULT_THRESHOLDS = tuple(round(0.05 * i, 2) for i in range(1, 17))  # 0.05..0.80


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", default=None)
    parser.add_argument(
        "--fixture",
        type=Path,
        required=True,
        help="JSONL split with source_text + privacy_mask (char offsets).",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--labels",
        nargs="+",
        default=None,
        help="Subset of canonical labels to sweep (default: all mapped).",
    )
    parser.add_argument("--max-positives", type=int, default=200)
    parser.add_argument("--max-negatives", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--thresholds", type=float, nargs="+", default=DEFAULT_THRESHOLDS)
    return parser.parse_args()


def load_rows(path):
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        text = record.get("source_text") or record.get("text") or ""
        mask = record.get("privacy_mask") or []
        spans = [
            (int(m["start"]), int(m["end"]), str(m["label"]))
            for m in mask
            if m.get("label") is not None
        ]
        rows.append({"text": text, "spans": spans})
    return rows


def build_examples(rows, source_labels, max_positives, max_negatives, rng):
    wanted = set(source_labels)
    positives, negatives = [], []
    for row in rows:
        gold = [(s, e) for (s, e, label) in row["spans"] if label in wanted]
        if gold:
            positives.append({"text": row["text"], "gold": gold})
        elif row["spans"]:  # has other PII -> hard negative
            negatives.append({"text": row["text"], "gold": []})
    rng.shuffle(positives)
    rng.shuffle(negatives)
    return positives[:max_positives], negatives[:max_negatives]


def _overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def _match(gold, predicted, exact):
    """Greedy one-to-one match. Returns (true_positives)."""
    used = [False] * len(gold)
    tp = 0
    for pred in predicted:
        for index, span in enumerate(gold):
            if used[index]:
                continue
            hit = (pred == span) if exact else _overlaps(pred, span)
            if hit:
                used[index] = True
                tp += 1
                break
    return tp


def metrics(measured, threshold, exact):
    gold_total = predicted_total = tp_total = 0
    for item in measured:
        gold = item["gold"]
        predicted = [
            (span["start_char"], span["end_char"])
            for span in item["predicted"]
            if span["score"] >= threshold
        ]
        gold_total += len(gold)
        predicted_total += len(predicted)
        tp_total += _match(gold, predicted, exact)
    precision = tp_total / predicted_total if predicted_total else 0.0
    recall = tp_total / gold_total if gold_total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": round(threshold, 4),
        "gold": gold_total,
        "predicted": predicted_total,
        "true_positives": tp_total,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main():
    args = parse_args()
    rng = random.Random(args.seed)
    rows = load_rows(args.fixture)
    label_map = DEFAULT_LABEL_MAP
    labels = args.labels or list(label_map)

    gateway = SecurityGateway(
        categories=["dynamic-pii"],
        max_level="l3",
        download_files=False,
        **({"model_dir": args.model_dir} if args.model_dir else {}),
    )
    gateway.warmup()

    min_threshold = min(args.thresholds)
    results = {}
    for label in labels:
        source_labels = label_map[label]
        positives, negatives = build_examples(
            rows, source_labels, args.max_positives, args.max_negatives, rng
        )
        gateway.set_dynamic_pii_config(
            {
                "labels": [label],
                "threshold": min_threshold,
                "execution_gate": {"type": "always"},
                "conditional_labels": [],
            }
        )
        measured = []
        for example in positives + negatives:
            scan = gateway.scan_category("dynamic-pii", example["text"])
            dynamic = next(
                (item for item in scan if item["category"] == "dynamic-pii"), None
            )
            measured.append(
                {
                    "gold": example["gold"],
                    "predicted": dynamic["evidence_spans"] if dynamic else [],
                }
            )

        relaxed = [metrics(measured, t, exact=False) for t in args.thresholds]
        exact = [metrics(measured, t, exact=True) for t in args.thresholds]
        best = max(
            relaxed,
            key=lambda item: (
                item["f1"],
                item["precision"],
                item["recall"],
                item["threshold"],
            ),
        )
        exact_at_best = next(
            item for item in exact if item["threshold"] == best["threshold"]
        )
        results[label] = {
            "source_labels": source_labels,
            "positives": len(positives),
            "negatives": len(negatives),
            "best": best,
            "exact_at_best": exact_at_best,
            "sweep_relaxed": relaxed,
            "sweep_exact": exact,
        }
        print(
            f"{label:<24} thr={best['threshold']:<4} "
            f"P={best['precision']:.3f} R={best['recall']:.3f} F1={best['f1']:.3f} "
            f"(exact F1={exact_at_best['f1']:.3f}, n+={len(positives)} n-={len(negatives)})",
            flush=True,
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(f"\nwrote {args.output}")


if __name__ == "__main__":
    main()
