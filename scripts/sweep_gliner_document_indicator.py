#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Evaluate GLiNER span scores as a binary document-level indicator."""

import argparse
import json
from pathlib import Path

from patronus_security import SecurityGateway


INDICATORS = (
    "individual_education_record",
    "student_academic_record",
    "confidential_student_information",
    "student_personal_data",
    "individual_student_information",
    "student_sensitive_information",
    "individual_student_record",
    "personenbezogene_bildungsakte",
    "personenbezogene_studierendendaten",
    "individuelle_schuelerdaten",
)

IDENTITY_LABELS = (
    "person",
    "student_identifier",
    "applicant_identifier",
    "research_participant_identifier",
    "parent_or_guardian",
)

EDUCATION_ENTITY_LABELS = (
    "student_identifier",
    "applicant_identifier",
    "academic_grade",
    "exam_result",
    "parent_or_guardian",
    "degree_program",
    "financial_aid",
    "research_participant_identifier",
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path(__file__).parents[1]
        / "python/patronus_security/benchmark_data/education_document_indicator.jsonl",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-fpr", type=float, default=0.1)
    return parser.parse_args()


def binary_metrics(rows, threshold):
    return binary_metrics_for_predictions(
        rows,
        [row["score"] >= threshold for row in rows],
        {"threshold": threshold},
    )


def binary_metrics_for_predictions(rows, predictions, parameters):
    tp = fp = tn = fn = 0
    for row, predicted in zip(rows, predictions):
        if row["positive"] and predicted:
            tp += 1
        elif row["positive"]:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        **parameters,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "f1": round(f1, 4),
    }


def select_operating_point(sweep, max_fpr):
    feasible = [item for item in sweep if item["fpr"] <= max_fpr]
    candidates = feasible or sweep
    return max(
        candidates,
        key=lambda item: (
            item["recall"],
            item["precision"],
            item.get("threshold", item.get("semantic_threshold", 0.0)),
            item.get("identity_threshold", 0.0),
        ),
    )


def main():
    args = parse_args()
    rows = [
        json.loads(line)
        for line in args.fixture.read_text().splitlines()
        if line.strip()
    ]
    gateway = SecurityGateway(
        categories=["dynamic-pii"],
        max_level="l3",
        model_dir=args.model_dir,
        download_files=False,
    )
    gateway.warmup()
    thresholds = [round(value / 100, 2) for value in range(5, 96, 5)]
    results = {}
    all_scores = {row["id"]: [] for row in rows}
    indicator_scores = {}

    for indicator in INDICATORS:
        gateway.set_dynamic_pii_config(
            {
                "labels": [indicator],
                "threshold": 0.05,
                "execution_gate": {"type": "always"},
                "conditional_labels": [],
            }
        )
        scored = []
        for row in rows:
            scan = gateway.scan_category("dynamic-pii", row["text"])
            dynamic = next(
                (item for item in scan if item["category"] == "dynamic-pii"), None
            )
            spans = dynamic["evidence_spans"] if dynamic else []
            score = max((span["score"] for span in spans), default=0.0)
            all_scores[row["id"]].append(score)
            scored.append({**row, "score": score, "spans": spans})
        sweep = [binary_metrics(scored, threshold) for threshold in thresholds]
        best = select_operating_point(sweep, args.max_fpr)
        results[indicator] = {"best": best, "sweep": sweep, "rows": scored}
        indicator_scores[indicator] = {row["id"]: row["score"] for row in scored}
        print(indicator, best, flush=True)

    ensemble = [
        {**row, "score": max(all_scores[row["id"]])}
        for row in rows
    ]
    sweep = [binary_metrics(ensemble, threshold) for threshold in thresholds]
    best = select_operating_point(sweep, args.max_fpr)
    results["max_score_ensemble"] = {"best": best, "sweep": sweep, "rows": ensemble}
    print("max_score_ensemble", best, flush=True)

    entity_scores = {row["id"]: {} for row in rows}
    for label in dict.fromkeys(IDENTITY_LABELS + EDUCATION_ENTITY_LABELS):
        gateway.set_dynamic_pii_config(
            {
                "labels": [label],
                "threshold": 0.05,
                "execution_gate": {"type": "always"},
                "conditional_labels": [],
            }
        )
        for row in rows:
            scan = gateway.scan_category("dynamic-pii", row["text"])
            dynamic = next(
                (item for item in scan if item["category"] == "dynamic-pii"), None
            )
            spans = dynamic["evidence_spans"] if dynamic else []
            entity_scores[row["id"]][label] = max(
                (span["score"] for span in spans), default=0.0
            )

    education_entity_ensemble = [
        {
            **row,
            "score": max(
                entity_scores[row["id"]][label]
                for label in EDUCATION_ENTITY_LABELS
            ),
        }
        for row in rows
    ]
    sweep = [
        binary_metrics(education_entity_ensemble, threshold)
        for threshold in thresholds
    ]
    best = select_operating_point(sweep, args.max_fpr)
    results["education_entity_ensemble"] = {
        "best": best,
        "sweep": sweep,
        "rows": education_entity_ensemble,
    }
    print("education_entity_ensemble", best, flush=True)

    for indicator in INDICATORS:
        sweep = []
        for semantic_threshold in thresholds:
            for identity_threshold in thresholds:
                predictions = [
                    indicator_scores[indicator][row["id"]] >= semantic_threshold
                    and max(
                        entity_scores[row["id"]][label]
                        for label in IDENTITY_LABELS
                    )
                    >= identity_threshold
                    for row in rows
                ]
                sweep.append(
                    binary_metrics_for_predictions(
                        rows,
                        predictions,
                        {
                            "semantic_threshold": semantic_threshold,
                            "identity_threshold": identity_threshold,
                        },
                    )
                )
        best = select_operating_point(sweep, args.max_fpr)
        key = f"{indicator}_and_identity"
        results[key] = {"best": best, "sweep": sweep}
        print(key, best, flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
