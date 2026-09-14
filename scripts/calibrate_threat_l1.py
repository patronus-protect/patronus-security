#!/usr/bin/env python3
"""Train a separate, precision-first Threat L1 document scorer from labeled CSVs.

Uses only unified_train.csv and unified_validation.csv. Validation negatives
are threshold-tuning data, not an independent holdout. Raw records stay in the
explicit output directory. Labels 0 (Injection) and 5 (toxicity) are excluded.
"""
import argparse
import csv
import json
import math
from pathlib import Path

import numpy as np
from calibrate_injection_l1 import JsonlScanner, normalized_text_hash, sha256_file

CLASSES = ["instruction_override", "secrets_access", "tool_abuse", "harmful_behavior", "exfiltration_attempt", "toxic_or_harmful", "benign"]


def feature_vector(candidates, rule_ids):
    present = {c["rule_id"] for c in candidates}
    return [float(r in present) for r in rule_ids] + [
        math.log1p(len(present)),
        math.log1p(max((c["end_byte"] - c["start_byte"] for c in candidates), default=0)),
        float(len({c["class_name"] for c in candidates})),
    ]


def fit(records, ridge=1.0):
    x = np.asarray([r["features"] for r in records]); y = np.asarray([r["label"] for r in records])
    if set(y) != {0, 1}:
        raise ValueError("Threat fit requires positive AND negative documents with L1 candidates")
    x = np.column_stack([np.ones(len(x)), x]); beta = np.zeros(x.shape[1])
    weights = np.asarray([len(y) / (2 * np.count_nonzero(y == label)) for label in y])
    # Keep frequent destructive-operation examples from drowning out rare rules.
    counts = {}
    for r in records:
        if r["label"]:
            for rule in {c["rule_id"] for c in r["candidates"]}:
                counts[rule] = counts.get(rule, 0) + 1
    positive_weights = np.asarray([sum(1 / counts[rule] for rule in {c["rule_id"] for c in r["candidates"]}) if r["label"] else 0.0 for r in records])
    weights[y == 1] = positive_weights[y == 1] * (len(y) / 2) / positive_weights.sum()
    penalty = np.full(x.shape[1], ridge); penalty[0] = 0
    for _ in range(100):
        probabilities = 1 / (1 + np.exp(-np.clip(x @ beta, -40, 40)))
        gradient = x.T @ (weights * (probabilities - y)) + penalty * beta
        hessian = x.T @ ((weights * probabilities * (1 - probabilities))[:, None] * x) + np.diag(penalty)
        step = np.linalg.solve(hessian, gradient)
        beta -= step
        if np.max(np.abs(step)) < 1e-8:
            return beta[1:], float(beta[0])
    raise ValueError("Threat logistic fit did not converge")


def score(features, coefficients, intercept):
    value = float(intercept + np.dot(features, coefficients))
    return 1 / (1 + math.exp(-value)) if value >= 0 else math.exp(value) / (1 + math.exp(value))


def metrics(records, coefficients, intercept, threshold):
    counts = dict(tp=0, fp=0, tn=0, fn=0)
    for r in records:
        accepted = bool(r["candidates"]) and score(r["features"], coefficients, intercept) >= threshold
        counts[("tp" if accepted else "fn") if r["label"] else ("fp" if accepted else "tn")] += 1
    return dict(**counts, recall=counts["tp"] / max(1, counts["tp"] + counts["fn"]),
                fpr=counts["fp"] / max(1, counts["fp"] + counts["tn"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--scanner-binary", type=Path, required=True)
    parser.add_argument("--regression-fixture", type=Path, help="Bilingual rule cases used as training data, never holdout")
    parser.add_argument("--acceptance-threshold", type=float, help="Explicit development operating point; default is zero observed FP")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(); args.output_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = Path(__file__).resolve().parents[1] / "rust/src/detectors/threat/rules.json"
    rule_ids = sorted(r["id"] for r in json.loads(catalog_path.read_text())["rules"])
    scanner = JsonlScanner(args.scanner_binary); records = []; seen = {}; excluded = {}; sources = {}
    try:
        for split, filename in [("fit", "unified_train.csv"), ("validation", "unified_validation.csv")]:
            path = args.dataset_dir / filename; sources[filename] = sha256_file(path); excluded[split] = 0
            with path.open() as source:
                for i, row in enumerate(csv.DictReader(source)):
                    label_id = int(row["label"])
                    if label_id not in range(len(CLASSES)):
                        raise ValueError("unknown Threat dataset label")
                    if label_id in (0, 5):
                        excluded[split] += 1; continue
                    label = int(label_id != 6); key = normalized_text_hash(row["text"])
                    if key in seen:
                        if seen[key] != label:
                            raise ValueError("conflicting labels for duplicate text")
                        excluded[split] += 1; continue
                    seen[key] = label
                    result = scanner.scan_category("threat", row["text"])[0]
                    candidates = result["layers"][0]["details"]["matched_rules"]
                    records.append(dict(id=f"{split}:{i}", split=split, label=label, text_hash=key,
                                        candidates=candidates, features=feature_vector(candidates, rule_ids)))
            print(f"Extracted {split}", flush=True)
        if args.regression_fixture:
            sources[args.regression_fixture.name] = sha256_file(args.regression_fixture)
            for row in json.loads(args.regression_fixture.read_text()):
                for lang in ["en", "de"]:
                    for negative in [False, True]:
                        text = row[("negative_" if negative else "") + lang]
                        key = normalized_text_hash(text)
                        if key in seen:
                            if seen[key] != int(not negative):
                                raise ValueError("conflicting regression label")
                            continue
                        seen[key] = int(not negative)
                        result = scanner.scan_category("threat", text)[0]
                        candidates = result["layers"][0]["details"]["matched_rules"]
                        records.append(dict(id=f"regression:{row['rule_id']}:{lang}:{negative}", split="fit", label=int(not negative), text_hash=key,
                                            candidates=candidates, features=feature_vector(candidates, rule_ids)))
    finally:
        scanner.close()
    (args.output_dir / "threat-candidates.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    fit_rows = [r for r in records if r["split"] == "fit" and r["candidates"]]
    coefficients, intercept = fit(fit_rows)
    negatives = [score(r["features"], coefficients, intercept) for r in records if not r["label"] and r["candidates"]]
    threshold = math.ceil((max(negatives) + 1e-5) * 1e6) / 1e6
    if args.acceptance_threshold is not None:
        threshold = args.acceptance_threshold
    if not 0 < threshold < 1:
        raise ValueError("No safe threshold margin remains")
    report = {split: metrics([r for r in records if r["split"] == split], coefficients, intercept, threshold) for split in ["fit", "validation"]}
    if (args.acceptance_threshold is None and any(m["fp"] for m in report.values())) or report["fit"]["tp"] == 0:
        raise ValueError("No useful zero-observed-FP operating point")
    examples = sorted((r for r in records if r["candidates"]), key=lambda r: score(r["features"], coefficients, intercept))
    chosen = [examples[0], examples[-1], max((r for r in examples if not r["label"]), key=lambda r: score(r["features"], coefficients, intercept))]
    artifact = dict(schema_version=1, model_id="ark-threat-l1-logistic-0.1.7", score_version="threat-l1-0.1.7",
                    rule_ids=rule_ids, feature_order=["rule:" + r for r in rule_ids] + ["rule_count_log1p", "max_span_log1p", "class_count"],
                    coefficients=coefficients.tolist(), intercept=intercept, acceptance_threshold=threshold,
                    calibration=dict(priority="minimize_false_positives", weighting="class balanced; positive rule coverage balanced", threshold_selection=("explicit development operating point" if args.acceptance_threshold is not None else "fit and validation negatives; validation is tuning data"), holdout_accessed=False,
                                     sources=sources, rules_sha256=sha256_file(catalog_path), scanner_sha256=sha256_file(args.scanner_binary), excluded=excluded,
                                     fit_candidate_documents=len(fit_rows), negative_candidate_documents=len(negatives), metrics=report),
                    golden_cases=[dict(features=r["features"], expected_score=score(r["features"], coefficients, intercept), expected_accepted=score(r["features"], coefficients, intercept) >= threshold) for r in chosen])
    (args.output_dir / "threat-scorer.json").write_text(json.dumps(artifact, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
