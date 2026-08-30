#!/usr/bin/env python3
"""Build and evaluate the versioned Injection-L1 candidate scorer.

The normal workflow never reads the final holdout:

  extract -> fit -> evaluate development validation

The final holdout requires the separate ``final-eval`` command and an explicit
``--allow-holdout`` flag. Raw dataset text and candidate rows stay outside the
repository; only the small scorer artifact and aggregate report are versioned.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

import numpy as np


SCHEMA_VERSION = 1
TOOL_VERSION = "injection-l1-calibration-0.1.6"
SEED = 42
SCORE_QUANTUM = 1e-6
THRESHOLD_SAFETY_QUANTA = 10
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
FEATURE_ORDER = [
    "critical_rule_count",
    "high_rule_count",
    "medium_rule_count",
    "low_rule_count",
    "exact_rule_count",
    "clause_window_rule_count",
    "rule_match_count",
    "structural_feature_count",
    "family_count",
    "producer_count",
    "source_derived_rule_count",
    "has_rule_and_structural",
    "span_length_log1p",
]
DEFAULT_DATASET_SUBDIR = Path(
    "ntdb/artifacts/experiments/"
    "injection_v41_mmbert_static_no_post_l2_lgbm_seed42/data"
)


@dataclass(frozen=True)
class SourceSpec:
    name: str
    filename: str
    role: str
    label: int
    max_documents: int | None = None


DEVELOPMENT_SOURCES = (
    SourceSpec("injection_train", "train.csv", "fit_positive", 1, 8_000),
    SourceSpec("injection_train_benign", "train.csv", "fit_negative", 0, 20_000),
    SourceSpec("hard_benign_full_calibration", "hard_benign_full_calibration.csv", "fit_negative", 0),
    SourceSpec("injection_validation", "validation.csv", "validation_positive", 1, 4_000),
    SourceSpec("injection_validation_benign", "validation.csv", "validation_negative", 0, 8_000),
    SourceSpec("hard_benign_full_validation", "hard_benign_full_validation.csv", "validation_negative", 0),
)
HOLDOUT_SOURCE = SourceSpec(
    "hard_benign_full_holdout", "hard_benign_full_holdout.csv", "final_negative", 0
)


@dataclass(frozen=True)
class FitDiagnostics:
    iterations: int
    converged: bool
    final_max_step: float
    final_projected_gradient_l2: float
    final_raw_gradient_l2: float
    objective: float
    feature_mean: list[float]
    feature_scale: list[float]


def stable_key(value: str) -> str:
    return hashlib.sha256(f"{SEED}:{value}".encode()).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalized_text_hash(text: str) -> str:
    normalized = text.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def runtime_versions() -> dict[str, str | bool]:
    try:
        ark_version = importlib.metadata.version("patronus-ark")
    except importlib.metadata.PackageNotFoundError:
        ark_version = "not-installed"
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
    except (OSError, subprocess.CalledProcessError):
        revision = "unknown"
        dirty = True
    return {
        "tool_version": TOOL_VERSION,
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "ark_package_version": ark_version,
        "scanner_model": "native:injection_l1",
        "repository_revision": revision,
        "repository_dirty": dirty,
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def valid_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def read_selected_rows(path: Path, label: int, limit: int | None) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if int(row["label"]) == label]
    if limit is not None and len(rows) > limit:
        rows.sort(key=lambda row: stable_key(row.get("id") or row.get("source_row_index") or row["text"]))
        rows = rows[:limit]
    return rows


def iter_result_candidates(result: dict) -> Iterator[tuple[str, dict]]:
    producer = str(result.get("model", "unknown"))
    for layer in result.get("layers", []):
        details = layer.get("details", {})
        for candidate in details.get("l1_candidates", []):
            yield producer, candidate


def _overlaps_or_touches(left: dict, right: dict) -> bool:
    return int(right["start_byte"]) <= int(left["end_byte"])


def aggregate_candidates(results: Iterable[dict]) -> list[dict]:
    """Merge producer candidates by span and preserve unique evidence."""
    flat = [
        {
            **candidate,
            "_producers": list(candidate.get("producers") or [producer]),
        }
        for result in results
        for producer, candidate in iter_result_candidates(result)
    ]
    flat.sort(
        key=lambda item: (
            int(item["start_byte"]),
            int(item["end_byte"]),
            tuple(item["_producers"]),
        )
    )
    groups: list[list[dict]] = []
    for candidate in flat:
        if groups and _overlaps_or_touches(groups[-1][-1], candidate):
            groups[-1].append(candidate)
            groups[-1].sort(key=lambda item: int(item["end_byte"]))
        else:
            groups.append([candidate])

    aggregated = []
    for group in groups:
        start = min(int(item["start_byte"]) for item in group)
        end = max(int(item["end_byte"]) for item in group)
        start_char = min(int(item.get("start_char", item["start_byte"])) for item in group)
        end_char = max(int(item.get("end_char", item["end_byte"])) for item in group)
        features = unique_dicts(
            feature
            for item in group
            for feature in item.get("features", [])
        )
        rule_severities: dict[str, str] = {}
        for item in group:
            for rule, severity in item.get("rule_severities", {}).items():
                previous = rule_severities.get(rule)
                if previous is None or SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(
                    previous, 0
                ):
                    rule_severities[rule] = severity
        aggregated.append(
            {
                "candidate_id": f"injection:l1:{start}:{end}",
                "start_byte": start,
                "end_byte": end,
                "start_char": start_char,
                "end_char": end_char,
                "rule_ids": sorted({rule for item in group for rule in item.get("rule_ids", [])}),
                "rule_severities": dict(sorted(rule_severities.items())),
                "families": sorted({family for item in group for family in item.get("families", [])}),
                "max_severity": max(
                    (str(item.get("max_severity", "low")) for item in group),
                    key=lambda value: SEVERITY_RANK.get(value, 0),
                ),
                "producers": sorted(
                    {producer for item in group for producer in item["_producers"]}
                ),
                "features": features,
            }
        )
    return aggregated


def unique_dicts(values: Iterable[dict]) -> list[dict]:
    seen: set[str] = set()
    output = []
    for value in values:
        key = str(value.get("feature_id"))
        if key not in seen:
            seen.add(key)
            output.append(value)
    return output


def feature_vector(candidate: dict) -> list[float]:
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rule_matches: set[str] = set()
    source_derived_rules: set[str] = set()
    exact_rules: set[str] = set()
    clause_window_rules: set[str] = set()
    structural = 0
    for feature in candidate.get("features", []):
        kind = feature.get("kind")
        if kind == "structural":
            structural += 1
        elif kind == "rule_match":
            rule_matches.add(str(feature.get("provenance", {}).get("rule_id", "")))
        provenance = feature.get("provenance", {})
        if kind == "rule_match" and feature.get("span_precision") == "exact":
            exact_rules.add(str(provenance.get("rule_id", "")))
        if kind == "rule_match" and feature.get("span_precision") in {"clause", "window", "document"}:
            clause_window_rules.add(str(provenance.get("rule_id", "")))
        source = str(provenance.get("source", ""))
        if source != "ark-native":
            source_derived_rules.add(str(provenance.get("rule_id", "")))

    for severity in candidate.get("rule_severities", {}).values():
        severities[severity if severity in severities else "low"] += 1
    return [
        float(severities["critical"]),
        float(severities["high"]),
        float(severities["medium"]),
        float(severities["low"]),
        float(len(exact_rules)),
        float(len(clause_window_rules)),
        float(len(rule_matches)),
        float(structural),
        float(len(candidate.get("families", []))),
        float(len(candidate.get("producers", []))),
        float(len(source_derived_rules)),
        float(bool(rule_matches) and structural > 0),
        math.log1p(max(0, int(candidate["end_byte"]) - int(candidate["start_byte"]))),
    ]


def strong_positive(candidate: dict, isolated_rule_ids: set[str]) -> bool:
    """Reject document-only weak labels that lack local rule corroboration."""
    rule_ids = set(candidate.get("rule_ids", []))
    if not rule_ids.intersection(isolated_rule_ids):
        return False
    vector = dict(zip(FEATURE_ORDER, feature_vector(candidate), strict=True))
    return bool(
        candidate.get("max_severity") == "critical"
        or vector["source_derived_rule_count"] > 0
        or vector["producer_count"] > 1
        or vector["has_rule_and_structural"] > 0
    )


def scanner():
    from patronus_ark import SecurityGateway

    gateway = SecurityGateway(categories=["injection"], max_level="l1", download_files=False)
    gateway.warmup()
    return gateway


def candidate_excerpt(text: str, candidate: dict) -> str:
    """Slice with Rust-provided character offsets, not UTF-8 byte offsets."""
    return text[int(candidate["start_char"]):int(candidate["end_char"])]


def extract_source(
    gateway, path: Path, spec: SourceSpec
) -> tuple[list[dict], dict, set[str]]:
    rows = read_selected_rows(path, spec.label, spec.max_documents)
    text_hashes = {normalized_text_hash(row["text"]) for row in rows}
    records = []
    documents_with_candidates = 0
    rejected_weak_positives = 0
    for index, row in enumerate(rows):
        text = row["text"]
        candidates = aggregate_candidates(gateway.scan_category("injection", text))
        documents_with_candidates += bool(candidates)
        for candidate in candidates:
            if spec.label == 1:
                excerpt = candidate_excerpt(text, candidate)
                isolated = aggregate_candidates(gateway.scan_category("injection", excerpt))
                isolated_rules = {rule for item in isolated for rule in item.get("rule_ids", [])}
                if not strong_positive(candidate, isolated_rules):
                    rejected_weak_positives += 1
                    continue
            records.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "sample_id": f"{spec.name}:{row.get('id') or row.get('source_row_index') or index}",
                    "source": spec.name,
                    "role": spec.role,
                    "label": spec.label,
                    "candidate": candidate,
                    "features": feature_vector(candidate),
                }
            )
    summary = {
        "name": spec.name,
        "role": spec.role,
        "path": spec.filename,
        "sha256": sha256_file(path),
        "documents_selected": len(rows),
        "documents_with_candidates": documents_with_candidates,
        "candidate_records": len(records),
        "rejected_weak_positive_candidates": rejected_weak_positives,
        "unique_text_hashes": len(text_hashes),
        "duplicate_documents_by_text_hash": len(rows) - len(text_hashes),
    }
    return records, summary, text_hashes


def write_jsonl(path: Path, records: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def validate_extraction_manifest(manifest: dict) -> None:
    require(manifest.get("schema_version") == SCHEMA_VERSION, "unsupported manifest schema")
    require(manifest.get("tool_version") == TOOL_VERSION, "manifest tool version mismatch")
    require(manifest.get("feature_order") == FEATURE_ORDER, "manifest feature order mismatch")
    require(manifest.get("holdout_accessed") is False, "development manifest accessed holdout")
    sources = manifest.get("sources")
    require(isinstance(sources, list) and sources, "manifest sources must be non-empty")
    expected = {spec.name: spec for spec in DEVELOPMENT_SOURCES}
    require(len(sources) == len(expected), "manifest source count mismatch")
    names: set[str] = set()
    for source in sources:
        name = source.get("name")
        require(name in expected and name not in names, f"invalid or duplicate source {name!r}")
        names.add(name)
        require(source.get("role") == expected[name].role, f"role mismatch for {name}")
        require(source.get("path") == expected[name].filename, f"path mismatch for {name}")
        require(valid_sha256(source.get("sha256")), f"invalid SHA-256 for {name}")
        for field in (
            "documents_selected",
            "documents_with_candidates",
            "candidate_records",
            "rejected_weak_positive_candidates",
        ):
            require(isinstance(source.get(field), int) and source[field] >= 0, f"invalid {field}")
    audit = manifest.get("train_validation_text_overlap_audit")
    require(isinstance(audit, dict), "missing train/validation text overlap audit")
    require(audit.get("overlap_count") == 0, "train/validation text hash overlap detected")


def validate_candidate_records(records: list[dict], manifest: dict) -> None:
    source_contract = {source["name"]: source for source in manifest["sources"]}
    seen_ids: set[tuple[str, str]] = set()
    for index, record in enumerate(records):
        prefix = f"candidate record {index}"
        require(record.get("schema_version") == SCHEMA_VERSION, f"{prefix}: schema mismatch")
        source = record.get("source")
        require(source in source_contract, f"{prefix}: unknown source")
        require(record.get("role") == source_contract[source]["role"], f"{prefix}: role mismatch")
        require(record.get("label") in (0, 1), f"{prefix}: invalid label")
        features = record.get("features")
        require(isinstance(features, list) and len(features) == len(FEATURE_ORDER), f"{prefix}: feature length")
        require(all(isinstance(value, (int, float)) and math.isfinite(value) for value in features), f"{prefix}: non-finite feature")
        candidate = record.get("candidate")
        require(isinstance(candidate, dict), f"{prefix}: missing candidate")
        rule_ids = candidate.get("rule_ids")
        severities = candidate.get("rule_severities")
        require(isinstance(rule_ids, list) and len(rule_ids) == len(set(rule_ids)), f"{prefix}: duplicate rules")
        require(isinstance(severities, dict) and set(severities) == set(rule_ids), f"{prefix}: severity keys")
        require(all(value in SEVERITY_RANK for value in severities.values()), f"{prefix}: severity value")
        require(candidate.get("start_byte", -1) <= candidate.get("end_byte", -1), f"{prefix}: byte span")
        require(candidate.get("start_char", -1) <= candidate.get("end_char", -1), f"{prefix}: char span")
        expected_features = feature_vector(candidate)
        require(np.allclose(features, expected_features, rtol=0.0, atol=1e-12), f"{prefix}: feature mismatch")
        identity = (str(record.get("sample_id")), str(candidate.get("candidate_id")))
        require(identity not in seen_ids, f"{prefix}: duplicate candidate identity")
        seen_ids.add(identity)


def validate_artifact(artifact: dict) -> None:
    require(artifact.get("schema_version") == SCHEMA_VERSION, "artifact schema mismatch")
    require(artifact.get("feature_order") == FEATURE_ORDER, "artifact feature order mismatch")
    coefficients = artifact.get("coefficients")
    require(isinstance(coefficients, list) and len(coefficients) == len(FEATURE_ORDER), "artifact coefficient length")
    require(all(isinstance(value, (int, float)) and math.isfinite(value) for value in coefficients), "artifact coefficients")
    require(all(value >= 0.0 for value in coefficients[:-1]), "evidence coefficient is negative")
    require(coefficients[-1] <= 0.0, "span length coefficient is positive")
    require(isinstance(artifact.get("intercept"), (int, float)), "artifact intercept")
    threshold = artifact.get("acceptance_threshold")
    require(isinstance(threshold, (int, float)) and 0.0 < threshold < 1.0, "artifact threshold")
    calibration = artifact.get("calibration")
    require(isinstance(calibration, dict), "artifact calibration")
    require(calibration.get("holdout_evaluated") is False, "artifact reports holdout evaluation")
    golden = artifact.get("golden_cases")
    require(isinstance(golden, list) and len(golden) >= 3, "artifact golden cases")
    for case in golden:
        require(len(case.get("features", [])) == len(FEATURE_ORDER), "golden feature length")
        expected = float(scores([{"features": case["features"]}], np.asarray(coefficients), float(artifact["intercept"]))[0])
        require(abs(expected - float(case["expected_score"])) <= 1e-12, "golden score mismatch")
        require(
            bool(expected >= threshold) == bool(case["expected_accepted"]),
            "golden decision mismatch",
        )


def validate_release_manifest(
    manifest: dict,
    artifact_path: Path,
    artifact: dict,
    *,
    require_holdout_locked: bool,
) -> None:
    require(manifest.get("schema_version") == SCHEMA_VERSION, "release manifest schema")
    require(manifest.get("feature_order") == FEATURE_ORDER, "release feature order")
    holdout = manifest.get("holdout")
    require(isinstance(holdout, dict), "release manifest holdout state")
    require(isinstance(holdout.get("accessed"), bool), "release manifest holdout access flag")
    if require_holdout_locked:
        require(holdout["accessed"] is False, "release manifest holdout is already accessed")
    gates = manifest.get("release_gates")
    require(isinstance(gates, dict), "missing release gates")
    require(float(gates.get("development_candidate_precision_min", 0.0)) > 0.0, "precision gate disabled")
    require(float(gates.get("development_document_false_positive_rate_max", 0.0)) > 0.0, "FPR gate disabled")
    require(isinstance(gates.get("hard_benign_accepted_false_positives_max"), int), "hard-benign gate")
    require(isinstance(gates.get("holdout_accepted_false_positives_max"), int), "holdout gate")
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict), "release artifacts")
    require(valid_sha256(artifacts.get("runtime_scorer_sha256")), "runtime artifact digest")
    require(sha256_file(artifact_path) == artifacts["runtime_scorer_sha256"], "runtime artifact is not frozen digest")
    require(artifact.get("feature_order") == manifest.get("feature_order"), "artifact/manifest feature mismatch")


def development_gate_report(artifact: dict, manifest: dict) -> dict:
    gates = manifest["release_gates"]
    calibration = artifact["calibration"]
    candidate = calibration["development_validation_metrics"]
    documents = calibration["development_validation_document_metrics"]
    hard_sources = [
        calibration["source_metrics"]["hard_benign_full_calibration"],
        calibration["source_metrics"]["hard_benign_full_validation"],
    ]
    checks = {
        "candidate_precision": {
            "value": candidate["precision"],
            "required_min": gates["development_candidate_precision_min"],
            "passed": candidate["precision"]
            >= gates["development_candidate_precision_min"],
        },
        "document_false_positive_rate": {
            "value": documents["document_false_positive_rate"],
            "required_max": gates["development_document_false_positive_rate_max"],
            "passed": documents["document_false_positive_rate"]
            <= gates["development_document_false_positive_rate_max"],
        },
        "hard_benign_accepted_false_positives": {
            "value": sum(source["accepted_documents"] for source in hard_sources),
            "required_max": gates["hard_benign_accepted_false_positives_max"],
            "passed": sum(source["accepted_documents"] for source in hard_sources)
            <= gates["hard_benign_accepted_false_positives_max"],
        },
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "development_only",
        "passed": all(check["passed"] for check in checks.values()),
        "checks": checks,
        "external_release_suites": manifest.get("external_release_suites", []),
        "holdout_accessed": manifest["holdout"]["accessed"],
    }


def final_holdout_release_gate(result: dict, manifest: dict) -> dict:
    accepted_documents = result["source_metrics"][HOLDOUT_SOURCE.name][
        "accepted_documents"
    ]
    required_max = manifest["release_gates"][
        "holdout_accepted_false_positives_max"
    ]
    return {
        "name": "holdout_accepted_false_positives",
        "value": accepted_documents,
        "required_max": required_max,
        "passed": accepted_documents <= required_max,
    }


def write_json_atomically_exclusive(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def fit_logistic_with_diagnostics(
    records: list[dict], ridge: float = 1.0
) -> tuple[np.ndarray, float, FitDiagnostics]:
    x = np.asarray([record["features"] for record in records], dtype=np.float64)
    y = np.asarray([record["label"] for record in records], dtype=np.float64)
    if set(y.tolist()) != {0.0, 1.0}:
        raise ValueError("fit data must contain positive and negative candidates")
    mean = x.mean(axis=0)
    scale = x.std(axis=0)
    scale[scale < 1e-9] = 1.0
    z = (x - mean) / scale
    class_weights = np.where(y == 1, 0.5 / (y == 1).mean(), 0.5 / (y == 0).mean())
    beta = np.zeros(z.shape[1] + 1, dtype=np.float64)
    first_moment = np.zeros_like(beta)
    second_moment = np.zeros_like(beta)
    converged = False
    step = np.full_like(beta, np.inf)
    actual_step = np.full_like(beta, np.inf)
    gradient = np.full_like(beta, np.inf)
    projected_gradient = np.full_like(beta, np.inf)
    for iteration in range(1, 5_001):
        previous_beta = beta.copy()
        logits = np.clip(beta[0] + z @ beta[1:], -40.0, 40.0)
        probabilities = 1.0 / (1.0 + np.exp(-logits))
        residual = class_weights * (probabilities - y)
        gradient = np.concatenate(
            ([residual.mean()], z.T @ residual / len(z) + ridge * beta[1:] / len(z))
        )
        first_moment = 0.9 * first_moment + 0.1 * gradient
        second_moment = 0.999 * second_moment + 0.001 * gradient * gradient
        corrected_first = first_moment / (1.0 - 0.9**iteration)
        corrected_second = second_moment / (1.0 - 0.999**iteration)
        step = 0.02 * corrected_first / (np.sqrt(corrected_second) + 1e-8)
        beta -= step
        # More independent evidence must never reduce the score. Only a wider,
        # less precise candidate span may carry a non-positive coefficient.
        beta[1:-1] = np.maximum(beta[1:-1], 0.0)
        beta[-1] = min(beta[-1], 0.0)
        actual_step = beta - previous_beta
        projected_gradient = gradient.copy()
        projected_gradient[1:-1][
            (beta[1:-1] <= 1e-15) & (gradient[1:-1] > 0.0)
        ] = 0.0
        if beta[-1] >= -1e-15 and gradient[-1] < 0.0:
            projected_gradient[-1] = 0.0
        if iteration > 500 and np.max(np.abs(actual_step)) < 1e-8:
            converged = True
            break
    coefficients = beta[1:] / scale
    intercept = beta[0] - float(coefficients @ mean)
    final_logits = np.clip(intercept + x @ coefficients, -40.0, 40.0)
    objective = float(
        np.mean(class_weights * (np.logaddexp(0.0, final_logits) - y * final_logits))
        + 0.5 * ridge * float(beta[1:] @ beta[1:]) / len(z)
    )
    diagnostics = FitDiagnostics(
        iterations=iteration,
        converged=converged,
        final_max_step=float(np.max(np.abs(actual_step))),
        final_projected_gradient_l2=float(np.linalg.norm(projected_gradient)),
        final_raw_gradient_l2=float(np.linalg.norm(gradient)),
        objective=objective,
        feature_mean=[float(value) for value in mean],
        feature_scale=[float(value) for value in scale],
    )
    return coefficients, intercept, diagnostics


def fit_logistic(records: list[dict], ridge: float = 1.0) -> tuple[np.ndarray, float]:
    coefficients, intercept, _ = fit_logistic_with_diagnostics(records, ridge)
    return coefficients, intercept


def scores(records: list[dict], coefficients: np.ndarray, intercept: float) -> np.ndarray:
    if not records:
        return np.asarray([], dtype=np.float64)
    x = np.asarray([record["features"] for record in records], dtype=np.float64)
    logits = np.clip(intercept + x @ coefficients, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-logits))


def conservative_threshold(records: list[dict], values: np.ndarray) -> float:
    negative = values[np.asarray([record["label"] == 0 for record in records])]
    if not len(negative):
        raise ValueError("threshold selection requires negative candidates")
    maximum = float(negative.max())
    raw = maximum + SCORE_QUANTUM * THRESHOLD_SAFETY_QUANTA
    threshold = round(
        math.ceil(raw / SCORE_QUANTUM) * SCORE_QUANTUM,
        max(0, round(-math.log10(SCORE_QUANTUM))),
    )
    if threshold >= 1.0:
        raise ValueError("negative score leaves no quantized threshold safety margin")
    return threshold


def build_golden_cases(
    records: list[dict], values: np.ndarray, coefficients: np.ndarray, intercept: float, threshold: float
) -> list[dict]:
    negative_indices = [index for index, record in enumerate(records) if record["label"] == 0]
    positive_indices = [index for index, record in enumerate(records) if record["label"] == 1]
    top_negative = max(negative_indices, key=lambda index: (values[index], -index))
    accepted_positive = [index for index in positive_indices if values[index] >= threshold]
    require(bool(accepted_positive), "no positive candidate clears threshold")
    lowest_positive = min(accepted_positive, key=lambda index: (values[index], index))

    def observed(name: str, index: int) -> dict:
        return {
            "name": name,
            "features": [float(value) for value in records[index]["features"]],
            "expected_score": float(values[index]),
            "expected_accepted": bool(values[index] >= threshold),
        }

    base = np.asarray(records[top_negative]["features"], dtype=np.float64)
    require(abs(float(coefficients[-1])) > 1e-12, "boundary golden needs span coefficient")

    def boundary(name: str, target_score: float) -> dict:
        vector = base.copy()
        target_logit = math.log(target_score / (1.0 - target_score))
        fixed_logit = intercept + float(vector[:-1] @ coefficients[:-1])
        vector[-1] = (target_logit - fixed_logit) / float(coefficients[-1])
        actual = float(scores([{"features": vector.tolist()}], coefficients, intercept)[0])
        return {
            "name": name,
            "features": [float(value) for value in vector],
            "expected_score": actual,
            "expected_accepted": bool(actual >= threshold),
        }

    return [
        observed("observed_top_negative", top_negative),
        boundary("one_quantum_below_threshold", threshold - SCORE_QUANTUM),
        boundary("one_quantum_above_threshold", threshold + SCORE_QUANTUM),
        observed("observed_lowest_accepted_positive", lowest_positive),
    ]


def metrics(records: list[dict], values: np.ndarray, threshold: float) -> dict:
    labels = np.asarray([record["label"] for record in records], dtype=np.int8)
    predictions = values >= threshold
    tp = int(np.sum(predictions & (labels == 1)))
    fp = int(np.sum(predictions & (labels == 0)))
    tn = int(np.sum(~predictions & (labels == 0)))
    fn = int(np.sum(~predictions & (labels == 1)))
    return {
        "candidate_count": len(records),
        "positive_candidates": int(np.sum(labels == 1)),
        "negative_candidates": int(np.sum(labels == 0)),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "threshold": threshold,
        "score_quantiles": {
            str(label): {
                str(quantile): float(np.quantile(values[labels == label], quantile))
                for quantile in (0.0, 0.5, 0.9, 0.99, 1.0)
            }
            for label in (0, 1)
            if np.any(labels == label)
        },
    }


def document_metrics(
    records: list[dict], values: np.ndarray, threshold: float, sources: list[dict], prefix: str
) -> dict:
    selected_sources = [source for source in sources if source["role"].startswith(prefix)]
    accepted_ids = {
        record["sample_id"]
        for record, value in zip(records, values, strict=True)
        if value >= threshold
    }
    positive_records = [record for record in records if record["label"] == 1]
    negative_records = [record for record in records if record["label"] == 0]
    positive_total = sum(
        source["documents_selected"]
        for source in selected_sources
        if source["role"].endswith("positive")
    )
    negative_total = sum(
        source["documents_selected"]
        for source in selected_sources
        if source["role"].endswith("negative")
    )
    positive_with_any = sum(
        source["documents_with_candidates"]
        for source in selected_sources
        if source["role"].endswith("positive")
    )
    negative_with_any = sum(
        source["documents_with_candidates"]
        for source in selected_sources
        if source["role"].endswith("negative")
    )
    strong_positive_ids = {record["sample_id"] for record in positive_records}
    negative_ids = {record["sample_id"] for record in negative_records}
    accepted_positive = len(accepted_ids.intersection(strong_positive_ids))
    accepted_negative = len(accepted_ids.intersection(negative_ids))
    return {
        "positive_documents": positive_total,
        "positive_documents_with_any_candidate": positive_with_any,
        "positive_candidate_coverage": positive_with_any / positive_total if positive_total else 0.0,
        "positive_documents_with_strong_candidate": len(strong_positive_ids),
        "accepted_positive_documents": accepted_positive,
        "end_to_end_document_recall": accepted_positive / positive_total if positive_total else 0.0,
        "negative_documents": negative_total,
        "negative_documents_with_any_candidate": negative_with_any,
        "accepted_negative_documents": accepted_negative,
        "document_false_positive_rate": accepted_negative / negative_total if negative_total else 0.0,
        "zero_observed_fp_upper_95_rule_of_three": 3.0 / negative_total
        if accepted_negative == 0 and negative_total
        else None,
    }


def source_metrics(
    records: list[dict], values: np.ndarray, threshold: float, sources: list[dict]
) -> dict[str, dict]:
    output = {}
    for source in sources:
        indexed = [
            (record, value)
            for record, value in zip(records, values, strict=True)
            if record["source"] == source["name"]
        ]
        accepted_candidates = int(sum(value >= threshold for _, value in indexed))
        accepted_documents = len(
            {record["sample_id"] for record, value in indexed if value >= threshold}
        )
        output[source["name"]] = {
            "role": source["role"],
            "label": indexed[0][0]["label"] if indexed else None,
            "documents": source["documents_selected"],
            "documents_with_candidates": source["documents_with_candidates"],
            "candidate_records": len(indexed),
            "accepted_candidates": accepted_candidates,
            "accepted_documents": accepted_documents,
            "accepted_document_rate": accepted_documents / source["documents_selected"]
            if source["documents_selected"]
            else 0.0,
        }
    return output


def cmd_extract(args: argparse.Namespace) -> None:
    dataset_dir = args.dataset_root / DEFAULT_DATASET_SUBDIR
    gateway = scanner()
    all_records: list[dict] = []
    sources = []
    role_hashes: dict[str, set[str]] = {"fit": set(), "validation": set()}
    for spec in DEVELOPMENT_SOURCES:
        records, summary, text_hashes = extract_source(
            gateway, dataset_dir / spec.filename, spec
        )
        all_records.extend(records)
        sources.append(summary)
        role_hashes["fit" if spec.role.startswith("fit_") else "validation"].update(
            text_hashes
        )
    overlap = sorted(role_hashes["fit"].intersection(role_hashes["validation"]))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "seed": SEED,
        "feature_order": FEATURE_ORDER,
        "positive_selection": "candidate must reproduce a rule in isolation and have critical, source-derived, multi-producer, or rule+structural corroboration",
        "holdout_accessed": False,
        "runtime_versions": runtime_versions(),
        "train_validation_text_overlap_audit": {
            "normalization": "CRLF-to-LF plus outer whitespace trim then SHA-256",
            "fit_unique_text_hashes": len(role_hashes["fit"]),
            "validation_unique_text_hashes": len(role_hashes["validation"]),
            "overlap_count": len(overlap),
            "overlap_hashes": overlap,
        },
        "sources": sources,
    }
    validate_extraction_manifest(manifest)
    validate_candidate_records(all_records, manifest)
    write_jsonl(args.output, all_records)
    args.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def cmd_fit(args: argparse.Namespace) -> None:
    records = read_jsonl(args.candidates)
    source_manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_extraction_manifest(source_manifest)
    validate_candidate_records(records, source_manifest)
    fit = [record for record in records if record["role"].startswith("fit_")]
    validation = [record for record in records if record["role"].startswith("validation_")]
    coefficients, intercept, diagnostics = fit_logistic_with_diagnostics(
        fit, ridge=args.ridge
    )
    require(all(value >= 0.0 for value in coefficients[:-1]), "fit violated evidence monotonicity")
    require(coefficients[-1] <= 0.0, "fit violated span monotonicity")
    fit_values = scores(fit, coefficients, intercept)
    validation_values = scores(validation, coefficients, intercept)
    all_values = np.concatenate([fit_values, validation_values])
    all_records = fit + validation
    threshold = conservative_threshold(all_records, all_values)
    fit_metrics = metrics(fit, fit_values, threshold)
    validation_metrics = metrics(validation, validation_values, threshold)
    fit_document_metrics = document_metrics(
        fit, fit_values, threshold, source_manifest["sources"], "fit_"
    )
    validation_document_metrics = document_metrics(
        validation, validation_values, threshold, source_manifest["sources"], "validation_"
    )
    per_source_metrics = source_metrics(
        all_records, all_values, threshold, source_manifest["sources"]
    )
    negative_scores = all_values[
        np.asarray([record["label"] == 0 for record in all_records])
    ]
    golden_cases = build_golden_cases(
        all_records, all_values, coefficients, intercept, threshold
    )
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "model_id": "ark-injection-l1-logistic-0.1.6",
        "score_version": "injection-l1-0.1.6",
        "feature_order": FEATURE_ORDER,
        "coefficients": [float(value) for value in coefficients],
        "intercept": float(intercept),
        "acceptance_threshold": threshold,
        "calibration": {
            "method": "candidate_level_l2_regularized_logistic_plus_zero_observed_fp_threshold",
            "priority": "minimize_false_positives",
            "target_observed_candidate_fpr": 0.0,
            "threshold_selection": {
                "selected_on": "fit negatives plus development-validation negatives",
                "development_validation_is_threshold_tuning_data": True,
                "maximum_observed_negative_score": float(negative_scores.max()),
                "score_quantum": SCORE_QUANTUM,
                "safety_quanta": THRESHOLD_SAFETY_QUANTA,
                "minimum_safety_margin": SCORE_QUANTUM * THRESHOLD_SAFETY_QUANTA,
                "quantized_threshold": threshold,
            },
            "ridge": args.ridge,
            "fit_diagnostics": asdict(diagnostics),
            "fit_metrics": fit_metrics,
            "development_validation_metrics": validation_metrics,
            "fit_document_metrics": fit_document_metrics,
            "development_validation_document_metrics": validation_document_metrics,
            "source_metrics": per_source_metrics,
            "coefficient_constraints": "evidence counts nonnegative; span_length_log1p nonpositive",
            "holdout_evaluated": False,
        },
        "provenance": {
            "tool_version": TOOL_VERSION,
            "seed": SEED,
            "sources": source_manifest["sources"],
            "positive_selection": source_manifest["positive_selection"],
            "candidate_dataset_sha256": sha256_file(args.candidates),
            "candidate_manifest_sha256": sha256_file(args.manifest),
            "runtime_versions": source_manifest["runtime_versions"],
            "train_validation_text_overlap_audit": source_manifest[
                "train_validation_text_overlap_audit"
            ],
        },
        "golden_cases": golden_cases,
        "reports": ["docs/research/injection-l1-calibration-0.1.6.md"],
    }
    validate_artifact(artifact)
    require(fit_metrics["fp"] == 0 and validation_metrics["fp"] == 0, "threshold admitted development false positive")
    args.artifact.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.report.write_text(
        json.dumps(
            {
                "fit_candidates": fit_metrics,
                "fit_documents": fit_document_metrics,
                "validation_candidates": validation_metrics,
                "validation_documents": validation_document_metrics,
                "sources": per_source_metrics,
                "threshold_selection": artifact["calibration"]["threshold_selection"],
                "fit_diagnostics": asdict(diagnostics),
                "train_validation_text_overlap_audit": source_manifest[
                    "train_validation_text_overlap_audit"
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def cmd_validate(args: argparse.Namespace) -> None:
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    release_manifest = json.loads(args.release_manifest.read_text(encoding="utf-8"))
    validate_artifact(artifact)
    validate_release_manifest(
        release_manifest, args.artifact, artifact, require_holdout_locked=False
    )
    report = development_gate_report(artifact, release_manifest)
    if args.output:
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if not report["passed"]:
        raise SystemExit("development release gates failed")
    print(json.dumps(report, indent=2, sort_keys=True))


def cmd_final_eval(args: argparse.Namespace) -> None:
    if not args.allow_holdout:
        raise SystemExit("refusing holdout access without --allow-holdout")
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite final report: {args.output}")
    if not valid_sha256(args.expected_artifact_sha256):
        raise SystemExit("--expected-artifact-sha256 must be a lowercase SHA-256")
    if not valid_sha256(args.expected_holdout_sha256):
        raise SystemExit("--expected-holdout-sha256 must be a lowercase SHA-256")
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    release_manifest = json.loads(args.release_manifest.read_text(encoding="utf-8"))
    validate_artifact(artifact)
    validate_release_manifest(
        release_manifest, args.artifact, artifact, require_holdout_locked=True
    )
    artifact_sha256 = sha256_file(args.artifact)
    if artifact_sha256 != args.expected_artifact_sha256:
        raise SystemExit("frozen artifact digest mismatch")
    dataset_path = args.dataset_root / DEFAULT_DATASET_SUBDIR / HOLDOUT_SOURCE.filename
    holdout_sha256 = sha256_file(dataset_path)
    if holdout_sha256 != args.expected_holdout_sha256:
        raise SystemExit("holdout input digest mismatch")
    records, source_summary, _ = extract_source(scanner(), dataset_path, HOLDOUT_SOURCE)
    if source_summary["documents_selected"] != args.expected_holdout_documents:
        raise SystemExit("holdout document-count mismatch")
    coefficients = np.asarray(artifact["coefficients"], dtype=np.float64)
    values = scores(records, coefficients, float(artifact["intercept"]))
    if sha256_file(args.artifact) != artifact_sha256:
        raise SystemExit("artifact changed during final evaluation")
    result = {
        "schema_version": SCHEMA_VERSION,
        "model_id": artifact["model_id"],
        "score_version": artifact["score_version"],
        "source": source_summary,
        "metrics": metrics(records, values, float(artifact["acceptance_threshold"])),
        "source_metrics": source_metrics(
            records, values, float(artifact["acceptance_threshold"]), [source_summary]
        ),
        "artifact_sha256": artifact_sha256,
        "holdout_sha256": holdout_sha256,
        "runtime_versions": runtime_versions(),
        "input_contract": {
            "expected_artifact_sha256": args.expected_artifact_sha256,
            "expected_holdout_sha256": args.expected_holdout_sha256,
            "expected_holdout_documents": args.expected_holdout_documents,
            "release_manifest_sha256": sha256_file(args.release_manifest),
        },
        "limitations": [
            "candidate metrics are correlated because one document may produce multiple candidates",
            "a zero observed false-positive count does not prove zero production false-positive rate",
            "this report covers only the frozen hard-benign holdout and not language, family, or latency gates",
        ],
        "holdout_accessed": True,
    }
    result["release_gate"] = final_holdout_release_gate(result, release_manifest)
    try:
        write_json_atomically_exclusive(args.output, result)
    except FileExistsError as error:
        raise SystemExit(f"refusing to overwrite final report: {args.output}") from error
    if not result["release_gate"]["passed"]:
        raise SystemExit(
            "final holdout release gate failed; archived report is preserved at "
            f"{args.output}"
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("extract")
    extract.add_argument("--dataset-root", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    extract.add_argument("--manifest", type=Path, required=True)
    extract.set_defaults(func=cmd_extract)

    fit = subparsers.add_parser("fit")
    fit.add_argument("--candidates", type=Path, required=True)
    fit.add_argument("--manifest", type=Path, required=True)
    fit.add_argument("--artifact", type=Path, required=True)
    fit.add_argument("--report", type=Path, required=True)
    fit.add_argument("--ridge", type=float, default=1.0)
    fit.set_defaults(func=cmd_fit)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--artifact", type=Path, required=True)
    validate.add_argument("--release-manifest", type=Path, required=True)
    validate.add_argument("--output", type=Path)
    validate.set_defaults(func=cmd_validate)

    final_eval = subparsers.add_parser("final-eval")
    final_eval.add_argument("--dataset-root", type=Path, required=True)
    final_eval.add_argument("--artifact", type=Path, required=True)
    final_eval.add_argument("--release-manifest", type=Path, required=True)
    final_eval.add_argument("--output", type=Path, required=True)
    final_eval.add_argument("--expected-artifact-sha256", required=True)
    final_eval.add_argument("--expected-holdout-sha256", required=True)
    final_eval.add_argument("--expected-holdout-documents", type=int, required=True)
    final_eval.add_argument("--allow-holdout", action="store_true")
    final_eval.set_defaults(func=cmd_final_eval)
    return result


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
