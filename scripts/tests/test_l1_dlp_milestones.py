from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "milestones.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_milestones", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def prf(recall: float, f1: float | None = None) -> dict:
    return {"tp": 0, "precision": 1.0, "recall": recall, "f1": recall if f1 is None else f1}


def report(providers: dict[str, float], credential_f1: float, fp_per_mb: float) -> dict:
    """The parts of a scoreboard report the milestones read."""
    return {
        "synthetic": {
            "providers": {entity: {"gold": 10, "exact": prf(recall), "overlap": prf(recall)}
                          for entity, recall in providers.items()},
            "groups": {"CREDENTIAL": {"gold": 10, "exact": prf(credential_f1), "overlap": prf(credential_f1)}},
        },
        "benign_code": {"fp": int(fp_per_mb * 10), "fp_per_mb": fp_per_mb},
    }


ENTITY_MAP = {
    "baselines": {"gitleaks": {"inventory": ["a-key", "b-key", "c-key", "d-key"]}},
    "taxonomy": {
        "API_KEY": {"family": "provider_secret"},
        "CREDENTIAL": {"family": "generic_credential"},
        "dlp.content.sql": {"family": "content_class"},
        "dlp.document.hr": {"family": "document_class"},
        "dlp.project_id": {"family": "business_identifier"},
    },
    "entities": [
        {"id": "p.a", "scope": "shared", "group": "API_KEY", "ark": ["dlp_a"], "gitleaks": ["a-key"]},
        {"id": "p.b", "scope": "shared", "group": "API_KEY", "ark": ["dlp_b"], "trufflehog": ["B"]},
        {"id": "p.ds", "scope": "shared", "group": "API_KEY", "ark": ["dlp_ds"], "detect_secrets": ["DsDetector"]},
        {"id": "c.pw", "scope": "shared", "group": "CREDENTIAL", "ark": ["dlp_pw"], "gitleaks": ["b-key"]},
        {"id": "p.c", "scope": "baseline_only", "gitleaks": ["c-key"], "backlog": "P99"},
        {"id": "x.d", "scope": "out_of_scope", "gitleaks": ["d-key"], "reason": "test"},
        {"id": "content.sql", "scope": "ark_only", "group": "dlp.content.sql", "ark": ["dlp_sql"]},
        {"id": "document.hr", "scope": "shared", "group": "dlp.document.hr", "ark": ["dlp_hr"],
         "google_dlp": ["DOCUMENT_TYPE/HR/RESUME"]},
        {"id": "id.project", "scope": "ark_only", "group": "dlp.project_id", "ark": ["dlp_project"]},
    ],
}

PATTERNS = [
    {"id": "dlp_a", "entity_group": "API_KEY", "validator_strength": "checksum"},
    {"id": "dlp_b", "entity_group": "API_KEY", "validator_strength": "format"},
    {"id": "dlp_ds", "entity_group": "API_KEY", "validator_strength": "structure"},
    {"id": "dlp_pw", "entity_group": "CREDENTIAL", "validator_strength": "none"},
    {"id": "dlp_sql", "entity_group": "dlp.content.sql", "validator_strength": "structure"},
    {"id": "dlp_hr", "entity_group": "dlp.document.hr", "validator_strength": "none"},
    {"id": "dlp_project", "entity_group": "dlp.project_id", "validator_strength": "checksum"},
]


def test_m1_entities_are_shared_provider_types_with_gitleaks_or_trufflehog():
    # Generic credentials belong to M2; detect-secrets is not an M1 tool.
    assert MODULE.m1_entities(ENTITY_MAP) == ["p.a", "p.b"]


def test_m1_holds_when_ark_recall_reaches_the_best_baseline_and_fp_per_mb_stays_below_gitleaks():
    head = report({"p.a": 0.9, "p.b": 0.8}, 0.9, 0.05)
    baselines = {"gitleaks": report({"p.a": 0.9}, 0.2, 0.2), "trufflehog": report({"p.b": 0.7}, 0.1, 1.4)}
    result = MODULE.m1(head, baselines, ["p.a", "p.b", "p.none"])
    assert result["met"] and (result["held"], result["entities"]) == (2, 2)  # no gold: not counted
    assert result["failed"] == [] and result["fp_per_mb"] == {"ark": 0.05, "gitleaks": 0.2}


def test_m1_misses_on_one_lower_recall_or_more_fp_per_mb_than_gitleaks():
    baselines = {"gitleaks": report({"p.a": 0.95}, 0.2, 0.2), "trufflehog": report({}, 0.1, 1.4)}
    lower = MODULE.m1(report({"p.a": 0.9, "p.b": 0.8}, 0.9, 0.05), baselines, ["p.a", "p.b"])
    assert not lower["met"] and lower["failed"] == ["p.a"] and lower["held"] == 1
    noisier = MODULE.m1(report({"p.a": 1.0, "p.b": 0.8}, 0.9, 0.3), baselines, ["p.a", "p.b"])
    assert not noisier["met"] and noisier["failed"] == []


def test_m2_needs_twenty_points_over_the_best_baseline_on_credentials():
    baselines = {"gitleaks": report({}, 0.30, 0.2), "detect-secrets": report({}, 0.45, 36.0)}
    met = MODULE.m2(report({}, 0.65, 0.0), baselines)
    assert met["met"] and met["best"] == "detect-secrets" and met["baseline_f1"] == 0.45
    assert not MODULE.m2(report({}, 0.64, 0.0), baselines)["met"]


def test_milestone_line_carries_aggregates_only():
    head = report({"p.a": 0.9, "p.b": 0.8}, 0.9, 0.05)
    baselines = {"gitleaks": report({"p.a": 0.95}, 0.2, 0.2), "trufflehog": report({}, 0.1, 1.4),
                 "detect-secrets": report({}, 0.3, 36.0)}
    line = MODULE.milestone_line("holdout", head, baselines, ["p.a", "p.b"])
    assert line == ("milestones holdout (default profile, exact spans): M1 MISSED (1/2 shared entities with "
                    "recall >= max(gitleaks, trufflehog); FP/MB benign code 0.05 <= gitleaks 0.2) | "
                    "M2 MET (CREDENTIAL F1 90.0 >= detect-secrets 30.0 + 20)")
    assert "p.a" not in line  # entity ids stay in the dev report


def test_m3_counts_from_entity_map_and_rule_meta():
    counts = MODULE.m3_counts(ENTITY_MAP, PATTERNS)
    # a-key and b-key have an ARK rule; c-key is baseline_only, d-key out of scope.
    assert counts["gitleaks"] == {"inventory": 4, "mapped": 2, "share": 0.5}
    # Secret formats: rules of the secret families; offline checks: checksum or structure among them.
    assert counts["secret_formats"] == {"rules": 4, "entities": 4}
    assert counts["offline_checks"] == {"rules": 2, "by_strength": {"checksum": 1, "structure": 1}}
    # Content/document classes without a secret-scanner counterpart; Google DLP is no secret scanner.
    assert counts["content_classes"] == ["content.sql", "document.hr"]
    assert counts["met"] == {"gitleaks": False, "secret_formats": False, "offline_checks": False,
                             "content_classes": False}


def test_m3_rejects_a_rule_without_rule_meta_or_an_unmapped_rule():
    import pytest

    with pytest.raises(ValueError, match="dlp_missing"):
        MODULE.m3_counts(ENTITY_MAP, PATTERNS[:-1] + [{"id": "dlp_missing", "entity_group": "API_KEY",
                                                       "validator_strength": "format"}])


def test_m3_on_the_repository_matches_the_rule_catalog():
    data = yaml.safe_load((ROOT / "research" / "dlp" / "entity_map.yaml").read_text(encoding="utf-8"))
    patterns = MODULE.dlp_patterns()
    counts = MODULE.m3_counts(data, patterns)
    secret = [p for p in patterns if data["taxonomy"][p["entity_group"]]["family"] in MODULE.SECRET_FAMILIES]
    assert counts["secret_formats"]["rules"] == len(secret)
    assert counts["gitleaks"]["inventory"] == len(data["baselines"]["gitleaks"]["inventory"])
    assert 0 < counts["gitleaks"]["mapped"] <= counts["gitleaks"]["inventory"]


def test_count_cli_prints_the_m3_table_and_json(capsys):
    assert MODULE.main(["count"]) == 0
    out = capsys.readouterr().out
    assert "| gitleaks default rules mapped |" in out and out.rstrip().splitlines()[-1].startswith("M3 ")
    assert MODULE.main(["count", "--json"]) == 0
    assert set(json.loads(capsys.readouterr().out)) >= {"gitleaks", "secret_formats", "offline_checks",
                                                         "content_classes", "met"}
