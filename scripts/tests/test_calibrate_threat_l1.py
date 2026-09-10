"""Numerical and feature-contract checks for the separate Threat scorer."""
import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import calibrate_threat_l1 as module


def candidate(rule, start=0, end=20, label="tool_abuse"):
    return dict(rule_id=rule, start_byte=start, end_byte=end, class_name=label)


def test_repeated_rule_matches_do_not_change_presence_features():
    findings = [candidate("a"), candidate("a", 30, 50), candidate("b", label="secrets_access")]
    vector = module.feature_vector(findings, ["a", "b", "c"])
    assert vector[:3] == [1, 1, 0]
    assert vector[3:] == [np.log1p(2), np.log1p(20), 2]
    assert module.feature_vector(findings, ["a", "b", "c"]) == module.feature_vector([findings[0], findings[2]], ["a", "b", "c"])
    assert module.feature_vector([], ["a"]) == [0, 0, 0, 0]


def test_fit_separates_rule_evidence_and_scores_are_finite():
    records = [dict(label=label, candidates=[candidate(rule)], features=features)
               for _ in range(8)
               for label, rule, features in [(1, "attack", [1, 0, 1]), (0, "documented", [0, 1, 1])]]
    coefficients, intercept = module.fit(records)
    assert module.score([1, 0, 1], coefficients, intercept) > .5
    assert module.score([0, 1, 1], coefficients, intercept) < .5
    assert module.score([0], [1000], 1000) == 1
    assert module.score([0], [-1000], -1000) == 0


def test_fit_rejects_missing_negative_candidates():
    with pytest.raises(ValueError, match="positive AND negative"):
        module.fit([dict(label=1, candidates=[candidate("a")], features=[1])])


def test_no_candidates_never_become_a_finding_even_with_large_intercept():
    result = module.metrics([dict(label=0, candidates=[], features=[0])], [0], 100, .5)
    assert result["fp"] == 0
    assert result["tn"] == 1
