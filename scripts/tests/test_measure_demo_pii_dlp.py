from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "measure_demo_pii_dlp.py"
SPEC = importlib.util.spec_from_file_location("measure_demo_pii_dlp", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_checked_in_demo_goldens_have_valid_unique_entity_spans():
    rows = MODULE.read_jsonl(MODULE.DEFAULT_GOLD)

    MODULE.validate_rows(rows)

    assert len(rows) == 21
    assert {row["scenario"] for row in rows} == {
        "customer_data",
        "source_code",
        "personnel_record",
    }
    assert {row["language"] for row in rows} == {"de", "en"}
    assert sum(row["case_type"] == "live_demo" for row in rows) == 3
    assert sum(row["case_type"] == "hard_negative" for row in rows) == 3


def test_blind_demo_golden_extensions_have_valid_unique_entity_spans():
    rows = [row for path in MODULE.BLIND_GOLDENS for row in MODULE.read_jsonl(path)]

    MODULE.validate_rows(rows)

    assert len(rows) == 66
    assert {row["scenario"] for row in rows} == {
        "customer_data",
        "source_code",
        "personnel_record",
    }
    assert {row["language"] for row in rows} == {"de", "en"}
    assert sum(row["case_type"] == "hard_negative" for row in rows) == 16


def test_scoring_keeps_exact_and_overlap_separate():
    gold = {("row", "EMAIL", 10, 20), ("row", "PHONE", 30, 40)}
    predicted = {("row", "EMAIL", 10, 20), ("row", "PHONE", 32, 40)}

    assert MODULE.score(gold, predicted, overlap=False) == {
        "gold": 2,
        "predicted": 2,
        "true_positives": 1,
        "false_positives": 1,
        "false_negatives": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }
    assert MODULE.score(gold, predicted, overlap=True)["f1"] == 1.0


def test_live_demo_l1_contract_is_exact():
    rows = [
        row
        for row in MODULE.read_jsonl(MODULE.DEFAULT_GOLD)
        if row["case_type"] == "live_demo"
    ]

    report = MODULE.measure_l1(rows)

    assert report["exact"]["precision"] == 1.0
    assert report["exact"]["recall"] == 1.0
    assert report["unexpected_predictions"] == {}


def test_augmented_demo_l1_stays_above_ninety_percent():
    rows = MODULE.read_jsonl(MODULE.DEFAULT_GOLD)

    report = MODULE.measure_l1(rows)

    assert report["exact"]["precision"] >= 0.9
    assert report["exact"]["recall"] >= 0.9
