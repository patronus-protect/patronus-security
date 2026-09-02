from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "measure_external_dlp_runtime.py"
SPEC = importlib.util.spec_from_file_location("measure_external_dlp_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_source_document_scoring_reports_recall_and_negative_fpr():
    rows = [
        {"id": "positive-hit", "document_label": MODULE.SOURCE_LABEL},
        {"id": "positive-miss", "document_label": MODULE.SOURCE_LABEL},
        {"id": "negative-hit", "document_label": None},
        {"id": "negative-clean", "document_label": None},
    ]

    assert MODULE.score_source_documents(rows, {"positive-hit", "negative-hit"}) == {
        "tp": 1,
        "fn": 1,
        "fp": 1,
        "tn": 1,
        "recall": 0.5,
        "negative_document_fpr": 0.5,
    }


def test_sql_scoring_separates_exact_and_overlap_recall_without_precision_claim():
    text = "CREATE TABLE a; ALTER TABLE b;"
    rows = [
        {
            "source_path": "sample.sql",
            "text": text,
            "entities": [{"entity_type": MODULE.SQL_LABEL, "start": 0, "end": 15}],
        },
        {
            "source_path": "sample.sql",
            "text": text,
            "entities": [{"entity_type": MODULE.SQL_LABEL, "start": 16, "end": 30}],
        },
    ]
    predictions = {"sample.sql": {(0, 15), (17, 30), (31, 35)}}

    assert MODULE.score_sql_spans(rows, predictions) == {
        "documents": 1,
        "gold": 2,
        "predicted_unscoped": 3,
        "exact_hits": 1,
        "overlap_hits": 2,
        "exact_recall": 0.5,
        "overlap_recall": 1.0,
        "precision": "not_reported_incomplete_gold_after_cap",
    }
