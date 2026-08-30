from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "evaluate_injection_l1_jsonl.py"
SPEC = importlib.util.spec_from_file_location("evaluate_injection_l1_jsonl", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_read_texts_and_document_metrics(tmp_path):
    source = tmp_path / "rows.jsonl"
    source.write_text(
        json.dumps({"text": "one"}) + "\n" + json.dumps({"text": "two"}) + "\n",
        encoding="utf-8",
    )
    assert MODULE.read_texts(source) == ["one", "two"]
    result = MODULE.metrics(
        {"documents": 10, "candidate_documents": 7, "accepted_documents": 6},
        {"documents": 20, "candidate_documents": 2, "accepted_documents": 1},
    )
    assert result == {
        "tp": 6,
        "fn": 4,
        "fp": 1,
        "tn": 19,
        "precision": 6 / 7,
        "recall": 0.6,
        "f1": 2 * (6 / 7) * 0.6 / ((6 / 7) + 0.6),
        "false_positive_rate": 0.05,
    }
