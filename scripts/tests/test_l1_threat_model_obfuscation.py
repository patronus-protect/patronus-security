from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "l1_threat" / "model_obfuscation.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_model_obfuscation", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def row(row_id: str, language: str, benign: bool, classes=(), dataset: str = "dolly_15k") -> dict:
    return {"id": row_id, "text": f"text {row_id}", "language": language, "benign": benign,
            "classes": list(classes), "dataset": dataset}


def test_sample_caps_benign_rows_and_positives_per_language():
    rows = [row(f"b{i}", "en", True) for i in range(5)] + [row(f"p{i}", "de", False, ["jailbreak"]) for i in range(4)]
    picked = MODULE.sample(rows, benign=2, positives=3)
    groups = sorted(r["group"] for r in picked)
    assert groups == ["benign", "benign", "pos:jailbreak", "pos:jailbreak", "pos:jailbreak"]


def test_variants_apply_every_obfuscation():
    texts = MODULE.variants([row("a", "en", True)])
    assert [t["id"] for t in texts] == ["a", *[f"a~{kind}" for kind in MODULE.KINDS]]
    zero_width = next(t for t in texts if t["id"] == "a~zero_width")["text"]
    assert "​" in zero_width


def test_rates_are_per_model_language_and_group():
    rows = [{**row("b", "en", True), "group": "benign"},
            {**row("p", "en", False, ["jailbreak"]), "group": "pos:jailbreak"}]
    flags = {"b": [], "p": ["jailbreak"]}
    for kind in MODULE.KINDS:
        flags[f"b~{kind}"] = ["jailbreak"] if kind == "zero_width" else []
        flags[f"p~{kind}"] = ["jailbreak"]
    result = MODULE.rates(rows, flags)
    assert result["jailbreak|en|benign"]["clean"] == 0.0
    assert result["jailbreak|en|benign"]["zero_width"] == 100.0
    assert result["jailbreak|en|positive"]["base64"] == 100.0
    assert result["jailbreak|de|benign"]["rows"] == 0
    assert "| jailbreak | en | benign | 1 | 0.00 | 100.00 |" in MODULE.render(result, "note")
