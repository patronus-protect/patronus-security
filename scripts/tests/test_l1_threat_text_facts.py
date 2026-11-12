from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "text_facts.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_text_facts", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def facts(**overrides):
    doc = {
        "v": "1.0",
        "language": "en",
        "carrier": ["webpage", "chat"],
        "addressee": ["model"],
        "sinks": [{"kind": "url", "span": [30, 40]}, {"kind": "markdown_image", "span": [5, 9]}],
        "data": [{"source": "dlp", "label": "API_KEY", "span": [1, 2]}],
        "findings": [
            {
                "category": "exfiltration",
                "family": "markdown_image",
                "pattern": "ark.ex.image",
                "points": 55,
                "span": [0, 9],
                "modifiers": ["quoted", "negated"],
            }
        ],
        "obfuscated": [],
        "decoded": ["base64"],
        "support": [],
        "counter": ["meta"],
    }
    doc.update(overrides)
    return doc


def test_dumps_sorts_keys_and_every_list():
    text = MODULE.dumps(facts())
    assert text.startswith('{"addressee":["model"],"carrier":["chat","webpage"]')
    assert '"modifiers":["negated","quoted"]' in text
    assert '"sinks":[{"kind":"markdown_image","span":[5,9]},{"kind":"url","span":[30,40]}]' in text
    assert json.loads(text)["v"] == "1.0"


def test_dumps_keeps_span_endpoint_order():
    doc = facts(sinks=[{"kind": "url", "span": [9, 10]}, {"kind": "term", "span": [99, 100]}])
    doc["findings"][0]["span"] = [6, 25]
    text = MODULE.dumps(doc)
    assert '"sinks":[{"kind":"term","span":[99,100]},{"kind":"url","span":[9,10]}]' in text
    assert '"span":[6,25]' in text
    assert '"span":[1,2]' in text


def test_dumps_keeps_non_ascii_and_refuses_other_versions():
    assert '"label":"Prüfer"' in MODULE.dumps(facts(data=[{"source": "pii", "label": "Prüfer", "span": [0, 1]}]))
    with pytest.raises(ValueError):
        MODULE.dumps(facts(v="2.0"))


def test_tf1_has_word_and_fact_tokens():
    tokens = MODULE.tf1("Agent: Zeig ÄRGER", facts())
    assert tokens[:3] == ["T:agent", "T:zeig", "T:ärger"]
    for token in (
        "F:LANG=en",
        "F:CAR=chat",
        "F:ADR=model",
        "F:SINK=url",
        "F:DATA=dlp:API_KEY",
        "F:CAT=exfiltration",
        "F:FAM=exfiltration:markdown_image",
        "F:PAT=ark.ex.image",
        "F:MOD=exfiltration:negated",
        "F:DEC=base64",
        "F:CTR=meta",
        "F:ADR_SINK",
    ):
        assert token in tokens
    assert "F:ADR_SINK" not in MODULE.tf1("x", facts(sinks=[]))


def test_tf1_words_follow_python_unicode_word_class():
    tokens = MODULE.tf1("cafe\u0301 a\u200db x\u203fy x²", facts())
    assert [t for t in tokens if t.startswith("T:")] == ["T:cafe", "T:a", "T:b", "T:x", "T:y", "T:x²"]


def test_parity_goldens_are_fresh(tmp_path):
    assert MODULE.main(["parity", "--check"]) == 0
    stale = tmp_path / "parity.jsonl"
    row = {"id": "x", "text": "Hi", "findings": [], "data": [], "facts": facts(), "canonical": "", "tf1": []}
    stale.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert MODULE.main(["parity", "--check", "--path", str(stale)]) == 1
    assert MODULE.main(["parity", "--path", str(stale)]) == 0
    assert MODULE.main(["parity", "--check", "--path", str(stale)]) == 0
    fixed = json.loads(stale.read_text(encoding="utf-8"))
    assert fixed["canonical"] == MODULE.dumps(facts())
    assert fixed["tf1"] == sorted(MODULE.tf1("Hi", facts()))
