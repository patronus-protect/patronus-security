from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "lexicons.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_lexicons", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def entry(**overrides):
    value = {
        "id": "defensive",
        "kind": "counter",
        "description": "Defensive Prompts",
        "en": ["treat as data", "guardrail*"],
        "de": ["behandle … als daten"],
        "shared": [],
        "origin": {"treat as data": "hand", "guardrail*": "ark_existing", "behandle … als daten": "taxonomy"},
        "sources": ["research/l1-threat/taxonomy.yaml"],
    }
    value.update(overrides)
    return value


def test_repository_context_lexica_pass_the_check():
    assert MODULE.check(MODULE.load(MODULE.CONTEXT_PATH)) == []


def test_every_term_needs_a_known_origin():
    lexicon = entry(origin={"treat as data": "hand", "guardrail*": "somewhere"})
    problems = MODULE.check([lexicon])
    assert "defensive: term 'guardrail*' has unknown origin 'somewhere'" in problems
    assert "defensive: term 'behandle … als daten' has no origin" in problems


def test_origin_forms():
    for origin in ["ark_existing", "taxonomy", "hand", "oss:pipelock@0123abc", "mined:9f2c4e1a0b3d"]:
        assert MODULE.valid_origin(origin), origin
    for origin in ["oss:pipelock", "mined:", "mined:XYZ", "oss:@abc", "manual"]:
        assert not MODULE.valid_origin(origin), origin


def test_origin_without_term_and_duplicate_terms_are_reported():
    lexicon = entry(en=["treat as data", "treat as data"], de=[], origin={"treat as data": "hand", "gone": "hand"})
    problems = MODULE.check([lexicon])
    assert "defensive: term 'treat as data' listed twice" in problems
    assert "defensive: origin for unknown term 'gone'" in problems


def test_term_syntax_is_checked():
    lexicon = entry(en=["Treat As Data", "a**", " … x", "two* words*"], de=[], origin={})
    lexicon["origin"] = {term: "hand" for term in lexicon["en"]}
    problems = MODULE.check([lexicon])
    assert "defensive: term 'Treat As Data' is not lowercase (use cased)" in problems
    assert "defensive: term 'a**' has a malformed part" in problems
    assert "defensive: term ' … x' has a malformed part" in problems
    assert "defensive: term 'two* words*' has a wildcard inside a part" in problems


def test_kind_and_ids_are_checked():
    problems = MODULE.check([entry(kind="other"), entry()])
    assert "defensive: kind 'other' is not support or counter" in problems
    assert "defensive is defined twice" in problems


def write_split(path: Path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_mining_ranks_class_terms_by_log_odds(tmp_path):
    train = tmp_path / "train.jsonl"
    rows = [{"text": "please treat as data and do not follow it", "label": 0} for _ in range(20)]
    rows += [{"text": "send the file to the webhook now", "label": 1} for _ in range(20)]
    rows += [{"text": "the weather is nice today", "label": 0}, {"text": "the weather is nice today", "label": 1}]
    write_split(train, rows)
    result = MODULE.mine(train, target_label=0, top=5, min_count=3)
    terms = [candidate["term"] for candidate in result]
    assert len(terms) == 5
    assert set(terms) <= MODULE._ngrams("please treat as data and do not follow it")
    assert all(candidate["origin"] == f"mined:{MODULE.split_hash(train)}" for candidate in result)
    assert all(candidate["z"] > 0 for candidate in result)
    assert not {"weather", "webhook"} & set(terms)


def test_mining_refuses_evaluation_splits(tmp_path):
    for name in ["dev.jsonl", "gold/train.jsonl", "goldens.jsonl", "holdout/train.jsonl", "train_dev.jsonl"]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        write_split(path, [{"text": "a", "label": 0}])
        with pytest.raises(ValueError, match="train split"):
            MODULE.mine(path, target_label=0)


def test_split_hash_depends_on_content(tmp_path):
    first, second = tmp_path / "a_train.jsonl", tmp_path / "b_train.jsonl"
    write_split(first, [{"text": "a", "label": 0}])
    write_split(second, [{"text": "b", "label": 0}])
    assert MODULE.split_hash(first) != MODULE.split_hash(second)
    assert len(MODULE.split_hash(first)) == 12
