from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "l1_threat" / "toxic_lexicon.py"
SPEC = importlib.util.spec_from_file_location("l1_toxic_lexicon", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

SOURCES = {
    "hand": {"id": "hand", "kind": "hand", "licence": "MIT", "url": "x", "revision": "1"},
    "nc": {"id": "nc", "kind": "word_list", "licence": "CC-BY-NC-4.0", "url": "x", "revision": "1"},
    "holdout": {"id": "holdout", "kind": "dataset_contrast", "licence": "CC-BY-4.0", "url": "x", "revision": "1",
                "use": False},
}
USABLE = {"hand": SOURCES["hand"], "holdout": SOURCES["holdout"]}


def test_hash_matches_the_rust_lookup():
    # parity case of toxic_lexicon.rs (hash_matches_the_python_builder)
    assert MODULE.normalize("Exämple") == "exaemple"
    assert MODULE.term_hash("Exämple") == "c16d2a5e7fcd8362"
    assert MODULE.normalize("3x@mp1e*") == "exampie"
    assert MODULE.normalize("  Two   Words ") == "two words"


def test_build_hashes_terms_per_family_without_plaintext():
    terms = [("insult", "Blorf", "hand"), ("insult", "blorf", "hand"), ("dehumanise", "grub", "hand"),
             ("violence_verb", "zap", "hand")]
    lexicon = MODULE.build(terms, USABLE)
    assert lexicon["families"]["insult"] == [MODULE.term_hash("blorf")]
    assert "blorf" not in json.dumps(lexicon)
    assert lexicon["sources"] == [{"id": "hand", "licence": "MIT", "revision": "1", "terms": 4}]
    assert MODULE.check(lexicon, USABLE) == []
    assert MODULE.families_of("You are a BL0RF and a grub.", lexicon) == {"insult", "dehumanise"}


def test_build_refuses_unlisted_unused_or_unlicensed_sources():
    with pytest.raises(ValueError, match="licence 'CC-BY-NC-4.0' is not allowed"):
        MODULE.build([("insult", "blorf", "hand")], SOURCES)
    with pytest.raises(ValueError, match="'holdout' is not listed for use"):
        MODULE.build([("insult", "blorf", "holdout")], USABLE)
    with pytest.raises(ValueError, match="'other' is not listed"):
        MODULE.build([("insult", "blorf", "other")], USABLE)
    with pytest.raises(ValueError, match="unknown family"):
        MODULE.build([("slur", "blorf", "hand")], USABLE)


def test_check_flags_empty_unsorted_and_unknown_source_entries():
    lexicon = MODULE.build([("insult", "a1", "hand"), ("dehumanise", "b", "hand"), ("violence_verb", "c", "hand")],
                           USABLE)
    lexicon["families"]["insult"] = ["zz"]
    lexicon["families"]["dehumanise"] = []
    lexicon["sources"].append({"id": "nc", "licence": "MIT"})
    problems = MODULE.check(lexicon, USABLE)
    assert "lexicon: family insult is not a sorted list of 16-hex hashes" in problems
    assert "lexicon: family dehumanise is empty" in problems
    assert "lexicon: source nc is not listed with its licence" in problems


def test_committed_lexicon_and_sources_check_clean(tmp_path):
    lexicon = json.loads(MODULE.LEXICON_PATH.read_text(encoding="utf-8"))
    assert MODULE.check(lexicon, MODULE.load_sources()) == []
    rows = tmp_path / "rows.jsonl"
    rows.write_text(json.dumps({"text": "a friendly note"}) + "\n", encoding="utf-8")
    assert MODULE.count(rows, lexicon) == {"rows": 1, "insult": 0, "dehumanise": 0, "violence_verb": 0}
