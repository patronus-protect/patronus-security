from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "taxonomy.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_taxonomy", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

RULES = {"ark.injection.override.discard_prior", "ark.threat.remote_execution"}
LEXICONS = {"injection.io_override", "threat.download_action"}
TASKS = {"IJ01", "PX01", "JB01", "S02", "X04"}


def family(family_id: str, **overrides):
    entry = {
        "id": family_id,
        "pattern": f"pattern_{family_id}",
        "title": "Family title",
        "priority": "must",
        "task": "IJ01",
        "shape": "VERB_DISCARD + OBJ_PRIOR_INSTRUCTIONS",
        "anchors": ["injection.io_override", "injection.prior_instructions"],
        "required_context": ["addressee"],
        "negative_context": ["meta"],
        "examples": {"de": ["<Imperativ VERWERFEN> <obige Anweisungen>"], "en": ["<imperative DISCARD> <prior instructions>"]},
        "carriers": ["chat", "email"],
        "existing_rules": [],
        "baseline_coverage": {"atr": "partial", "pipelock": "none"},
        "gap": "German separable verbs",
        "scored_only": False,
    }
    entry.update(overrides)
    return entry


def minimal_taxonomy():
    classes = {name: {"category": name, "families": [family(f"{name}_core")]} for name in MODULE.CLASSES}
    classes["instruction_injection"]["category"] = "injection"
    classes["instruction_injection"]["families"][0]["existing_rules"] = ["ark.injection.override.discard_prior"]
    classes["instruction_injection"]["lexicons"] = [
        {"id": "injection.prior_instructions", "kind": "support", "task": "S02", "title": "prior instructions"}
    ]
    return {
        "schema": MODULE.SCHEMA,
        "lexicons": [
            {"id": "addressee", "kind": "support", "task": "S02", "title": "addressee"},
            {"id": "meta", "kind": "counter", "task": "S02", "title": "security documentation"},
        ],
        "classes": classes,
        "handoffs": [{"target": "shell_command", "task": "X04", "rules": ["ark.threat.remote_execution"]}],
    }


def problems(taxonomy):
    return MODULE.check(taxonomy, rules=RULES, lexicons=LEXICONS, tasks=TASKS)


def test_minimal_taxonomy_is_clean():
    assert problems(minimal_taxonomy()) == []


def test_unmapped_rule_fails():
    taxonomy = minimal_taxonomy()
    taxonomy["handoffs"] = []
    assert problems(taxonomy) == ["rule ark.threat.remote_execution is not mapped"]


def test_rule_mapped_by_two_families_fails():
    taxonomy = minimal_taxonomy()
    taxonomy["classes"]["jailbreak"]["families"][0]["existing_rules"] = ["ark.injection.override.discard_prior"]
    assert problems(taxonomy) == ["rule ark.injection.override.discard_prior is mapped 2 times"]


def test_rule_mapped_by_family_and_handoff_fails():
    taxonomy = minimal_taxonomy()
    taxonomy["classes"]["unsafe_action"]["families"][0]["existing_rules"] = ["ark.threat.remote_execution"]
    assert problems(taxonomy) == ["rule ark.threat.remote_execution is mapped 2 times"]


def test_unknown_rule_fails():
    taxonomy = minimal_taxonomy()
    taxonomy["classes"]["jailbreak"]["families"][0]["existing_rules"] = ["ark.injection.jailbreak.unknown"]
    assert problems(taxonomy) == ["mapped rule ark.injection.jailbreak.unknown does not exist"]


def test_must_family_without_task_fails():
    taxonomy = minimal_taxonomy()
    del taxonomy["classes"]["jailbreak"]["families"][0]["task"]
    assert problems(taxonomy) == ["jailbreak.jailbreak_core: must-family without task"]


def test_should_family_without_task_is_allowed():
    taxonomy = minimal_taxonomy()
    entry = taxonomy["classes"]["jailbreak"]["families"][0]
    entry["priority"] = "should"
    del entry["task"]
    assert problems(taxonomy) == []


def test_unknown_task_fails():
    taxonomy = minimal_taxonomy()
    taxonomy["classes"]["jailbreak"]["families"][0]["task"] = "ZZ99"
    assert problems(taxonomy) == ["jailbreak.jailbreak_core: task ZZ99 is not in backlog.yaml"]


@pytest.mark.parametrize("key", MODULE.CONTEXT_KEYS)
def test_unknown_lexicon_id_fails(key):
    taxonomy = minimal_taxonomy()
    taxonomy["classes"]["jailbreak"]["families"][0][key] = ["jailbreak.not_declared"]
    assert problems(taxonomy) == [f"jailbreak.jailbreak_core: unknown lexicon id jailbreak.not_declared in {key}"]


def test_planned_lexicon_must_be_new_and_unique():
    taxonomy = minimal_taxonomy()
    taxonomy["lexicons"].append({"id": "injection.io_override", "kind": "support", "task": "S02", "title": "x"})
    taxonomy["classes"]["jailbreak"]["lexicons"] = [{"id": "addressee", "kind": "support", "task": "S02", "title": "x"}]
    assert problems(taxonomy) == [
        "lexicon injection.io_override (core) is declared as planned but already exists",
        "lexicon addressee is declared 2 times",
    ]


def test_lexicon_with_unknown_key_fails():
    # An unquoted comma in a flow mapping title turns the rest of the title into extra keys.
    taxonomy = minimal_taxonomy()
    taxonomy["lexicons"][0]["step by step"] = None
    assert problems(taxonomy) == ["lexicon addressee (core): keys id, kind, step by step, task, title, expected id, kind, task, title"]


def test_schema_errors_are_reported():
    taxonomy = minimal_taxonomy()
    entry = taxonomy["classes"]["jailbreak"]["families"][0]
    entry.update(priority="high", carriers=["fax"], examples={"en": ["<shape>"]}, baseline_coverage={"other": "most"})
    del taxonomy["classes"]["toxic_language"]
    assert problems(taxonomy) == [
        "class toxic_language is missing",
        "jailbreak.jailbreak_core: priority 'high' is not one of must, should, could",
        "jailbreak.jailbreak_core: unknown carrier fax",
        "jailbreak.jailbreak_core: no de example shape",
        "jailbreak.jailbreak_core: unknown baseline other",
        "jailbreak.jailbreak_core: coverage 'most' of other is not one of full, partial, none",
    ]


def test_existing_rule_ids_reads_catalogs_native_rules_and_threat_rules(tmp_path):
    rules_dir = tmp_path / "ark-core/src/detectors/injection/rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "catalog.json").write_text(
        json.dumps({"rules": [{"id": "prompt-armor.pi-001", "canonical_id": "ark.injection.override.discard_prior"}, {"id": "ark.injection.leak.own_prompt"}]})
    )
    (rules_dir / "l1_scorer.json").write_text(json.dumps({"coefficients": {}}))
    (rules_dir.parent / "structural.rs").write_text(
        'rule_id: "ark.injection.structure.native".to_string(),\n#[cfg(test)]\nrule_id: "ark.injection.test.fixture"\n'
    )
    threat = tmp_path / "rust/src/detectors/threat/rules.json"
    threat.parent.mkdir(parents=True)
    threat.write_text(json.dumps({"rules": [{"id": "ark.threat.remote_execution"}]}))
    assert MODULE.existing_rule_ids(tmp_path) == {
        "ark.injection.override.discard_prior",
        "ark.injection.leak.own_prompt",
        "ark.injection.structure.native",
        "ark.threat.remote_execution",
    }


def test_repository_taxonomy_is_clean():
    taxonomy = MODULE.load()
    assert MODULE.check(
        taxonomy,
        rules=MODULE.existing_rule_ids(),
        lexicons=MODULE.existing_lexicon_ids(),
        tasks=MODULE.backlog_task_ids(),
    ) == []
    assert MODULE.main(["check"]) == 0


def golden(**overrides):
    row = {"id": "threat_l1-x-pos-01", "class": "jailbreak", "family": "jailbreak_core", "carrier": "chat"}
    row.update(overrides)
    return row


def test_matching_golden_is_clean():
    rule = {"class": "instruction_injection", "family": "instruction_injection_core",
            "rule_id": "ark.injection.override.discard_prior"}
    assert MODULE.golden_problems(minimal_taxonomy(), [golden(), golden(**rule)]) == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"family": "unknown"}, "family unknown is not a family of class jailbreak"),
        ({"class": "toxic_language"}, "family jailbreak_core is not a family of class toxic_language"),
        ({"carrier": "webpage"}, "unknown carrier 'webpage'"),
        ({"rule_id": "ark.injection.override.discard_prior"},
         "rule ark.injection.override.discard_prior is not mapped by family jailbreak.jailbreak_core"),
    ],
)
def test_mismatched_golden_fails(overrides, message):
    assert MODULE.golden_problems(minimal_taxonomy(), [golden(**overrides)]) == [f"golden threat_l1-x-pos-01: {message}"]


def test_repository_goldens_match_the_taxonomy():
    assert MODULE.golden_problems(MODULE.load(), MODULE.load_goldens()) == []


def test_backlog_task_ids_rejects_duplicate_keys(tmp_path):
    backlog = tmp_path / "backlog.yaml"
    backlog.write_text("tasks:\n  - id: M07\n    status: done\n    status: todo\n", encoding="utf-8")
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        MODULE.backlog_task_ids(backlog)


def test_backlog_task_ids_reads_tasks_and_recurring(tmp_path):
    backlog = tmp_path / "backlog.yaml"
    backlog.write_text("tasks:\n  - id: M07\nrecurring:\n  - id: TRIAGE\n", encoding="utf-8")
    assert MODULE.backlog_task_ids(backlog) == {"M07", "TRIAGE"}


def test_repository_must_families_cover_de_and_en_for_every_class():
    taxonomy = MODULE.load()
    for name in MODULE.CLASSES:
        musts = [entry for entry in taxonomy["classes"][name]["families"] if entry["priority"] == "must"]
        assert musts, name
        assert all(entry["examples"]["de"] and entry["examples"]["en"] for entry in musts), name


def test_main_fails_on_broken_taxonomy(tmp_path, capsys):
    taxonomy = copy.deepcopy(MODULE.load())
    taxonomy["classes"]["jailbreak"]["families"][0]["anchors"] = ["jailbreak.not_declared"]
    path = tmp_path / "taxonomy.yaml"
    path.write_text(yaml.safe_dump(taxonomy, allow_unicode=True))
    assert MODULE.main(["check", "--taxonomy", str(path)]) == 1
    assert "unknown lexicon id jailbreak.not_declared" in capsys.readouterr().err
