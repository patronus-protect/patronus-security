from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "entity_map.py"
SPEC = importlib.util.spec_from_file_location("l1_entity_map", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

sys.path.insert(0, str(ROOT / "python"))
from patronus_ark import external_pii_eval  # noqa: E402


def _load_runner(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "l1_presidio" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


RUN_PRESIDIO = _load_runner("run_presidio")


def raw_map():
    return yaml.safe_load(MODULE.ENTITY_MAP_PATH.read_text(encoding="utf-8"))


def minimal_map():
    return {
        "schema": MODULE.SCHEMA,
        "presidio_version": "2.2.364",
        "entities": [
            {
                "id": "pii.email",
                "scope": "shared",
                "ark": ["EMAIL"],
                "presidio": ["EMAIL_ADDRESS"],
                "corpora": {"gretel-synthetic-pii-finance": ["EMAIL"]},
            },
            {"id": "pii.swift_bic", "scope": "ark_only", "ark": ["SWIFT_CODE"], "presidio": [], "corpora": {}},
            {"id": "pii.url", "scope": "presidio_only", "ark": [], "presidio": ["URL"], "corpora": {}},
            {
                "id": "entity.person_name",
                "scope": "semantic",
                "ark": [],
                "presidio": ["PERSON"],
                "corpora": {"tab": ["PERSON"]},
            },
        ],
    }


# ── the checked-in map ───────────────────────────────────────────────────────


def test_checked_in_map_loads_and_uses_every_scope():
    entity_map = MODULE.load()
    assert entity_map.presidio_version == "2.2.364"
    assert {entity.scope for entity in entity_map.entities.values()} == set(MODULE.SCOPES)


def test_every_ark_label_of_the_pii_registry_is_mapped():
    labels = MODULE.ark_labels_from_source()
    # 37 rules -> 30 labels at the time of E03; the set only grows from here.
    assert {"EMAIL", "STEUERID", "NATIONALID", "LICENSEPLATE", "CREDITCARD_EXPIRY"} <= labels
    entity_map = MODULE.load()
    unmapped = sorted(label for label in labels if entity_map.ark_label(label) is None)
    assert unmapped == []


def test_map_names_no_ark_label_that_the_registry_lacks():
    assert MODULE.load().ark_labels() == MODULE.ark_labels_from_source()


def test_runtime_maps_agree_with_the_entity_map():
    entity_map = MODULE.load()
    for label, benchmark in external_pii_eval.ARK_OUTPUT_MAP.items():
        assert entity_map.ark_label(label) == benchmark, label
    for entity, benchmark in RUN_PRESIDIO.PRESIDIO_OUTPUT_MAP.items():
        assert entity_map.presidio_entity(entity) == benchmark, entity
    known = set(entity_map.entities)
    assert set(external_pii_eval.ENTITY_MAP.values()) <= known


def test_corpus_labels_match_the_external_pii_manifest():
    entity_map = MODULE.load()
    manifest = external_pii_eval.load_manifest()
    assert set(entity_map.corpora()) == set(manifest)
    for corpus_id, corpus in manifest.items():
        expected = {label.lower(): benchmark for label, benchmark in corpus["label_map"].items()}
        assert entity_map.corpus_labels(corpus_id) == expected, corpus_id


def test_check_reports_no_problems_for_the_checked_in_map():
    assert MODULE.check(MODULE.load()) == []


def test_scopes_follow_the_l1_program():
    entity_map = MODULE.load()
    scope = entity_map.scope
    assert scope("pii.email") == "shared"
    assert scope("pii.iban") == "shared"
    assert scope("pii.de.tax_id") == "shared"
    assert scope("pii.swift_bic") == "ark_only"
    assert scope("pii.credit_card.cvv") == "ark_only"
    assert scope("pii.url") == "presidio_only"
    for benchmark in ("entity.person_name", "entity.location", "entity.organization", "entity.nrp"):
        assert scope(benchmark) == "semantic"
    assert entity_map.presidio_entity("DE_TAX_ID") == "pii.de.tax_id"
    assert entity_map.ark_label("STEUERID") == "pii.de.tax_id"
    assert entity_map.corpus_label("gretel-synthetic-pii-finance", "SWIFT_BIC_CODE") == "pii.swift_bic"
    assert entity_map.corpus_label("tab", "unknown") is None
    assert "pii.email" in entity_map.ids("shared")
    assert "pii.email" not in entity_map.ids("ark_only")


# ── validation of malformed maps ─────────────────────────────────────────────


def test_minimal_map_is_valid():
    entity_map = MODULE.EntityMap.from_dict(minimal_map())
    assert entity_map.ark_label("EMAIL") == "pii.email"
    assert entity_map.presidio_entity("URL") == "pii.url"
    assert entity_map.corpus_label("tab", "person") == "entity.person_name"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda m: m.update(schema="other"), "schema"),
        (lambda m: m["entities"][0].update(scope="both"), "scope"),
        (lambda m: m["entities"][0].update(id="Email"), "id"),
        (lambda m: m["entities"].append(copy.deepcopy(m["entities"][1])), "duplicate"),
        (lambda m: m["entities"][0].update(presidio=[]), "shared"),
        (lambda m: m["entities"][1].update(presidio=["SWIFT"]), "ark_only"),
        (lambda m: m["entities"][2].update(ark=["URL"]), "presidio_only"),
        (lambda m: m["entities"][3].update(ark=["PERSON"]), "semantic"),
        (lambda m: m["entities"][3].update(id="pii.person"), "semantic"),
        (lambda m: m["entities"][1].update(ark=["EMAIL"]), "EMAIL"),
        (lambda m: m["entities"][2].update(presidio=["EMAIL_ADDRESS"]), "EMAIL_ADDRESS"),
        (lambda m: m["entities"][3]["corpora"].update({"gretel-synthetic-pii-finance": ["email"]}), "email"),
        (lambda m: m["entities"][0].update(ark="EMAIL"), "list"),
        (lambda m: m["entities"][0].update(extra=1), "extra"),
    ],
)
def test_malformed_maps_are_rejected(mutate, message):
    payload = minimal_map()
    mutate(payload)
    with pytest.raises(ValueError, match=message):
        MODULE.EntityMap.from_dict(payload)


def test_check_finds_unmapped_and_stale_ark_labels():
    entity_map = MODULE.EntityMap.from_dict(minimal_map())
    problems = MODULE.check(
        entity_map,
        ark_labels={"EMAIL", "PHONE"},
        ark_output_map={},
        presidio_output_map={},
        benchmark_aliases={},
        manifest={},
    )
    assert any("PHONE" in problem and "not mapped" in problem for problem in problems)
    assert any("SWIFT_CODE" in problem and "not in the registry" in problem for problem in problems)


def test_check_finds_runtime_and_manifest_disagreements():
    entity_map = MODULE.EntityMap.from_dict(minimal_map())
    problems = MODULE.check(
        entity_map,
        ark_labels={"EMAIL", "SWIFT_CODE"},
        ark_output_map={"EMAIL": "pii.mail"},
        presidio_output_map={"URL": "pii.link"},
        benchmark_aliases={"handle": "pii.handle"},
        manifest={
            "gretel-synthetic-pii-finance": {"label_map": {"EMAIL": "pii.email", "iban": "pii.iban"}},
            "tab": {"label_map": {"PERSON": "entity.person_name"}},
            "new-corpus": {"label_map": {}},
        },
    )
    text = "\n".join(problems)
    assert "ARK_OUTPUT_MAP" in text and "pii.mail" in text
    assert "PRESIDIO_OUTPUT_MAP" in text and "pii.link" in text
    assert "pii.handle" in text
    assert "iban" in text
    assert "new-corpus" in text


def test_check_compares_the_presidio_registry_when_given():
    entity_map = MODULE.EntityMap.from_dict(minimal_map())
    problems = MODULE.check(
        entity_map,
        ark_labels={"EMAIL", "SWIFT_CODE"},
        ark_output_map={},
        presidio_output_map={},
        benchmark_aliases={},
        manifest={
            "gretel-synthetic-pii-finance": {"label_map": {"EMAIL": "pii.email"}},
            "tab": {"label_map": {"PERSON": "entity.person_name"}},
        },
        presidio_entities={"EMAIL_ADDRESS", "URL", "PERSON", "AU_TFN"},
    )
    assert len(problems) == 1 and "AU_TFN" in problems[0]


def test_ark_labels_are_parsed_from_the_rust_registry(tmp_path):
    source = tmp_path / "pii.rs"
    source.write_text(
        "pub static PII_PATTERNS: &[PiiPattern] = &[\n"
        '    PiiPattern {\n        name: "a",\n        pattern: r"x",\n        entity_group: "EMAIL",\n'
        "        validator: None,\n        captured_value: false,\n    },\n"
        '    PiiPattern {\n        name: "b",\n        pattern: r"y",\n        entity_group: "PHONE",\n'
        "        validator: None,\n        captured_value: false,\n    },\n];\n",
        encoding="utf-8",
    )
    assert MODULE.ark_labels_from_source(source) == {"EMAIL", "PHONE"}


def test_cli_check_succeeds_and_fails(tmp_path):
    ok = subprocess.run(
        [sys.executable, str(SCRIPT), "check"], capture_output=True, text=True, cwd=ROOT
    )
    assert ok.returncode == 0, ok.stderr
    assert "entity map ok" in ok.stdout

    broken = raw_map()
    broken["entities"] = [entity for entity in broken["entities"] if "EMAIL" not in entity["ark"]]
    path = tmp_path / "entity_map.yaml"
    path.write_text(yaml.safe_dump(broken), encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(SCRIPT), "check", "--map", str(path)], capture_output=True, text=True, cwd=ROOT
    )
    assert failed.returncode == 1
    assert "EMAIL" in failed.stderr


def test_cli_table_lists_every_entity(tmp_path):
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "table"], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout
    for benchmark in MODULE.load().entities:
        assert f"`{benchmark}`" in out


def presidio_available():
    try:
        return importlib.util.find_spec("presidio_analyzer") is not None
    except (ImportError, ValueError):
        return False


@pytest.mark.skipif(not presidio_available(), reason="presidio_analyzer is not installed")
def test_every_presidio_entity_of_the_pinned_registry_is_mapped():
    entity_map = MODULE.load()
    registry = MODULE.presidio_registry_entities()
    assert {"EMAIL_ADDRESS", "DE_TAX_ID", "PERSON"} <= registry
    assert MODULE.check(entity_map, presidio_entities=registry) == []
