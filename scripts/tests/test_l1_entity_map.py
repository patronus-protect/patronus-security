from __future__ import annotations

import copy
import importlib.util
import re
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
        "source_families": {
            "ark_authored": ["pii_l1", "l1_bilingual_rules", "ark-synthetic-de-eu", "ark-synthetic-vat-1", "ark-synthetic-vat-2"],
            "neutral": ["gretel-synthetic-pii-finance", "tab"],
        },
    }


# ── the checked-in map ───────────────────────────────────────────────────────


def test_checked_in_map_loads_and_uses_every_scope():
    entity_map = MODULE.load()
    assert entity_map.presidio_version == "2.2.364"
    assert {entity.scope for entity in entity_map.entities.values()} == set(MODULE.SCOPES)


def test_every_ark_label_of_the_pii_registry_is_mapped():
    labels = MODULE.ark_labels_from_source()
    # 39 rules -> 28 labels at the time of E03.
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


def test_vat_ids_have_one_label_and_id_per_country():
    # B01: DE and IT VAT IDs are shared with Presidio, the other six countries are ARK-only; B02 adds
    # eleven ARK-only countries (Greece: label prefix EL, ID country gr).
    # B16: eleven more ARK-only countries; XI (Northern Ireland) shares the UK label.
    entity_map = MODULE.load()
    for label, benchmark, scope in (
        ("VAT_ID_DE", "pii.de.vat_id", "shared"),
        ("VAT_ID_IT", "pii.it.vat_code", "shared"),
        ("VAT_ID_AT", "pii.at.vat_id", "ark_only"),
        ("VAT_ID_CH", "pii.ch.vat_id", "ark_only"),
        ("VAT_ID_FR", "pii.fr.vat_id", "ark_only"),
        ("VAT_ID_NL", "pii.nl.vat_id", "ark_only"),
        ("VAT_ID_BE", "pii.be.vat_id", "ark_only"),
        ("VAT_ID_ES", "pii.es.vat_id", "ark_only"),
        ("VAT_ID_BG", "pii.bg.vat_id", "ark_only"),
        ("VAT_ID_CY", "pii.cy.vat_id", "ark_only"),
        ("VAT_ID_CZ", "pii.cz.vat_id", "ark_only"),
        ("VAT_ID_DK", "pii.dk.vat_id", "ark_only"),
        ("VAT_ID_EE", "pii.ee.vat_id", "ark_only"),
        ("VAT_ID_EL", "pii.gr.vat_id", "ark_only"),
        ("VAT_ID_FI", "pii.fi.vat_id", "ark_only"),
        ("VAT_ID_HR", "pii.hr.vat_id", "ark_only"),
        ("VAT_ID_HU", "pii.hu.vat_id", "ark_only"),
        ("VAT_ID_IE", "pii.ie.vat_id", "ark_only"),
        ("VAT_ID_LT", "pii.lt.vat_id", "ark_only"),
        ("VAT_ID_LU", "pii.lu.vat_id", "ark_only"),
        ("VAT_ID_LV", "pii.lv.vat_id", "ark_only"),
        ("VAT_ID_MT", "pii.mt.vat_id", "ark_only"),
        ("VAT_ID_PL", "pii.pl.vat_id", "ark_only"),
        ("VAT_ID_PT", "pii.pt.vat_id", "ark_only"),
        ("VAT_ID_RO", "pii.ro.vat_id", "ark_only"),
        ("VAT_ID_SE", "pii.se.vat_id", "ark_only"),
        ("VAT_ID_SI", "pii.si.vat_id", "ark_only"),
        ("VAT_ID_SK", "pii.sk.vat_id", "ark_only"),
        ("VAT_ID_NO", "pii.no.vat_id", "ark_only"),
        ("VAT_ID_GB", "pii.uk.vat_id", "ark_only"),
    ):
        assert entity_map.ark_label(label) == benchmark
        assert entity_map.scope(benchmark) == scope
    assert entity_map.presidio_entity("DE_VAT_ID") == "pii.de.vat_id"
    assert entity_map.presidio_entity("IT_VAT_CODE") == "pii.it.vat_code"


def test_uk_nhs_number_is_shared_with_presidio():
    # B-UK: the NHS number gets its own label; NINO, passport and driving licence keep theirs.
    entity_map = MODULE.load()
    assert entity_map.ark_label("NHS_NUMBER") == "pii.uk.nhs_number"
    assert entity_map.presidio_entity("UK_NHS") == "pii.uk.nhs_number"
    assert entity_map.scope("pii.uk.nhs_number") == "shared"
    assert entity_map.ark_label("NATIONALID") == "pii.uk.national_insurance_number"


def test_bsnr_is_shared_with_presidio():
    # B-DE1: the BSNR gets its own label (format and context, no check digit).
    entity_map = MODULE.load()
    assert entity_map.ark_label("FACILITY_NUMBER_BSNR") == "pii.de.bsnr"
    assert entity_map.presidio_entity("DE_BSNR") == "pii.de.bsnr"
    assert entity_map.scope("pii.de.bsnr") == "shared"


def test_au_and_sg_identifiers_are_shared_with_presidio():
    # B-APAC: one label per numbering system, named like the Presidio entity.
    entity_map = MODULE.load()
    for entity_id, label in [
        ("pii.au.abn", "AU_ABN"),
        ("pii.au.acn", "AU_ACN"),
        ("pii.au.tfn", "AU_TFN"),
        ("pii.au.medicare", "AU_MEDICARE"),
        ("pii.sg.nric_fin", "SG_NRIC_FIN"),
        ("pii.sg.uen", "SG_UEN"),
    ]:
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.presidio_entity(label) == entity_id
        assert entity_map.scope(entity_id) == "shared"


def test_nordic_personal_numbers_have_one_label_per_country():
    # B-NORD: SE and FI are shared with Presidio; Presidio has no DK CPR or NO fødselsnummer.
    entity_map = MODULE.load()
    for entity_id, label, scope in [
        ("pii.se.personnummer", "SE_PERSONNUMMER", "shared"),
        ("pii.fi.personal_identity_code", "FI_PERSONAL_IDENTITY_CODE", "shared"),
        ("pii.dk.cpr", "DK_CPR", "ark_only"),
        ("pii.no.fodselsnummer", "NO_FODSELSNUMMER", "ark_only"),
    ]:
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.scope(entity_id) == scope
    assert entity_map.presidio_entity("SE_PERSONNUMMER") == "pii.se.personnummer"
    assert entity_map.presidio_entity("FI_PERSONAL_IDENTITY_CODE") == "pii.fi.personal_identity_code"
def test_fr_nl_be_national_numbers_are_ark_only():
    # B-EU1: one label per numbering system; Presidio 2.2.364 has no recognizer for them.
    entity_map = MODULE.load()
    for entity_id, label in [
        ("pii.fr.nir", "FR_NIR"),
        ("pii.fr.siren", "FR_SIREN"),
        ("pii.fr.siret", "FR_SIRET"),
        ("pii.nl.bsn", "NL_BSN"),
        ("pii.be.national_number", "BE_NATIONAL_NUMBER"),
    ]:
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.scope(entity_id) == "ark_only"


def test_at_ch_pt_ie_national_numbers_are_ark_only():
    # B-EU2: one label per numbering system; Presidio 2.2.364 has no recognizer for them. The PT NIF is
    # an ID of its own, apart from the PT VAT ID (B16).
    entity_map = MODULE.load()
    for entity_id, label in [
        ("pii.at.social_security_number", "AT_SOCIAL_SECURITY_NUMBER"),
        ("pii.ch.ahv_number", "CH_AHV_NUMBER"),
        ("pii.pt.nif", "PT_NIF"),
        ("pii.ie.ppsn", "IE_PPSN"),
    ]:
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.scope(entity_id) == "ark_only"
    assert entity_map.ark_label("VAT_ID_PT") == "pii.pt.vat_id"


def test_korean_registration_numbers_are_shared_with_presidio():
    # B-KR: the checksum part of A14 and T12, one label per numbering system, each matching the
    # Presidio 2.2.364 entity of the same name.
    entity_map = MODULE.load()
    for entity_id, label in [("pii.kr.rrn", "KR_RRN"), ("pii.kr.frn", "KR_FRN"), ("pii.kr.brn", "KR_BRN")]:
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.presidio_entity(label) == entity_id
        assert entity_map.scope(entity_id) == "shared"


def test_spanish_and_italian_personal_numbers_are_shared_with_presidio():
    # B-ESIT: the check-letter numbers of A11 and A12, one label each, matching the Presidio 2.2.364
    # entity of the same name; the CIF and the Partita IVA stay with the VAT IDs.
    entity_map = MODULE.load()
    for entity_id, label in [("pii.es.nif", "ES_NIF"), ("pii.es.nie", "ES_NIE"), ("pii.it.fiscal_code", "IT_FISCAL_CODE")]:
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.presidio_entity(label) == entity_id
        assert entity_map.scope(entity_id) == "shared"
    assert entity_map.ark_label("VAT_ID_ES") == "pii.es.vat_id"
    assert entity_map.ark_label("VAT_ID_IT") == "pii.it.vat_code"


def test_polish_pesel_is_shared_and_regon_is_ark_only():
    # A13: one label per numbering system; PESEL matches the Presidio 2.2.364 entity of the same name,
    # Presidio has no REGON recognizer, and the NIP stays with the PL VAT ID.
    entity_map = MODULE.load()
    assert entity_map.ark_label("PL_PESEL") == "pii.pl.pesel"
    assert entity_map.presidio_entity("PL_PESEL") == "pii.pl.pesel"
    assert entity_map.scope("pii.pl.pesel") == "shared"
    assert entity_map.ark_label("PL_REGON") == "pii.pl.regon"
    assert entity_map.scope("pii.pl.regon") == "ark_only"
    assert entity_map.ark_label("VAT_ID_PL") == "pii.pl.vat_id"


def test_indian_identifiers_are_shared_with_presidio():
    # B-IN: one label per numbering system, each matching the Presidio 2.2.364 entity of the same name.
    entity_map = MODULE.load()
    for label, entity_id in (
        ("IN_AADHAAR", "pii.in.aadhaar"),
        ("IN_GSTIN", "pii.in.gstin"),
        ("IN_PAN", "pii.in.pan"),
        ("IN_VOTER", "pii.in.voter_id"),
    ):
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.presidio_entity(label) == entity_id
        assert entity_map.scope(entity_id) == "shared"


def test_luhn_identifiers_are_shared_with_presidio():
    # B-LUHN: the checksum parts of T13 and T09, one label per numbering system, each matching the
    # Presidio 2.2.364 entity of the same name.
    entity_map = MODULE.load()
    for entity_id, label in [
        ("pii.se.organisationsnummer", "SE_ORGANISATIONSNUMMER"),
        ("pii.ca.sin", "CA_SIN"),
        ("pii.tr.national_id", "TR_NATIONAL_ID"),
        ("pii.za.id_number", "ZA_ID_NUMBER"),
    ]:
        assert entity_map.ark_label(label) == entity_id
        assert entity_map.presidio_entity(label) == entity_id
        assert entity_map.scope(entity_id) == "shared"


# ── validation of malformed maps ─────────────────────────────────────────────


def test_every_gold_source_has_its_family():
    entity_map = MODULE.load()
    assert entity_map.families == {
        "pii_l1": "ark_authored",
        "l1_bilingual_rules": "ark_authored",
        "ark-synthetic-de-eu": "ark_authored",
        "ark-synthetic-vat-1": "ark_authored",
        "ark-synthetic-vat-2": "ark_authored",
        "gretel-synthetic-pii-finance": "neutral",
        "ai4privacy-openpii-nano-1k": "neutral",
        "tab": "neutral",
        "presidio-evaluator-synth-v2": "presidio_favored",
        "presidio-analyzer-recognizer-tests": "presidio_favored",
    }
    assert set(entity_map.families) == set(external_pii_eval.load_manifest()) | set(MODULE.ARK_GOLD_SOURCES)
    assert MODULE.MILESTONE_FAMILIES == ("neutral", "presidio_favored")
    assert all(path.is_file() for path in MODULE.ARK_GOLD_SOURCES.values())


def test_presidio_favored_corpora_use_presidio_entity_names():
    entity_map = MODULE.load()
    assert entity_map.corpus_label("presidio-analyzer-recognizer-tests", "CREDIT_CARD") == "pii.credit_card.pan"
    assert entity_map.corpus_label("presidio-analyzer-recognizer-tests", "DE_TAX_ID") == "pii.de.tax_id"
    assert entity_map.corpus_label("presidio-evaluator-synth-v2", "DOMAIN_NAME") == "pii.url"
    assert entity_map.corpus_label("presidio-evaluator-synth-v2", "ZIP_CODE") is None
    # Every recognizer-test label is the Presidio entity of the same id.
    for label, benchmark in entity_map.corpus_labels("presidio-analyzer-recognizer-tests").items():
        assert entity_map.presidio_entity(label.upper()) == benchmark


def test_check_reports_untagged_and_unknown_gold_sources():
    payload = minimal_map()
    payload["source_families"]["neutral"] = ["gretel-synthetic-pii-finance", "no-such-corpus"]
    problems = MODULE.check(
        MODULE.EntityMap.from_dict(payload),
        ark_labels={"EMAIL", "SWIFT_CODE"},
        ark_output_map={},
        presidio_output_map={},
        benchmark_aliases={},
        manifest={
            "gretel-synthetic-pii-finance": {"label_map": {"EMAIL": "pii.email"}},
            "tab": {"label_map": {"PERSON": "entity.person_name"}},
        },
    )
    assert problems == [
        "gold source tab has no source family",
        "source family entry no-such-corpus is not a known gold source",
    ]


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
        (lambda m: m["source_families"].update(favored=["x"]), "source family"),
        (lambda m: m["source_families"]["neutral"].append("pii_l1"), "pii_l1"),
        (lambda m: m.update(source_families=["tab"]), "source_families"),
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


def _generate_docs():
    return MODULE._load_file("_ark_generate_docs", ROOT / "scripts" / "generate_docs.py")


def _write_split_registry(root: Path, registry: str) -> Path:
    (root / "common.rs").write_text(
        "use super::{pii::PiiPattern, validators};\n\n"
        "pub(super) const EMAIL: PiiPattern = PiiPattern {\n"
        '    name: "pii_email",\n    pattern: r"x@y",\n    entity_group: "EMAIL",\n'
        "    validator: None,\n    captured_value: false,\n};\n\n"
        "pub(super) const IPV4: PiiPattern = PiiPattern {\n"
        '    name: "pii_ipv4",\n    pattern: r"\\d+",\n    entity_group: "IP_ADDRESS",\n'
        "    validator: Some(validators::ip_address),\n    captured_value: false,\n};\n",
        encoding="utf-8",
    )
    (root / "de.rs").write_text(
        "use super::{pii::PiiPattern, validators};\n\n"
        "pub(super) const PHONE: PiiPattern = PiiPattern {\n"
        '    name: "pii_phone_de",\n    pattern: r"\\+49",\n    entity_group: "PHONE",\n'
        "    validator: Some(validators::unanchored_phone),\n    captured_value: false,\n};\n",
        encoding="utf-8",
    )
    source = root / "pii.rs"
    source.write_text(registry, encoding="utf-8")
    return source


def test_module_split_registry_is_resolved_in_registry_order(tmp_path):
    source = _write_split_registry(
        tmp_path,
        "use super::{common, de};\n\n"
        "pub static PII_PATTERNS: &[PiiPattern] = &[\n"
        "    common::EMAIL,\n    de::PHONE,\n    common::IPV4,\n];\n",
    )
    rules = _generate_docs().parse_native_patterns(source, "PiiPattern")
    assert [(rule["id"], rule["entity_group"], rule["validator"]) for rule in rules] == [
        ("pii_email", "EMAIL", None),
        ("pii_phone_de", "PHONE", "unanchored_phone"),
        ("pii_ipv4", "IP_ADDRESS", "ip_address"),
    ]
    assert MODULE.ark_labels_from_source(source) == {"EMAIL", "PHONE", "IP_ADDRESS"}


def test_registry_parse_reports_score_model_fields():
    # K02: base points and validator strength per rule feed the rule catalog.
    rules = _generate_docs().parse_native_patterns(MODULE.PII_SOURCE_PATH, "PiiPattern")
    by_id = {rule["id"]: rule for rule in rules}
    assert by_id["pii_credit_card"]["strength"] == "checksum"
    assert by_id["pii_ipv4"]["strength"] == "format"
    assert by_id["pii_email"]["strength"] == "format"
    assert by_id["pii_kfz_kennzeichen_de"]["strength"] == "format"
    for rule in rules:
        assert rule["strength"] in {"checksum", "format", "none"}, rule
        assert isinstance(rule["base_score"], int) and 1 <= rule["base_score"] <= 100, rule
        assert (rule["strength"] == "none") == (rule["validator"] is None), rule


def test_registry_parse_tolerates_rules_without_score_fields(tmp_path):
    source = _write_split_registry(
        tmp_path,
        "pub static PII_PATTERNS: &[PiiPattern] = &[\n    common::EMAIL,\n];\n",
    )
    [rule] = _generate_docs().parse_native_patterns(source, "PiiPattern")
    assert rule["strength"] is None and rule["base_score"] is None


def test_module_split_registry_rejects_unknown_references(tmp_path):
    source = _write_split_registry(
        tmp_path,
        "pub static PII_PATTERNS: &[PiiPattern] = &[\n    common::EMAIL,\n    de::MISSING,\n];\n",
    )
    with pytest.raises(ValueError, match="de::MISSING"):
        _generate_docs().parse_native_patterns(source, "PiiPattern")


def test_checked_in_registry_order_matches_the_rust_order_test():
    rust_test = (ROOT / "rust" / "tests" / "pii_registry_order.rs").read_text(encoding="utf-8")
    # rustfmt wraps long entries over several lines.
    expected = re.findall(r'\(\s*"(pii_\w+)",\s*"(\w+)",?\s*\)', rust_test)
    rules = _generate_docs().parse_native_patterns(MODULE.PII_SOURCE_PATH, "PiiPattern")
    assert [(rule["id"], rule["entity_group"]) for rule in rules] == expected
    assert len(expected) == 158


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
