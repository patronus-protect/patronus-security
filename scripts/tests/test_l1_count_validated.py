from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "count_validated.py"
SPEC = importlib.util.spec_from_file_location("l1_count_validated", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

ENTITY_MAP = MODULE.ENTITY_MAP_MODULE
Unit = MODULE.Unit
ArkRule = MODULE.ArkRule


def raw_map():
    return yaml.safe_load(ENTITY_MAP.ENTITY_MAP_PATH.read_text(encoding="utf-8"))


def minimal_payload():
    return {
        "schema": ENTITY_MAP.SCHEMA,
        "presidio_version": "2.2.364",
        "entities": [
            {"id": "pii.iban", "scope": "shared", "ark": ["IBAN"], "presidio": ["IBAN_CODE"], "corpora": {}},
            {"id": "pii.swift_bic", "scope": "ark_only", "ark": ["SWIFT_CODE"], "presidio": [], "corpora": {}},
            {
                "id": "entity.passport_number",
                "scope": "shared",
                "ark": ["PASSPORT_NUMBER"],
                "presidio": ["DE_PASSPORT", "UK_PASSPORT"],
                "corpora": {},
            },
            {"id": "pii.de.vat_id", "scope": "presidio_only", "ark": [], "presidio": ["DE_VAT_ID"], "corpora": {}},
            {"id": "pii.it.vat_code", "scope": "presidio_only", "ark": [], "presidio": ["IT_VAT_CODE"], "corpora": {}},
            {"id": "pii.de.bsnr", "scope": "presidio_only", "ark": [], "presidio": ["DE_BSNR"], "corpora": {}},
        ],
        "checksums": {
            "ark": {
                "mod97": {"algorithm": "ISO 7064 MOD 97-10"},
                "bic": None,
                "de_document_number": {"algorithm": "ICAO 9303 7-3-1", "country": "de"},
            },
            "presidio": {
                "IBAN_CODE": {"algorithm": "ISO 7064 MOD 97-10"},
                "DE_PASSPORT": {"algorithm": "ICAO 9303 7-3-1", "country": "de"},
                "DE_VAT_ID": {"algorithm": "ISO 7064 MOD 11,10"},
                "IT_VAT_CODE": {"algorithm": "Luhn"},
                "DE_BSNR": None,
            },
        },
    }


MINIMAL_ARK_RULES = [
    ArkRule("pii_iban_de", "IBAN", "mod97"),
    ArkRule("pii_iban_generic", "IBAN", "mod97"),
    ArkRule("pii_swift_bic_context", "SWIFT_CODE", "bic"),
    ArkRule("pii_passport_number_de", "PASSPORT_NUMBER", "de_document_number"),
]


def load_minimal(payload=None):
    payload = payload or minimal_payload()
    return ENTITY_MAP.EntityMap.from_dict(payload), MODULE.rules_from_dict(payload)


# ── the counting rule ────────────────────────────────────────────────────────


def test_checksum_entries_count_once_per_entity_and_country():
    entity_map, rules = load_minimal()
    counts = MODULE.count(entity_map, rules, ark_rules=MINIMAL_ARK_RULES)
    assert set(counts.presidio) == {
        Unit("pii.iban", None),
        Unit("entity.passport_number", "de"),
        Unit("pii.de.vat_id", "de"),
        Unit("pii.it.vat_code", "it"),
    }
    # pii_iban_de and pii_iban_generic share one unit; the BIC check is format only.
    assert set(counts.ark) == {Unit("pii.iban", None), Unit("entity.passport_number", "de")}
    assert counts.ark[Unit("pii.iban", None)] == ("pii_iban_de: mod97", "pii_iban_generic: mod97")


def test_format_only_validation_does_not_count():
    entity_map, rules = load_minimal()
    counts = MODULE.count(entity_map, rules, ark_rules=MINIMAL_ARK_RULES)
    assert Unit("pii.de.bsnr", "de") not in counts.presidio
    assert Unit("pii.swift_bic", None) not in counts.ark
    assert rules.presidio["DE_BSNR"] is None
    assert rules.ark["bic"] is None


def test_vat_ids_count_per_country():
    entity_map, rules = load_minimal()
    counts = MODULE.count(entity_map, rules, ark_rules=MINIMAL_ARK_RULES)
    vat = sorted(unit for unit in counts.presidio if unit.entity_id.endswith((".vat_id", ".vat_code")))
    assert vat == [Unit("pii.de.vat_id", "de"), Unit("pii.it.vat_code", "it")]


def test_one_cross_country_id_counts_each_country():
    payload = minimal_payload()
    payload["checksums"]["presidio"]["UK_PASSPORT"] = {"algorithm": "ICAO 9303 7-3-1", "country": "uk"}
    entity_map, rules = load_minimal(payload)
    counts = MODULE.count(entity_map, rules, ark_rules=MINIMAL_ARK_RULES)
    assert {unit for unit in counts.presidio if unit.entity_id == "entity.passport_number"} == {
        Unit("entity.passport_number", "de"),
        Unit("entity.passport_number", "uk"),
    }


def test_country_comes_from_the_entity_id():
    assert MODULE.id_country("pii.de.tax_id") == "de"
    assert MODULE.id_country("pii.us.medical_license") == "us"
    assert MODULE.id_country("pii.iban") is None
    assert MODULE.id_country("pii.credit_card.pan") is None
    assert MODULE.id_country("entity.passport_number") is None


def test_m3_target_is_twice_the_presidio_count():
    entity_map, rules = load_minimal()
    counts = MODULE.count(entity_map, rules, ark_rules=MINIMAL_ARK_RULES)
    assert MODULE.M3_FACTOR == 2
    assert counts.target == 8
    assert counts.m3_met is False
    assert counts.shared == {Unit("pii.iban", None), Unit("entity.passport_number", "de")}


# ── the checked-in map ───────────────────────────────────────────────────────


def test_checked_in_map_is_consistent_with_the_pii_registry():
    entity_map = ENTITY_MAP.load()
    rules = MODULE.load_rules()
    assert MODULE.check(entity_map, rules) == []


def test_checked_in_presidio_count_matches_the_pinned_registry():
    # Presidio 2.2.364: 43 pattern recognizers with validate_result, 35 of them compute a check digit.
    rules = MODULE.load_rules()
    assert len(rules.presidio) == 43
    format_only = {entity for entity, rule in rules.presidio.items() if rule is None}
    assert format_only == {
        "DE_BSNR",
        "EMAIL_ADDRESS",
        "IN_GSTIN",
        "IN_VEHICLE_REGISTRATION",
        "KR_DRIVER_LICENSE",
        "TR_LICENSE_PLATE",
        "UK_DRIVING_LICENCE",
        "UK_VEHICLE_REGISTRATION",
    }
    counts = MODULE.count(ENTITY_MAP.load(), rules)
    assert len(counts.presidio) == 35
    assert counts.target == 70
    assert Unit("entity.passport_number", "de") in counts.presidio
    assert Unit("pii.identity_card_number", "de") in counts.presidio
    assert Unit("pii.financial_account_number", "us") in counts.presidio


def test_checked_in_ark_count():
    counts = MODULE.count(ENTITY_MAP.load(), MODULE.load_rules())
    # At T03 only Luhn, MOD 97-10 and the Steuer-ID check compute a check digit; B01 adds
    # one VAT ID per country, F08 the German passport and identity card (ICAO 9303), B02 one VAT ID
    # for each of eleven more countries, B16 eleven more VAT IDs (GB and XI count once), B-UK the
    # NHS number (mod 11), B-APAC the AU ABN, ACN, TFN and Medicare number and the SG NRIC/FIN and UEN,
    # B-DE1 the German pension and health insurance numbers and the LANR, B-NORD the SE personnummer,
    # the DK CPR number, the NO fødselsnummer and the FI personal identity code, B-ACCT the ABA
    # routing number, B-EU1 the FR NIR, SIREN and SIRET, the NL BSN and the BE national number, B-LUHN
    # the SE organisationsnummer, the CA SIN, the TR T.C. Kimlik No and the ZA ID number, B-EU2 the AT social
    # security number, the CH AHV number, the PT NIF (apart from the PT VAT ID) and the IE PPSN, B-KR the
    # KR resident, foreigner and business registration numbers, B-ESIT the ES NIF, the ES NIE and the IT
    # codice fiscale (the CIF and the Partita IVA are the ES and IT VAT IDs), A13 the PL PESEL and REGON (the
    # NIP is the PL VAT ID), B-IN the IN Aadhaar number and GSTIN (the PAN and the voter ID are format only),
    # A06 the US DEA number and NPI, B-DEVID the IMEI, MEID and ICCID (the IMSI has no check digit),
    # B-FIN the VIN (North American check digit), ISIN, LEI and DE PZN, A02 the crypto wallet address
    # (Base58Check, Bech32 and EIP-55).
    assert set(counts.ark) == {
        Unit("pii.credit_card.pan", None),
        Unit("pii.iban", None),
        Unit("pii.de.tax_id", "de"),
        Unit("pii.de.vat_id", "de"),
        Unit("pii.at.vat_id", "at"),
        Unit("pii.ch.vat_id", "ch"),
        Unit("pii.fr.vat_id", "fr"),
        Unit("pii.nl.vat_id", "nl"),
        Unit("pii.be.vat_id", "be"),
        Unit("pii.it.vat_code", "it"),
        Unit("pii.es.vat_id", "es"),
        Unit("pii.lu.vat_id", "lu"),
        Unit("pii.lv.vat_id", "lv"),
        Unit("pii.mt.vat_id", "mt"),
        Unit("pii.pl.vat_id", "pl"),
        Unit("pii.pt.vat_id", "pt"),
        Unit("pii.ro.vat_id", "ro"),
        Unit("pii.se.vat_id", "se"),
        Unit("pii.si.vat_id", "si"),
        Unit("pii.sk.vat_id", "sk"),
        Unit("pii.no.vat_id", "no"),
        Unit("pii.uk.vat_id", "uk"),
        Unit("entity.passport_number", "de"),
        Unit("pii.identity_card_number", "de"),
        Unit("pii.bg.vat_id", "bg"),
        Unit("pii.cy.vat_id", "cy"),
        Unit("pii.cz.vat_id", "cz"),
        Unit("pii.dk.vat_id", "dk"),
        Unit("pii.ee.vat_id", "ee"),
        Unit("pii.gr.vat_id", "gr"),
        Unit("pii.fi.vat_id", "fi"),
        Unit("pii.hr.vat_id", "hr"),
        Unit("pii.hu.vat_id", "hu"),
        Unit("pii.ie.vat_id", "ie"),
        Unit("pii.lt.vat_id", "lt"),
        Unit("pii.uk.nhs_number", "uk"),
        Unit("pii.au.abn", "au"),
        Unit("pii.au.acn", "au"),
        Unit("pii.au.tfn", "au"),
        Unit("pii.au.medicare", "au"),
        Unit("pii.sg.nric_fin", "sg"),
        Unit("pii.sg.uen", "sg"),
        Unit("pii.de.social_security_number", "de"),
        Unit("pii.de.health_insurance_number", "de"),
        Unit("pii.de.lanr", "de"),
        Unit("pii.se.personnummer", "se"),
        Unit("pii.dk.cpr", "dk"),
        Unit("pii.no.fodselsnummer", "no"),
        Unit("pii.fi.personal_identity_code", "fi"),
        Unit("pii.financial_account_number", "us"),
        Unit("pii.fr.nir", "fr"),
        Unit("pii.fr.siren", "fr"),
        Unit("pii.fr.siret", "fr"),
        Unit("pii.nl.bsn", "nl"),
        Unit("pii.be.national_number", "be"),
        Unit("pii.se.organisationsnummer", "se"),
        Unit("pii.ca.sin", "ca"),
        Unit("pii.tr.national_id", "tr"),
        Unit("pii.za.id_number", "za"),
        Unit("pii.at.social_security_number", "at"),
        Unit("pii.ch.ahv_number", "ch"),
        Unit("pii.pt.nif", "pt"),
        Unit("pii.ie.ppsn", "ie"),
        Unit("pii.kr.rrn", "kr"),
        Unit("pii.kr.frn", "kr"),
        Unit("pii.kr.brn", "kr"),
        Unit("pii.es.nif", "es"),
        Unit("pii.es.nie", "es"),
        Unit("pii.it.fiscal_code", "it"),
        Unit("pii.pl.pesel", "pl"),
        Unit("pii.pl.regon", "pl"),
        Unit("pii.in.aadhaar", "in"),
        Unit("pii.in.gstin", "in"),
        Unit("pii.us.medical_license", "us"),
        Unit("pii.us.npi", "us"),
        Unit("pii.imei", None),
        Unit("pii.meid", None),
        Unit("pii.iccid", None),
        Unit("pii.vin", None),
        Unit("pii.isin", None),
        Unit("pii.lei", None),
        Unit("pii.de.pzn", "de"),
        Unit("pii.crypto_wallet", None),
    }
    assert len(counts.ark) == 83
    # A13 reaches the M3 target (2 × 35 = 70).
    assert counts.m3_met is True


def test_ark_rules_are_read_from_the_pii_registry():
    rules = {rule.name: rule for rule in MODULE.ark_rules_from_source()}
    assert rules["pii_credit_card"] == ArkRule("pii_credit_card", "CREDITCARD", "payment_card", "checksum")
    assert rules["pii_steuer_id_de"].validator == "steuer_id"
    assert rules["pii_kfz_kennzeichen_de"].validator == "de_licence_plate"


def test_ark_rules_carry_the_score_model_strength():
    # K02: the score model weighs `strength` of every registry entry; it must agree with checksums.ark.
    rules = {rule.name: rule for rule in MODULE.ark_rules_from_source()}
    assert rules["pii_iban_de"].strength == "checksum"
    assert rules["pii_steuer_id_de"].strength == "checksum"
    assert rules["pii_swift_bic_context"].strength == "format"
    assert rules["pii_passport_number_de"].strength == "format"
    assert rules["pii_kfz_kennzeichen_de"].strength == "format"
    # T30: the plate was the last PII rule without a validator.
    assert {rule.strength for rule in rules.values()} == {"checksum", "format"}


# ── problems ─────────────────────────────────────────────────────────────────


def test_unclassified_and_unused_ark_validators_are_problems():
    entity_map, rules = load_minimal()
    ark_rules = MINIMAL_ARK_RULES + [ArkRule("pii_new", "SWIFT_CODE", "new_check")]
    problems = MODULE.check(entity_map, rules, ark_rules=ark_rules[1:])
    assert any("new_check" in problem and "not classified" in problem for problem in problems)
    problems = MODULE.check(entity_map, rules, ark_rules=MINIMAL_ARK_RULES[:3])
    assert any("de_document_number" in problem and "not used" in problem for problem in problems)


def test_score_strength_contradicting_the_classification_is_a_problem():
    entity_map, rules = load_minimal()
    consistent = [
        ArkRule("pii_iban_de", "IBAN", "mod97", "checksum"),
        ArkRule("pii_swift_bic_context", "SWIFT_CODE", "bic", "format"),
        ArkRule("pii_passport_number_de", "PASSPORT_NUMBER", "de_document_number", "checksum"),
        ArkRule("pii_plain", "SWIFT_CODE", None, "none"),
    ]
    assert MODULE.check(entity_map, rules, ark_rules=consistent) == []
    for broken in (
        ArkRule("pii_iban_de", "IBAN", "mod97", "format"),
        ArkRule("pii_swift_bic_context", "SWIFT_CODE", "bic", "checksum"),
        ArkRule("pii_plain", "SWIFT_CODE", None, "format"),
        ArkRule("pii_swift_bic_context", "SWIFT_CODE", "bic", "none"),
    ):
        problems = MODULE.check(entity_map, rules, ark_rules=consistent + [broken])
        assert any(broken.name in problem and "strength" in problem for problem in problems), broken


def test_unmapped_labels_and_entities_are_problems():
    payload = minimal_payload()
    payload["checksums"]["presidio"]["XX_UNKNOWN"] = {"algorithm": "Luhn"}
    entity_map, rules = load_minimal(payload)
    problems = MODULE.check(entity_map, rules, ark_rules=MINIMAL_ARK_RULES + [ArkRule("pii_x", "NOPE", "mod97")])
    assert any("XX_UNKNOWN" in problem for problem in problems)
    assert any("NOPE" in problem for problem in problems)


def test_country_conflicting_with_the_id_is_a_problem():
    payload = minimal_payload()
    payload["checksums"]["presidio"]["DE_VAT_ID"] = {"algorithm": "ISO 7064 MOD 11,10", "country": "at"}
    entity_map, rules = load_minimal(payload)
    problems = MODULE.check(entity_map, rules, ark_rules=MINIMAL_ARK_RULES)
    assert any("DE_VAT_ID" in problem and "at" in problem for problem in problems)


def test_check_compares_the_presidio_registry_when_given():
    entity_map, rules = load_minimal()
    registry = {"IBAN_CODE", "DE_PASSPORT", "DE_VAT_ID", "DE_BSNR", "AU_TFN"}
    problems = MODULE.check(
        entity_map, rules, ark_rules=MINIMAL_ARK_RULES, presidio_validated=registry, presidio_version="2.2.364"
    )
    assert any("AU_TFN" in problem and "not classified" in problem for problem in problems)
    assert any("IT_VAT_CODE" in problem and "validate_result" in problem for problem in problems)
    problems = MODULE.check(
        entity_map,
        rules,
        ark_rules=MINIMAL_ARK_RULES,
        presidio_validated=set(rules.presidio),
        presidio_version="2.2.365",
    )
    assert any("2.2.365" in problem and "2.2.364" in problem for problem in problems)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(ark="luhn"),
        lambda c: c["ark"].update(mod97={"algorithm": ""}),
        lambda c: c["ark"].update(mod97={"algorithm": "x", "weights": [1]}),
        lambda c: c["presidio"].update(DE_VAT_ID={"algorithm": "x", "country": "DEU"}),
        lambda c: c.update(extra={}),
    ],
)
def test_invalid_checksum_sections_are_rejected(mutate):
    payload = minimal_payload()
    mutate(payload["checksums"])
    with pytest.raises(ValueError):
        MODULE.rules_from_dict(payload)


def test_missing_checksum_section_is_rejected():
    payload = minimal_payload()
    del payload["checksums"]
    with pytest.raises(ValueError):
        MODULE.rules_from_dict(payload)


# ── report and CLI ───────────────────────────────────────────────────────────


def test_markdown_report_names_both_counts_and_the_target():
    entity_map, rules = load_minimal()
    text = MODULE.markdown(MODULE.count(entity_map, rules, ark_rules=MINIMAL_ARK_RULES))
    assert "| `pii.de.vat_id` | de | – | DE_VAT_ID (ISO 7064 MOD 11,10) |" in text
    assert "ARK 2, Presidio 4" in text
    assert "M3 (≥ 2× Presidio = 8): offen" in text


def test_cli_count_json_and_check(tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "count", "--json"], capture_output=True, text=True, check=True
    )
    payload = json.loads(result.stdout)
    assert payload["presidio_version"] == "2.2.364"
    assert payload["presidio"]["count"] == 35
    assert payload["ark"]["count"] == 83
    assert payload["m3"] == {"factor": 2, "target": 70, "met": True}
    assert {
        "entity_id": "pii.de.tax_id",
        "country": "de",
        "sources": ["pii_steuer_id_de: steuer_id", "pii_steuer_id_de_context_free: steuer_id_issued"],
    } in payload["ark"]["units"]
    # B01/B02/B16: one VAT unit per country, the bare Partita IVA rule shares the IT validator.
    vat = {unit["entity_id"]: unit for unit in payload["ark"]["units"] if unit["entity_id"].endswith((".vat_id", ".vat_code"))}
    assert sorted(vat) == [
        "pii.at.vat_id", "pii.be.vat_id", "pii.bg.vat_id", "pii.ch.vat_id", "pii.cy.vat_id",
        "pii.cz.vat_id", "pii.de.vat_id", "pii.dk.vat_id", "pii.ee.vat_id", "pii.es.vat_id",
        "pii.fi.vat_id", "pii.fr.vat_id", "pii.gr.vat_id", "pii.hr.vat_id", "pii.hu.vat_id",
        "pii.ie.vat_id", "pii.it.vat_code", "pii.lt.vat_id", "pii.lu.vat_id", "pii.lv.vat_id", "pii.mt.vat_id",
        "pii.nl.vat_id", "pii.no.vat_id", "pii.pl.vat_id", "pii.pt.vat_id", "pii.ro.vat_id", "pii.se.vat_id",
        "pii.si.vat_id", "pii.sk.vat_id", "pii.uk.vat_id",
    ]
    # B-UK: the NHS number is the one UK unit with a check digit; NINO, passport and licence are forms.
    assert {"entity_id": "pii.uk.nhs_number", "country": "uk", "sources": ["pii_nhs_number_uk: uk_nhs_number"]} in (
        payload["ark"]["units"]
    )
    # B-APAC: one unit per numbering system; the context-free rules share the validator.
    apac = {unit["entity_id"]: unit["sources"] for unit in payload["ark"]["units"] if unit["country"] in ("au", "sg")}
    assert apac == {
        "pii.au.abn": ["pii_abn_au: au_abn", "pii_abn_au_context_free: au_abn"],
        "pii.au.acn": ["pii_acn_au: au_acn"],
        "pii.au.tfn": ["pii_tfn_au: au_tfn"],
        "pii.au.medicare": ["pii_medicare_au: au_medicare", "pii_medicare_au_context_free: au_medicare"],
        "pii.sg.nric_fin": ["pii_nric_fin_sg: sg_nric_fin", "pii_nric_fin_sg_context_free: sg_nric_fin"],
        "pii.sg.uen": ["pii_uen_sg: sg_uen", "pii_uen_sg_context_free: sg_uen"],
    }
    # B-DE1: the check digit replaces the format check of the field-bound rules; the bare and
    # proximity rules share the validator. The BSNR has no check digit and is no unit.
    de1 = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.de.social_security_number", "pii.de.health_insurance_number", "pii.de.lanr")
    }
    assert de1 == {
        "pii.de.social_security_number": [
            "pii_rentenversicherung_de: de_social_security_number",
            "pii_rentenversicherung_de_context_free: de_social_security_number",
        ],
        "pii.de.health_insurance_number": [
            "pii_health_insurance_number_de: de_health_insurance_number",
            "pii_health_insurance_number_de_context_free: de_health_insurance_number",
        ],
        "pii.de.lanr": ["pii_physician_number_lanr_de: lanr", "pii_physician_number_lanr_de_proximity: lanr"],
    }
    assert "pii.de.bsnr" not in {unit["entity_id"] for unit in payload["ark"]["units"]}
    # B-NORD: one unit per country; the CPR unit rests on its mod-11 sum, which dk_cpr requires.
    nordic = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"]
        in ("pii.se.personnummer", "pii.dk.cpr", "pii.no.fodselsnummer", "pii.fi.personal_identity_code")
    }
    assert nordic == {
        "pii.se.personnummer": [
            "pii_personnummer_se: se_personnummer",
            "pii_personnummer_se_context_free: se_personnummer",
        ],
        "pii.dk.cpr": ["pii_cpr_dk: dk_cpr", "pii_cpr_dk_context_free: dk_cpr"],
        "pii.no.fodselsnummer": [
            "pii_fodselsnummer_no: no_fodselsnummer",
            "pii_fodselsnummer_no_context_free: no_fodselsnummer",
        ],
        "pii.fi.personal_identity_code": ["pii_hetu_fi: fi_hetu", "pii_hetu_fi_context_free: fi_hetu"],
    }
    # B-ACCT: the ABA routing number is a US unit of the account number ID, shared with Presidio's
    # ABA_ROUTING_NUMBER; the field-bound account rule checks the form only.
    assert {
        "entity_id": "pii.financial_account_number",
        "country": "us",
        "sources": [
            "pii_aba_routing_number_us: aba_routing_number",
            "pii_aba_routing_number_us_context_free: aba_routing_number",
        ],
    } in payload["ark"]["units"]
    # B-EU1: one unit per numbering system; the context-free rules share the validator.
    eu1 = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.fr.nir", "pii.fr.siren", "pii.fr.siret", "pii.nl.bsn", "pii.be.national_number")
    }
    assert eu1 == {
        "pii.fr.nir": ["pii_nir_fr: fr_nir", "pii_nir_fr_context_free: fr_nir"],
        "pii.fr.siren": ["pii_siren_fr: fr_siren"],
        "pii.fr.siret": ["pii_siret_fr: fr_siret", "pii_siret_fr_context_free: fr_siret"],
        "pii.nl.bsn": ["pii_bsn_nl: nl_bsn", "pii_bsn_nl_context_free: nl_bsn"],
        "pii.be.national_number": [
            "pii_national_number_be: be_national_number",
            "pii_national_number_be_context_free: be_national_number",
        ],
    }
    # B-LUHN: one unit per country, each shared with Presidio; the T.C. Kimlik No has no
    # context-free rule.
    luhn = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.se.organisationsnummer", "pii.ca.sin", "pii.tr.national_id", "pii.za.id_number")
    }
    assert luhn == {
        "pii.se.organisationsnummer": [
            "pii_organisationsnummer_se: se_organisationsnummer",
            "pii_organisationsnummer_se_context_free: se_organisationsnummer",
        ],
        "pii.ca.sin": ["pii_sin_ca: ca_sin", "pii_sin_ca_context_free: ca_sin"],
        "pii.tr.national_id": ["pii_national_id_tr: tr_national_id"],
        "pii.za.id_number": ["pii_id_number_za: za_id_number", "pii_id_number_za_context_free: za_id_number"],
    }
    # B-EU2: one unit per country; the PT NIF counts apart from the PT VAT ID, whose rule keeps its own
    # validator; the NIF and the PPSN have no context-free rule.
    eu2 = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.at.social_security_number", "pii.ch.ahv_number", "pii.pt.nif", "pii.ie.ppsn")
    }
    assert eu2 == {
        "pii.at.social_security_number": [
            "pii_social_security_number_at: at_social_security_number",
            "pii_social_security_number_at_context_free: at_social_security_number",
        ],
        "pii.ch.ahv_number": ["pii_ahv_number_ch: ch_ahv_number", "pii_ahv_number_ch_context_free: ch_ahv_number"],
        "pii.pt.nif": ["pii_nif_pt: pt_nif"],
        "pii.ie.ppsn": ["pii_ppsn_ie: ie_ppsn"],
    }
    # B-KR: three Korean units, each shared with Presidio.
    kr = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.kr.rrn", "pii.kr.frn", "pii.kr.brn")
    }
    assert kr == {
        "pii.kr.rrn": ["pii_rrn_kr: kr_rrn", "pii_rrn_kr_context_free: kr_rrn"],
        "pii.kr.frn": ["pii_frn_kr: kr_frn", "pii_frn_kr_context_free: kr_frn"],
        "pii.kr.brn": ["pii_brn_kr: kr_brn", "pii_brn_kr_context_free: kr_brn"],
    }
    # B-ESIT: NIF, NIE and codice fiscale are units of their own; the bare CIF and Partita IVA rules
    # reuse the VAT validators and count with the VAT IDs (no second unit).
    es_it = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.es.nif", "pii.es.nie", "pii.it.fiscal_code")
    }
    assert es_it == {
        "pii.es.nif": ["pii_nif_es: es_nif", "pii_nif_es_context_free: es_nif"],
        "pii.es.nie": ["pii_nie_es: es_nie", "pii_nie_es_context_free: es_nie"],
        "pii.it.fiscal_code": ["pii_fiscal_code_it: it_fiscal_code", "pii_fiscal_code_it_context_free: it_fiscal_code"],
    }
    assert vat["pii.es.vat_id"]["sources"] == ["pii_vat_id_es: es_vat_id", "pii_vat_id_es_proximity: es_vat_id"]
    assert vat["pii.it.vat_code"]["sources"] == ["pii_vat_id_it: it_vat_id", "pii_vat_id_it_proximity: it_vat_id"]
    assert vat["pii.pt.vat_id"]["sources"] == ["pii_vat_id_pt: pt_vat_id"]
    # A13: PESEL and REGON are units of their own; the bare NIP rule reuses the B16 validator and counts
    # with the PL VAT ID (no second unit).
    pl = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.pl.pesel", "pii.pl.regon")
    }
    assert pl == {"pii.pl.pesel": ["pii_pesel_pl: pl_pesel"], "pii.pl.regon": ["pii_regon_pl: pl_regon"]}
    assert vat["pii.pl.vat_id"]["sources"] == ["pii_vat_id_pl: pl_vat_id", "pii_vat_id_pl_proximity: pl_vat_id"]
    # B-IN: Aadhaar (Verhoeff) and GSTIN (mod 36) count; the PAN validator checks a form only and the voter
    # ID has none.
    india = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"].startswith("pii.in.")
    }
    assert india == {
        "pii.in.aadhaar": ["pii_aadhaar_in: in_aadhaar", "pii_aadhaar_in_context_free: in_aadhaar"],
        "pii.in.gstin": ["pii_gstin_in: in_gstin", "pii_gstin_in_context_free: in_gstin"],
    }
    # A06: the DEA number (mod-10 digit) and the NPI (Luhn behind 80840) count once each, shared with Presidio.
    medical = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.us.medical_license", "pii.us.npi")
    }
    assert medical == {
        "pii.us.medical_license": ["pii_dea_number_us: us_dea_number"],
        "pii.us.npi": ["pii_npi_us: us_npi", "pii_npi_us_context_free: us_npi"],
    }
    # B-DEVID: the IMEI, MEID and ICCID are international and count once each; the IMSI is format only.
    device = {
        unit["entity_id"]: (unit["country"], unit["sources"])
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.imei", "pii.meid", "pii.iccid", "pii.imsi")
    }
    assert device == {
        "pii.imei": (None, ["pii_imei: imei"]),
        "pii.meid": (None, ["pii_meid: meid"]),
        "pii.iccid": (None, ["pii_iccid: iccid"]),
    }
    # B-FIN: the VIN counts by its North American check digit (the European form is format only), the
    # ISIN, LEI and PZN by their own check digits; VIN, ISIN and LEI are international, the PZN German.
    fin = {
        unit["entity_id"]: unit["sources"]
        for unit in payload["ark"]["units"]
        if unit["entity_id"] in ("pii.vin", "pii.isin", "pii.lei", "pii.de.pzn")
    }
    assert fin == {
        "pii.vin": ["pii_vin: vin_check_digit"],
        "pii.isin": ["pii_isin: isin"],
        "pii.lei": ["pii_lei: lei"],
        "pii.de.pzn": ["pii_pzn_de: de_pzn"],
    }
    # A02: one international unit for the crypto wallet address; the lower-case Ethereum form has no checksum.
    crypto = next(unit for unit in payload["ark"]["units"] if unit["entity_id"] == "pii.crypto_wallet")
    assert crypto["sources"] == [
        "pii_crypto_btc: btc_address",
        "pii_crypto_eth: eth_checksum_address",
        "pii_crypto_ltc: ltc_address",
    ]
    # B02: the Greek rule keeps the VIES prefix EL, the benchmark ID follows ISO 3166 (gr).
    assert vat["pii.gr.vat_id"]["sources"] == ["pii_vat_id_el: el_vat_id"]
    assert vat["pii.it.vat_code"]["sources"] == ["pii_vat_id_it: it_vat_id", "pii_vat_id_it_proximity: it_vat_id"]
    # F08: German passport and identity card (ICAO 9303 7-3-1) count per country; the
    # field-bound rules keep the format-only de_document_number.
    assert {
        "entity_id": "entity.passport_number",
        "country": "de",
        "sources": [
            "pii_passport_number_de_context_free: de_passport_number",
            "pii_passport_number_de_legacy: de_passport_number",
        ],
    } in payload["ark"]["units"]
    assert {
        "entity_id": "pii.identity_card_number",
        "country": "de",
        "sources": [
            "pii_identity_card_number_de_context_free: de_identity_card_number",
            "pii_identity_card_number_de_legacy: de_identity_card_number",
        ],
    } in payload["ark"]["units"]

    result = subprocess.run([sys.executable, str(SCRIPT), "check"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    broken = raw_map()
    broken["checksums"]["ark"].pop("payment_card")
    path = tmp_path / "map.yaml"
    path.write_text(yaml.safe_dump(broken), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), "check", "--map", str(path)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "payment_card" in result.stderr


def test_the_entity_map_check_still_accepts_the_checksum_section():
    assert raw_map()["checksums"]
    assert subprocess.run(
        [sys.executable, str(ENTITY_MAP.__file__), "check"], capture_output=True, text=True
    ).returncode == 0


# ── against the installed Presidio ───────────────────────────────────────────


def presidio_available():
    try:
        return importlib.util.find_spec("presidio_analyzer") is not None
    except (ImportError, ValueError):
        return False


@pytest.mark.skipif(not presidio_available(), reason="presidio_analyzer is not installed")
def test_classification_covers_exactly_the_pinned_registry():
    rules = MODULE.load_rules()
    assert MODULE.presidio_version() == "2.2.364"
    assert MODULE.presidio_validated_entities() == set(rules.presidio)
    assert (
        MODULE.check(
            ENTITY_MAP.load(),
            rules,
            presidio_validated=MODULE.presidio_validated_entities(),
            presidio_version=MODULE.presidio_version(),
        )
        == []
    )
