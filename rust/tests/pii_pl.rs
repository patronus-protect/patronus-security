// SPDX-License-Identifier: GPL-3.0-only
//! Polish identifiers (A13).
//!
//! Two numbering systems with a check digit, one label each: the PESEL
//! (`PL_PESEL`, eleven digits with the birth date, the century in the month and a
//! check digit weighted 1-3-7-9 mod 10) and the REGON (`PL_REGON`, nine digits
//! weighted mod 11, or fourteen whose first nine are a REGON of their own). Each
//! is reported in every mode when a term of the label stands near it or is its
//! key; bare digits need the term in every mode. The NIP is the body of the
//! Polish VAT ID: without `PL` it reuses the B16 validator under `VAT_ID_PL` and,
//! unlike the bare Partita IVA, needs a NIP term (balanced/recall only).

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const PESEL: &str = "pii_pesel_pl";
const REGON: &str = "pii_regon_pl";
const NIP: &str = "pii_vat_id_pl_proximity";
const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];
const SCORED: [PiiMode; 2] = [PiiMode::Balanced, PiiMode::Recall];

fn pii_result(text: &str, mode: PiiMode) -> SecurityScanResult {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix {
        pii_mode: mode,
        ..Default::default()
    });
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

/// `(text, score)` of every span with `label`.
fn spans(text: &str, mode: PiiMode, label: &str) -> Vec<(String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == label)
        .map(|span| (span.text, span.score))
        .collect()
}

/// Rule ids that matched with the value text they matched.
fn rules(text: &str, mode: PiiMode) -> Vec<(String, String)> {
    let result = pii_result(text, mode);
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| {
            let start = rule["start_byte"].as_u64().unwrap() as usize;
            let end = rule["end_byte"].as_u64().unwrap() as usize;
            (
                rule["rule_id"].as_str().unwrap().to_owned(),
                text[start..end].to_owned(),
            )
        })
        .collect()
}

fn pattern(rule_id: &str) -> &'static PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

/// `rule_id` reports `value`, the only span of its label, in each of `modes`.
fn assert_reports(rule_id: &str, text: &str, value: &str, modes: &[PiiMode]) {
    let label = pattern(rule_id).entity_group;
    for &mode in modes {
        assert!(
            rules(text, mode)
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report the expected value in {text:?}"
        );
        let found = spans(text, mode, label);
        assert!(
            found.len() == 1 && found[0].0 == value,
            "{mode}: the expected value must be the only {label} span in {text:?}"
        );
    }
}

fn assert_silent(text: &str, label: &str, modes: &[PiiMode]) {
    for &mode in modes {
        assert!(
            spans(text, mode, label).is_empty(),
            "{mode}: no {label} expected in {text:?}"
        );
    }
}

// ── validators ───────────────────────────────────────────────────────────────

#[test]
fn pesel_validator_checks_the_date_and_check_digit() {
    for valid in [
        "02070803628",
        "44051401359",
        "90110536890",
        // month + 20: born in 2005
        "05241690065",
        "05310456684",
        "01252230429",
    ] {
        assert!(validators::pl_pesel(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "02070803629",
        "44051401358",
        "12345678901",
        // month 13, 30 February, month + 80: born in 1899 (not accepted)
        "02130803627",
        "50023004039",
        "99832799684",
        // form
        "0207080362",
        "020708036281",
        "0207080362A",
        "02070-803628",
        "00000000000",
    ] {
        assert!(!validators::pl_pesel(invalid), "{invalid}");
    }
}

#[test]
fn regon_validator_checks_nine_and_fourteen_digits() {
    for valid in [
        "123456785",
        "732065814",
        "926240204",
        "12345678512347",
        "95217292048588",
        "14394440582149",
    ] {
        assert!(validators::pl_regon(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "123456786",
        "797289257",
        "14394440582148",
        // the first nine of a fourteen-digit REGON fail
        "12345678612342",
        // one repeated digit, form
        "000000000",
        "00000000000000",
        "12345678",
        "1234567851",
        "12345678A",
        "123-456-785",
    ] {
        assert!(!validators::pl_regon(invalid), "{invalid}");
    }
}

#[test]
fn the_bare_nip_reuses_the_vat_validator() {
    // B16 validator without the country prefix: one unit with the VAT ID.
    for valid in [
        "5260250995",
        "526-025-09-95",
        "943-16-38-485",
        "PL5260250995",
    ] {
        assert!(validators::pl_vat_id(valid), "{valid}");
    }
    for invalid in ["5260250996", "526025099", "52602509951"] {
        assert!(!validators::pl_vat_id(invalid), "{invalid}");
    }
    let validator = |rule_id: &str| pattern(rule_id).validator.map(|check| check as usize);
    assert_eq!(validator(NIP), validator("pii_vat_id_pl"));
    let rule = pattern(NIP);
    assert!(rule.requires_context && rule.scored_only);
    assert_eq!(rule.entity_group, "VAT_ID_PL");
}

#[test]
fn the_polish_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    for (rule_id, label, check) in [
        (PESEL, "PL_PESEL", validators::pl_pesel as fn(&str) -> bool),
        (REGON, "PL_REGON", validators::pl_regon),
    ] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, label, "{rule_id}");
        assert_eq!(rule.strength, ValidatorStrength::Checksum, "{rule_id}");
        assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
        assert!(!rule.captured_value, "{rule_id}");
        assert!(rule.requires_context && !rule.scored_only, "{rule_id}");
        assert!(
            score::score(rule, Context::Support { gap: 48 }) >= balanced,
            "{rule_id}"
        );
        // No context-free rule: bare digits always need a term.
        assert_eq!(
            PII_PATTERNS
                .iter()
                .filter(|pattern| pattern.entity_group == label)
                .count(),
            1,
            "{label}"
        );
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (PESEL, "PESEL: 02070803628", "02070803628"),
        (PESEL, "Her PESEL number is 90110536890.", "90110536890"),
        (PESEL, "{\"pesel\": \"88030387058\"}", "88030387058"),
        (
            PESEL,
            "Die polnische Personenkennzahl lautet 01252230429.",
            "01252230429",
        ),
        (PESEL, "Numer PESEL: 88050729397", "88050729397"),
        (REGON, "REGON: 123456785", "123456785"),
        (
            REGON,
            "The company's REGON number is 732065814.",
            "732065814",
        ),
        (REGON, "{\"regon\": \"12345678512347\"}", "12345678512347"),
        (REGON, "REGON-Nummer: 797289256", "797289256"),
        (REGON, "Numer REGON: 215521652", "215521652"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (PESEL, "pesel,age\n72052773904,42", "72052773904"),
        (REGON, "regon,employees\n926240204,31", "926240204"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
    // The bare NIP too, in the scored modes; a generic VAT key still decides nothing.
    for text in [
        "nip,employees\n5260250995,42",
        "firma;nip;pracownicy\nACME;5260250995;42",
    ] {
        assert_reports(NIP, text, "5260250995", &SCORED);
        assert_silent(text, "VAT_ID_PL", &[PiiMode::Strict]);
    }
    for text in ["vat,employees\n5260250995,42", "nip,employees\n5260250995-1,42"] {
        for mode in MODES {
            assert!(
                !rules(text, mode).iter().any(|(rule, _)| rule == NIP),
                "{mode}: {text}"
            );
        }
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // check fails
        ("PL_PESEL", "PESEL: 02070803629"),
        ("PL_PESEL", "PESEL: 02130803627"),
        ("PL_REGON", "REGON: 123456786"),
        ("PL_REGON", "REGON: 12345678612342"),
        ("PL_REGON", "REGON: 000000000"),
        // no term, also in the scored modes
        ("PL_PESEL", "90110536890"),
        ("PL_PESEL", "Reference 02070803628 was archived."),
        ("PL_REGON", "12345678512347"),
        ("PL_REGON", "Vorgang 797289256 wurde abgeschlossen."),
        // part of a longer value
        ("PL_PESEL", "PESEL: 02070803628-1"),
        ("PL_REGON", "REGON-Nummer: 797289256-1"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── the bare NIP, scored modes only ──────────────────────────────────────────

#[test]
fn a_bare_nip_needs_a_term_and_is_reported_in_the_scored_modes_only() {
    for (text, value) in [
        ("NIP: 5260250995", "5260250995"),
        ("{\"nip\": \"2143864618\"}", "2143864618"),
        (
            "Our Polish tax identification number is 943-16-38-485.",
            "943-16-38-485",
        ),
        ("Polish VAT number: 984-055-15-28", "984-055-15-28"),
        ("NIP-Nummer: 4106325383", "4106325383"),
    ] {
        assert_reports(NIP, text, value, &SCORED);
        assert_silent(text, "VAT_ID_PL", &[PiiMode::Strict]);
    }
    for text in [
        "5260250995",
        "Reference 5260250995 was archived.",
        "NIP: 5260250996",
        "NIP: 5260250995-1",
        "Invoice number 2143864618 is overdue.",
    ] {
        assert_silent(text, "VAT_ID_PL", &MODES);
    }
    // A generic VAT term does not make ten valid digits a NIP: the VAT ID of
    // another country with a spaced prefix, another number before a VAT term.
    for text in [
        "VAT number: 5260250995",
        "{\"country\": \"SK\", \"vat_id\": \"SK 928 762 01 99\"}",
        "Please quote National Provider Identifier 2877096117 in any reply. The VAT ID on file is DE136695976.",
    ] {
        for mode in MODES {
            assert!(
                !rules(text, mode).iter().any(|(rule, _)| rule == NIP),
                "{mode}: {text}"
            );
        }
    }
    // The body of a prefixed VAT ID is no bare NIP of its own.
    for text in ["NIP: PL 5260250995", "{\"vat_id\": \"PL 526-025-09-95\"}"] {
        for mode in SCORED {
            assert!(
                !rules(text, mode).iter().any(|(rule, _)| rule == NIP),
                "{mode}: {text}"
            );
        }
    }
    assert_reports(
        "pii_vat_id_pl",
        "NIP: PL 5260250995",
        "PL 5260250995",
        &SCORED,
    );
}
