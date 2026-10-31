// SPDX-License-Identifier: GPL-3.0-only
//! US medical licence numbers (A06).
//!
//! The DEA registration number (`MEDICAL_LICENSE`) is a registrant type letter,
//! the initial of the registrant's last name (or `9`) and seven digits, the last
//! the units digit of `d1 + d3 + d5 + 2 × (d2 + d4 + d6)`. The National Provider
//! Identifier (`US_NPI`) is ten digits, first 1 or 2, plain or grouped 4-3-3,
//! the last a Luhn check digit over the digits behind the card issuer prefix
//! `80840`. Both are reported in every mode when a term of the label stands near
//! them or is their key; in `balanced` and `recall` the grouped NPI is also
//! reported bare (K05). A DEA number or ten plain digits alone prove too little.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const DEA: &str = "pii_dea_number_us";
const NPI: &str = "pii_npi_us";
const NPI_BARE: &str = "pii_npi_us_context_free";
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
fn dea_validator_checks_the_registrant_type_and_check_digit() {
    for valid in [
        "PF4225315",
        "PC0499233",
        "MW9582847",
        "GT2813891",
        "RT4231344",
        "X95988285",
        "FS3578309",
        // presidio-analyzer and the DEA's own examples
        "AB1234563",
        "BB1388568",
    ] {
        assert!(validators::us_dea_number(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "PF4225316",
        "FS3578300",
        "AB1234567",
        // I, N, O, Q, V, W, Y, Z are no registrant type
        "IF4225315",
        "WF4225315",
        // a digit other than 9 as the second character
        "P14225315",
        // form
        "PF422531",
        "PF42253150",
        "pf4225315",
        "PF 4225315",
        "PFA225315",
    ] {
        assert!(!validators::us_dea_number(invalid), "{invalid}");
    }
}

#[test]
fn npi_validator_checks_the_luhn_digit_behind_80840_and_the_form() {
    for valid in [
        "1850184619",
        "1670933500",
        "2458556968",
        "2942978760",
        "1850-184-619",
        "2458 556 968",
        // presidio-analyzer test values
        "1003000126",
        "1234567893",
        "1245319599",
        "1234-567-893",
    ] {
        assert!(validators::us_npi(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "1850184610",
        "1234567890",
        // first digit other than 1 or 2, Luhn-valid behind 80840
        "3850184615",
        "0850184611",
        "9850184612",
        // one repeated digit before the check digit is never issued
        "1111111112",
        "2222222228",
        // form
        "185018461",
        "18501846190",
        "1850-184 619",
        "1850.184.619",
        "185-0184-619",
        "185018461A",
    ] {
        assert!(!validators::us_npi(invalid), "{invalid}");
    }
}

#[test]
fn the_medical_licence_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    for (rule_id, label, check, scored_only) in [
        (
            DEA,
            "MEDICAL_LICENSE",
            validators::us_dea_number as fn(&str) -> bool,
            false,
        ),
        (NPI, "US_NPI", validators::us_npi, false),
        (NPI_BARE, "US_NPI", validators::us_npi, true),
    ] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, label, "{rule_id}");
        assert_eq!(rule.strength, ValidatorStrength::Checksum, "{rule_id}");
        assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
        assert!(!rule.captured_value, "{rule_id}");
        assert_eq!(rule.scored_only, scored_only, "{rule_id}");
        assert_eq!(rule.requires_context, !scored_only, "{rule_id}");
        if scored_only {
            assert!(score::rule_score(rule) >= balanced, "{rule_id}");
        } else {
            assert!(
                score::score(rule, Context::Support { gap: 48 }) >= balanced,
                "{rule_id}"
            );
        }
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (DEA, "DEA number: PF4225315", "PF4225315"),
        (
            DEA,
            "The prescriber's DEA registration is MW9582847.",
            "MW9582847",
        ),
        (DEA, "{\"dea_number\": \"GT2813891\"}", "GT2813891"),
        (DEA, "DEA-Nummer: RT4231344", "RT4231344"),
        (
            DEA,
            "Die DEA-Registrierungsnummer der Praxis lautet X95988285.",
            "X95988285",
        ),
        (DEA, "Unsere Unterlagen nennen als DEA-Nummer: RN4135883.", "RN4135883"),
        (NPI, "NPI: 1850184619", "1850184619"),
        (
            NPI,
            "The National Provider Identifier on file is 1670933500.",
            "1670933500",
        ),
        (NPI, "{\"npi\": \"2458-556-968\"}", "2458-556-968"),
        (NPI, "NPI 1234567893 and NPI 1245319599", "1234567893"),
        (NPI, "Provider identifier 1245319599", "1245319599"),
        (NPI, "NPI-Nummer: 2942978760", "2942978760"),
        (
            NPI,
            "Die NPI des behandelnden Arztes lautet 1102167388.",
            "1102167388",
        ),
    ] {
        for &mode in &MODES {
            assert!(
                rules(text, mode)
                    .iter()
                    .any(|(rule, found)| rule == rule_id && found == value),
                "{mode}: {rule_id} must report {value} in {text:?}"
            );
        }
    }
    for (rule_id, text, value) in [
        (DEA, "DEA number: PF4225315", "PF4225315"),
        (DEA, "{\"dea_number\": \"GT2813891\"}", "GT2813891"),
        (DEA, "DEA-Nummer: RT4231344", "RT4231344"),
        (NPI, "NPI: 1850184619", "1850184619"),
        (NPI, "{\"npi\": \"2458-556-968\"}", "2458-556-968"),
        (NPI, "NPI-Nummer: 2942978760", "2942978760"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (DEA, "dea_number,age\nPC0499233,42", "PC0499233"),
        (
            DEA,
            "nr;name;dea_nummer\n1;Javier Sánchez;FS3578309",
            "FS3578309",
        ),
        (NPI, "npi,age\n1756663302,42", "1756663302"),
        (
            NPI,
            "nr;name;plz;npi;betrag\n1;Anna Schäfer;30317;2256738982;1.943,29 €",
            "2256738982",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // check fails
        ("MEDICAL_LICENSE", "DEA number: PF4225316"),
        ("MEDICAL_LICENSE", "DEA-Nummer: IF4225315"),
        ("MEDICAL_LICENSE", "DEA-Nummer: P14225315"),
        ("US_NPI", "NPI: 1850184610"),
        ("US_NPI", "NPI: 3850184615"),
        ("US_NPI", "NPI-Nummer: 1111111112"),
        // no term, also in the scored modes
        ("MEDICAL_LICENSE", "PF4225315"),
        ("MEDICAL_LICENSE", "Reference PF4225315 was archived."),
        ("MEDICAL_LICENSE", "Vorgang RT4231344 wurde abgeschlossen."),
        ("US_NPI", "1850184619"),
        ("US_NPI", "1003000126"),
        ("US_NPI", "Reference 1850184619 was archived."),
        ("US_NPI", "Vorgang 2942978760 wurde abgeschlossen."),
        // part of a longer value
        ("MEDICAL_LICENSE", "DEA number: PF4225315-2"),
        ("MEDICAL_LICENSE", "DEA number: XPF4225315"),
        ("US_NPI", "NPI: 18501846190"),
        ("US_NPI", "NPI: 1850-184-619-4"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare grouped NPIs, scored modes only ─────────────────────────────────────

#[test]
fn bare_grouped_npis_are_reported_in_the_scored_modes_only() {
    for (text, value) in [
        ("1234-567-893", "1234-567-893"),
        ("Referral to 1850-184-619 is pending.", "1850-184-619"),
        ("Überweisung an 2458 556 968 folgt.", "2458 556 968"),
    ] {
        assert_reports(NPI_BARE, text, value, &SCORED);
        assert_silent(text, "US_NPI", &[PiiMode::Strict]);
    }
    for text in [
        // check fails, first digit, mixed grouping
        "Referral to 1850-184-610 is pending.",
        "Referral to 3850-184-615 is pending.",
        "Referral to 1850-184 619 is pending.",
        // part of a longer run
        "Ref 1850-184-619-4",
        "Ref 77-1850-184-619",
    ] {
        assert_silent(text, "US_NPI", &MODES);
    }
}
