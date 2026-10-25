// SPDX-License-Identifier: GPL-3.0-only
//! German health care and social insurance numbers (B-DE1: F10, F11, F12).
//!
//! Three numbering systems carry a check digit that the field-bound rules now
//! compute instead of checking the form only: the health insurance number (KVNR,
//! § 290 SGB V: the letter as 01…26 and eight digits, weights 1-2, cross sums,
//! mod 10), the pension insurance number (RVNR, VKVV § 4: birth day 01–31 or
//! 51–81 and month 01–12, the letter as 01…26, weights 2-1-2-5-7-1-2-1-2-1-2-1,
//! cross sums, mod 10) and the lifelong physician number (LANR, KBV: six digits
//! weighted 4-9, the seventh digit is the complement to 10). In `balanced` and
//! `recall` the KVNR (uppercase letter) and the RVNR (bare or in its printed
//! 2-6-1-3 groups) are also reported without a field name (K05). Nine bare digits
//! pass the LANR check one time in ten: the scored modes add the LANR with a term
//! near it or as its key, never bare. The BSNR (Betriebsstättennummer) has no check
//! digit: a new label, nine digits with a BSNR term in every mode (format, no M3
//! unit).

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const RVNR: &str = "pii_rentenversicherung_de";
const RVNR_CONTEXT_FREE: &str = "pii_rentenversicherung_de_context_free";
const KVNR: &str = "pii_health_insurance_number_de";
const KVNR_CONTEXT_FREE: &str = "pii_health_insurance_number_de_context_free";
const LANR: &str = "pii_physician_number_lanr_de";
const LANR_PROXIMITY: &str = "pii_physician_number_lanr_de_proximity";
const BSNR: &str = "pii_facility_number_bsnr_de";
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
fn health_insurance_number_validator_checks_the_kvnr_digit() {
    for valid in [
        // § 290 SGB V Anlage 1 and the presidio-analyzer tests
        "A000500015",
        "B123456782",
        "Z000000005",
        "A123456780",
        "X123456788",
        "Z987654321",
        "T345678916",
        // a lowercase letter after a field name
        "a123456780",
    ] {
        assert!(validators::de_health_insurance_number(valid), "{valid}");
    }
    for invalid in [
        // one digit off
        "M123456789",
        "A123456789",
        "X123456789",
        "B123456783",
        // nine zeros pass the check after S (19) but are never issued
        "S000000000",
        "A000000000",
        // length and alphabet
        "1123456780",
        "A12345678",
        "A1234567890",
        "AB12345678",
        "Ä123456780",
    ] {
        assert!(
            !validators::de_health_insurance_number(invalid),
            "{invalid}"
        );
    }
}

#[test]
fn pension_insurance_number_validator_checks_the_date_and_the_rvnr_digit() {
    for valid in [
        // DRV example and the presidio-analyzer test value
        "15070649C103",
        "65070803A019",
        "65180539W001",
        "12120356A122",
        "53270587M011",
        // printed groups and a lowercase letter after a field name
        "15 070649 C 103",
        "65 230109 Z 872",
        "15070649c103",
        // birth day + 50 (Ergänzungsmerkmal)
        "12570356A128",
        "15570649C104",
    ] {
        assert!(validators::de_social_security_number(valid), "{valid}");
    }
    for invalid in [
        // one digit off
        "15070649C100",
        "65070803A018",
        "12123456A123",
        // check digit right, birth date impossible: day 00, 32, 82, month 13
        "15000649C105",
        "15073249C102",
        "15078249C100",
        "15071349C107",
        // the presidio-analyzer negative: day 00 with the DRV check digit
        "15070049C103",
        // length and alphabet
        "1507064C103",
        "150706490103",
        "15070649CC03",
        "150706491C03",
    ] {
        assert!(!validators::de_social_security_number(invalid), "{invalid}");
    }
}

#[test]
fn lanr_validator_checks_the_weighted_4_9_digit() {
    for valid in [
        // KBV example and the presidio-analyzer tests
        "123456601",
        "100000601",
        "234567701",
        "987654401",
        "999999901",
        "141421356",
        "765432203",
    ] {
        assert!(validators::lanr(valid), "{valid}");
    }
    for invalid in [
        // one digit off
        "234567601",
        "100000401",
        "123456789",
        "987654321",
        // one repeated digit passes the check (4 + 9 = 13 per pair) but is no number
        "000000000",
        "111111111",
        "222222222",
        // length and alphabet
        "12345660",
        "1234566010",
        "12345660A",
    ] {
        assert!(!validators::lanr(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_de1_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check, strength) in [
        (
            &[RVNR, RVNR_CONTEXT_FREE][..],
            "SOCIALID",
            validators::de_social_security_number as fn(&str) -> bool,
            ValidatorStrength::Checksum,
        ),
        (
            &[KVNR, KVNR_CONTEXT_FREE][..],
            "HEALTH_INSURANCE_NUMBER",
            validators::de_health_insurance_number,
            ValidatorStrength::Checksum,
        ),
        (
            &[LANR, LANR_PROXIMITY][..],
            "PHYSICIAN_NUMBER_LANR",
            validators::lanr,
            ValidatorStrength::Checksum,
        ),
        (
            &[BSNR][..],
            "FACILITY_NUMBER_BSNR",
            validators::nine_digits,
            ValidatorStrength::Format,
        ),
    ] {
        for rule_id in rule_ids {
            let rule = pattern(rule_id);
            assert_eq!(rule.entity_group, label, "{rule_id}");
            assert_eq!(rule.strength, strength, "{rule_id}");
            assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
        }
    }
    // The field-bound rules keep their mode and their scores of the format check:
    // the check digit replaces base points.
    for (rule_id, expected) in [(RVNR, 0.90), (KVNR, 0.85), (LANR, 0.70)] {
        let rule = pattern(rule_id);
        assert!(
            rule.captured_value && !rule.requires_context && !rule.scored_only,
            "{rule_id}"
        );
        assert_eq!(score::rule_score(rule), expected, "{rule_id}");
    }
    let balanced = PiiMode::Balanced.min_score().unwrap();
    let recall = PiiMode::Recall.min_score().unwrap();
    for rule_id in [RVNR_CONTEXT_FREE, KVNR_CONTEXT_FREE] {
        let rule = pattern(rule_id);
        assert!(
            rule.scored_only && !rule.requires_context && !rule.captured_value,
            "{rule_id}"
        );
        // Bare, the check digit reaches the balanced threshold; a nearer
        // counter-context term drops it below the recall threshold.
        assert_eq!(score::rule_score(rule), 0.55, "{rule_id}");
        assert!(score::score(rule, Context::Counter) < recall, "{rule_id}");
    }
    let lanr = pattern(LANR_PROXIMITY);
    assert!(lanr.scored_only && lanr.requires_context && !lanr.captured_value);
    let bsnr = pattern(BSNR);
    assert!(!bsnr.scored_only && bsnr.requires_context && !bsnr.captured_value);
    for rule in [lanr, bsnr] {
        // The farthest term still clears the balanced threshold.
        assert!(
            score::score(rule, Context::Support { gap: 48 }) >= balanced,
            "{}",
            rule.name
        );
    }
}

// ── field-bound rules: the check digit decides in every mode ────────────────

#[test]
fn field_bound_values_with_a_valid_check_digit_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (
            RVNR,
            "Sozialversicherungsnummer: 15070649C103",
            "15070649C103",
        ),
        (RVNR, "SV-Nr.: 65 230109 Z 872", "65 230109 Z 872"),
        (
            RVNR,
            "German pension insurance number: 12120356A122",
            "12120356A122",
        ),
        (
            RVNR,
            "Rentenversicherungsnummer 15570649C104",
            "15570649C104",
        ),
        (KVNR, "Versichertennummer: A123456780", "A123456780"),
        (KVNR, "KVNR = Z987654321", "Z987654321"),
        (KVNR, "Health insurance number b123456782", "b123456782"),
        (LANR, "LANR: 123456601", "123456601"),
        (LANR, "Lebenslange Arztnummer 987654401", "987654401"),
        (LANR, "Physician number: 234567701", "234567701"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn field_bound_values_with_a_wrong_check_digit_are_silent_in_every_mode() {
    for (label, text) in [
        ("SOCIALID", "Sozialversicherungsnummer: 12123456A123"),
        ("SOCIALID", "SV-Nr.: 15 070649 C 100"),
        ("SOCIALID", "Rentenversicherungsnummer: 15071349C107"),
        ("SOCIALID", "Pension insurance number: 15070049C103"),
        ("HEALTH_INSURANCE_NUMBER", "Versichertennummer: A123456789"),
        ("HEALTH_INSURANCE_NUMBER", "KVNR: M123456789"),
        ("HEALTH_INSURANCE_NUMBER", "KVNR: S000000000"),
        ("PHYSICIAN_NUMBER_LANR", "LANR: 123456789"),
        ("PHYSICIAN_NUMBER_LANR", "Physician number: 234567601"),
        ("PHYSICIAN_NUMBER_LANR", "LANR: 111111111"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare KVNR and RVNR, scored modes only ────────────────────────────────────

#[test]
fn bare_kvnr_and_rvnr_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (
            KVNR_CONTEXT_FREE,
            "Bitte A123456780 auf das Rezept übertragen.",
            "A123456780",
        ),
        (KVNR_CONTEXT_FREE, "B123456782", "B123456782"),
        (
            KVNR_CONTEXT_FREE,
            "Please add Z987654321 to the claim.",
            "Z987654321",
        ),
        (
            KVNR_CONTEXT_FREE,
            "Die Versichertennummer lautet M234568003.",
            "M234568003",
        ),
        (
            RVNR_CONTEXT_FREE,
            "Bitte 15070649C103 im Personalbogen eintragen.",
            "15070649C103",
        ),
        (RVNR_CONTEXT_FREE, "65070803A019", "65070803A019"),
        (
            RVNR_CONTEXT_FREE,
            "Please file 65 180539 W 001 with HR.",
            "65 180539 W 001",
        ),
        (
            RVNR_CONTEXT_FREE,
            "Meine Rentenversicherungsnummer ist 53270587M011.",
            "53270587M011",
        ),
    ] {
        assert_reports(rule_id, text, value, &SCORED);
        assert_silent(text, pattern(rule_id).entity_group, &[PiiMode::Strict]);
    }
    // Bare, the value scores the check digit alone; a support term adds to it.
    assert_eq!(
        spans("B123456782", PiiMode::Balanced, "HEALTH_INSURANCE_NUMBER"),
        [("B123456782".to_owned(), 0.55)]
    );
    assert_eq!(
        spans(
            "Die Versichertennummer lautet B123456782",
            PiiMode::Balanced,
            "HEALTH_INSURANCE_NUMBER"
        ),
        [("B123456782".to_owned(), 0.80)]
    );
}

#[test]
fn bare_kvnr_and_rvnr_lookalikes_stay_silent() {
    for (label, text) in [
        // check digit or birth date fails
        ("HEALTH_INSURANCE_NUMBER", "Bitte A123456789 prüfen."),
        ("SOCIALID", "Bitte 15070649C100 prüfen."),
        ("SOCIALID", "Batch 15070049C103 shipped."),
        // a nearer counter-context term
        ("HEALTH_INSURANCE_NUMBER", "Rechnungsnummer A123456780"),
        ("HEALTH_INSURANCE_NUMBER", "Order number Z987654321"),
        ("SOCIALID", "Rechnungsnummer 15070649C103"),
        ("SOCIALID", "Ticket number 65070803A019"),
        // lowercase without a field name
        ("HEALTH_INSURANCE_NUMBER", "Code a123456780 entered."),
        ("SOCIALID", "Code 15070649c103 entered."),
        // part of a longer value
        ("HEALTH_INSURANCE_NUMBER", "AB123456780"),
        ("SOCIALID", "Ref 15070649C103-2"),
        // a field that names another value
        ("HEALTH_INSURANCE_NUMBER", "Auftragscode: A123456780"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── LANR with a term, scored modes only ──────────────────────────────────────

#[test]
fn a_lanr_near_its_term_is_reported_in_the_scored_modes() {
    for (text, value) in [
        ("Arztnummer 987654401 auf dem Rezept.", "987654401"),
        ("Die LANR des Hausarztes lautet 123456601.", "123456601"),
        (
            "Rezept ausgestellt von Dr. Weber (Arzt-Nr. 234567701)",
            "234567701",
        ),
        (
            "The physician number on the prescription is 999999901.",
            "999999901",
        ),
        ("{\"arztnummer\": \"765432203\"}", "765432203"),
    ] {
        assert_reports(LANR_PROXIMITY, text, value, &SCORED);
        assert_silent(text, "PHYSICIAN_NUMBER_LANR", &[PiiMode::Strict]);
    }
}

#[test]
fn a_lanr_needs_its_term_and_a_valid_check_digit() {
    for text in [
        // no term: nine digits pass the check one time in ten
        "234567701",
        "Order 234567701 shipped.",
        "Bestellnummer 123456601",
        // the term names the next value, or a digit stands between
        "LANR 123456601 · BSNR 721234567",
        // check digit, repeated digit, longer number
        "Arztnummer: 123456789",
        "Arztnummer 111111111",
        "Arztnummer 1234566019",
        "Arztnummer 123456601-2",
    ] {
        let expected = usize::from(text == "LANR 123456601 · BSNR 721234567");
        for mode in MODES {
            assert_eq!(
                spans(text, mode, "PHYSICIAN_NUMBER_LANR").len(),
                expected,
                "{mode}: {text:?}"
            );
        }
    }
}

// ── BSNR: format and term, every mode ───────────────────────────────────────

#[test]
fn a_bsnr_with_its_term_or_key_is_reported_in_every_mode() {
    for (text, value) in [
        ("Betriebsstättennummer: 021234568", "021234568"),
        ("BSNR 711234567 der Praxis.", "711234567"),
        ("Als BSNR ist 781819850 hinterlegt.", "781819850"),
        ("{\"bsnr\": \"381789045\"}", "381789045"),
        ("My practice number is 613645811.", "613645811"),
        ("practice,bsnr\nDr. Weber,981234560", "981234560"),
        ("bsnr,age\n721234567,42", "721234567"),
    ] {
        assert_reports(BSNR, text, value, &MODES);
    }
}

#[test]
fn a_bsnr_needs_its_term_and_nine_digits_of_its_own() {
    for text in [
        // presidio-analyzer reports bare nine digits at 0.2 below its threshold too
        "021234568",
        "Order 721234567 shipped.",
        "Bestellnummer 721234567",
        "BSNR: 000000000",
        "BSNR: 72123456",
        "BSNR: 7212345670",
        "Practice number 721234567-2",
        "BSNR, order number 721234567",
        "Die BSNR steht auf dem Stempel.",
    ] {
        assert_silent(text, "FACILITY_NUMBER_BSNR", &MODES);
    }
}

#[test]
fn lanr_and_bsnr_on_one_line_keep_their_own_terms() {
    // The medical letter header of the E05 gold set: each term binds the value
    // right after it; a term never reaches across another number.
    let text = "LANR 123456601 · BSNR 721234567";
    let values = |mode, label| {
        spans(text, mode, label)
            .into_iter()
            .map(|(value, _)| value)
            .collect::<Vec<_>>()
    };
    for mode in MODES {
        assert_eq!(
            values(mode, "PHYSICIAN_NUMBER_LANR"),
            ["123456601"],
            "{mode}"
        );
        assert_eq!(
            values(mode, "FACILITY_NUMBER_BSNR"),
            ["721234567"],
            "{mode}"
        );
    }
}
