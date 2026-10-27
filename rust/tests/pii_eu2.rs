// SPDX-License-Identifier: GPL-3.0-only
//! Austrian, Swiss, Portuguese and Irish identifiers (B-EU2: B06, B07, B14).
//!
//! Four numbering systems with a check digit or letter, one label each: the
//! Austrian social security number (`AT_SOCIAL_SECURITY_NUMBER`, weighted mod 11),
//! the Swiss AHV number (`CH_AHV_NUMBER`, 756 and EAN-13), the Portuguese NIF
//! (`PT_NIF`, the mod-11 check of the Portuguese VAT ID, a label of its own) and the
//! Irish PPS number (`IE_PPSN`, the check letter of the Irish VAT number). Each
//! label has a rule that reports the value in every mode when a term of the label
//! stands near it or is its key. In `balanced` and `recall` the printed forms
//! `NNNN DDMMYY` (Austria, with a calendar date) and `756.NNNN.NNNN.NN` (Switzerland)
//! are also reported bare (K05). Ten bare digits, nine digits (NIF) and seven
//! digits with a letter (PPSN) need the term in every mode.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const SOCIAL_SECURITY_NUMBER: &str = "pii_social_security_number_at";
const SOCIAL_SECURITY_NUMBER_CONTEXT_FREE: &str = "pii_social_security_number_at_context_free";
const AHV_NUMBER: &str = "pii_ahv_number_ch";
const AHV_NUMBER_CONTEXT_FREE: &str = "pii_ahv_number_ch_context_free";
const NIF: &str = "pii_nif_pt";
const PPSN: &str = "pii_ppsn_ie";
const CONTEXT_BOUND: [&str; 4] = [SOCIAL_SECURITY_NUMBER, AHV_NUMBER, NIF, PPSN];
const CONTEXT_FREE: [&str; 2] = [SOCIAL_SECURITY_NUMBER_CONTEXT_FREE, AHV_NUMBER_CONTEXT_FREE];
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
fn social_security_number_validator_checks_the_weighted_sum() {
    for valid in [
        // the example of the Dachverband: serial 123, check 7, 1 January 1980
        "1237 010180",
        "1237010180",
        "4566 150372",
        "2346 240588",
        "5676120865",
        "6783 300946",
        // days above 31 and months above 12 when a day runs out of serials
        "6788 320946",
        "9121 281479",
    ] {
        assert!(validators::at_social_security_number(valid), "{valid}");
    }
    for invalid in [
        // check digit off by one
        "1238 010180",
        "4565150372",
        // a serial below 100
        "0237 010180",
        // remainder 10 is never issued: 1240 010180 sums to 87, 87 mod 11 = 10
        "1240 010180",
        // length, separators and alphabet
        "123 7010180",
        "1237-010180",
        "123701018",
        "12370101800",
        "1237 01018A",
    ] {
        assert!(!validators::at_social_security_number(invalid), "{invalid}");
    }
}

#[test]
fn ahv_number_validator_checks_the_prefix_and_ean13() {
    for valid in [
        "756.1234.5678.97",
        "7561234567897",
        "756 1234 5678 97",
        "756.9876.5432.17",
        "756.3141.5926.58",
    ] {
        assert!(validators::ch_ahv_number(valid), "{valid}");
    }
    for invalid in [
        // EAN-13 check digit off by one
        "756.1234.5678.98",
        "7569876543218",
        // EAN-13 valid, but not the Swiss country code 756
        "757.1234.5678.94",
        "4006381333931",
        // length, separators and alphabet
        "756.1234.5678.9",
        "756-1234-5678-97",
        "75612345678970",
        "756.1234.5678.9A",
    ] {
        assert!(!validators::ch_ahv_number(invalid), "{invalid}");
    }
}

#[test]
fn nif_validator_shares_the_check_of_the_vat_id() {
    for valid in [
        "501964843",
        "123456789",
        "253876125",
        "188 294 759",
        "612-345-980",
        "293847568",
    ] {
        assert!(validators::pt_nif(valid), "{valid}");
        // The VAT ID is the same nine digits behind `PT`.
        let vat = format!("PT{}", valid.replace([' ', '-'], ""));
        assert!(validators::pt_vat_id(&vat), "{vat}");
    }
    for invalid in [
        // check digit off by one
        "501964844",
        "253876126",
        // a leading zero
        "012345675",
        // the country code is the VAT ID's, not the NIF's
        "PT501964843",
        // length and alphabet
        "50196484",
        "5019648430",
        "50196484A",
    ] {
        assert!(!validators::pt_nif(invalid), "{invalid}");
    }
}

#[test]
fn ppsn_validator_checks_the_letter_of_the_vat_number() {
    for valid in [
        // python-stdnum test values
        "1234567T",
        "1234567FA",
        "8765432S",
        "2345678DB",
        "6543210R",
        // older second letters, not counted in the check
        "1234567TW",
        "1234567TX",
        "3141592SW",
    ] {
        assert!(validators::ie_ppsn(valid), "{valid}");
    }
    for invalid in [
        // check letter off
        "1234567U",
        "1234567TA",
        "8765432T",
        // a second letter that is never issued
        "1234567FC",
        // seven zeros, with the matching check letter W
        "0000000W",
        // length and alphabet
        "123456T",
        "12345678T",
        "1234567",
        "1234567t",
        // a multibyte character across the seventh byte
        "123456äT",
    ] {
        assert!(!validators::ie_ppsn(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_eu2_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check) in [
        (
            &[SOCIAL_SECURITY_NUMBER, SOCIAL_SECURITY_NUMBER_CONTEXT_FREE][..],
            "AT_SOCIAL_SECURITY_NUMBER",
            validators::at_social_security_number as fn(&str) -> bool,
        ),
        (
            &[AHV_NUMBER, AHV_NUMBER_CONTEXT_FREE][..],
            "CH_AHV_NUMBER",
            validators::ch_ahv_number,
        ),
        (&[NIF][..], "PT_NIF", validators::pt_nif),
        (&[PPSN][..], "IE_PPSN", validators::ie_ppsn),
    ] {
        for rule_id in rule_ids {
            let rule = pattern(rule_id);
            assert_eq!(rule.entity_group, label, "{rule_id}");
            assert_eq!(rule.strength, ValidatorStrength::Checksum, "{rule_id}");
            assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
            assert!(!rule.captured_value, "{rule_id}");
        }
    }
    let balanced = PiiMode::Balanced.min_score().unwrap();
    let recall = PiiMode::Recall.min_score().unwrap();
    for rule_id in CONTEXT_BOUND {
        let rule = pattern(rule_id);
        assert!(rule.requires_context && !rule.scored_only, "{rule_id}");
        // The farthest term still clears the balanced threshold.
        assert!(
            score::score(rule, Context::Support { gap: 48 }) >= balanced,
            "{rule_id}"
        );
    }
    for rule_id in CONTEXT_FREE {
        let rule = pattern(rule_id);
        assert!(rule.scored_only && !rule.requires_context, "{rule_id}");
        // Bare, the check digit reaches the balanced threshold; a nearer
        // counter-context term drops it below the recall threshold.
        assert_eq!(score::rule_score(rule), 0.55, "{rule_id}");
        assert!(score::score(rule, Context::Counter) < recall, "{rule_id}");
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (
            SOCIAL_SECURITY_NUMBER,
            "Sozialversicherungsnummer: 1237 010180",
            "1237 010180",
        ),
        (
            SOCIAL_SECURITY_NUMBER,
            "Die österreichische Versicherungsnummer lautet 4566150372.",
            "4566150372",
        ),
        (SOCIAL_SECURITY_NUMBER, "VSNR 6783 300946", "6783 300946"),
        (
            SOCIAL_SECURITY_NUMBER,
            "{\"svnr\": \"2346240588\"}",
            "2346240588",
        ),
        (
            SOCIAL_SECURITY_NUMBER,
            "My Austrian social security number is 5676 120865.",
            "5676 120865",
        ),
        (
            AHV_NUMBER,
            "AHV-Nummer: 756.1234.5678.97",
            "756.1234.5678.97",
        ),
        (AHV_NUMBER, "AHV-Nr. 7569876543217", "7569876543217"),
        (
            AHV_NUMBER,
            "Numéro AVS : 756 3141 5926 58",
            "756 3141 5926 58",
        ),
        (
            AHV_NUMBER,
            "Die Sozialversicherungsnummer lautet 756.2718.2818.27.",
            "756.2718.2818.27",
        ),
        (
            AHV_NUMBER,
            "{\"ahv_number\": \"7561618033987\"}",
            "7561618033987",
        ),
        (NIF, "NIF: 501964843", "501964843"),
        (NIF, "Número de contribuinte 253 876 125", "253 876 125"),
        (
            NIF,
            "The Portuguese tax number on file is 188294759.",
            "188294759",
        ),
        (NIF, "{\"nif\": \"612345980\"}", "612345980"),
        (
            NIF,
            "Die portugiesische Steuernummer lautet 293847568.",
            "293847568",
        ),
        (PPSN, "PPS Number: 1234567T", "1234567T"),
        (PPSN, "My PPSN is 1234567FA.", "1234567FA"),
        (PPSN, "{\"ppsn\": \"8765432S\"}", "8765432S"),
        (
            PPSN,
            "Die irische PPS-Nummer lautet 2345678DB.",
            "2345678DB",
        ),
        (PPSN, "Personal Public Service Number 6543210R", "6543210R"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (
            SOCIAL_SECURITY_NUMBER,
            "svnr,alter\n1237010180,46",
            "1237010180",
        ),
        (AHV_NUMBER, "ahv,alter\n7561234567897,42", "7561234567897"),
        (NIF, "nif,idade\n501964843,42", "501964843"),
        (PPSN, "ppsn,age\n1234567T,42", "1234567T"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
    // A cell that holds more than the value is still part of a longer number.
    assert_silent("nif,idade\n501964843-4,42", "PT_NIF", &MODES);
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // no term: the bare forms that are never context-free
        ("AT_SOCIAL_SECURITY_NUMBER", "Reference 1237010180"),
        ("CH_AHV_NUMBER", "Artikel 7561234567897"),
        ("PT_NIF", "Order 501964843 shipped."),
        ("PT_NIF", "501 964 843"),
        ("IE_PPSN", "Reference 1234567T"),
        ("IE_PPSN", "1234567FA"),
        // check fails
        (
            "AT_SOCIAL_SECURITY_NUMBER",
            "Sozialversicherungsnummer: 1238 010180",
        ),
        ("AT_SOCIAL_SECURITY_NUMBER", "VSNR 0237 010180"),
        ("CH_AHV_NUMBER", "AHV-Nummer: 756.1234.5678.98"),
        ("PT_NIF", "NIF: 501964844"),
        ("IE_PPSN", "PPS Number: 1234567U"),
        ("IE_PPSN", "PPS Number: 1234567FC"),
        // part of a longer value
        ("AT_SOCIAL_SECURITY_NUMBER", "VSNR 1237 010180 5"),
        ("CH_AHV_NUMBER", "AHV-Nummer: 756.1234.5678.97.1"),
        ("PT_NIF", "NIF: 501964843-1"),
        ("IE_PPSN", "PPSN: AB1234567T"),
        // a nearer counter-context term
        (
            "AT_SOCIAL_SECURITY_NUMBER",
            "Versicherungsnummer-Schreiben, Bestellnummer 1237010180",
        ),
        ("PT_NIF", "NIF letter, invoice number 501964843"),
        ("IE_PPSN", "PPSN letter, order number 1234567T"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

#[test]
fn a_nif_is_no_vat_id_and_a_vat_id_is_no_nif() {
    // The same nine digits: behind `PT` the body of a VAT ID (scored modes only),
    // bare with a NIF term a NIF.
    for text in ["NIF: PT501964843", "Contribuinte: PT 501 964 843"] {
        assert_silent(text, "PT_NIF", &MODES);
        for mode in SCORED {
            assert_eq!(spans(text, mode, "VAT_ID_PT").len(), 1, "{mode}: {text}");
        }
    }
    assert_silent("NIF: 501 964 843", "VAT_ID_PT", &MODES);
}

// ── bare values, scored modes only ───────────────────────────────────────────

#[test]
fn bare_values_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (
            SOCIAL_SECURITY_NUMBER_CONTEXT_FREE,
            "1237 010180",
            "1237 010180",
        ),
        (
            SOCIAL_SECURITY_NUMBER_CONTEXT_FREE,
            "Patientin 2346 240588 wurde aufgenommen.",
            "2346 240588",
        ),
        (
            AHV_NUMBER_CONTEXT_FREE,
            "756.1234.5678.97",
            "756.1234.5678.97",
        ),
        (
            AHV_NUMBER_CONTEXT_FREE,
            "Employee 756.9876.5432.17 starts on Monday.",
            "756.9876.5432.17",
        ),
    ] {
        assert_reports(rule_id, text, value, &SCORED);
        let label = pattern(rule_id).entity_group;
        assert_silent(text, label, &[PiiMode::Strict]);
        assert_eq!(
            spans(text, PiiMode::Balanced, label),
            [(value.to_owned(), 0.55)],
            "{text}"
        );
    }
}

#[test]
fn bare_lookalikes_stay_silent_in_every_mode() {
    for (label, text) in [
        // ten digits without the space, or a date that is no calendar date
        ("AT_SOCIAL_SECURITY_NUMBER", "1237010180"),
        ("AT_SOCIAL_SECURITY_NUMBER", "6788 320946"),
        ("AT_SOCIAL_SECURITY_NUMBER", "9121 281479"),
        // thirteen digits or groups by spaces: also an EAN-13 or a reference
        ("CH_AHV_NUMBER", "7561234567897"),
        ("CH_AHV_NUMBER", "756 1234 5678 97"),
        // invalid check
        ("AT_SOCIAL_SECURITY_NUMBER", "1238 010180"),
        ("CH_AHV_NUMBER", "756.1234.5678.98"),
        // part of a longer value or a phone number
        ("AT_SOCIAL_SECURITY_NUMBER", "+43 1237 010180"),
        (
            "AT_SOCIAL_SECURITY_NUMBER",
            "Teil 1237 010180-2 ist lieferbar.",
        ),
        ("CH_AHV_NUMBER", "Version 756.1234.5678.97.3"),
        // a nearer counter-context term
        ("AT_SOCIAL_SECURITY_NUMBER", "Bestellnummer 1237 010180"),
        ("CH_AHV_NUMBER", "Order number 756.1234.5678.97"),
    ] {
        assert_silent(text, label, &MODES);
    }
}
