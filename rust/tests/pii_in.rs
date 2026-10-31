// SPDX-License-Identifier: GPL-3.0-only
//! Indian identifiers (B-IN).
//!
//! Two numbering systems with a real check: the Aadhaar number (`IN_AADHAAR`,
//! twelve digits, first digit 2–9, plain or grouped 4-4-4, Verhoeff check digit)
//! and the GSTIN (`IN_GSTIN`, state code, the PAN of the holder, entity number,
//! `Z` and a mod-36 check character). The PAN (`IN_PAN`, holder type in the
//! fourth letter) and the voter ID (`IN_VOTER`, EPIC, three letters and seven
//! digits) are format and context only. Each is reported in every mode when a term of the label stands near it
//! or is its key; in `balanced` and `recall` the grouped Aadhaar number and the
//! GSTIN are also reported bare (K05).

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const AADHAAR: &str = "pii_aadhaar_in";
const AADHAAR_BARE: &str = "pii_aadhaar_in_context_free";
const GSTIN: &str = "pii_gstin_in";
const GSTIN_BARE: &str = "pii_gstin_in_context_free";
const PAN: &str = "pii_pan_in";
const VOTER: &str = "pii_voter_id_in";
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
fn aadhaar_validator_checks_the_verhoeff_digit_and_the_form() {
    for valid in [
        "591533759365",
        "5915 3375 9365",
        "8797-7332-6157",
        "4294:5428:4060",
        // presidio-analyzer test values
        "399876543211",
        "3998 7654 3211",
        "3123-4567-8909",
        "3123:4567:8909",
    ] {
        assert!(validators::in_aadhaar(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "591533759366",
        "5915 3375 9364",
        "123456789012",
        "1234:5678:9012",
        // leading 0 or 1 with a valid Verhoeff digit
        "029454284068",
        "123456789010",
        // a palindrome is never issued
        "358683386853",
        // form
        "59153375936",
        "5915337593651",
        "5915 33759365",
        "5915-3375 9365",
        "5915.3375.9365",
        "59153375936A",
    ] {
        assert!(!validators::in_aadhaar(invalid), "{invalid}");
    }
}

#[test]
fn gstin_validator_checks_the_state_entity_and_check_character() {
    for valid in [
        "10BAGFF2439K3ZL",
        "20DWWHC5119Y4Z0",
        "06CXKCD8583B3Z4",
        "15JEDHV3851A1ZZ",
        "34LAMCC6452E4ZB",
    ] {
        assert!(validators::in_gstin(valid), "{valid}");
    }
    for invalid in [
        // check character fails (also the presidio-analyzer values)
        "10BAGFF2439K3ZM",
        "27ABCDE1234F1Z5",
        "07PQRST6789K1Z2",
        // state code 00 and 45, entity number 0, each with a valid check character
        "00BAGFF2439K3ZM",
        "45RWETR6874M6ZU",
        "36RWETR6874M0ZZ",
        // no Z, form
        "27ABCDE1234F1Y5",
        "27ABCDE1234F1Z",
        "27ABCDE1234F1Z55",
        "10bagff2439k3zl",
    ] {
        assert!(!validators::in_gstin(invalid), "{invalid}");
    }
}

#[test]
fn pan_validator_checks_the_holder_type_and_serial() {
    for valid in [
        "BNZPM2501F",
        "AAACR5055K",
        "AAFFS9921J",
        "ABCPD1234Z",
        "ABBPM4567S",
    ] {
        assert!(validators::in_pan(valid), "{valid}");
    }
    for invalid in [
        // fourth letter is no holder type
        "BNZXM2501F",
        "ABCDE1234F",
        // serial 0000, form
        "BNZPM0000F",
        "BNZPM25010",
        "BNZP2501F",
        "bnzpm2501f",
    ] {
        assert!(!validators::in_pan(invalid), "{invalid}");
    }
}

#[test]
fn the_indian_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    for (rule_id, label, check, strength, scored_only) in [
        (
            AADHAAR,
            "IN_AADHAAR",
            Some(validators::in_aadhaar as fn(&str) -> bool),
            ValidatorStrength::Checksum,
            false,
        ),
        (
            AADHAAR_BARE,
            "IN_AADHAAR",
            Some(validators::in_aadhaar),
            ValidatorStrength::Checksum,
            true,
        ),
        (
            GSTIN,
            "IN_GSTIN",
            Some(validators::in_gstin),
            ValidatorStrength::Checksum,
            false,
        ),
        (
            GSTIN_BARE,
            "IN_GSTIN",
            Some(validators::in_gstin),
            ValidatorStrength::Checksum,
            true,
        ),
        (
            PAN,
            "IN_PAN",
            Some(validators::in_pan),
            ValidatorStrength::Format,
            false,
        ),
        (
            VOTER,
            "IN_VOTER",
            Some(validators::in_voter_id),
            ValidatorStrength::Format,
            false,
        ),
    ] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, label, "{rule_id}");
        assert_eq!(rule.strength, strength, "{rule_id}");
        assert_eq!(
            validator(rule),
            check.map(|check| check as usize),
            "{rule_id}"
        );
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

#[test]
fn voter_id_validator_checks_the_epic_form() {
    for valid in ["KLT4471920", "WBX0938264", "MUP5632811", "CPJ4467918"] {
        assert!(validators::in_voter_id(valid), "{valid}");
    }
    for invalid in [
        // serial 0000000, form
        "KLT0000000",
        "KLT447192",
        "KL44719201",
        "KLT44719201",
        "klt4471920",
        "1234567890",
    ] {
        assert!(!validators::in_voter_id(invalid), "{invalid}");
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (AADHAAR, "Aadhaar number: 5915 3375 9365", "5915 3375 9365"),
        (AADHAAR, "My Aadhaar is 599979610811.", "599979610811"),
        (
            AADHAAR,
            "{\"aadhaar\": \"8797-7332-6157\"}",
            "8797-7332-6157",
        ),
        (AADHAAR, "Aadhaar-Nummer: 4294 5428 4060", "4294 5428 4060"),
        (
            AADHAAR,
            "Die Aadhaar-Nummer des Antragstellers lautet 398288889437.",
            "398288889437",
        ),
        (GSTIN, "GSTIN: 10BAGFF2439K3ZL", "10BAGFF2439K3ZL"),
        (
            GSTIN,
            "Our GST number is 20DWWHC5119Y4Z0.",
            "20DWWHC5119Y4Z0",
        ),
        (GSTIN, "{\"gstin\": \"06CXKCD8583B3Z4\"}", "06CXKCD8583B3Z4"),
        (
            GSTIN,
            "Die GSTIN des Lieferanten lautet 16KGICL5894M8ZW.",
            "16KGICL5894M8ZW",
        ),
        (PAN, "PAN: BNZPM2501F", "BNZPM2501F"),
        (
            PAN,
            "The Permanent Account Number on file is AFZPK7190K.",
            "AFZPK7190K",
        ),
        (PAN, "{\"pan_number\": \"AAACR5055K\"}", "AAACR5055K"),
        (PAN, "Indische PAN: DKLPR3307N", "DKLPR3307N"),
        (
            PAN,
            "Die PAN-Nummer des Kunden lautet EHTPV5562Q.",
            "EHTPV5562Q",
        ),
        (VOTER, "Voter ID: KLT4471920", "KLT4471920"),
        (
            VOTER,
            "You can vote with your EPIC number WBX0938264.",
            "WBX0938264",
        ),
        (VOTER, "{\"voter_id\": \"DLH5520731\"}", "DLH5520731"),
        (VOTER, "Indische Wähler-ID: TNV2048837", "TNV2048837"),
        (
            VOTER,
            "Die EPIC-Nummer der Antragstellerin lautet UPK6610294.",
            "UPK6610294",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (AADHAAR, "aadhaar,age\n406928830752,42", "406928830752"),
        (
            GSTIN,
            "gstin,employees\n30IDYTH1820Z4Z7,31",
            "30IDYTH1820Z4Z7",
        ),
        (PAN, "pan,age\nCQWPS4821L,42", "CQWPS4821L"),
        (VOTER, "epic,age\nMHR1186402,42", "MHR1186402"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // check fails
        ("IN_AADHAAR", "Aadhaar number: 5915 3375 9366"),
        ("IN_AADHAAR", "Aadhaar number: 1234 5678 9010"),
        ("IN_AADHAAR", "Aadhaar-Nummer: 0294 5428 4068"),
        ("IN_GSTIN", "GSTIN: 10BAGFF2439K3ZM"),
        ("IN_GSTIN", "GSTIN: 45RWETR6874M6ZU"),
        ("IN_GSTIN", "GSTIN: 27ABCDE1234F1Y5"),
        ("IN_PAN", "PAN: BNZXM2501F"),
        ("IN_PAN", "PAN: BNZPM0000F"),
        ("IN_VOTER", "Voter ID: KLT447192"),
        ("IN_VOTER", "Voter ID: KL44719201"),
        // no term, also in the scored modes
        ("IN_AADHAAR", "599979610811"),
        ("IN_AADHAAR", "Reference 599979610811 was archived."),
        ("IN_PAN", "Reference BNZPM2501F was archived."),
        ("IN_PAN", "BNZPM2501F"),
        ("IN_VOTER", "Reference KLT4471920 was archived."),
        ("IN_VOTER", "KLT4471920"),
        // part of a longer value
        ("IN_AADHAAR", "Aadhaar number: 5915 3375 9365 7"),
        ("IN_AADHAAR", "Aadhaar-Nummer: 4294-5428-4060-1"),
        ("IN_GSTIN", "GSTIN: 10BAGFF2439K3ZL5"),
        ("IN_PAN", "PAN: BNZPM2501F7"),
        ("IN_VOTER", "Voter ID: KLT4471920-1"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare grouped Aadhaar numbers and GSTINs, scored modes only ───────────────

#[test]
fn bare_grouped_aadhaar_numbers_and_gstins_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (
            AADHAAR_BARE,
            "Applicant 5352 4277 1202 joined in May.",
            "5352 4277 1202",
        ),
        (AADHAAR_BARE, "6532-0568-8226", "6532-0568-8226"),
        (AADHAAR_BARE, "3998 7654 3211", "3998 7654 3211"),
        (
            GSTIN_BARE,
            "Invoice from 25OLGTA9304C8ZW is due.",
            "25OLGTA9304C8ZW",
        ),
        (GSTIN_BARE, "28MHVAN9845P9Z6", "28MHVAN9845P9Z6"),
    ] {
        assert_reports(rule_id, text, value, &SCORED);
        assert_silent(text, pattern(rule_id).entity_group, &[PiiMode::Strict]);
    }
    for (label, text) in [
        // check fails
        ("IN_AADHAAR", "Applicant 5352 4277 1203 joined in May."),
        ("IN_GSTIN", "Invoice from 25OLGTA9304C8ZX is due."),
        // the twelve digits inside a grouped card number or a longer run
        ("IN_AADHAAR", "Card 5352 4277 1202 4242"),
        ("IN_AADHAAR", "Ref 1111 5352 4277 1202"),
    ] {
        assert_silent(text, label, &MODES);
    }
}
