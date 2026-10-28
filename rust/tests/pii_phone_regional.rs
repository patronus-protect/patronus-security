// SPDX-License-Identifier: GPL-3.0-only
//! Regional national phone numbers via the `phonenumber` crate (F01).
//!
//! `pii_phone_regional` reports a grouped national number without a country prefix
//! (`416 60 039`, `03.93.92.16.85`, `0688 843 79 56`) when a phone term or a
//! structural key supports it and the number is valid in one of the numbering plans
//! of `validators::PHONE_REGIONS` (`validators::in_phone_region`, checked after the
//! context gate). It runs in `balanced` and `recall` only, after
//! the other phone rules, which keep their spans; `strict` is unchanged. Reserved
//! placeholder numbers (T01: NANP 555-01xx, `+1 000-000-0000`) stay positive.

use patronus_ark::detectors::pii::{score::PiiMode, validators};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

fn scan(text: &str, mode: PiiMode) -> SecurityScanResult {
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

fn phone_spans(text: &str, mode: PiiMode) -> Vec<String> {
    scan(text, mode)
        .evidence_spans
        .iter()
        .filter(|span| span.label == "PHONE")
        .map(|span| span.text.clone())
        .collect()
}

fn regional_rules(text: &str, mode: PiiMode) -> Vec<String> {
    scan(text, mode).layers[0]
        .details
        .get("matched_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|rule| rule["rule_id"] == "pii_phone_regional")
        .map(|rule| {
            let start = rule["start_byte"].as_u64().unwrap() as usize;
            let end = rule["end_byte"].as_u64().unwrap() as usize;
            text[start..end].to_owned()
        })
        .collect()
}

/// `(text, value)`: a national number with a phone term, valid in a regional plan.
const POSITIVES: &[(&str, &str)] = &[
    ("Mobile: 416 60 039\nDesk: n/a", "416 60 039"),
    (
        "Can someone call me on 9472 7916? I have some questions.",
        "9472 7916",
    ),
    ("Mobile: 03.93.92.16.85\nOrt: Paris", "03.93.92.16.85"),
    ("Please call me at 0494 92 82 32 tomorrow.", "0494 92 82 32"),
    ("Handy: 0688 843 79 56", "0688 843 79 56"),
    ("Mobil erreichbar unter 0699 868 88 55.", "0699 868 88 55"),
    ("Telefon: 044 668 18 00", "044 668 18 00"),
    (
        "Can someone call me on (64) 3591-3246? Thanks.",
        "(64) 3591-3246",
    ),
    ("My Japanese phone number is 090-1234-5678", "090-1234-5678"),
    ("Fax: 28-64-66-98", "28-64-66-98"),
];

#[test]
fn regional_numbers_with_a_phone_term_are_reported_in_balanced() {
    for (text, value) in POSITIVES {
        assert!(
            phone_spans(text, PiiMode::Balanced).contains(&(*value).to_owned()),
            "{text:?}: {:?}",
            phone_spans(text, PiiMode::Balanced)
        );
    }
}

#[test]
fn strict_never_runs_the_regional_rule() {
    for (text, _) in POSITIVES {
        assert!(
            regional_rules(text, PiiMode::Strict).is_empty(),
            "{text:?} in strict"
        );
    }
}

/// Hard negatives: no phone term, a date, an amount, an invalid number or a number
/// outside every regional plan.
const NEGATIVES: &[&str] = &[
    "Order 416 60 039 shipped today.",
    "Rechnung 0494 92 82 32 vom Mai",
    "Mobile: 31.12.2024",
    "Telefon: 2024-12-31",
    "Phone: 11 11 11 11",
    "Phone: 000 000 000",
    "Mobile: 12 34",
    "Tel.: 0000 000 0000",
    "Phone: 123 456 789 012 345",
    "Ticket 03.93.92.16.85 ist erledigt.",
];

#[test]
fn regional_rule_stays_silent_on_hard_negatives() {
    for mode in [PiiMode::Balanced, PiiMode::Recall] {
        for text in NEGATIVES {
            assert!(
                regional_rules(text, mode).is_empty(),
                "{text:?} in {mode:?}: {:?}",
                regional_rules(text, mode)
            );
        }
    }
}

#[test]
fn earlier_phone_rules_keep_their_spans() {
    for (text, value) in [
        ("Phone: (415) 555-0132", "(415) 555-0132"),
        ("Rückruf bitte unter (030) 1234567.", "(030) 1234567"),
        ("Desk: +41 (0)96 471 07 95", "+41 (0)96 471 07 95"),
    ] {
        assert_eq!(
            phone_spans(text, PiiMode::Balanced),
            vec![value.to_owned()],
            "{text:?}"
        );
    }
}

#[test]
fn placeholder_numbers_stay_positive() {
    for (text, value) in [
        ("Call me at 212-555-0147.", "212-555-0147"),
        ("Phone: (555) 010-0199", "(555) 010-0199"),
        ("Phone: +1 000-000-0000", "+1 000-000-0000"),
        ("Phone: +1 555 0100 123", "+1 555 0100 123"),
    ] {
        for mode in [PiiMode::Strict, PiiMode::Balanced] {
            assert!(
                phone_spans(text, mode).contains(&value.to_owned()),
                "{text:?} in {mode:?}: {:?}",
                phone_spans(text, mode)
            );
        }
    }
}

#[test]
fn regional_validator_vectors() {
    for valid in [
        "030 1234567",
        "0176 90817263",
        "020 7946 0958",
        "01 23 45 67 89",
        "044 668 18 00",
        "0664 1234567",
        "41660039",
        "(64) 3591-3246",
    ] {
        assert!(validators::regional_phone(valid), "{valid}");
        assert!(validators::in_phone_region(valid), "{valid}");
    }
    for invalid in [
        "31.12.2024",
        "2024-12-31",
        "000 000 000",
        "1111111",
        "12 34 56",
        "0000 000 0000",
        "123 456 789 012 345",
    ] {
        assert!(!validators::regional_phone(invalid), "{invalid}");
    }
    // The right shape, but no valid number in any regional plan.
    for outside in ["0000 1234567", "0001 234 567"] {
        assert!(validators::regional_phone(outside), "{outside}");
        assert!(!validators::in_phone_region(outside), "{outside}");
    }
}
