// SPDX-License-Identifier: GPL-3.0-only
//! Phone span boundaries (T18, TRIAGE 2026-W43 bucket 3).
//!
//! A phone number never continues across a line break: `pii_phone_international`
//! separated digits with `\s`, so `+1-123-456-7890\n\n2` took the item number of the
//! next line. A NANP trunk prefix (`1-800-123-4567`, `1 (800) 123-4567`) and a `00`
//! international prefix in front of a 3-3-4 number (`001 415 555 2671`) are part of
//! the span; the `+49`/`0049` forms keep theirs. The prefix only widens a number the
//! rules found before: no prefix alone, and no other `00` number, is a new match.
//! The validator is unchanged.

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

/// `(rule_id, value)` of every matched rule.
fn rules(text: &str, result: &SecurityScanResult) -> Vec<(String, String)> {
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

fn phone_spans(result: &SecurityScanResult) -> Vec<String> {
    result
        .evidence_spans
        .iter()
        .filter(|span| span.label == "PHONE")
        .map(|span| span.text.clone())
        .collect()
}

const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];

/// `(text, rule, value)`: the number ends before the line break.
const LINE_BREAK: [(&str, &str, &str); 8] = [
    (
        "Call +1-123-456-7890\n\n2. Next step",
        "pii_phone_international",
        "+1-123-456-7890",
    ),
    (
        "Telefon: +49 30 1234567\n2. Ansprechpartnerin",
        "pii_phone_international",
        "+49 30 1234567",
    ),
    (
        "Telefon: +49 30 1234567\n2. Ansprechpartnerin",
        "pii_phone_de",
        "+49 30 1234567",
    ),
    (
        "Zentrale 0049 170 1234567\n\n2",
        "pii_phone_de",
        "0049 170 1234567",
    ),
    (
        "Fax +44 20 7946 0958\r\n3 pages",
        "pii_phone_international",
        "+44 20 7946 0958",
    ),
    (
        "Mobile: +1 212 555 0147\u{2028}9 am to 5 pm",
        "pii_phone_international",
        "+1 212 555 0147",
    ),
    (
        "Office: 212-555-0147\n\n1 floor up",
        "pii_phone_us",
        "212-555-0147",
    ),
    // A horizontal space other than U+0020 still separates digit groups.
    (
        "Tel. +49\u{a0}30\u{a0}1234567",
        "pii_phone_international",
        "+49\u{a0}30\u{a0}1234567",
    ),
];

/// A number split by a line break is two values, neither of them a phone number.
const SPLIT: [&str; 5] = [
    "Units per shelf:\n212\n555 0100",
    "Lagerbestand je Regal:\n415\n555-2671",
    "Positions\n+49 30\n12345",
    "Bestand: 415\r\n555 2671",
    "Codes 212\u{2029}555.0100",
];

/// `(text, value)`: `pii_phone_us` reports `value` with its prefix, the only PHONE span.
const PREFIXED: [(&str, &str); 12] = [
    ("Call us at 1-800-123-4567 today.", "1-800-123-4567"),
    ("Toll-free: 1-800-959-5525", "1-800-959-5525"),
    ("Customer service 1 (800) 123-4567", "1 (800) 123-4567"),
    ("Support: 1.800.555.0199", "1.800.555.0199"),
    ("Hotline 1 888 555 0123 (24/7)", "1 888 555 0123"),
    ("Gebührenfreie Hotline: 1-800-123-4567", "1-800-123-4567"),
    ("US-Kundendienst unter 1 (800) 555-0199", "1 (800) 555-0199"),
    ("Aus Deutschland: 001 415 555 2671", "001 415 555 2671"),
    ("From abroad dial 001-518-640-0854.", "001-518-640-0854"),
    ("Contact 001 377-894.5296 for details.", "001 377-894.5296"),
    ("Büro Mexiko-Stadt 0052 555 123 4567", "0052 555 123 4567"),
    ("Reach the desk at 0044 207 946 0958.", "0044 207 946 0958"),
];

#[test]
fn validator_vectors_are_unchanged() {
    for (_, value) in PREFIXED {
        assert!(validators::unanchored_phone(value), "{value}");
    }
    for (_, _, value) in LINE_BREAK {
        assert!(validators::unanchored_phone(value), "{value}");
    }
    // The trunk prefix adds no digit the validator would need: repeated digits,
    // too few digits and masked numbers stay invalid with it.
    for value in ["1-111-111-1111", "1-800", "001 XXX XXX XXXX", "00000000000"] {
        assert!(!validators::unanchored_phone(value), "{value}");
    }
}

#[test]
fn a_number_ends_before_a_line_break() {
    for (text, rule, value) in LINE_BREAK {
        let result = scan(text, PiiMode::Strict);
        let found = rules(text, &result);
        assert!(
            found.contains(&(rule.to_owned(), value.to_owned())),
            "{text:?}: {found:?}"
        );
        assert!(
            found.iter().all(|(_, value)| !value.contains(['\n', '\r'])),
            "{text:?}: {found:?}"
        );
        assert_eq!(phone_spans(&result), vec![value.to_owned()], "{text:?}");
    }
}

#[test]
fn a_number_ends_before_a_line_break_in_scored_modes() {
    for mode in [PiiMode::Balanced, PiiMode::Recall] {
        for (text, value) in [
            ("Call +1-123-456-7890\n\n2. Next step", "+1-123-456-7890"),
            (
                "Telefon: +49 30 1234567\n2. Ansprechpartnerin",
                "+49 30 1234567",
            ),
            ("Phone: 212-555-0147\n\n1 floor up", "212-555-0147"),
        ] {
            let result = scan(text, mode);
            assert_eq!(
                phone_spans(&result),
                vec![value.to_owned()],
                "{mode:?}: {text:?}"
            );
        }
    }
}

#[test]
fn digits_split_by_a_line_break_stay_silent() {
    for text in SPLIT {
        for mode in MODES {
            let result = scan(text, mode);
            assert!(
                phone_spans(&result).is_empty(),
                "{mode:?}: {text:?}: {:?}",
                rules(text, &result)
            );
        }
    }
}

#[test]
fn trunk_and_international_prefix_are_part_of_the_span() {
    for (text, value) in PREFIXED {
        let result = scan(text, PiiMode::Strict);
        assert!(
            rules(text, &result).contains(&("pii_phone_us".to_owned(), value.to_owned())),
            "{text}: {:?}",
            rules(text, &result)
        );
        assert_eq!(phone_spans(&result), vec![value.to_owned()], "{text}");
    }
}

#[test]
fn trunk_prefix_is_part_of_the_span_in_scored_modes() {
    for mode in [PiiMode::Balanced, PiiMode::Recall] {
        for (text, value) in [
            ("Phone: 1-800-123-4567", "1-800-123-4567"),
            ("Telefon: 1 (800) 555-0199", "1 (800) 555-0199"),
            ("Phone: 001 415 555 2671", "001 415 555 2671"),
        ] {
            let result = scan(text, mode);
            assert_eq!(
                phone_spans(&result),
                vec![value.to_owned()],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn plus_and_0049_forms_keep_their_prefix() {
    for (text, rule, value) in [
        (
            "Call +1-800-123-4567 now",
            "pii_phone_international",
            "+1-800-123-4567",
        ),
        (
            "Phone: +1 (415) 555-2671",
            "pii_phone_international",
            "+1 (415) 555-2671",
        ),
        ("Ruf 0049 30 1234567 an", "pii_phone_de", "0049 30 1234567"),
        (
            "Telefon:\n0049 30 1234567",
            "pii_phone_de",
            "0049 30 1234567",
        ),
        (
            "Kommunikationssegment: COM+0049 30 1234567:TE'",
            "pii_phone_de",
            "0049 30 1234567",
        ),
    ] {
        let result = scan(text, PiiMode::Strict);
        assert!(
            rules(text, &result).contains(&(rule.to_owned(), value.to_owned())),
            "{text}: {:?}",
            rules(text, &result)
        );
        assert_eq!(phone_spans(&result), vec![value.to_owned()], "{text}");
    }
}

#[test]
fn a_prefix_needs_its_own_boundary() {
    // Digits or letters right before the `1`/`00` are no prefix: the span keeps the
    // national number it had before.
    for (text, value) in [
        ("Ref 21-800-123-4567", "800-123-4567"),
        ("Order 11-800-123-4567", "800-123-4567"),
        ("Box 0001 415 555 2671", "415 555 2671"),
        ("Code A1-800-123-4567", "800-123-4567"),
        ("Hotline:\n1\n800-123-4567", "800-123-4567"),
    ] {
        let result = scan(text, PiiMode::Strict);
        assert_eq!(phone_spans(&result), vec![value.to_owned()], "{text:?}");
    }
}

#[test]
fn a_prefix_alone_adds_no_match() {
    for text in [
        "Hotline 1-800-FLOWERS",
        "Kapitel 1-800 bis 1-900",
        "Version 1.800.12 freigegeben",
        "Bestellnummer 001-2345-6789",
        "Teilenummer 001-555-01",
        "Ticket 1800-123-4567",
        "Call 0044 20 7946 0958",
        "Belegnummer 0012345678",
        "Rufnummer 0033 1 23 45 67 89",
    ] {
        for mode in MODES {
            let result = scan(text, mode);
            assert!(
                phone_spans(&result).is_empty(),
                "{mode:?}: {text}: {:?}",
                rules(text, &result)
            );
        }
    }
}
