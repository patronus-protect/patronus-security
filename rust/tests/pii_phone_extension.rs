// SPDX-License-Identifier: GPL-3.0-only
//! NANP extensions inside the phone span (F18, baseline bucket P5, candidate C3).
//!
//! `pii_phone_us` ended with `\d{4}\b`, which never holds before an attached `x`:
//! `345-899-3560x4587` was no match, and `pii_phone_international`, the earlier rule,
//! cut `+1-604-696-5272x565` to `+1-604-696`. An extension (`x4587`, `ext 123`,
//! `ext. 123`, `extension 12`) right after a NANP number now belongs to its span; a
//! bare `x` or `ext` without digits ends the span before it, and letters attached to
//! the number (`4567xl`) still yield no match. Other numbers keep their span, and the
//! validator checks the number without the extension.

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

/// `(text, value)`: `pii_phone_us` reports `value` with its extension, the only PHONE span.
const EXTENDED: [(&str, &str); 12] = [
    ("Call 345-899-3560x4587 today.", "345-899-3560x4587"),
    ("Phone: 212-555-0147 ext. 123", "212-555-0147 ext. 123"),
    ("Office: (212) 736-4410 ext 204", "(212) 736-4410 ext 204"),
    (
        "Support line 1-800-959-5525 extension 12",
        "1-800-959-5525 extension 12",
    ),
    ("Fax: (579)888-3058x12", "(579)888-3058x12"),
    (
        "Dial 001-518-640-0854x123 from abroad.",
        "001-518-640-0854x123",
    ),
    ("Hotline 1-800-123-4567 Ext. 9", "1-800-123-4567 Ext. 9"),
    ("Desk 415.555.2671 X88", "415.555.2671 X88"),
    ("Telefon (USA): 345-899-3560x4587", "345-899-3560x4587"),
    (
        "Büro New York: 212-555-0147 Ext. 123",
        "212-555-0147 Ext. 123",
    ),
    (
        "{\"telefon_us\": \"(303) 499-7111 ext 42\"}",
        "(303) 499-7111 ext 42",
    ),
    ("Name;Telefon\nMiller;206-386-4636x7", "206-386-4636x7"),
];

/// `(text, value)`: both phone rules report the `+1` number with its extension.
const PLUS_ONE: [(&str, &str); 3] = [
    (
        "Call me at +1-604-696-5272x565 tomorrow.",
        "+1-604-696-5272x565",
    ),
    (
        "Rückruf unter +1 212 555 0147 ext. 31",
        "+1 212 555 0147 ext. 31",
    ),
    ("Phone: +1 (415) 555-2671 x204", "+1 (415) 555-2671 x204"),
];

/// `(text, value)`: letters without digits are no extension; the span ends before them.
const BARE: [(&str, &str); 6] = [
    ("Phone: 212-555-0147 ext (ask reception)", "212-555-0147"),
    ("Phone: 212-555-0147 x", "212-555-0147"),
    ("Telefon: 212-555-0147 Ext. bitte erfragen", "212-555-0147"),
    ("Call 415-555-2671 extension pending", "415-555-2671"),
    ("Call 415-555-2671 extra 5 minutes", "415-555-2671"),
    ("Mobile: +1 415 555 2671 x 22", "+1 415 555 2671"),
];

/// No new match: letters attached to the number, extensions without a number, failed numbers.
const SILENT: [&str; 10] = [
    "SKU 212-555-0147xl",
    "Artikelcode 212-555-0147XL",
    "Extension x4587 only",
    "Durchwahl: ext. 4587",
    "Resolution 1920x1080",
    "Phone: (111) 111-1111 x12",
    "Phone: 999-999-9999 ext. 12",
    "Phone: XXX-XXX-XXXX x123",
    "Bestellnummer 2026-104-88x12",
    "Ticket 1800-123-4567x5",
];

#[test]
fn the_validator_checks_the_number_without_its_extension() {
    for (_, value) in EXTENDED.iter().chain(&PLUS_ONE) {
        assert!(validators::unanchored_phone(value), "{value}");
    }
    // The extension digits do not count: with them this value has 19 digits.
    assert!(validators::unanchored_phone("001-518-640-0854x123456"));
    for value in [
        "(111) 111-1111 x12",
        "999-999-9999 ext. 12",
        "1-800 x1234567",
    ] {
        assert!(!validators::unanchored_phone(value), "{value}");
    }
    // Numbers without letters are checked as before.
    assert!(validators::unanchored_phone("+49 30 1234567"));
    assert!(!validators::unanchored_phone("0000000000"));
}

#[test]
fn the_extension_belongs_to_the_span() {
    for (text, value) in EXTENDED {
        for mode in MODES {
            let result = scan(text, mode);
            if mode == PiiMode::Strict {
                assert!(
                    rules(text, &result).contains(&("pii_phone_us".to_owned(), value.to_owned())),
                    "{text}: {:?}",
                    rules(text, &result)
                );
            }
            assert_eq!(
                phone_spans(&result),
                vec![value.to_owned()],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn a_plus_one_number_keeps_its_extension_in_both_rules() {
    for (text, value) in PLUS_ONE {
        for mode in MODES {
            let result = scan(text, mode);
            let found = rules(text, &result);
            for rule in ["pii_phone_international", "pii_phone_us"] {
                assert!(
                    found.contains(&(rule.to_owned(), value.to_owned())),
                    "{mode:?}: {text}: {found:?}"
                );
            }
            assert_eq!(
                phone_spans(&result),
                vec![value.to_owned()],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn a_bare_x_or_ext_ends_the_span_before_it() {
    for (text, value) in BARE {
        for mode in MODES {
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
fn an_extension_adds_no_match() {
    for text in SILENT {
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

#[test]
fn other_numbers_keep_their_span() {
    // Only a NANP number takes an extension: `+49`, `+44` and a `+1` without ten
    // digits end where they ended before.
    for (text, value) in [
        ("Telefon: +49 30 1234567 x12", "+49 30 1234567"),
        ("Fax +44 20 7946 0958 ext. 4", "+44 20 7946 0958"),
        ("Zentrale 0049 170 1234567 Durchwahl 12", "0049 170 1234567"),
    ] {
        for mode in MODES {
            let result = scan(text, mode);
            assert_eq!(
                phone_spans(&result),
                vec![value.to_owned()],
                "{mode:?}: {text}"
            );
        }
    }
    for text in ["Code +12345678x9", "Ref +1 555 0147x12"] {
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
