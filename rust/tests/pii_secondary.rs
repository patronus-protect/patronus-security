// SPDX-License-Identifier: GPL-3.0-only
//! Secondary evidence in `strict` (T07, TRIAGE 2026-W42 bucket 4).
//!
//! Decision 2026-10-14: strict keeps emitting both labels bit-identically, but the
//! card-shaped part of a valid IBAN (`CREDITCARD` on a BBAN that is a card number) and
//! `FINANCIAL_ACCOUNT_NUMBER` on an IBAN value are secondary evidence of the IBAN.
//! `details.secondary_evidence` lists them as `{label, start_byte, end_byte, reason,
//! primary_label}` with `reason` `iban_value` (the same span as the IBAN) or `iban_part`
//! (inside it). Evaluations score primary findings only. A card or account next to an
//! IBAN, and digits inside an IBAN form whose check digits fail, stay primary. The
//! scored modes resolve these overlaps instead (K07) and list nothing. Validators are
//! not relaxed: the vectors below pass or fail the checksum they name.

use std::collections::BTreeSet;
use std::path::Path;

use patronus_ark::detectors::pii::{overlap::SECONDARY_IN_IBAN, score::PiiMode, validators};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::Value;

fn scanner(mode: PiiMode) -> SecurityGateway {
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
}

fn scan(scanner: &SecurityGateway, text: &str) -> SecurityScanResult {
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

fn strict(text: &str) -> SecurityScanResult {
    scan(&scanner(PiiMode::Strict), text)
}

/// `(label, text)` of every evidence span.
fn spans(result: &SecurityScanResult) -> Vec<(String, String)> {
    result
        .evidence_spans
        .iter()
        .map(|span| (span.label.clone(), span.text.clone()))
        .collect()
}

/// `(label, value, reason, primary_label)` of every secondary evidence entry.
fn secondary(text: &str, result: &SecurityScanResult) -> Vec<(String, String, String, String)> {
    result.layers[0]
        .details
        .get("secondary_evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| {
            let (start, end) = (
                entry["start_byte"].as_u64().unwrap() as usize,
                entry["end_byte"].as_u64().unwrap() as usize,
            );
            (
                entry["label"].as_str().unwrap().to_owned(),
                text[start..end].to_owned(),
                entry["reason"].as_str().unwrap().to_owned(),
                entry["primary_label"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn entry(label: &str, value: &str, reason: &str) -> (String, String, String, String) {
    (label.into(), value.into(), reason.into(), "IBAN".into())
}

fn owned(spans: &[(&str, &str)]) -> Vec<(String, String)> {
    spans
        .iter()
        .map(|(label, text)| (label.to_string(), text.to_string()))
        .collect()
}

/// Valid IBANs whose BBAN digits are a card number: Luhn plus an 18-digit Maestro IIN
/// (B-PAN; a BBAN without a card IIN, e.g. `4306 …` or `8415 …`, is no card).
const IBANS_WITH_LUHN_DIGITS: [(&str, &str); 6] = [
    ("DE94 5001 0517 5401 2345 65", "5001 0517 5401 2345 65"),
    ("DE11 6005 0101 7400 1234 56", "6005 0101 7400 1234 56"),
    ("DE87 6605 0101 1002 3456 78", "6605 0101 1002 3456 78"),
    ("DE45 5005 0201 1234 5678 98", "5005 0201 1234 5678 98"),
    ("DE70 5625 0030 1234 5067 86", "5625 0030 1234 5067 86"),
    ("DE06 6826 5123 3080 5169 78", "6826 5123 3080 5169 78"),
];

/// IBAN forms whose check digits fail, with card-number BBAN digits: no valid IBAN.
const IBAN_FORMS_WITH_LUHN_DIGITS: [(&str, &str); 3] = [
    ("DE74 6009 0800 1237 8945 61", "6009 0800 1237 8945 61"),
    ("DE34 6659 4134 6836 7322 13", "6659 4134 6836 7322 13"),
    ("DE90 5007 0010 1755 2630 33", "5007 0010 1755 2630 33"),
];

/// Valid IBANs under an account field name: `(text, iban, account value)`.
const IBANS_ON_ACCOUNT_FIELDS: [(&str, &str, &str); 5] = [
    (
        "Bank account: GB82WEST12345698765432",
        "GB82WEST12345698765432",
        "GB82WEST12345698765432",
    ),
    (
        "Kontonummer: GB33BUKB20201555555555",
        "GB33BUKB20201555555555",
        "GB33BUKB20201555555555",
    ),
    (
        "Account number: DE89370400440532013000",
        "DE89370400440532013000",
        "DE89370400440532013000",
    ),
    (
        "{\"kontonummer\": \"DE75512108001245126199\"}",
        "DE75512108001245126199",
        "DE75512108001245126199",
    ),
    (
        "Kontonummer: DE89 3704 0044 0532 0130 00",
        "DE89 3704 0044 0532 0130 00",
        "DE89",
    ),
];

#[test]
fn checksum_vectors_pass_or_fail_what_they_name() {
    for (iban, digits) in IBANS_WITH_LUHN_DIGITS {
        assert!(validators::mod97(iban), "IBAN vector fails mod97");
        assert!(validators::payment_card(digits), "{digits}");
    }
    for (form, digits) in IBAN_FORMS_WITH_LUHN_DIGITS {
        assert!(!validators::mod97(form), "{form}");
        assert!(validators::payment_card(digits), "{digits}");
    }
    for (_, iban, _) in IBANS_ON_ACCOUNT_FIELDS {
        assert!(
            validators::mod97(iban),
            "account-field IBAN vector fails mod97"
        );
    }
    // Invalid vectors: one changed digit breaks each checksum.
    assert!(!validators::mod97("DE94 5001 0517 5401 2345 66"));
    assert!(!validators::luhn("5001 0517 5401 2345 66"));
    // Luhn-valid BBANs without a card IIN: no card, so nothing to mark (B-PAN).
    for digits in ["4306 0967 1234 5678 00", "8415 3776 0207 7642 65"] {
        assert!(
            validators::luhn(digits) && !validators::payment_card(digits),
            "{digits}"
        );
    }
    assert!(!validators::mod97("GB82WEST12345698765433"));
}

#[test]
fn secondary_labels_are_card_and_account() {
    assert_eq!(
        SECONDARY_IN_IBAN.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from(["CREDITCARD", "FINANCIAL_ACCOUNT_NUMBER"])
    );
}

#[test]
fn card_digits_inside_a_valid_iban_are_secondary_in_strict() {
    for (iban, digits) in IBANS_WITH_LUHN_DIGITS {
        for text in [
            format!("IBAN: {iban}"),
            format!("Überweisung an {iban} erhalten."),
            format!("{{\"iban\": \"{iban}\"}}"),
        ] {
            let result = strict(&text);
            // Bit-identical: both labels stay in the evidence.
            assert_eq!(
                spans(&result),
                owned(&[("IBAN", iban), ("CREDITCARD", digits)]),
                "strict evidence of an IBAN text"
            );
            assert_eq!(
                secondary(&text, &result),
                vec![entry("CREDITCARD", digits, "iban_part")],
                "secondary marks of an IBAN text"
            );
        }
    }
}

#[test]
fn account_findings_on_an_iban_value_are_secondary_in_strict() {
    for (text, iban, account) in IBANS_ON_ACCOUNT_FIELDS {
        let result = strict(text);
        let labels = spans(&result);
        assert!(
            labels.contains(&("IBAN".into(), iban.into()))
                && labels.contains(&("FINANCIAL_ACCOUNT_NUMBER".into(), account.into())),
            "{text}: {labels:?}"
        );
        let reason = if account == iban {
            "iban_value"
        } else {
            "iban_part"
        };
        let marked = secondary(text, &result);
        assert!(
            marked.contains(&entry("FINANCIAL_ACCOUNT_NUMBER", account, reason)),
            "{text}: {marked:?}"
        );
        assert!(
            marked.iter().all(|(label, ..)| label != "IBAN"),
            "{text}: {marked:?}"
        );
    }
    // An account field on a grouped IBAN with a Luhn-valid BBAN: both are secondary.
    let text = "Bank account: DE44 5001 0517 5407 3249 31";
    assert_eq!(
        secondary(text, &strict(text)),
        vec![
            entry("FINANCIAL_ACCOUNT_NUMBER", "DE44", "iban_part"),
            entry("CREDITCARD", "5001 0517 5407 3249 31", "iban_part"),
        ]
    );
}

#[test]
fn findings_next_to_an_iban_or_in_a_failing_iban_form_stay_primary() {
    for text in [
        "Karte 4111 1111 1111 1111, IBAN DE60 5393 3633 8750 0474 39",
        "Card 4111 1111 1111 1111, IBAN DE06 6826 5123 3080 5169 78",
        "Depotnummer: DP-77120\nKontonummer: DE89370400440532013000",
        "Account number: ACC-44001234\nBank account: GB82WEST12345698765432",
    ] {
        let result = strict(text);
        let marked = secondary(text, &result);
        for span in &result.evidence_spans {
            let inside_iban = result.evidence_spans.iter().any(|iban| {
                iban.label == "IBAN"
                    && iban.start_byte <= span.start_byte
                    && span.end_byte <= iban.end_byte
            });
            let listed = marked
                .iter()
                .any(|(label, value, ..)| *label == span.label && *value == span.text);
            assert_eq!(
                listed,
                inside_iban && span.label != "IBAN",
                "{text}: {} {:?}",
                span.label,
                span.text
            );
        }
        assert!(
            result.evidence_spans.len() > marked.len() + 1,
            "{text}: the neighbour must stay primary"
        );
    }
    // No valid IBAN: strict keeps the card digits of a failing IBAN form primary.
    for (form, digits) in IBAN_FORMS_WITH_LUHN_DIGITS {
        let text = format!("IBAN: {form}");
        let result = strict(&text);
        assert_eq!(spans(&result), owned(&[("CREDITCARD", digits)]), "{text}");
        assert!(secondary(&text, &result).is_empty(), "{text}");
    }
    // One changed digit: no IBAN, no card, nothing to mark.
    let text = "IBAN: DE94 5001 0517 5401 2345 66";
    let result = strict(text);
    assert!(result.evidence_spans.is_empty(), "{:?}", spans(&result));
    assert!(secondary(text, &result).is_empty());
}

#[test]
fn strict_class_and_confidence_stay_as_before() {
    // The marker adds evidence detail only; strict findings, class and confidence
    // are those of K02.
    let result = strict("IBAN: DE94 5001 0517 5401 2345 65");
    assert_eq!(result.class_name, "IBAN");
    assert_eq!(result.confidence, 1.0);
    assert!(result.evidence_spans.iter().all(|span| span.score == 1.0));
}

#[test]
fn scored_modes_resolve_instead_of_marking() {
    for mode in [PiiMode::Balanced, PiiMode::Recall] {
        let scanner = scanner(mode);
        for text in [
            "IBAN: DE94 5001 0517 5401 2345 65",
            "Bank account: GB82WEST12345698765432",
            "Bank account: DE44 5001 0517 5407 3249 31",
        ] {
            let result = scan(&scanner, text);
            assert!(
                !result.layers[0].details.contains_key("secondary_evidence"),
                "{mode:?}: {text}"
            );
            assert!(
                result
                    .evidence_spans
                    .iter()
                    .all(|span| span.label == "IBAN"),
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn texts_without_an_iban_list_no_secondary_evidence() {
    for text in [
        "Karte: 4111 1111 1111 1111",
        "Kontonummer: ACC-44001234",
        "Mail ada@example.com",
    ] {
        let result = strict(text);
        assert!(!result.evidence_spans.is_empty(), "{text}");
        assert!(
            !result.layers[0].details.contains_key("secondary_evidence"),
            "{text}"
        );
    }
}

#[derive(Deserialize)]
struct Row {
    text: String,
    #[serde(default)]
    pii_mode: Option<String>,
}

fn golden_texts() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/pii_l1.jsonl");
    std::fs::read_to_string(path)
        .expect("pii_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str::<Row>(line).expect("golden row"))
        .filter(|row| row.pii_mode.is_none())
        .map(|row| row.text)
        .collect()
}

#[test]
fn every_secondary_entry_on_a_golden_is_a_card_or_account_inside_a_reported_iban() {
    let scanner = scanner(PiiMode::Strict);
    let mut marked = 0;
    for text in golden_texts() {
        let result = scan(&scanner, &text);
        let spans = &result.evidence_spans;
        let iban_of = |start: usize, end: usize| {
            spans.iter().find(|span| {
                span.label == "IBAN" && span.start_byte <= start && end <= span.end_byte
            })
        };
        let entries = result.layers[0]
            .details
            .get("secondary_evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in &entries {
            let label = entry["label"].as_str().unwrap();
            let (start, end) = (
                entry["start_byte"].as_u64().unwrap() as usize,
                entry["end_byte"].as_u64().unwrap() as usize,
            );
            assert!(SECONDARY_IN_IBAN.contains(&label), "{text:?}: {entry}");
            assert!(
                spans.iter().any(|span| span.label == label
                    && span.start_byte == start
                    && span.end_byte == end),
                "{text:?}: {entry} names no evidence span"
            );
            let iban = iban_of(start, end).unwrap_or_else(|| panic!("{text:?}: {entry}"));
            let reason = if (iban.start_byte, iban.end_byte) == (start, end) {
                "iban_value"
            } else {
                "iban_part"
            };
            assert_eq!(entry["reason"], reason, "{text:?}: {entry}");
            assert_eq!(entry["primary_label"], "IBAN", "{text:?}: {entry}");
        }
        // Conversely every card or account span inside a reported IBAN is listed.
        for span in spans {
            if SECONDARY_IN_IBAN.contains(&span.label.as_str())
                && iban_of(span.start_byte, span.end_byte).is_some()
            {
                assert!(
                    entries
                        .iter()
                        .any(|entry| entry["label"] == span.label.as_str()
                            && entry["start_byte"] == span.start_byte
                            && entry["end_byte"] == span.end_byte),
                    "{text:?}: {} {:?} is not marked",
                    span.label,
                    span.text
                );
                marked += 1;
            }
        }
    }
    assert!(
        marked >= 20,
        "only {marked} secondary findings on the goldens"
    );
}

#[derive(Deserialize)]
struct Probe {
    category: String,
    rule_id: String,
    #[serde(default)]
    secondary: Option<SecondaryProbe>,
}

#[derive(Deserialize)]
struct SecondaryProbe {
    de: String,
    en: String,
}

#[test]
fn bilingual_secondary_probes_mark_their_rule() {
    let probes: Vec<Probe> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let scanner = scanner(PiiMode::Strict);
    let mut probed = BTreeSet::new();
    for probe in probes.iter().filter(|probe| probe.category == "pii") {
        let Some(secondary) = &probe.secondary else {
            continue;
        };
        assert_ne!(secondary.de, secondary.en, "translate {}", probe.rule_id);
        for text in [&secondary.de, &secondary.en] {
            let result = scan(&scanner, text);
            let rules = result.layers[0].details["matched_rules"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let entries = result.layers[0].details["secondary_evidence"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert!(
                rules.iter().any(|rule| {
                    rule["rule_id"] == probe.rule_id.as_str()
                        && entries.iter().any(|entry| {
                            entry["start_byte"] == rule["start_byte"]
                                && entry["end_byte"] == rule["end_byte"]
                        })
                }),
                "{}: {text:?}: {entries:?}",
                probe.rule_id
            );
            assert!(
                result
                    .evidence_spans
                    .iter()
                    .any(|span| span.label == "IBAN"),
                "{}: {text:?}",
                probe.rule_id
            );
        }
        probed.insert(probe.rule_id.as_str());
    }
    assert_eq!(
        probed,
        BTreeSet::from(["pii_credit_card", "pii_financial_account_number"])
    );
}
