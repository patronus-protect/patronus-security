// SPDX-License-Identifier: GPL-3.0-only
//! Cross-label overlap resolution in the scored modes (K07).
//!
//! In `balanced` and `recall` one value yields one label among the number labels
//! that compete for the same digits (`overlap::COMPETING_LABELS`: IBAN, card,
//! account, Steuer-ID, phone, VAT IDs of IT, FR, HR and LT). Of two overlapping findings with different labels
//! the first in this order wins: an IBAN (country code and MOD-97 prove the kind
//! of value), the longer value (a card-shaped part of an IBAN or a longer number
//! is a coincidence), context that supports its own label (a field name such as
//! `Telefon:` or `Kontonummer:`, a structural key, a nearby support term), a
//! checksum, the higher score, the earlier rule. A card-shaped part of a printed
//! IBAN form (`DE64 7172 …`) yields even when the IBAN's check digits fail. The
//! loser leaves `evidence_spans`; its `matched_rules` entry stays and names
//! `overlap` (`reason`, `yields_to`). Strict keeps both labels (decision T07);
//! labels outside the competing set keep their overlaps. Document numbers
//! (`overlap::DOCUMENT_LABELS`: passport, identity card, F08) compete with an
//! overlapping finding of any other label, since their context-free check digit
//! (7-3-1 mod 10) fits one in ten letter-led codes. Validators are not
//! relaxed: the vectors below pass or fail the checksum they name.

use std::collections::BTreeSet;
use std::path::Path;

use patronus_ark::detectors::pii::{
    overlap::{COMPETING_LABELS, DOCUMENT_LABELS},
    score::PiiMode,
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::Value;

const SCORED: [PiiMode; 2] = [PiiMode::Balanced, PiiMode::Recall];

const REASONS: [&str; 7] = [
    "iban",
    "longer_value",
    "context",
    "checksum",
    "score",
    "rule_order",
    "iban_form",
];

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

fn pii_result(text: &str, mode: PiiMode) -> SecurityScanResult {
    scan(&scanner(mode), text)
}

fn matched_rules(result: &SecurityScanResult) -> Vec<Value> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array().cloned())
        .unwrap_or_default()
}

/// `(label, text)` of every evidence span.
fn spans(text: &str, mode: PiiMode) -> Vec<(String, String)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .map(|span| (span.label, span.text))
        .collect()
}

fn owned(spans: &[(&str, &str)]) -> Vec<(String, String)> {
    spans
        .iter()
        .map(|(label, text)| (label.to_string(), text.to_string()))
        .collect()
}

/// The `overlap` object of the `matched_rules` entry of `rule_id` on `value`.
fn overlap_of(text: &str, mode: PiiMode, rule_id: &str, value: &str) -> Value {
    let rules = matched_rules(&pii_result(text, mode));
    let rule = rules
        .iter()
        .find(|rule| {
            rule["rule_id"] == rule_id
                && text.get(
                    rule["start_byte"].as_u64().unwrap() as usize
                        ..rule["end_byte"].as_u64().unwrap() as usize,
                ) == Some(value)
        })
        .unwrap_or_else(|| {
            panic!(
                "{rule_id} missing at the expected span ({} matched rules)",
                rules.len()
            )
        });
    rule["overlap"].clone()
}

/// Strict reports `label` on `value` next to the winner: the probe exercises the
/// resolution (decision T07 keeps strict bit-identical).
fn assert_strict_overlap(text: &str, label: &str, value: &str) {
    assert!(
        spans(text, PiiMode::Strict).contains(&(label.into(), value.into())),
        "strict lost {label} ({} chars in a {}-char text)",
        value.chars().count(),
        text.chars().count()
    );
}

/// Valid IBANs whose BBAN digits are a card number (Luhn plus a Maestro IIN, B-PAN):
/// strict reports a card inside them.
const IBANS_WITH_LUHN_DIGITS: [(&str, &str); 4] = [
    ("DE94 5001 0517 5401 2345 65", "5001 0517 5401 2345 65"),
    ("DE11 6005 0101 7400 1234 56", "6005 0101 7400 1234 56"),
    ("DE87 6605 0101 1002 3456 78", "6605 0101 1002 3456 78"),
    ("DE45 5005 0201 1234 5678 98", "5005 0201 1234 5678 98"),
];

/// IBAN forms whose check digits fail, with card-number BBAN digits.
const IBAN_FORMS_WITH_LUHN_DIGITS: [(&str, &str); 6] = [
    ("DE74 6009 0800 1237 8945 61", "6009 0800 1237 8945 61"),
    ("DE34 6659 4134 6836 7322 13", "6659 4134 6836 7322 13"),
    ("DE90 5007 0010 1755 2630 33", "5007 0010 1755 2630 33"),
    ("AT77 5761 4565 6741 3978", "5761 4565 6741 3978"),
    ("AT56 6000 0123 4567 8900", "6000 0123 4567 8900"),
    // Valid, but grouped IBANs outside DE are not reported yet (T05).
    ("AT29 5600 0001 2345 6785", "5600 0001 2345 6785"),
];

/// Phone numbers whose digits after `+` pass Luhn; since B-PAN no card starts after `+`.
const PHONES_WITH_LUHN_DIGITS: [(&str, &str); 4] = [
    ("+49 89 2019 4400", "49 89 2019 4400"),
    ("+49 69 3361 9496", "49 69 3361 9496"),
    ("+44 20 6642 3850", "44 20 6642 3850"),
    ("+49 89 4613 8662", "49 89 4613 8662"),
];

#[test]
fn checksum_vectors_pass_or_fail_what_they_name() {
    for (iban, digits) in IBANS_WITH_LUHN_DIGITS {
        assert!(validators::mod97(iban), "IBAN vector fails mod97");
        assert!(validators::luhn(digits), "{digits}");
    }
    for (form, digits) in IBAN_FORMS_WITH_LUHN_DIGITS {
        assert_eq!(validators::mod97(form), form.starts_with("AT29"), "{form}");
        assert!(validators::payment_card(digits), "{digits}");
    }
    for (_, digits) in IBANS_WITH_LUHN_DIGITS {
        assert!(
            validators::payment_card(digits),
            "BBAN digits of an IBAN vector fail payment_card"
        );
    }
    for (_, digits) in PHONES_WITH_LUHN_DIGITS {
        assert!(validators::luhn(digits), "{digits}");
    }
    for value in [
        "0151 2345 6789 01",
        "0157-09-316-8811",
        "4111-1111-1111-1111",
        "5555-5555-5555-4444",
    ] {
        assert!(validators::luhn(value), "{value}");
    }
    // Invalid vectors: one changed digit breaks each checksum.
    assert!(!validators::mod97("DE94 5001 0517 5401 2345 66"));
    assert!(!validators::luhn("49 89 2019 4401"));
    assert!(!validators::luhn("0151 2345 6789 02"));
}

#[test]
fn competing_labels_are_the_number_labels() {
    let labels: BTreeSet<_> = COMPETING_LABELS.into_iter().collect();
    assert_eq!(
        labels,
        BTreeSet::from([
            "AU_ABN",
            "CREDITCARD",
            "FINANCIAL_ACCOUNT_NUMBER",
            "IBAN",
            "NHS_NUMBER",
            "PHONE",
            "STEUERID",
            "VAT_ID_FR",
            "VAT_ID_HR",
            "VAT_ID_IT",
            "VAT_ID_LT",
            "VAT_ID_LV"
        ])
    );
}

/// French VAT IDs (key and SIREN) whose digits after `FR ` are also an issued
/// Steuer-ID, grouped 2-3-3-3 like the context-free Steuer-ID form.
const FR_VAT_IDS_WITH_STEUER_ID_DIGITS: [&str; 2] = ["44 796 082 147", "47 508 826 930"];

#[test]
fn a_french_vat_id_keeps_the_steuer_id_digits_inside_it() {
    // B01 review: the digits of a spaced French VAT ID can also be a context-free Steuer-ID. Like a
    // Partita IVA the VAT ID is the longer value and wins; strict reports neither (both scored-only).
    for grouped in FR_VAT_IDS_WITH_STEUER_ID_DIGITS {
        let compact: String = grouped.split(' ').collect();
        for digits in [grouped, compact.as_str()] {
            assert!(validators::steuer_id_issued(digits), "{digits}");
            let value = format!("FR {digits}");
            assert!(validators::fr_vat_id(&value), "{value}");
            let text = format!("Invoice sent to {value} yesterday.");
            assert!(
                pii_result(&text, PiiMode::Strict)
                    .evidence_spans
                    .iter()
                    .all(|span| span.label != "VAT_ID_FR" && span.label != "STEUERID"),
                "strict: {text}"
            );
            for mode in SCORED {
                assert_eq!(
                    spans(&text, mode),
                    owned(&[("VAT_ID_FR", value.as_str())]),
                    "{mode:?}"
                );
                let overlap = overlap_of(&text, mode, "pii_steuer_id_de_context_free", digits);
                assert_eq!(overlap["reason"], "longer_value", "{mode:?}: {text}");
                assert_eq!(overlap["yields_to"], "VAT_ID_FR", "{mode:?}: {text}");
            }
        }
    }
}

/// Croatian VAT IDs (OIB) whose eleven digits after `HR ` are also an issued
/// Steuer-ID.
const HR_VAT_IDS_WITH_STEUER_ID_DIGITS: [&str; 3] = ["57419348408", "32678194777", "35009487265"];

#[test]
fn a_croatian_vat_id_keeps_the_steuer_id_digits_inside_it() {
    // B02: the eleven digits of a spaced Croatian VAT ID can also be a context-free Steuer-ID. Like
    // the French VAT ID and the Partita IVA the VAT ID is the longer value and wins; strict reports
    // neither (both scored-only).
    for digits in HR_VAT_IDS_WITH_STEUER_ID_DIGITS {
        assert!(validators::steuer_id_issued(digits), "{digits}");
        let value = format!("HR {digits}");
        assert!(validators::hr_vat_id(&value), "{value}");
        let text = format!("Invoice sent to {value} yesterday.");
        assert!(
            pii_result(&text, PiiMode::Strict)
                .evidence_spans
                .iter()
                .all(|span| span.label != "VAT_ID_HR" && span.label != "STEUERID"),
            "strict: {text}"
        );
        for mode in SCORED {
            assert_eq!(
                spans(&text, mode),
                owned(&[("VAT_ID_HR", value.as_str())]),
                "{mode:?}"
            );
            let overlap = overlap_of(&text, mode, "pii_steuer_id_de_context_free", digits);
            assert_eq!(overlap["reason"], "longer_value", "{mode:?}: {text}");
            assert_eq!(overlap["yields_to"], "VAT_ID_HR", "{mode:?}: {text}");
        }
    }
}

#[test]
fn a_lithuanian_vat_id_keeps_the_card_digits_inside_it() {
    // B02: the twelve digits of a spaced Lithuanian VAT ID (temporary taxpayer) can pass the card
    // IIN, length and Luhn check. The VAT ID is the longer value and wins in the scored modes;
    // strict reports no VAT ID and keeps its card finding bit-identical.
    let digits = "621223427710";
    assert!(validators::payment_card(digits));
    let value = format!("LT {digits}");
    assert!(validators::lt_vat_id(&value), "{value}");
    let text = format!("Invoice sent to {value} yesterday.");
    assert_eq!(
        spans(&text, PiiMode::Strict),
        owned(&[("CREDITCARD", digits)]),
        "strict: {text}"
    );
    for mode in SCORED {
        assert_eq!(
            spans(&text, mode),
            owned(&[("VAT_ID_LT", value.as_str())]),
            "{mode:?}"
        );
        let overlap = overlap_of(&text, mode, "pii_credit_card", digits);
        assert_eq!(overlap["reason"], "longer_value", "{mode:?}: {text}");
        assert_eq!(overlap["yields_to"], "VAT_ID_LT", "{mode:?}: {text}");
    }
}

#[test]
fn document_labels_compete_with_every_label() {
    assert_eq!(DOCUMENT_LABELS, ["PASSPORT_NUMBER", "IDENTITY_CARD_NUMBER"]);
    for mode in SCORED {
        // The passport field name beats the bare identity card check digit ...
        let found = spans("Passport number: Y22400855", mode);
        assert_eq!(found, [("PASSPORT_NUMBER".into(), "Y22400855".into())]);
        // ... and a customer number field beats a bare passport check digit.
        let found = spans("Kundennummer K12345676", mode);
        assert_eq!(found, [("CUSTOMER_ID".into(), "K12345676".into())]);
        let rules = matched_rules(&pii_result("Kundennummer K12345676", mode));
        let loser = rules
            .iter()
            .find(|rule| rule["rule_id"] == "pii_passport_number_de_context_free")
            .unwrap();
        assert_eq!(loser["overlap"]["reason"], "context");
        assert_eq!(loser["overlap"]["yields_to"], "CUSTOMER_ID");
    }
    // Strict keeps every label and runs no context-free rule.
    assert_eq!(
        spans("Kundennummer K12345676", PiiMode::Strict),
        [("CUSTOMER_ID".into(), "K12345676".into())]
    );
}

#[test]
fn an_iban_keeps_the_luhn_valid_digits_inside_it() {
    for (iban, digits) in IBANS_WITH_LUHN_DIGITS {
        let text = format!("IBAN: {iban}");
        assert_strict_overlap(&text, "CREDITCARD", digits);
        for mode in SCORED {
            assert_eq!(spans(&text, mode), owned(&[("IBAN", iban)]), "{mode:?}");
            let overlap = overlap_of(&text, mode, "pii_credit_card", digits);
            assert_eq!(overlap["reason"], "iban", "{mode:?}");
            assert_eq!(overlap["yields_to"], "IBAN", "{mode:?}");
        }
    }
}

#[test]
fn an_iban_outranks_the_account_field_that_holds_it() {
    for (text, iban, account) in [
        (
            "Bank account: GB82WEST12345698765432",
            "GB82WEST12345698765432",
            "GB82WEST12345698765432",
        ),
        (
            "Kontonummer: DE89 3704 0044 0532 0130 00",
            "DE89 3704 0044 0532 0130 00",
            "DE89",
        ),
    ] {
        assert_strict_overlap(text, "FINANCIAL_ACCOUNT_NUMBER", account);
        for mode in SCORED {
            assert_eq!(spans(text, mode), owned(&[("IBAN", iban)]), "{mode:?}");
            let overlap = overlap_of(text, mode, "pii_financial_account_number", account);
            assert_eq!(overlap["reason"], "iban", "{mode:?}: {text}");
            assert_eq!(overlap["yields_to"], "IBAN", "{mode:?}: {text}");
        }
    }
}

#[test]
fn a_phone_number_keeps_its_digits_that_pass_luhn() {
    // B-PAN: the digits after `+` are no card in any mode, so nothing competes.
    for (phone, _) in PHONES_WITH_LUHN_DIGITS {
        let text = format!("Rückruf unter {phone}");
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            assert_eq!(spans(&text, mode), owned(&[("PHONE", phone)]), "{mode:?}");
            assert!(
                matched_rules(&pii_result(&text, mode))
                    .iter()
                    .all(|rule| rule["rule_id"] != "pii_credit_card"),
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn supporting_context_outranks_a_bare_checksum_on_the_same_value() {
    // B-PAN: Luhn-valid phone digits without a card IIN (`0151 …`, `0157 …`) are no card in
    // any mode, so the phone rule reports them without competition.
    for (text, value) in [
        ("Telefon: 0151 2345 6789 01", "0151 2345 6789 01"),
        ("Mobile: 0151 2345 6789 01", "0151 2345 6789 01"),
        (
            "The assessment is scheduled via telephone at 0157-09-316-8811.",
            "0157-09-316-8811",
        ),
        ("Rückruf bitte unter 0157-09-316-8811.", "0157-09-316-8811"),
    ] {
        assert!(!validators::payment_card(value), "{value}");
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            let found = spans(text, mode);
            assert!(
                found.iter().all(|(label, _)| label != "CREDITCARD"),
                "{mode:?}: {text}: {found:?}"
            );
        }
        for mode in SCORED {
            assert_eq!(spans(text, mode), owned(&[("PHONE", value)]), "{mode:?}");
        }
    }
    for (text, label, rule_id, value) in [
        (
            "Kontonummer: 4111-1111-1111-1111",
            "FINANCIAL_ACCOUNT_NUMBER",
            "pii_financial_account_number",
            "4111-1111-1111-1111",
        ),
        (
            "Account number: 5555-5555-5555-4444",
            "FINANCIAL_ACCOUNT_NUMBER",
            "pii_financial_account_number",
            "5555-5555-5555-4444",
        ),
    ] {
        assert_strict_overlap(text, "CREDITCARD", value);
        for mode in SCORED {
            let result = pii_result(text, mode);
            let kept: Vec<_> = result
                .evidence_spans
                .iter()
                .map(|span| (span.label.clone(), span.text.clone()))
                .collect();
            assert_eq!(kept, owned(&[(label, value)]), "{mode:?}");
            // The card scored higher (0.75); the result now reports the winner.
            assert_eq!(result.class_name, label, "{mode:?}: {text}");
            assert_eq!(
                result.confidence, result.evidence_spans[0].score,
                "{mode:?}: {text}"
            );
            assert!(
                matched_rules(&result)
                    .iter()
                    .any(|rule| rule["rule_id"] == rule_id && rule.get("overlap").is_none()),
                "{mode:?}: {text}"
            );
            let overlap = overlap_of(text, mode, "pii_credit_card", value);
            assert_eq!(overlap["reason"], "context", "{mode:?}: {text}");
            assert_eq!(overlap["yields_to"], label, "{mode:?}: {text}");
        }
    }
}

#[test]
fn card_digits_inside_an_iban_form_are_no_card() {
    for (form, digits) in IBAN_FORMS_WITH_LUHN_DIGITS {
        for text in [
            format!("IBAN: {form}"),
            format!("Wire to {form} bounced."),
            format!("{{\"iban\": \"{form}\"}}"),
        ] {
            assert_strict_overlap(&text, "CREDITCARD", digits);
            for mode in SCORED {
                let result = pii_result(&text, mode);
                assert!(
                    result.evidence_spans.is_empty(),
                    "{mode:?}: {text}: {:?}",
                    result.evidence_spans
                );
                assert_eq!(result.class_name, "safe", "{mode:?}: {text}");
                assert_eq!(result.confidence, 1.0, "{mode:?}: {text}");
                let overlap = overlap_of(&text, mode, "pii_credit_card", digits);
                assert_eq!(overlap["reason"], "iban_form", "{mode:?}: {text}");
                assert!(overlap.get("yields_to").is_none(), "{mode:?}: {text}");
            }
        }
    }
}

#[test]
fn an_account_value_at_the_start_of_an_iban_form_yields() {
    // A failing grouped IBAN under an account field: the account rule captures only the country
    // code and check digits, which start the printed form and are part of it, not an account number.
    for text in [
        "Bank account: DE00 1234 5678 9012 3456 78",
        "Account number: GB00 WEST 1234 5698 7654 32",
    ] {
        for mode in SCORED {
            let found = spans(text, mode);
            assert!(
                found
                    .iter()
                    .all(|(label, _)| label != "FINANCIAL_ACCOUNT_NUMBER"),
                "{mode:?}: {found:?}"
            );
        }
    }
}

#[test]
fn cards_outside_an_iban_form_stay_cards() {
    for text in [
        "Karte 4111 1111 1111 1111",
        "Card DE 4111 1111 1111 1111",
        "Kartennummer: 4111 1111 1111 1111 (DE12)",
        "Ref DE12-4111 1111 1111 1111",
        "Card no. 5555 5555 5555 4444 for AB12",
    ] {
        for mode in SCORED {
            let found = spans(text, mode);
            assert!(
                found.iter().any(|(label, value)| label == "CREDITCARD"
                    && (value == "4111 1111 1111 1111" || value == "5555 5555 5555 4444")),
                "{mode:?}: {text}: {found:?}"
            );
        }
    }
}

#[test]
fn separate_values_keep_their_findings() {
    let text = "Karte 4111 1111 1111 1111, IBAN DE60 5393 3633 8750 0474 39, Tel. +49 69 3361 9496";
    for mode in SCORED {
        assert_eq!(
            spans(text, mode),
            owned(&[
                ("CREDITCARD", "4111 1111 1111 1111"),
                ("IBAN", "DE60 5393 3633 8750 0474 39"),
                ("PHONE", "+49 69 3361 9496"),
            ]),
            "{mode:?}"
        );
    }
}

#[test]
fn labels_outside_the_competing_set_keep_their_overlaps() {
    let text = "Username: ada@example.com";
    for mode in SCORED {
        assert_eq!(
            spans(text, mode),
            owned(&[
                ("EMAIL", "ada@example.com"),
                ("USERNAME", "ada@example.com")
            ]),
            "{mode:?}"
        );
    }
}

#[test]
fn strict_keeps_both_labels() {
    // Decision T07: strict stays bit-identical; it never names `overlap`.
    for text in [
        "IBAN: DE94 5001 0517 5401 2345 65",
        "Bank account: GB82WEST12345698765432",
        "Rückruf unter +49 89 2019 4400",
        "IBAN: DE74 6009 0800 1237 8945 61",
    ] {
        let result = pii_result(text, PiiMode::Strict);
        assert!(
            matched_rules(&result)
                .iter()
                .all(|rule| rule.get("overlap").is_none()),
            "{text}"
        );
    }
}

#[derive(Deserialize)]
struct Row {
    text: String,
}

fn golden_texts() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/pii_l1.jsonl");
    std::fs::read_to_string(path)
        .expect("pii_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str::<Row>(line).expect("golden row").text)
        .collect()
}

/// In the scored modes no two findings of different competing labels overlap,
/// and every `overlap` entry names a reason and a surviving winner.
fn assert_resolved(scanner: &SecurityGateway, text: &str, mode: PiiMode) {
    let result = scan(scanner, text);
    let spans = &result.evidence_spans;
    for (index, a) in spans.iter().enumerate() {
        for b in &spans[index + 1..] {
            let document = |label: &str| DOCUMENT_LABELS.contains(&label);
            let competing = ((COMPETING_LABELS.contains(&a.label.as_str())
                && COMPETING_LABELS.contains(&b.label.as_str()))
                || document(&a.label)
                || document(&b.label))
                && a.label != b.label;
            assert!(
                !(competing && a.start_byte < b.end_byte && b.start_byte < a.end_byte),
                "{mode:?}: {text:?}: {} {:?} overlaps {} {:?}",
                a.label,
                a.text,
                b.label,
                b.text
            );
        }
    }
    for rule in matched_rules(&result) {
        let Some(overlap) = rule.get("overlap") else {
            continue;
        };
        let reason = overlap["reason"].as_str().unwrap_or_default();
        assert!(REASONS.contains(&reason), "{mode:?}: {text:?}: {rule}");
        let (start, end) = (
            rule["start_byte"].as_u64().unwrap() as usize,
            rule["end_byte"].as_u64().unwrap() as usize,
        );
        if reason == "iban_form" {
            continue;
        }
        let winner = overlap["yields_to"].as_str().unwrap_or_default();
        assert!(
            spans
                .iter()
                .any(|span| span.label == winner && span.start_byte < end && start < span.end_byte),
            "{mode:?}: {text:?}: {rule}: no {winner} finding"
        );
    }
}

#[test]
fn no_competing_overlap_remains_on_any_golden() {
    let texts = golden_texts();
    assert!(texts.len() > 800);
    for mode in SCORED {
        let scanner = scanner(mode);
        for text in &texts {
            assert_resolved(&scanner, text, mode);
        }
    }
}

#[derive(Deserialize)]
struct Probe {
    category: String,
    rule_id: String,
    #[serde(default)]
    overlap: Option<OverlapProbe>,
}

#[derive(Deserialize)]
struct OverlapProbe {
    de: String,
    en: String,
}

#[test]
fn bilingual_overlap_probes_keep_their_rule() {
    let probes: Vec<Probe> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let mut probed = 0;
    for probe in probes.iter().filter(|probe| probe.category == "pii") {
        let Some(overlap) = &probe.overlap else {
            continue;
        };
        assert_ne!(overlap.de, overlap.en, "translate {}", probe.rule_id);
        for text in [&overlap.de, &overlap.en] {
            let strict = pii_result(text, PiiMode::Strict);
            let labels: BTreeSet<_> = strict
                .evidence_spans
                .iter()
                .map(|span| span.label.as_str())
                .collect();
            assert!(
                labels.len() > 1,
                "{}: {text:?} has no overlap",
                probe.rule_id
            );
            for mode in SCORED {
                let scanner = scanner(mode);
                assert_resolved(&scanner, text, mode);
                let result = scan(&scanner, text);
                assert_eq!(result.evidence_spans.len(), 1, "{mode:?}: {text:?}");
                let span = &result.evidence_spans[0];
                assert!(
                    matched_rules(&result).iter().any(|rule| {
                        rule["rule_id"] == probe.rule_id.as_str()
                            && rule["start_byte"] == span.start_byte
                            && rule["end_byte"] == span.end_byte
                            && rule.get("overlap").is_none()
                    }),
                    "{mode:?}: {}: {text:?}",
                    probe.rule_id
                );
            }
        }
        probed += 1;
    }
    // Since B-PAN phone numbers have no card-shaped digits left to probe (no card after `+`
    // or without a card IIN): IBAN, generic IBAN and account remain.
    assert!(probed >= 3, "only {probed} overlap probes");
}
