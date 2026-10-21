// SPDX-License-Identifier: GPL-3.0-only
//! Payment card precision (B-PAN = T19 + F02, TRIAGE 2026-W43 bucket 4, baseline N1/P8).
//!
//! On Gretel Finance most card FP were the digits after the `+` of a phone number
//! (`+[44 20 1234 5678]`), EDIFACT/SWIFT date-time stamps (`DTM+137:[202201010800]`,
//! `20220314-123456`) and the digit segments of tokens (`xoxb-…-485275870833-…`); on the
//! synthetic set ZA ID numbers and KR resident registration numbers that pass Luhn, on the
//! presidio-analyzer tests `1748503543012`. A card now needs the IIN prefix and a length of
//! its brand ([`validators::CARD_IIN_RANGES`]) besides Luhn, in every mode, so the
//! context-free card of `balanced` passes the same table. Luhn itself is unchanged.

use std::path::Path;

use patronus_ark::detectors::pii::{
    score::PiiMode,
    validators::{self, card_brand, payment_card, CardBrand, CARD_IIN_RANGES},
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;

const MODES: [PiiMode; 2] = [PiiMode::Strict, PiiMode::Balanced];

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

fn cards(text: &str, mode: PiiMode) -> Vec<String> {
    scan(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == "CREDITCARD")
        .map(|span| span.text)
        .collect()
}

/// `(brand, Luhn-valid number)` at the edges of every IIN range and length of the table.
const BRAND_VECTORS: [(CardBrand, &str); 30] = [
    (CardBrand::AmericanExpress, "347314925860733"),
    (CardBrand::AmericanExpress, "377314925860736"),
    (CardBrand::DinersClub, "30073149258601"),
    (CardBrand::DinersClub, "3057314925860731492"),
    (CardBrand::DinersClub, "30957314925863"),
    (CardBrand::DinersClub, "36731492586076"),
    (CardBrand::DinersClub, "3873149258607319"),
    (CardBrand::DinersClub, "3973149258607314920"),
    (CardBrand::Jcb, "3573149258607312"),
    (CardBrand::Jcb, "3589731492586073144"),
    (CardBrand::Jcb, "180073149258609"),
    (CardBrand::Jcb, "213173149258608"),
    (CardBrand::Mir, "2200731492586072"),
    (CardBrand::Mir, "2204731492586073141"),
    (CardBrand::Mastercard, "2221731492586077"),
    (CardBrand::Mastercard, "2720731492586073"),
    (CardBrand::Mastercard, "5173149258607311"),
    (CardBrand::Mastercard, "5573149258607317"),
    (CardBrand::Visa, "4731492586074"),
    (CardBrand::Visa, "4731492586073147"),
    (CardBrand::Visa, "4731492586073149253"),
    (CardBrand::Discover, "6011731492586072"),
    (CardBrand::Discover, "6447314925860739"),
    (CardBrand::Discover, "6497314925860731497"),
    (CardBrand::Discover, "6573149258607315"),
    (CardBrand::UnionPay, "6273149258607318"),
    (CardBrand::UnionPay, "6273149258607314922"),
    (CardBrand::Maestro, "507314925862"),
    (CardBrand::Maestro, "6973149258607314927"),
    (CardBrand::Uatp, "173149258607312"),
];

/// Luhn-valid numbers outside the table: a known prefix with a length of no brand, or a
/// prefix next to a range.
const NO_BRAND: [(&str, &str); 14] = [
    ("Amex has 15 digits", "3473149258607313"),
    ("diners range ends at 305", "30673149258608"),
    ("JCB 35 has 16-19 digits", "357314925860730"),
    ("JCB 1800 has 15 digits", "1800731492586078"),
    ("Mir ends at 2204", "2205731492586077"),
    ("Mastercard 2-series ends at 2720", "2721731492586072"),
    ("Mastercard 51-55 has 16 digits", "557314925860738"),
    ("Visa has 13, 16 or 19 digits", "47314925860736"),
    ("Visa has 13, 16 or 19 digits", "473149258607319"),
    ("UATP has 15 digits", "1731492586073143"),
    ("no brand starts with 7", "7073149258607318"),
    ("no brand starts with 8", "8731492586073148"),
    ("no brand starts with 9", "9731492586073146"),
    ("no brand starts with 33", "3373149258607314"),
];

#[test]
fn every_brand_range_is_tested_at_its_edges() {
    for range in CARD_IIN_RANGES {
        assert_eq!(range.low.len(), range.high.len(), "{range:?}");
        assert!(range.low <= range.high, "{range:?}");
        assert!(!range.lengths.is_empty(), "{range:?}");
        assert!(
            range
                .lengths
                .iter()
                .all(|length| (12..=19).contains(length)),
            "{range:?}: Luhn accepts 12-19 digits"
        );
        assert!(
            BRAND_VECTORS
                .iter()
                .any(|(brand, number)| *brand == range.brand
                    && (number.starts_with(range.low) || number.starts_with(range.high))),
            "{range:?} has no vector"
        );
    }
    let brands: std::collections::BTreeSet<_> = CARD_IIN_RANGES
        .iter()
        .map(|range| format!("{:?}", range.brand))
        .collect();
    assert_eq!(brands.len(), 10, "{brands:?}");
}

#[test]
fn brand_vectors_pass_luhn_and_the_table() {
    for (brand, number) in BRAND_VECTORS {
        assert!(validators::luhn(number), "{number}");
        assert_eq!(card_brand(number), Some(brand), "{number}");
        assert!(payment_card(number), "{number}");
        // Separators do not change the brand or the length.
        let grouped = number
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(card_brand(&grouped), Some(brand), "{grouped}");
        assert!(payment_card(&grouped), "{grouped}");
    }
}

#[test]
fn luhn_valid_numbers_outside_the_table_are_no_card() {
    for (reason, number) in NO_BRAND {
        assert!(validators::luhn(number), "{number}: Luhn is unchanged");
        assert_eq!(card_brand(number), None, "{number}: {reason}");
        assert!(!payment_card(number), "{number}: {reason}");
    }
}

#[test]
fn a_failing_luhn_sum_is_no_card_for_any_brand() {
    for (_, number) in BRAND_VECTORS {
        let last = number.as_bytes()[number.len() - 1] - b'0';
        let broken = format!("{}{}", &number[..number.len() - 1], (last + 1) % 10);
        assert!(!validators::luhn(&broken), "{broken}");
        assert!(
            card_brand(&broken).is_some(),
            "{broken}: the table only looks at the IIN"
        );
        assert!(!payment_card(&broken), "{broken}");
    }
    for value in ["4111 1111 1111 1112", "5555 5555 5555 4445"] {
        assert!(!payment_card(value), "{value}");
    }
}

/// 13 digits that open with a valid YYMMDD birth date and pass Luhn: ZA ID numbers and KR
/// resident registration numbers with a Visa or Maestro prefix.
const BIRTH_DATE_IDS: [&str; 9] = [
    "4506095123081",
    "6804114321085",
    "6109240123185",
    "4901015009082",
    "5708151234088",
    "470312-1081835",
    "640918-2196672",
    "590724-1069401",
    "450630-2848967",
];

#[test]
fn birth_date_ids_and_time_stamps_are_no_card() {
    for value in BIRTH_DATE_IDS {
        assert!(validators::luhn(value), "{value}");
        assert!(
            card_brand(value).is_some(),
            "{value}: Visa or Maestro prefix"
        );
        assert!(!payment_card(value), "{value}");
    }
    // Stamps that open with YYYYMMDD; the UATP-shaped one has a brand.
    for value in [
        "202201010800",
        "20220314-123456",
        "20220413123456",
        "199912312359596",
    ] {
        assert!(validators::luhn(value), "{value}");
        assert!(!payment_card(value), "{value}");
    }
    assert_eq!(card_brand("199912312359596"), Some(CardBrand::Uatp));
    // 13-digit cards whose first six digits are no date stay cards (presidio-evaluator gold).
    for value in [
        "4047737215142",
        "4563824065059",
        "4934106496652",
        "4731492586074",
    ] {
        assert!(payment_card(value), "{value}");
    }
}

/// Hard negatives with their DE and EN frame: the card rule reports nothing in any mode.
/// Provider-shaped tokens are assembled with `concat!` so that no literal token is committed.
const HARD_NEGATIVES: [&str; 18] = [
    "Kontaktnummer: +44 20 1234 5678",
    "Phone: +44 20 1234 5678",
    "- Kontaktnummer: +49 123 456 7890",
    "Call us at +49 123 456 7890.",
    "Rückruf unter +63 917 123 4565",
    "Mobile: +63 917 123 4565",
    "PER*PI*John Doe*TE*+491234567890",
    "Belegdatum: DTM+137:202201010800'",
    "Message date: DTM+137:202201010800'",
    "Handels-ID: 20220314-123456-ABC",
    "\"TradeID\": \"20220314-123456-ABC-IBK\"",
    concat!(
        "Slack-Token: xox",
        "b-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL"
    ),
    concat!(
        ":32A:xox",
        "b-997605677177-485275870833-t2VJdhdgBlIo58gou6ZuqmoL"
    ),
    concat!(
        "<ApplicationReference>xox",
        "b-190859546532-444400602512-VFj9zu3edjQez6RY4UOFZnzi</ApplicationReference>"
    ),
    "Paketversion: pkg-507314925862-485275870833-amd64",
    "Südafrikanische ID-Nummer: 4506095123081",
    "Resident Registration Number: 590724-1069401",
    "1748503543012",
];

#[test]
fn hard_negatives_have_no_card_in_any_mode() {
    for text in HARD_NEGATIVES {
        for mode in MODES {
            assert_eq!(cards(text, mode), Vec::<String>::new(), "{mode:?}: {text}");
        }
    }
}

#[test]
fn digits_after_a_plus_are_no_card_sub_span() {
    // Neither the whole run nor a part of it: the card match after `+` is dropped, and
    // the search resumes behind it.
    for text in [
        "+44 20 1234 5678",
        "+49 123 456 7890",
        "+63 917 123 4565",
        "+6011 7314 9258 6072",
    ] {
        assert!(validators::luhn(text), "{text}");
        for mode in MODES {
            assert!(cards(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}

/// `(text, card)`: the card span stays exactly `card` in every mode.
const KEPT: [(&str, &str); 14] = [
    ("Diners Club: 3673 149258 6076", "3673 149258 6076"),
    ("Maestro: 507314925862", "507314925862"),
    ("Mir-Karte: 2200 7314 9258 6072", "2200 7314 9258 6072"),
    ("Kartennummer: 2221731492586077", "2221731492586077"),
    ("Card number: 2720-7314-9258-6073", "2720-7314-9258-6073"),
    ("UnionPay 6273149258607314922", "6273149258607314922"),
    (
        "JCB card number: 3589 7314 9258 6073 144",
        "3589 7314 9258 6073 144",
    ),
    ("Amex 3773 149258 60736", "3773 149258 60736"),
    (
        "It was charged to 6011 7314 9258 6072.",
        "6011 7314 9258 6072",
    ),
    ("Card: 4111 1111 1111 1111", "4111 1111 1111 1111"),
    (
        "Tel. +49 30 1234567, Karte 5555 5555 5555 4444",
        "5555 5555 5555 4444",
    ),
    ("Ref DE12-4111 1111 1111 1111", "4111 1111 1111 1111"),
    ("card_number=4111111111111111", "4111111111111111"),
    ("|911|2241670869124334|", "2241670869124334"),
];

#[test]
fn cards_of_every_brand_stay_found() {
    for (text, card) in KEPT {
        for mode in MODES {
            assert_eq!(
                cards(text, mode),
                vec![card.to_string()],
                "{mode:?}: {text}"
            );
        }
    }
}

#[derive(Deserialize)]
struct Entity {
    label: String,
    text: String,
}

#[derive(Deserialize)]
struct Row {
    entities: Vec<Entity>,
}

#[test]
fn every_luhn_valid_card_of_the_goldens_passes_the_table() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/pii_l1.jsonl");
    let mut checked = 0;
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let row: Row = serde_json::from_str(line).unwrap();
        for entity in row
            .entities
            .iter()
            .filter(|entity| entity.label == "CREDITCARD")
        {
            let digits: String = entity.text.chars().filter(char::is_ascii_digit).collect();
            if validators::luhn(&digits) {
                assert!(payment_card(&digits), "{}", entity.text);
                checked += 1;
            }
        }
    }
    assert!(checked >= 60, "only {checked} Luhn-valid golden cards");
}
