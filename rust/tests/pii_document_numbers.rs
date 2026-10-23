// SPDX-License-Identifier: GPL-3.0-only
//! German passport and identity card numbers with ICAO 9303 check digits (F08).
//!
//! Each document has its own check-digit validator (weights 7-3-1, letters
//! A=10 … Z=35), so each counts as one M3 unit. Passport serials start with
//! C, F, G, H, J or K, identity card serials with L, M, N, P, R, T, V, W, X or Y;
//! the other characters come from the ICAO alphabet without vowels and lookalikes
//! (`0-9CFGHJKLMNPRTVWXYZ`). Accepted forms: eight characters plus the check
//! digit (`F12345671`, the form presidio-analyzer and its tests use), the nine
//! character serial plus the check digit of the MRZ (`C01X00T478`,
//! `T220001293`) and the old numeric serial of ten digits (`1220001297`).
//!
//! The rules are scored-only (K05): strict stays bit-identical, where the
//! field-bound rules keep their format check (a printed nine-character serial
//! carries no check digit of its own). `balanced` and `recall` report a
//! letter-led value without a field name; the old numeric form needs a document
//! term nearby or as its key. A field-bound value of another label wins on the
//! same characters, and a nearer counter-context term drops the value.
//! Validators are never relaxed.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

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

/// `(label, text, score)` of every span.
fn spans(text: &str, mode: PiiMode) -> Vec<(String, String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .map(|span| (span.label, span.text, span.score))
        .collect()
}

fn document_spans(text: &str, mode: PiiMode) -> Vec<(String, String, f64)> {
    spans(text, mode)
        .into_iter()
        .filter(|(label, ..)| DOCUMENT_LABELS.contains(&label.as_str()))
        .collect()
}

fn pattern(rule_id: &str) -> &'static PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

const SCORED: [PiiMode; 2] = [PiiMode::Balanced, PiiMode::Recall];
const DOCUMENT_LABELS: [&str; 2] = ["PASSPORT_NUMBER", "IDENTITY_CARD_NUMBER"];

type Validator = fn(&str) -> bool;

/// Rule, label and validator of every F08 rule, in registry order.
const RULES: [(&str, &str, Validator); 4] = [
    (
        "pii_passport_number_de_context_free",
        "PASSPORT_NUMBER",
        validators::de_passport_number,
    ),
    (
        "pii_passport_number_de_legacy",
        "PASSPORT_NUMBER",
        validators::de_passport_number,
    ),
    (
        "pii_identity_card_number_de_context_free",
        "IDENTITY_CARD_NUMBER",
        validators::de_identity_card_number,
    ),
    (
        "pii_identity_card_number_de_legacy",
        "IDENTITY_CARD_NUMBER",
        validators::de_identity_card_number,
    ),
];

/// Letter-led values with a correct ICAO check digit: eight characters plus
/// the check digit, or the MRZ form (nine characters plus the check digit).
const PASSPORTS: &[&str] = &[
    "C01X00T41",
    "F12345671",
    "CZ6311T03",
    "G00000002",
    "c01234565",
    "H1J2K3L47",
    "K2L4M6N82",
    "J7T3X9V54",
    "FX93K2L58",
    "C01X00T478",
    "CF21823027",
];
const IDENTITY_CARDS: &[&str] = &[
    "L01X00T44",
    "l01x00t44",
    "LZ6311T48",
    "M3N7P9R11",
    "X12345677",
    "N7YF1F0W5",
    "TX7M4H2P1",
    "R5N8L3W90",
    "T220001293",
    "L01X00T471",
];
/// The old numeric serial (authority code, serial, check digit); both
/// documents used it, so the label comes from the context.
const LEGACY: &[&str] = &["1220001297", "3000123454"];

/// Values whose form, series or check digit fails, for both validators.
const INVALID: &[(&str, &str)] = &[
    ("C01X00T42", "check digit fails"),
    (
        "C01X00T47",
        "printed specimen serial without its check digit",
    ),
    ("F12345672", "check digit fails"),
    ("L01X00T45", "check digit fails"),
    ("T22000129", "nPA serial of 2010 without its check digit"),
    ("C01X00T479", "MRZ check digit fails"),
    ("T220001294", "MRZ check digit fails"),
    ("1220001298", "old numeric check digit fails"),
    ("0000000000", "zero serial"),
    ("B01X00T41", "B is no document series"),
    ("D12345675", "D is no document series"),
    ("C01A00T41", "A is excluded from the ICAO alphabet"),
    ("C01X00T4E", "the check digit is a digit"),
    ("C01x00T41", "mixed case"),
    ("C01X00T4", "eight characters"),
    ("C01X00T4781", "eleven characters"),
    ("122000129", "nine digits"),
    ("", "empty"),
];

#[test]
fn icao_check_digits_follow_doc_9303() {
    // ICAO Doc 9303 part 3: weights 7-3-1, digits at face value, A=10 … Z=35, `<` = 0.
    for (data, digit) in [
        ("C01X00T47", 8),
        ("T22000129", 3),
        ("L01X00T47", 1),
        ("122000129", 7),
        ("F1234567", 1),
        ("L898902C<", 3),
        ("D23145890", 7),
    ] {
        assert_eq!(validators::icao_check_digit(data), Some(digit), "{data}");
    }
    for data in ["C01X00T4-", "Ä1", "C01 X00"] {
        assert_eq!(validators::icao_check_digit(data), None, "{data}");
    }
}

#[test]
fn each_document_has_its_own_scored_only_checksum_rule() {
    for (rule, label, _) in RULES {
        let pattern = pattern(rule);
        assert_eq!(pattern.entity_group, label, "{rule}");
        assert_eq!(pattern.strength, ValidatorStrength::Checksum, "{rule}");
        assert!(pattern.scored_only, "{rule}: strict stays bit-identical");
        assert!(!pattern.captured_value, "{rule}");
        assert!(
            score::rule_score(pattern) >= PiiMode::Balanced.min_score().unwrap(),
            "{rule}"
        );
        assert!(
            score::score(pattern, Context::Counter) < PiiMode::Recall.min_score().unwrap(),
            "{rule}"
        );
    }
    // Ten bare digits with a mod-10 digit prove too little: the old form needs a term.
    let bound: Vec<_> = RULES
        .iter()
        .filter(|(rule, ..)| pattern(rule).requires_context)
        .map(|(rule, ..)| *rule)
        .collect();
    assert_eq!(
        bound,
        [
            "pii_passport_number_de_legacy",
            "pii_identity_card_number_de_legacy"
        ]
    );
    // The field-bound rules keep the format check: a printed serial has no check digit.
    for rule in ["pii_passport_number_de", "pii_identity_card_number_de"] {
        assert_eq!(pattern(rule).strength, ValidatorStrength::Format, "{rule}");
        assert!(!pattern(rule).scored_only, "{rule}");
    }
}

#[test]
fn validators_accept_check_digits_of_their_own_series() {
    for value in PASSPORTS.iter().chain(LEGACY) {
        assert!(validators::de_passport_number(value), "{value}");
    }
    for value in IDENTITY_CARDS.iter().chain(LEGACY) {
        assert!(validators::de_identity_card_number(value), "{value}");
    }
    for value in PASSPORTS {
        assert!(!validators::de_identity_card_number(value), "{value}");
    }
    for value in IDENTITY_CARDS {
        assert!(!validators::de_passport_number(value), "{value}");
    }
}

#[test]
fn validators_reject_failing_check_digits_and_forms() {
    for (value, reason) in INVALID {
        assert!(
            !validators::de_passport_number(value),
            "passport {value} ({reason})"
        );
        assert!(
            !validators::de_identity_card_number(value),
            "identity card {value} ({reason})"
        );
    }
    // The format validator of the field-bound rules is unchanged.
    assert!(validators::de_document_number("C01X00T47"));
    assert!(validators::de_document_number("T22000129"));
    assert!(!validators::de_document_number("B01X00T47"));
}

#[test]
fn strict_reports_no_bare_document_number() {
    for value in PASSPORTS.iter().chain(IDENTITY_CARDS).chain(LEGACY) {
        for text in [
            format!("Bitte {value} übernehmen."),
            format!("Personalausweis Nr. {value}"),
            format!("Pass-Nr.: {value}"),
        ] {
            assert!(document_spans(&text, PiiMode::Strict).is_empty(), "{text}");
        }
    }
}

#[test]
fn scored_modes_report_letter_led_values_without_a_field_name() {
    for mode in SCORED {
        for (label, values) in [
            ("PASSPORT_NUMBER", PASSPORTS),
            ("IDENTITY_CARD_NUMBER", IDENTITY_CARDS),
        ] {
            for value in values {
                let text = format!("Bitte {value} übernehmen.");
                assert_eq!(
                    spans(&text, mode),
                    [(label.to_string(), value.to_string(), 0.55)],
                    "{mode:?}: {text}"
                );
            }
        }
        for value in LEGACY {
            let text = format!("Bitte {value} übernehmen.");
            assert!(document_spans(&text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}

#[test]
fn pass_nr_and_document_terms_raise_the_score() {
    for (text, label, value) in [
        // Baseline P6: the presidio-analyzer DE passport test sentence.
        ("Pass-Nr.: F12345671", "PASSPORT_NUMBER", "F12345671"),
        ("Pass-Nr. C01X00T41", "PASSPORT_NUMBER", "C01X00T41"),
        ("Pass Nr: G00000002", "PASSPORT_NUMBER", "G00000002"),
        ("Reisepass-Nr. C01X00T478", "PASSPORT_NUMBER", "C01X00T478"),
        ("my passport C01X00T41", "PASSPORT_NUMBER", "C01X00T41"),
        ("Ausweis-Nr. L01X00T44", "IDENTITY_CARD_NUMBER", "L01X00T44"),
        (
            "Ausweis Nr. T220001293",
            "IDENTITY_CARD_NUMBER",
            "T220001293",
        ),
        ("ID card no. X12345677", "IDENTITY_CARD_NUMBER", "X12345677"),
    ] {
        for mode in SCORED {
            assert_eq!(
                spans(text, mode),
                [(label.to_string(), value.to_string(), 0.80)],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn a_field_bound_value_keeps_its_field_score() {
    // Field-bound (format, 0.80) and context-free (checksum, 0.80) rules report
    // the same span once.
    for mode in SCORED {
        assert_eq!(
            spans("Reisepassnummer: C01X00T41", mode),
            [("PASSPORT_NUMBER".into(), "C01X00T41".into(), 0.80)],
        );
        assert_eq!(
            spans("Personalausweis: L01X00T44.", mode),
            [("IDENTITY_CARD_NUMBER".into(), "L01X00T44".into(), 0.80)],
        );
        // A printed serial without a check digit still reports after its field name.
        assert_eq!(
            spans("Passnummer: C01X00T47", mode),
            [("PASSPORT_NUMBER".into(), "C01X00T47".into(), 0.80)],
        );
    }
}

#[test]
fn the_old_numeric_serial_needs_a_document_term_or_key() {
    for mode in SCORED {
        for (text, label) in [
            ("Personalausweis Nr. 1220001297", "IDENTITY_CARD_NUMBER"),
            (
                "Alte Ausweisnummer: 1220001297 (bis 2010)",
                "IDENTITY_CARD_NUMBER",
            ),
            (
                "{\"ausweisnummer\": \"1220001297\"}",
                "IDENTITY_CARD_NUMBER",
            ),
            ("Reisepass-Nr. 3000123454", "PASSPORT_NUMBER"),
            ("old passport number: 3000123454", "PASSPORT_NUMBER"),
        ] {
            let value = text
                .split(|ch: char| !ch.is_ascii_digit())
                .find(|part| part.len() == 10)
                .unwrap();
            assert_eq!(
                spans(text, mode),
                [(label.to_string(), value.to_string(), 0.80)],
                "{mode:?}: {text}"
            );
        }
        for text in [
            "Bitte 1220001297 übernehmen.",
            "Personalausweis Nr. 1220001298",
            "Kundennummer 1220001297",
        ] {
            assert!(document_spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}

#[test]
fn the_mrz_line_of_an_identity_card_reports_the_serial() {
    for mode in SCORED {
        assert_eq!(
            document_spans("IDD<<T220001293<<<<<<<<<<<<<<<", mode),
            [("IDENTITY_CARD_NUMBER".into(), "T220001293".into(), 0.55)],
        );
    }
}

#[test]
fn a_field_of_another_label_wins_on_the_same_characters() {
    for mode in SCORED {
        // A US-style passport value that passes the identity card check digit.
        assert!(validators::de_identity_card_number("Y22400855"));
        assert_eq!(
            document_spans("Passport number: Y22400855", mode),
            [("PASSPORT_NUMBER".into(), "Y22400855".into(), 0.80)],
        );
        assert!(validators::de_passport_number("K12345676"));
        for text in ["Kundennummer: K12345676", "Kundennummer K12345676"] {
            assert_eq!(
                spans(text, mode)
                    .into_iter()
                    .map(|(label, ..)| label)
                    .collect::<Vec<_>>(),
                ["CUSTOMER_ID"],
                "{mode:?}: {text}"
            );
        }
        // A field name of another label beats a document term after the value.
        assert!(validators::de_identity_card_number("P77991091"));
        assert_eq!(
            spans(
                "Please quote MRN P77991091 in any reply. Please quote Identity card number: L01X00T44",
                mode
            ),
            [
                ("PATIENT_ID".into(), "P77991091".into(), 0.70),
                ("IDENTITY_CARD_NUMBER".into(), "L01X00T44".into(), 0.80)
            ],
        );
    }
}

#[test]
fn a_field_that_names_another_value_keeps_a_bare_check_digit_silent() {
    // The field says what the code is: a DEA number, a codice fiscale, a driving
    // licence column. A document term or key keeps it; a key that names nothing
    // known (`Reisepass (neu): …`) counts as another field.
    assert!(validators::de_identity_card_number("RN4135883"));
    assert!(validators::de_passport_number("J34051905"));
    assert!(validators::de_identity_card_number("W68057400"));
    for mode in SCORED {
        for text in [
            "Unsere Unterlagen nennen als DEA-Nummer: RN4135883.",
            "Codice Fiscale: J34051905",
            "nr;name;dea_nummer\n1;Javier Sánchez;RN4135883",
            "row,name,driver_license_number\n1,Emily Harrison,W68057400",
            "{\"member_code\": \"J34051905\"}",
            "Referenz=W68057400",
        ] {
            assert!(document_spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
        for (text, label, value) in [
            (
                "nr;name;ausweis_nr\n1;Javier Sánchez;RN4135883",
                "IDENTITY_CARD_NUMBER",
                "RN4135883",
            ),
            (
                "row,name,passport_no\n1,Emily Harrison,J34051905",
                "PASSPORT_NUMBER",
                "J34051905",
            ),
            (
                "Reisepass Nr. (neu) J34051905",
                "PASSPORT_NUMBER",
                "J34051905",
            ),
            ("Ausweis-Nr.=RN4135883", "IDENTITY_CARD_NUMBER", "RN4135883"),
        ] {
            assert_eq!(
                document_spans(text, mode),
                [(label.to_string(), value.to_string(), 0.80)],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn a_foreign_key_keeps_an_old_numeric_serial_silent_despite_a_nearby_document_term() {
    // The old numeric serial takes a document term from proximity only when no
    // key names another value: a document term on the line before does not
    // claim the value of an unrelated key.
    assert!(validators::de_identity_card_number("1220001297"));
    assert!(validators::de_passport_number("3000123454"));
    for mode in SCORED {
        for text in [
            "passport: archived\nmember_code: 1220001297",
            "{\"passport\": \"archived\", \"member_code\": \"3000123454\"}",
            "Personalausweis: abgelaufen\nVorgang: 1220001297",
            "Reisepass: archiviert\nVorgang=3000123454",
        ] {
            assert!(document_spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
        for (text, label, value) in [
            (
                "member: archived\npassport_no: 3000123454",
                "PASSPORT_NUMBER",
                "3000123454",
            ),
            (
                "Vorgang: offen\nAusweisnummer: 1220001297",
                "IDENTITY_CARD_NUMBER",
                "1220001297",
            ),
        ] {
            assert_eq!(
                document_spans(text, mode),
                [(label.to_string(), value.to_string(), 0.80)],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn counter_context_and_values_inside_longer_tokens_stay_silent() {
    for mode in SCORED {
        for text in [
            "Bestellnummer C01X00T41",
            "Rechnungsnummer L01X00T44 bitte angeben.",
            "Order number F12345671 has shipped.",
            "Ticket number T220001293 was closed.",
            "Pfad /exports/C01X00T41/2026 archiviert.",
            "Messreihe C01X00T41-3 abgeschlossen.",
            "Artikel XC01X00T41 vergriffen.",
            "Version 2.L01X00T44 installiert.",
            "Code C01X00T41X gesperrt.",
            "Bitte C01X00T42 übernehmen.",
            "Bitte T22000129 übernehmen.",
            "Bitte C01x00T41 übernehmen.",
        ] {
            assert!(document_spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}
