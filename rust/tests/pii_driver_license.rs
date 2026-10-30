// SPDX-License-Identifier: GPL-3.0-only
//! Driver's licence numbers: German card, US state formats, Italian patente (F15).
//!
//! Three field-bound rules share one field part: a licence field name in DE, EN, IT, FR,
//! ES or NL, before the value or as its structural key (K04), with prose such as "my
//! driver's license number is" or "lautet" between them. The value decides the rule:
//! eleven characters (`pii_driver_license_number_de`), a US state format
//! (`pii_driver_license_number_us`, digit groups optionally joined by hyphens) or the
//! patente (`pii_driver_license_number_it`). No format carries a check digit, so a number
//! without a licence field name stays negative in every mode, and the validators only
//! check the form. The UK licence (B-UK) encodes surname, birth date and initials and is
//! also reported bare in `balanced`/`recall`; its rules are tested in `pii_uk.rs`.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const LABEL: &str = "DRIVER_LICENSE_NUMBER";
const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];

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

/// `(text, score)` of every driver's licence span.
fn licence_spans(text: &str, mode: PiiMode) -> Vec<(String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == LABEL)
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

/// `rule_id` reports exactly `value` as the only licence span in every mode.
fn assert_reports(rule_id: &str, text: &str, value: &str) {
    for mode in MODES {
        let found = rules(text, mode);
        assert!(
            found
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report {value:?} in {text:?}: {found:?}"
        );
        let spans = licence_spans(text, mode);
        assert_eq!(
            spans
                .iter()
                .map(|(span, _)| span.as_str())
                .collect::<Vec<_>>(),
            [value],
            "{mode}: {text:?}"
        );
    }
}

fn assert_silent(text: &str) {
    for mode in MODES {
        let spans = licence_spans(text, mode);
        assert!(
            spans.is_empty(),
            "{mode}: no licence in {text:?}: {spans:?}"
        );
    }
}

const RULES: [&str; 3] = [
    "pii_driver_license_number_de",
    "pii_driver_license_number_us",
    "pii_driver_license_number_it",
];

#[test]
fn the_three_rules_bind_a_field_name_and_check_the_form() {
    for rule_id in RULES {
        let pattern = pattern(rule_id);
        assert_eq!(pattern.entity_group, LABEL, "{rule_id}");
        assert!(pattern.captured_value, "{rule_id} binds a field name");
        assert!(
            !pattern.requires_context && !pattern.scored_only,
            "{rule_id}"
        );
        assert_eq!(pattern.strength, ValidatorStrength::Format, "{rule_id}");
        assert!(pattern.validator.is_some(), "{rule_id}");
        // A field-bound value clears the balanced threshold with its field name.
        assert!(
            score::score(pattern, Context::Field) >= 0.5,
            "{rule_id}: {}",
            score::score(pattern, Context::Field)
        );
    }
    // Registry order: the German card number keeps an eleven-character value that a
    // US format also takes (`D1234567890`).
    let position = |rule_id: &str| {
        PII_PATTERNS
            .iter()
            .position(|pattern| pattern.name == rule_id)
            .unwrap()
    };
    assert!(position(RULES[0]) < position(RULES[1]));
    assert!(position(RULES[1]) < position(RULES[2]));
}

#[test]
fn us_state_format_vectors() {
    for valid in [
        "6940579",           // 7 digits (presidio-evaluator synth)
        "2270-66-1551",      // 10 digits, hyphen groups (presidio-evaluator synth)
        "F162823540116",     // letter + 12 digits (Florida)
        "U62928788557186",   // letter + 14 digits (New Jersey)
        "H12234567",         // letter + 8 digits (presidio-analyzer test)
        "S530-460-72-345-0", // Florida, printed groups
        "D400-7836-0001",    // Illinois, printed groups
        "B6728301",          // California
        "492817365",         // New York
        "41827365",          // Texas
        "AB123456",          // two letters + digits (Ohio)
        "123AB4567",         // Iowa
        "12345678AB",        // eight digits + two letters
        "1234567A",          // seven digits + letter (Vermont)
        "AB123456C",         // two letters, six digits, letter
        "12ABC34567",        // two digits, three letters, five digits
        "WDLABCD456DG",      // Washington
        "G577-7354-469-9",   // Gretel finance, letter + 11 digits
        "26-413530-81",      // Gretel finance, 10 digits
    ] {
        assert!(validators::us_driver_license_number(valid), "{valid}");
    }
    for invalid in [
        "D123",             // letter + three digits
        "12345",            // five digits
        "123456789012345",  // fifteen digits
        "ABCDEFGH",         // letters only
        "ABC12345",         // three letters before digits
        "2031-04-30",       // ISO date (expiry)
        "30-04-2031",       // day-month-year date
        "04-30-2031",       // month-day-year date (US expiry)
        "04-30-31",         // month-day-year date, two-digit year
        "RG61031335",       // two letters + eight digits
        "B072RRE2A57",      // German card number
        "4111111111111111", // sixteen digits (card)
        "d1234567",         // lowercase
        "MORGA657054SM9IJ", // UK licence (B-UK)
    ] {
        assert!(!validators::us_driver_license_number(invalid), "{invalid}");
    }
}

#[test]
fn it_patente_vectors() {
    for valid in [
        "RM5512345K",
        "AB1234567C",
        "U1H34K56LX",
        "U1B2C3D4EF",
        "U12345678Z",
    ] {
        assert!(validators::it_driver_license_number(valid), "{valid}");
    }
    for invalid in [
        "AB123456C",   // six digits
        "AB12345678C", // eight digits
        "ab1234567c",  // lowercase
        "A11234567C",  // one letter
        "AB1234567",   // no final letter
        "U1A2345678",  // A is no paper-licence character
        "U1H34K56L9",  // final digit
        "990123456B",  // presidio-analyzer IT hard negative
        "U2H34K56LX",  // U2
    ] {
        assert!(!validators::it_driver_license_number(invalid), "{invalid}");
    }
}

#[test]
fn de_card_number_vectors_are_unchanged() {
    for valid in ["B072RRE2A57", "J0101234K56", "KO12345678X"] {
        assert!(validators::de_driver_license_number(valid), "{valid}");
    }
    for invalid in ["B072RRE2A5", "B072RRE2A57X", "B072-RRE2A57"] {
        assert!(!validators::de_driver_license_number(invalid), "{invalid}");
    }
}

#[test]
fn prose_phrasing_counts_as_field_name() {
    for (rule_id, text, value) in [
        (
            RULES[1],
            "My driver's license number is 6940579",
            "6940579",
        ),
        (
            RULES[1],
            "my driver's license number is 2270-66-1551",
            "2270-66-1551",
        ),
        (
            RULES[1],
            "My driver's license number is F162823540116",
            "F162823540116",
        ),
        (
            RULES[1],
            "The agreement is made with Vito Travaglia-Gaito, with a driver's license number of G577-7354-469-9, and his residence.",
            "G577-7354-469-9",
        ),
        (
            RULES[1],
            "Her driver’s license number is B6728301.",
            "B6728301",
        ),
        (
            RULES[1],
            "Die Führerscheinnummer lautet 6915030052.",
            "6915030052",
        ),
        (
            RULES[0],
            "Die Führerscheinnummer lautet J0101234K57.",
            "J0101234K57",
        ),
        (
            RULES[2],
            "La patente di guida è RM5512345K.",
            "RM5512345K",
        ),
    ] {
        assert_reports(rule_id, text, value);
    }
}

#[test]
fn field_names_in_every_language_bind_each_format() {
    for (rule_id, text, value) in [
        // DE field names.
        (RULES[0], "Führerschein-Nr.: B072RRE2A57", "B072RRE2A57"),
        (RULES[1], "Führerscheinnummer: T36493663", "T36493663"),
        (
            RULES[1],
            "US-Führerschein-Nr. D400-7836-0001",
            "D400-7836-0001",
        ),
        (RULES[1], "Fahrerlaubnisnummer = 492817365", "492817365"),
        (
            RULES[2],
            "Italienischer Führerschein: RM5512345K",
            "RM5512345K",
        ),
        // EN field names.
        (RULES[0], "Driving licence no.: B072RRE2A59", "B072RRE2A59"),
        (RULES[1], "Driver License Number: C28328724", "C28328724"),
        (
            RULES[1],
            "DL number: S530-460-72-345-0",
            "S530-460-72-345-0",
        ),
        (RULES[1], "Driver's License: V11227209-Hebert", "V11227209"),
        (
            RULES[1],
            "Washington driver license WDLABCD456DG",
            "WDLABCD456DG",
        ),
        (
            RULES[2],
            "Italian driving licence: U1H34K56LX",
            "U1H34K56LX",
        ),
        // IT, FR, ES, NL field names.
        (RULES[2], "Numero di patente: AB1234567C", "AB1234567C"),
        (RULES[2], "N. patente PD4401234Z", "PD4401234Z"),
        (
            RULES[1],
            "Numero di patente: C35-5710-197-76",
            "C35-5710-197-76",
        ),
        (
            RULES[1],
            "Licence de conducteur : D84-5122-431-46",
            "D84-5122-431-46",
        ),
        (
            RULES[1],
            "Numéro de permis de conduire : 41827365",
            "41827365",
        ),
        (RULES[1], "Licencia de conducir: B6728301", "B6728301"),
        (RULES[1], "Rijbewijsnummer: S38387690", "S38387690"),
        (RULES[0], "Rijbewijs J0101234K56", "J0101234K56"),
    ] {
        assert_reports(rule_id, text, value);
    }
}

#[test]
fn structural_keys_bind_each_format() {
    for (rule_id, text, value) in [
        (
            RULES[1],
            r#"{"driver_license_number": "K0472618"}"#,
            "K0472618",
        ),
        (
            RULES[1],
            "name,driver_license,email\nJane Doe,L5149233,jane@example.com",
            "L5149233",
        ),
        (
            RULES[0],
            "nr;name;fuehrerschein\n1;Jonas Weber;OI19631511K",
            "OI19631511K",
        ),
        (
            RULES[1],
            "<driver_license_number>MB6118130</driver_license_number>",
            "MB6118130",
        ),
        (
            RULES[2],
            r#"{"numero_patente": "TO7712345B"}"#,
            "TO7712345B",
        ),
        (RULES[1], "rijbewijsnummer: S3838769", "S3838769"),
    ] {
        assert_reports(rule_id, text, value);
    }
}

#[test]
fn numbers_without_a_licence_field_name_stay_negative() {
    for text in [
        // Bare values (presidio-analyzer recognizer tests): no field, no finding.
        "H12234567",
        "KO12345678X",
        "RM5512345K",
        "2270-66-1551",
        // Another field or a generic licence.
        "Order number: 41827365",
        "Bestellnummer 41827365 ist eingegangen.",
        "The licence number L4718203 belongs to a software seat.",
        "License D1234567890",
        "Lizenznummer L4718203 der Software",
        "Número de patente: 1234567",
        // A licence term without a value.
        "Driving licence since 2015, no points.",
        "Der Führerschein wurde 2019 umgetauscht.",
        "Führerscheinklasse: BE, gültig bis 2031",
        "La patente è scaduta nel 2019.",
        "Patente nautica n. 4471",
        // Values that no licence format takes.
        "Driver's license number: 2031-04-30",
        "Führerscheinnummer: 30-04-2031",
        "Driver's license number: 04-30-2031",
        "Führerscheinnummer: 04-30-2031",
        "Driver's license number: D123",
        "Driver's license number: ABCDEFGHIJ",
        "Numero di patente: U1A2345678",
        "Numero di patente: ab1234567c",
        "Numero di patente: AB-1234567-C",
        "Führerscheinnummer: B072RRE2A5",
    ] {
        assert_silent(text);
    }
}

#[test]
fn balanced_scores_follow_the_rule_base() {
    for (rule_id, text) in [
        (RULES[0], "Führerscheinnummer: B072RRE2A57"),
        (RULES[1], "My driver's license number is 6940579"),
        (RULES[2], "Numero di patente: AB1234567C"),
    ] {
        let expected = score::score(pattern(rule_id), Context::Field);
        for mode in [PiiMode::Balanced, PiiMode::Recall] {
            let spans = licence_spans(text, mode);
            assert_eq!(spans.len(), 1, "{mode}: {text}: {spans:?}");
            assert_eq!(spans[0].1, expected, "{mode}: {text}");
        }
        assert_eq!(licence_spans(text, PiiMode::Strict)[0].1, 1.0, "{text}");
    }
}

/// Q-ID: a note in parentheses between the field name and the value
/// (`Führerscheinnummer (falls relevant): …`) and a value in parentheses after the
/// field name (`la licencia de conducir (M45114072)`) keep the binding. A note with a
/// digit is no note, and the value keeps its state format.
#[test]
fn parentheses_around_note_or_value_keep_the_field_name() {
    for (text, value) in [
        (
            "10. Führerscheinnummer (falls relevant): 3330234369",
            "3330234369",
        ),
        ("Führerschein (Klasse B): B6728301", "B6728301"),
        (
            "5. Número de licencia de conducir (opcional): G37722093",
            "G37722093",
        ),
        ("Driver's license number (optional): D4007836", "D4007836"),
        (
            "como el pasaporte y la licencia de conducir (M45114072), en un bolso",
            "M45114072",
        ),
        ("a copy of your driver's licence (S38387690).", "S38387690"),
    ] {
        assert_reports(RULES[1], text, value);
    }
    for text in [
        "a valid driver's licence (ND8CD4YGQ3) is required.",
        "Führerschein (Klasse B) gültig bis 30-04-2031",
        "Driver's license (front side) scanned.",
        "Führerscheinnummer (Anlage 3): ABCDEFG",
        "driver's licence (12)",
        "Driver's license (section 4) 41827365",
    ] {
        assert_silent(text);
    }
}
