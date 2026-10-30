// SPDX-License-Identifier: GPL-3.0-only
//! Passport and identity card numbers by field name (B-PASS: T24, A05, B08, T10,
//! baseline P6).
//!
//! `pii_passport_number_field` reports six to nine letters and digits, at least five
//! digits, right after an explicit passport field name (EN/DE/ES/FR/IT/NL) in every
//! mode. Format only: one letter and exactly six digits is no passport form, a value
//! in German passport form must pass its ICAO 9303 check digit, one repeated digit and
//! a run of seven ascending digits are placeholders. With a document term near the
//! value or as its key: the US letter form (one letter, eight digits), the Austrian and
//! Swiss passport and identity card (one letter, seven digits), the Italian carta
//! d'identità and the Spanish pasaporte (three letters, six digits).

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const FIELD: &str = "pii_passport_number_field";
const US: &str = "pii_passport_number_us";
const AT_CH: &str = "pii_passport_number_at_ch";
const ID_AT_CH: &str = "pii_identity_card_number_at_ch";
const ID_IT: &str = "pii_identity_card_number_it";
const ES: &str = "pii_passport_number_es";
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

/// Texts of every span with `label`.
fn spans(text: &str, mode: PiiMode, label: &str) -> Vec<String> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == label)
        .map(|span| span.text)
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

/// `rule_id` reports `value`, the only span of its label, in every mode.
fn assert_reports(rule_id: &str, text: &str, value: &str) {
    let label = pattern(rule_id).entity_group;
    for mode in MODES {
        assert!(
            rules(text, mode)
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report {value} in {text:?}"
        );
        assert_eq!(
            spans(text, mode, label),
            [value],
            "{mode}: {value} must be the only {label} span in {text:?}"
        );
    }
}

fn assert_silent(text: &str, label: &str) {
    for mode in MODES {
        assert!(
            spans(text, mode, label).is_empty(),
            "{mode}: no {label} expected in {text:?}"
        );
    }
}

// ── validators ───────────────────────────────────────────────────────────────

#[test]
fn field_validator_checks_the_passport_form() {
    for valid in [
        "S17933286",
        "X45929398",
        "AAA482913",
        "SG9943897",
        "NZ137286",
        "O0606527",
        "621475562",
        "48291366",
        "07RY12580",
        // German passport form with a valid ICAO 9303 check digit
        "F48291366",
    ] {
        assert!(validators::passport_number_field(valid), "{valid}");
    }
    for invalid in [
        // one letter and exactly six digits
        "A482913",
        "K482913",
        // German passport form, ICAO 9303 check digit fails
        "F48291367",
        "C01X00T42",
        // letters inside the digits outside the French form (the German
        // rules read `C01X00T41`)
        "482913X7",
        "C01X00T41",
        "C01X00T4E",
        "M123A4567",
        // placeholders: one repeated digit, seven ascending digits
        "777777777",
        "A00000000",
        "12345678",
        "D12345675",
        // too few digits, too short, too long, lower case
        "ABCD1234",
        "48291",
        "4829136601",
        "x45929398",
    ] {
        assert!(!validators::passport_number_field(invalid), "{invalid}");
    }
}

#[test]
fn document_validators_check_their_country_forms() {
    for valid in ["A12803456", "Z90381274", "S17933286", "F48291366"] {
        assert!(validators::us_passport_number(valid), "{valid}");
    }
    for invalid in [
        "A1280345",
        "AB2803456",
        "128034567",
        "a12803456",
        "A11111111",
        "A12345678",
        "C48291036",
    ] {
        assert!(!validators::us_passport_number(invalid), "{invalid}");
    }
    for valid in ["P4366918", "X0217453", "E3092741"] {
        assert!(validators::letter_seven_digits(valid), "{valid}");
    }
    for invalid in ["P436691", "P43669181", "PA366918", "p4366918", "P4444444"] {
        assert!(!validators::letter_seven_digits(invalid), "{invalid}");
    }
    for valid in ["CA48213EF", "CB90217KD", "AY4417825"] {
        assert!(validators::it_identity_card_number(valid), "{valid}");
    }
    for invalid in [
        "CA4821EF",
        "CA48213E",
        "C148213EF",
        "ca48213ef",
        "CA00000EF",
    ] {
        assert!(!validators::it_identity_card_number(invalid), "{invalid}");
    }
    for valid in ["PAA482913", "XDA902174", "AAA123456"] {
        assert!(validators::es_passport_number(valid), "{valid}");
    }
    for invalid in ["PA4829136", "PAA48291", "paa482913", "PAA000000"] {
        assert!(!validators::es_passport_number(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_passport_rules_have_their_label_strength_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let field = pattern(FIELD);
    assert_eq!(field.entity_group, "PASSPORT_NUMBER");
    assert_eq!(field.strength, ValidatorStrength::Format);
    assert_eq!(
        validator(field),
        Some(validators::passport_number_field as fn(&str) -> bool as usize)
    );
    assert!(field.captured_value && !field.requires_context && !field.scored_only);
    for (rule_id, label, check) in [
        (
            US,
            "PASSPORT_NUMBER",
            validators::us_passport_number as fn(&str) -> bool,
        ),
        (AT_CH, "PASSPORT_NUMBER", validators::letter_seven_digits),
        (
            ID_AT_CH,
            "IDENTITY_CARD_NUMBER",
            validators::letter_seven_digits,
        ),
        (
            ID_IT,
            "IDENTITY_CARD_NUMBER",
            validators::it_identity_card_number,
        ),
        (ES, "PASSPORT_NUMBER", validators::es_passport_number),
    ] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, label, "{rule_id}");
        assert_eq!(rule.strength, ValidatorStrength::Format, "{rule_id}");
        assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
        assert!(
            rule.requires_context && !rule.scored_only && !rule.captured_value,
            "{rule_id}"
        );
    }
}

// ── generic passport field name ──────────────────────────────────────────────

#[test]
fn a_passport_field_name_binds_the_value_in_every_mode() {
    for (text, value) in [
        ("Passport Number: S17933286", "S17933286"),
        (
            "Witness: Darusman Ratulangi (Passport No. SG9943897)",
            "SG9943897",
        ),
        (
            "Passport_number 621475562, a customer reference",
            "621475562",
        ),
        ("{\"passport_number\": \"X45929398\"}", "X45929398"),
        ("my travel passport is A12803456", "A12803456"),
        ("Reisepassnummer: O0606527", "O0606527"),
        (
            "Bitte führen Sie Ihren Reisepass (D5832368) mit.",
            "D5832368",
        ),
        ("Pass-Nr.: S17933286", "S17933286"),
        ("Mi pasaporte es AAA482913", "AAA482913"),
        (
            "le passeport numéro 07RY12580 doit être présenté.",
            "07RY12580",
        ),
        (
            "Avviso: presentare passaporto n. M0572847 e tessera.",
            "M0572847",
        ),
        ("Paspoortnummer: NX4127095", "NX4127095"),
    ] {
        assert_reports(FIELD, text, value);
    }
}

#[test]
fn a_passport_field_name_does_not_make_any_value_a_passport_number() {
    for text in [
        // the holdout shape (run 20261022T171514Z): one letter and exactly six digits
        "Passport number: A482913",
        "passport number B740261",
        "Reisepassnummer: K482913",
        "Número de pasaporte: B740261",
        // German passport form whose ICAO check digit fails
        "Passport no. F48291367",
        "Pass-Nr.: G48291366",
        "Passport no. C01X00T42",
        // placeholders and other shapes
        "Passport no. 777777777",
        "My passport is 12345678",
        "Passport no. D12345675",
        "Passport number: 482913X7",
        "Pass-Nr.: 1234567890",
        "Passport no. 4829",
        "Passport photo 48291366 attached.",
        "Kompass 4829136 eingetroffen.",
        "Passport no. 48291366-2",
    ] {
        assert_silent(text, "PASSPORT_NUMBER");
    }
}

// ── country forms with a document term ───────────────────────────────────────

#[test]
fn country_forms_need_a_document_term() {
    for (rule_id, text, value) in [
        (US, "US passport Z12803456 expires in 2031.", "Z12803456"),
        (
            US,
            "name,passport,nationality\nJane Doe,A48291036,American",
            "A48291036",
        ),
        (US, "Der US-Reisepass A48291036 ist gültig.", "A48291036"),
        (
            AT_CH,
            "Austrian passport P4366918 issued in Vienna.",
            "P4366918",
        ),
        (AT_CH, "Der Reisepass S0418362 ist abgelaufen.", "S0418362"),
        (
            ID_AT_CH,
            "Identitätskarte E3092741, Kanton Bern.",
            "E3092741",
        ),
        (ID_AT_CH, "Her identity card C3810467 is valid.", "C3810467"),
        (ID_IT, "Carta d'identità n. CA48213EF", "CA48213EF"),
        (
            ID_IT,
            "Italian identity card CA48213EF issued in Rome.",
            "CA48213EF",
        ),
        (ES, "El pasaporte PAA482913 caduca en 2031.", "PAA482913"),
        (
            ES,
            "Spanish passport PAA482913 issued in Madrid.",
            "PAA482913",
        ),
    ] {
        assert_reports(rule_id, text, value);
    }
    for (text, label) in [
        ("Order A48291036 has shipped.", "PASSPORT_NUMBER"),
        ("US passport A00000000", "PASSPORT_NUMBER"),
        ("Reisepass (USA): C48291036", "PASSPORT_NUMBER"),
        ("Bestellung P4366918 ist eingegangen.", "PASSPORT_NUMBER"),
        ("Swiss passport P4366918/2", "PASSPORT_NUMBER"),
        ("Invoice E3092741 is due.", "IDENTITY_CARD_NUMBER"),
        ("Identity card e3092741", "IDENTITY_CARD_NUMBER"),
        ("Ordine CA48213EF spedito.", "IDENTITY_CARD_NUMBER"),
        ("Carta d'identità CA00000EF", "IDENTITY_CARD_NUMBER"),
        ("Pedido PAA482913 enviado.", "PASSPORT_NUMBER"),
        ("Spanish passport paa482913", "PASSPORT_NUMBER"),
    ] {
        assert_silent(text, label);
    }
}
