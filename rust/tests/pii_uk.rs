// SPDX-License-Identifier: GPL-3.0-only
//! United Kingdom identifiers (B-UK: A07, baseline P6, candidate C4).
//!
//! The NHS number carries a weighted mod-11 check digit; `pii_nhs_number_uk`
//! reports ten digits (`943 476 5919`, `943-476-5919`, `9434765919`) in every mode
//! when an NHS term stands near the value or is its key. The National Insurance
//! number (NINO) keeps its unchanged prefix/suffix validator: the field-bound rule
//! now also reads the value in pairs (`AB 12 34 56 C`), and a bare NINO in one case
//! (`AB123456C`, `hh 01 02 03 d`) is reported in `balanced`/`recall` only. A UK
//! passport number (`AB1234567`) needs a passport term near it. The UK driving
//! licence (`MORGA657054SM9IJ`: surname, date of birth, initials) is bound to a
//! licence field name in every mode and reported bare in the scored modes; its
//! form has no check digit.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const NHS: &str = "pii_nhs_number_uk";
const NINO: &str = "pii_ni_uk";
const NINO_CONTEXT_FREE: &str = "pii_ni_uk_context_free";
const PASSPORT: &str = "pii_passport_number_uk";
const LICENCE: &str = "pii_driver_license_number_uk";
const LICENCE_CONTEXT_FREE: &str = "pii_driver_license_number_uk_context_free";
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
fn nhs_number_validator_checks_the_mod_11_digit() {
    for valid in [
        "9434765919",
        "943 476 5919",
        "943-476-5919",
        "4526018155",
        "4908301662",
        "6351819091",
        "7378657972",
        "4014710491",
    ] {
        assert!(validators::uk_nhs_number(valid), "{valid}");
    }
    for invalid in [
        // last digit off by one
        "9434765918",
        "4526018156",
        "6351819090",
        // remainder 1: the check digit would be 10, never issued
        "1234567890",
        // one repeated digit passes mod 11 but is no number
        "0000000000",
        "4444444444",
        // length and alphabet
        "943476591",
        "94347659190",
        "943 476 591X",
        "943/476/5919",
    ] {
        assert!(!validators::uk_nhs_number(invalid), "{invalid}");
    }
}

#[test]
fn nino_validator_is_unchanged_and_the_context_free_one_adds_one_case() {
    for valid in [
        "AB123456C",
        "AB 12 34 56 C",
        "CE 123456 A",
        "hh 01 02 03 d",
        "tw987654a",
    ] {
        assert!(validators::uk_nino(valid), "{valid}");
        assert!(validators::uk_nino_context_free(valid), "{valid}");
    }
    for invalid in [
        "BG123456A",
        "GB123456A",
        "QQ123456C",
        "FQ 00 00 00 C",
        "UV 98 76 54 B",
        "AO123456C",
        "AB123456E",
        "AB12345C",
    ] {
        assert!(!validators::uk_nino(invalid), "{invalid}");
        assert!(!validators::uk_nino_context_free(invalid), "{invalid}");
    }
    // Mixed case passes after a field name only.
    for mixed in ["Ab123456C", "AB123456c", "hH 01 02 03 d"] {
        assert!(validators::uk_nino(mixed), "{mixed}");
        assert!(!validators::uk_nino_context_free(mixed), "{mixed}");
    }
}

#[test]
fn uk_driver_licence_validator_checks_surname_birth_date_and_initials() {
    for valid in [
        "MORGA657054SM9IJ",
        "SMIT9801015JK2CD",
        "SMITH851010AB1CD",
        // female: month plus 50
        "SMITH862310AB1CD",
        "LEE99802123JA9MN",
        "JONES710238HA3DX",
    ] {
        assert!(validators::uk_driver_license_number(valid), "{valid}");
    }
    for invalid in [
        // surname only 9s, a 9 before a letter, a digit in the surname
        "99999801015JK2CD",
        "9MITH851010AB1CD",
        "SM1TH851010AB1CD",
        // month 00, 13, 50, 63
        "SMITH800010AB1CD",
        "SMITH813010AB1CD",
        "SMITH850101AB1CD",
        "SMITH863010AB1CD",
        // day 00 and 32
        "SMITH851000AB1CD",
        "SMITH801320AB1CD",
        // check letters must be letters, lowercase is no licence form
        "SMITH851010AB112",
        "smith851010ab1cd",
        // length
        "SMITH851010AB1C",
        "SMITH851010AB1CDE",
    ] {
        assert!(!validators::uk_driver_license_number(invalid), "{invalid}");
    }
}

#[test]
fn uk_passport_validator_checks_two_letters_and_seven_digits() {
    for valid in ["AB1234567", "XY9876543", "GB1234567"] {
        assert!(validators::uk_passport_number(valid), "{valid}");
    }
    for invalid in [
        "ab1234567",
        "AB123456",
        "AB12345678",
        "ABC123456",
        "A12345678",
        "123456789",
    ] {
        assert!(!validators::uk_passport_number(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_uk_rules_have_their_label_strength_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let nhs = pattern(NHS);
    assert_eq!(nhs.entity_group, "NHS_NUMBER");
    assert_eq!(nhs.strength, ValidatorStrength::Checksum);
    assert_eq!(
        validator(nhs),
        Some(validators::uk_nhs_number as fn(&str) -> bool as usize)
    );
    assert!(nhs.requires_context && !nhs.scored_only && !nhs.captured_value);

    let nino = pattern(NINO);
    assert_eq!(
        validator(nino),
        Some(validators::uk_nino as fn(&str) -> bool as usize),
        "the field-bound NINO validator is not relaxed"
    );
    let nino_free = pattern(NINO_CONTEXT_FREE);
    assert_eq!(nino_free.entity_group, "NATIONALID");
    assert_eq!(nino_free.strength, ValidatorStrength::Format);
    assert_eq!(
        validator(nino_free),
        Some(validators::uk_nino_context_free as fn(&str) -> bool as usize)
    );
    assert!(nino_free.scored_only && !nino_free.requires_context && !nino_free.captured_value);

    let passport = pattern(PASSPORT);
    assert_eq!(passport.entity_group, "PASSPORT_NUMBER");
    assert_eq!(passport.strength, ValidatorStrength::Format);
    assert_eq!(
        validator(passport),
        Some(validators::uk_passport_number as fn(&str) -> bool as usize)
    );
    assert!(passport.requires_context && !passport.scored_only && !passport.captured_value);

    for rule_id in [LICENCE, LICENCE_CONTEXT_FREE] {
        let licence = pattern(rule_id);
        assert_eq!(licence.entity_group, "DRIVER_LICENSE_NUMBER", "{rule_id}");
        assert_eq!(licence.strength, ValidatorStrength::Format, "{rule_id}");
        assert_eq!(
            validator(licence),
            Some(validators::uk_driver_license_number as fn(&str) -> bool as usize),
            "{rule_id}"
        );
    }
    assert!(pattern(LICENCE).captured_value && !pattern(LICENCE).scored_only);
    let licence_free = pattern(LICENCE_CONTEXT_FREE);
    assert!(licence_free.scored_only && !licence_free.captured_value);

    let balanced = PiiMode::Balanced.min_score().unwrap();
    let recall = PiiMode::Recall.min_score().unwrap();
    // The farthest term still clears the balanced threshold ...
    for rule_id in [NHS, PASSPORT] {
        assert!(score::score(pattern(rule_id), Context::Support { gap: 48 }) >= balanced);
    }
    // ... a bare format value just reaches it, and a nearer counter-context term
    // drops it below the recall threshold.
    for rule_id in [NINO_CONTEXT_FREE, LICENCE_CONTEXT_FREE] {
        assert_eq!(score::rule_score(pattern(rule_id)), balanced, "{rule_id}");
        assert!(
            score::score(pattern(rule_id), Context::Counter) < recall,
            "{rule_id}"
        );
    }
}

// ── NHS number ───────────────────────────────────────────────────────────────

#[test]
fn nhs_number_with_a_term_or_key_is_reported_in_every_mode() {
    for (text, value) in [
        ("NHS number: 943 476 5919", "943 476 5919"),
        ("NHS No. 943-476-5919", "943-476-5919"),
        ("Patient NHS number 4526018155, ward 7", "4526018155"),
        ("His NHS number is 490 830 1662.", "490 830 1662"),
        ("4908301662 is her NHS number.", "4908301662"),
        (
            "National Health Service number: 635 181 9091",
            "635 181 9091",
        ),
        ("Die NHS-Nummer lautet 737 865 7972.", "737 865 7972"),
        ("NHS-Nr. 4014710491", "4014710491"),
        ("{\"nhs_number\": \"943 476 5919\"}", "943 476 5919"),
        ("<nhsNumber>4526018155</nhsNumber>", "4526018155"),
        (
            "name,nhs_number,ward\nJane Doe,635-181-9091,Ward 7",
            "635-181-9091",
        ),
        ("nhs_no=4908301662", "4908301662"),
    ] {
        assert_reports(NHS, text, value, &MODES);
    }
}

#[test]
fn nhs_number_needs_a_term_a_valid_digit_and_a_value_of_its_own() {
    for text in [
        // no NHS term
        "Call 943 476 5919 today.",
        "Reference 4526018155",
        "Bitte 490 830 1662 übernehmen.",
        // check digit fails
        "NHS number: 943 476 5918",
        "NHS-Nummer: 4526018156",
        // check digit 10 or one repeated digit
        "NHS number: 123 456 7890",
        "NHS number: 000 000 0000",
        // part of a longer number, mixed separators
        "NHS number: 943 476 5919 2",
        "NHS number: +943 476 5919",
        "NHS number: 943-476 5919",
        "NHS-Nummer: 943/476/5919",
        // a nearer counter-context term
        "NHS trust, order number 4526018155",
        "NHS-Klinik, Bestellnummer 4526018155",
    ] {
        assert_silent(text, "NHS_NUMBER", &MODES);
    }
}

#[test]
fn nhs_number_beats_an_overlapping_phone_without_phone_context() {
    let text = "NHS number: 943-476-5919";
    for mode in SCORED {
        assert!(
            spans(text, mode, "PHONE").is_empty(),
            "{mode}: the NHS term decides the label"
        );
        assert_eq!(spans(text, mode, "NHS_NUMBER").len(), 1, "{mode}");
    }
}

// ── National Insurance number ────────────────────────────────────────────────

#[test]
fn nino_after_a_field_name_in_pairs_without_spaces_and_lowercase() {
    for (text, value) in [
        ("NI number: JK 55 66 77 B", "JK 55 66 77 B"),
        (
            "Here is my National Insurance Number YZ 61 48 68 B",
            "YZ 61 48 68 B",
        ),
        ("NINO: ab123456c", "ab123456c"),
        ("National insurance no: hh 01 02 03 d", "hh 01 02 03 d"),
        ("NI No.: tw987654a", "tw987654a"),
        ("NINO AB123456C", "AB123456C"),
        (
            "Britische Sozialversicherungsnummer: ce 12 34 56 a",
            "ce 12 34 56 a",
        ),
        ("NINO: WL 304115 C", "WL 304115 C"),
    ] {
        assert_reports(NINO, text, value, &MODES);
    }
}

#[test]
fn bare_nino_in_one_case_is_reported_in_the_scored_modes_only() {
    for (text, value) in [
        ("hh 01 02 03 d", "hh 01 02 03 d"),
        ("tw987654a", "tw987654a"),
        ("AB123456C", "AB123456C"),
        ("Employee record: JK 55 66 77 B", "JK 55 66 77 B"),
        ("Mitarbeiterin PR 482917 A, Standort London", "PR 482917 A"),
    ] {
        assert_reports(NINO_CONTEXT_FREE, text, value, &SCORED);
        assert_silent(text, "NATIONALID", &[PiiMode::Strict]);
    }
    for (text, value) in [
        ("hh 01 02 03 d", "hh 01 02 03 d"),
        ("AB123456C", "AB123456C"),
    ] {
        assert_eq!(
            spans(text, PiiMode::Balanced, "NATIONALID"),
            [(value.to_owned(), 0.50)]
        );
    }
}

#[test]
fn invalid_prefixes_mixed_case_and_counter_context_stay_negative() {
    for text in [
        // prefixes and letters HMRC never issues, also after a field name
        "NINO: BG123456A",
        "National insurance number: FQ 00 00 00 C",
        "This isn't a valid national insurance number UV 98 76 54 B",
        "GB123456A",
        "QQ 12 34 56 C",
        "AB123456E",
        // mixed case without a field name
        "Ab123456C",
        "hH 01 02 03 d",
        // part of a longer token or number
        "XAB123456C",
        "AB123456C-7",
        // a nearer counter-context term
        "Order number AB123456C",
        "Bestellnummer ab123456c",
    ] {
        assert_silent(text, "NATIONALID", &MODES);
    }
}

// ── UK passport ──────────────────────────────────────────────────────────────

#[test]
fn uk_passport_number_with_a_passport_term_in_every_mode() {
    for (text, value) in [
        ("Passport number: AB1234567", "AB1234567"),
        ("Her UK passport AB1234567 expires in 2031.", "AB1234567"),
        ("My passport is XY9876543", "XY9876543"),
        (
            "Reisepass-Nr. GB1234567 (Vereinigtes Königreich)",
            "GB1234567",
        ),
        ("{\"passport_number\": \"PA4567812\"}", "PA4567812"),
    ] {
        assert_reports(PASSPORT, text, value, &MODES);
    }
    for text in [
        "AB1234567",
        "ab1234567",
        "Ticket AB1234567",
        "Passport number: AB123456",
        "Passport number: ABC123456",
        "Passport photo order number AB1234567",
    ] {
        assert_silent(text, "PASSPORT_NUMBER", &MODES);
    }
}

// ── UK driving licence ───────────────────────────────────────────────────────

#[test]
fn uk_driver_licence_after_a_licence_field_name_in_every_mode() {
    for (text, value) in [
        (
            "Driving licence number: MORGA657054SM9IJ",
            "MORGA657054SM9IJ",
        ),
        ("My driving licence is SMIT9801015JK2CD", "SMIT9801015JK2CD"),
        ("Führerscheinnummer: SMITH851010AB1CD", "SMITH851010AB1CD"),
        (
            "{\"driving_licence\": \"JONES710238HA3DX\"}",
            "JONES710238HA3DX",
        ),
    ] {
        assert_reports(LICENCE, text, value, &MODES);
    }
}

#[test]
fn bare_uk_driver_licence_is_reported_in_the_scored_modes_only() {
    for (text, value) in [
        ("MORGA657054SM9IJ", "MORGA657054SM9IJ"),
        ("Licence: MORGA607054SM9IJ ok", "MORGA607054SM9IJ"),
        ("SMITH862310AB1CD", "SMITH862310AB1CD"),
        ("Fahrer LEE99802123JA9MN, Depot Leeds", "LEE99802123JA9MN"),
    ] {
        assert_reports(LICENCE_CONTEXT_FREE, text, value, &SCORED);
        assert_silent(text, "DRIVER_LICENSE_NUMBER", &[PiiMode::Strict]);
    }
    assert_eq!(
        spans(
            "MORGA657054SM9IJ",
            PiiMode::Balanced,
            "DRIVER_LICENSE_NUMBER"
        ),
        [("MORGA657054SM9IJ".to_owned(), 0.50)]
    );
    for text in [
        "99999801015JK2CD",
        "SMITH813010AB1CD",
        "SMITH801320AB1CD",
        "morga657054sm9ij",
        "XMORGA657054SM9IJ",
        "MORGA657054SM9IJ-2",
        "Order number MORGA657054SM9IJ",
        "Driving licence number: SMITH813010AB1CD",
    ] {
        assert_silent(text, "DRIVER_LICENSE_NUMBER", &MODES);
    }
}
