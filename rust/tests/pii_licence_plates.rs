// SPDX-License-Identifier: GPL-3.0-only
//! Licence plates (T30).
//!
//! A plate carries no check digit, and ARK keeps no district-code list (F16 stays
//! deferred): both plate rules are field-bound in every mode. They share one field
//! part, the DE/EN plate field names before the value (`Kfz-Kennzeichen:`,
//! `Number plate |`, `The Vehicle registration on file is`, `My car, registration`,
//! `My car reg is`) or as its structural key (`kennzeichen`, `license_plate`). The
//! German value may carry a hyphen before the digits (`K-MH-2476`) and the `E`/`H`
//! suffix; the UK current form (`AB51 ABC`) needs an issued age identifier. A bare
//! value without a plate term is no finding in any mode, also the TR, IN and NG
//! values of the presidio-analyzer tests.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const DE: &str = "pii_kfz_kennzeichen_de";
const UK: &str = "pii_vehicle_registration_uk";
const LABEL: &str = "LICENSEPLATE";
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

/// `(text, score)` of every plate span.
fn plates(text: &str, mode: PiiMode) -> Vec<(String, f64)> {
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

/// `rule_id` reports `value`, the only plate span, in every mode.
fn assert_reports(rule_id: &str, text: &str, value: &str) {
    for mode in MODES {
        assert!(
            rules(text, mode)
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report {value:?} in {text:?}"
        );
        let found = plates(text, mode);
        assert!(
            found.len() == 1 && found[0].0 == value,
            "{mode}: {value:?} must be the only plate in {text:?}, got {found:?}"
        );
    }
}

fn assert_silent(text: &str) {
    for mode in MODES {
        assert!(
            plates(text, mode).is_empty(),
            "{mode}: no plate expected in {text:?}"
        );
    }
}

// ── validator ────────────────────────────────────────────────────────────────

#[test]
fn de_licence_plate_validator_checks_length_and_number() {
    for valid in [
        "B-AB 1234E",
        "M XY 42",
        "K-A 778H",
        "K-MH-2476",
        "H-J-6815E",
        "FÜ-EJ 3281H",
        "KA HW 29H",
        "BÖ-GR-3108E",
        "HH-MU 4720",
        "B-A 1",
        "DO-AB 1234H",
    ] {
        assert!(validators::de_licence_plate(valid), "{valid} must be valid");
    }
    for invalid in [
        // more than eight characters without separators and suffix
        "ABC-DE 1234",
        "ABC-DE 1234E",
        "LÖW-AB 1234",
        // a number with a leading zero
        "B-AB 0123",
        "K-MH-0476",
        "M XY 0",
    ] {
        assert!(
            !validators::de_licence_plate(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn uk_vehicle_registration_validator_checks_the_age_identifier() {
    for valid in [
        // presidio-analyzer tests and its current-format range
        "AB51 ABC", "BD62XYZ", "AB02 ABC", "AB29 ABC", "AB79 ABC", "AB51-ABC",
        // ark_authored dev forms
        "LW02 ULF", "KS54 WLS", "YB68 TXM",
    ] {
        assert!(
            validators::uk_vehicle_registration(valid),
            "{valid} must be valid"
        );
    }
    for invalid in [
        // presidio-analyzer negatives: never issued area letters and age identifiers
        "IB51 ABC",
        "AQ51 ABC",
        "AB00 ABC",
        "AB80 ABC",
        // age identifiers outside 02–29 and 51–79
        "AB01 ABC",
        "AB30 ABC",
        "AB50 ABC",
        "AB99 ABC",
        // I and Q are no random letters; lowercase, short, long or mixed forms
        "AB51 IBC",
        "AB51 AQC",
        "ab51 abc",
        "AB51 AB",
        "AB51 ABCD",
        "A51 ABC",
        "AB5 ABC",
        "AB51  ABC",
        "AB51_ABC",
        "",
    ] {
        assert!(
            !validators::uk_vehicle_registration(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn plate_rules_are_field_bound_format_rules_in_every_mode() {
    for rule_id in [DE, UK] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, LABEL);
        assert!(rule.captured_value, "{rule_id} binds a field name");
        assert!(!rule.requires_context && !rule.scored_only, "{rule_id}");
        // Field bonus: both rules reach the same score in the scored modes.
        assert_eq!(score::rule_score(rule), 0.65, "{rule_id}");
        assert_eq!(rule.strength, ValidatorStrength::Format, "{rule_id}");
        assert!(rule.validator.is_some(), "{rule_id}");
    }
}

// ── German plates ────────────────────────────────────────────────────────────

#[test]
fn de_plates_with_a_hyphen_before_the_digits_and_a_suffix() {
    for (text, value) in [
        ("Kfz-Kennzeichen: AC-F-1471", "AC-F-1471"),
        ("Kennzeichen:\tE-L-3328", "E-L-3328"),
        ("Kfz-Kennzeichen: MS-DX 3004E", "MS-DX 3004E"),
        (
            "Nachtrag zu meinen Daten, Kfz-Kennzeichen HH-MU 4720.",
            "HH-MU 4720",
        ),
        (
            "Unsere Unterlagen nennen als Kennzeichen: KA HW 29H.",
            "KA HW 29H",
        ),
        (
            "Ich bestätige folgende Angabe (Kennzeichen): BÖ-GR-3108E.",
            "BÖ-GR-3108E",
        ),
        ("Als Kennzeichen ist DD-S-4934 hinterlegt.", "DD-S-4934"),
        ("Kennzeichen | H-J-6815E", "H-J-6815E"),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plates_after_english_plate_field_names_and_prose() {
    for (text, value) in [
        ("Number plate: FÜ-CB 3876", "FÜ-CB 3876"),
        ("Number plate | HH-M 2328H", "HH-M 2328H"),
        (
            "The Vehicle registration on file is MA-A 1879H.",
            "MA-A 1879H",
        ),
        (
            "My car, registration FÜ-EJ 3281H, was parked outside.",
            "FÜ-EJ 3281H",
        ),
        (
            "Our records list the Number plate as K-MH-2476.",
            "K-MH-2476",
        ),
        ("Licence plate number: F-RF-8363H", "F-RF-8363H"),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plates_under_a_structural_key() {
    for (text, value) in [
        (r#"{"kennzeichen": "K-MH-2476"}"#, "K-MH-2476"),
        (r#"{"license_plate": "F-RF-8363H"}"#, "F-RF-8363H"),
        (r#"{"kfzKennzeichen": "BÖ-GR-3108E"}"#, "BÖ-GR-3108E"),
        ("<numberPlate>DD-S-4934</numberPlate>", "DD-S-4934"),
        (
            "nr;name;kennzeichen\n1;Jonas Weber;HH AW 7914H",
            "HH AW 7914H",
        ),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plates_keep_the_existing_forms() {
    for (text, value) in [
        ("KFZ-Kennzeichen: B-AB 1234E", "B-AB 1234E"),
        ("Vehicle registration M XY 42", "M XY 42"),
        ("Nummernschild: K-A 778H", "K-A 778H"),
        (
            "Mein Wagen mit dem Kennzeichen BN-Y 2890 stand vor dem Haus.",
            "BN-Y 2890",
        ),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plate_lookalikes_stay_silent() {
    for text in [
        // bare values and other field names
        "K-MH-2476",
        "Bestellnummer: AB-CD-1234",
        "Order number: K-MZ-2471",
        "Parkplatz B-AB 1234E",
        // words after the field name, too many digits, too long a prefix
        "Das Kennzeichen ist am 12. Mai abgelaufen.",
        "Kennzeichen: K-MZ-24710",
        "Kennzeichen: BERLIN-123",
        "Kennzeichen: B-12 345",
        "Kennzeichen: ABC-DE 1234",
        "Kennzeichen: B-AB 0123",
        // a lowercase value is no printed plate
        "Kennzeichen: ab-cd 12",
        // a generic registration number names no plate
        "Registration number: K-MH-2476",
    ] {
        assert_silent(text);
    }
}

// ── UK plates ────────────────────────────────────────────────────────────────

#[test]
fn uk_plates_after_plate_field_names_and_prose() {
    for (text, value) in [
        ("The Vehicle registration on file is LW02 ULF.", "LW02 ULF"),
        (
            "My car, registration YB68 TXM, was parked outside.",
            "YB68 TXM",
        ),
        // presidio-analyzer test case
        ("My car reg is AB51 ABC and it expires", "AB51 ABC"),
        ("Number plate | BD62XYZ", "BD62XYZ"),
        ("Kennzeichen: LW02 ULG", "LW02 ULG"),
        ("Car registration number: KS54 WLS", "KS54 WLS"),
    ] {
        assert_reports(UK, text, value);
    }
}

#[test]
fn uk_plates_under_a_structural_key() {
    for (text, value) in [
        (r#"{"license_plate": "KS54 WLS"}"#, "KS54 WLS"),
        (r#"{"licensePlate": "KS54 WLT"}"#, "KS54 WLT"),
        (r#"{"kennzeichen": "LW02 ULF"}"#, "LW02 ULF"),
        ("row,name,license_plate\n1,Ada Weber,YB68 TXM", "YB68 TXM"),
    ] {
        assert_reports(UK, text, value);
    }
}

#[test]
fn uk_plate_lookalikes_stay_silent() {
    for text in [
        // presidio-analyzer values: bare, also the valid ones, and its negatives
        "AB51 ABC",
        "BD62XYZ",
        "IB51 ABC",
        "AQ51 ABC",
        "AB00 ABC",
        "AB80 ABC",
        // invalid forms after a plate field name
        "Vehicle registration: AB80 ABC",
        "Number plate: IB51 ABC",
        "Licence plate: AB51 ABCD",
        // other field names
        "Order number: AB51 ABC",
        "Bestellnummer: AB51 ABC",
        "My car registration is overdue.",
    ] {
        assert_silent(text);
    }
}

#[test]
fn bare_plates_of_other_countries_stay_silent() {
    // presidio_favored TR, IN, NG and UK prefix/suffix values (T27 open: no rule).
    for text in [
        "34 ABC 1234",
        "34ABC1234",
        "07 AB 123",
        "KA53ME3456",
        "MN2412",
        "APP-456CV",
        "ABJ-001AA",
        "Plates: APP-456CV and KJA-999PZ",
        "A123 BCD",
        "K1 ABC",
        "ABC 1D",
    ] {
        assert_silent(text);
    }
}
