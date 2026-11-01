// SPDX-License-Identifier: GPL-3.0-only
//! Vehicle, securities, legal entity and pharmaceutical identifiers (B-FIN).
//!
//! The VIN (`VIN`, ISO 3779) is seventeen characters without `I`, `O` and `Q`,
//! the last four digits; North American VINs carry a check digit in the ninth
//! place (`pii_vin`), European VINs none (`pii_vin_format`). The ISIN (`ISIN`,
//! ISO 6166) ends in a Luhn digit over its expanded letters, the LEI (`LEI`,
//! ISO 17442) in two MOD 97-10 check digits, the PZN (`DE_PZN`) in a mod-11
//! digit weighted 1 to 7. Every rule reports a value only with a term of its
//! label near it or as its key, in every mode: each check passes one random
//! value in ten or eleven.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const VIN: &str = "pii_vin";
const VIN_FORMAT: &str = "pii_vin_format";
const ISIN: &str = "pii_isin";
const LEI: &str = "pii_lei";
const PZN: &str = "pii_pzn_de";
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
fn vin_validators_check_the_form_and_the_north_american_check_digit() {
    for valid in [
        "1HGCM82633A004352",
        "1M8GDM9AXKP042788",
        "JH4KA7561PC008269",
        "2T1L6ARK0WR085116",
        "3VW7F2UY9EA028312",
        "5YJVP9W99YW399564",
    ] {
        assert!(validators::vin_check_digit(valid), "{valid}");
        assert!(validators::vin(valid), "{valid}");
    }
    // European VINs: the form without a check digit.
    for european in [
        "WVWZZZ1JZXW000001",
        "WBA3A5C51CF256985",
        "WDDNKMP0W5D872942",
        "VF1UT301GGF059608",
        "ZFAU72SPYGU518727",
    ] {
        assert!(validators::vin(european), "{european}");
        assert!(!validators::vin_check_digit(european), "{european}");
    }
    for invalid in [
        // I, O and Q are no VIN characters
        "1HGCM82633I004352",
        "1HGCM82633O004352",
        "WVWZZZ1JZQW000001",
        // the last four are digits, at least one letter
        "1HGCM82633A00435A",
        "12345678901234567",
        // form
        "1HGCM82633A00435",
        "1HGCM82633A0043521",
        "1hgcm82633a004352",
        "1HGCM8263 A004352",
    ] {
        assert!(!validators::vin(invalid), "{invalid}");
        assert!(!validators::vin_check_digit(invalid), "{invalid}");
    }
    // check digit fails
    for invalid in [
        "1HGCM82634A004352",
        "1M8GDM9A1KP042788",
        "JH4KA7562PC008269",
    ] {
        assert!(validators::vin(invalid), "{invalid}");
        assert!(!validators::vin_check_digit(invalid), "{invalid}");
    }
}

#[test]
fn isin_validator_checks_the_luhn_digit_over_the_expanded_letters() {
    for valid in [
        "US0378331005",
        "DE0007164600",
        "US5949181045",
        "DE000BAY0017",
        "GB0002634946",
        "FR0000131104",
        "DE000A1EWWW0",
        "XS1329094590",
        "USGLHFQ7RGU4",
    ] {
        assert!(validators::isin(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "US0378331006",
        "DE0007164601",
        "DE000BAY0018",
        // swapped letters and digits keep the length, not the check
        "US0378331050",
        // form: country letters, a digit at the end, length, case
        "0S0378331005",
        "DE000BAY001A",
        "US037833100",
        "US03783310055",
        "us0378331005",
        "US 0378331005",
    ] {
        assert!(!validators::isin(invalid), "{invalid}");
    }
}

#[test]
fn lei_validator_checks_the_mod_97_check_digits() {
    for valid in [
        "529900T8BM49AURSDO55",
        "5493001KJTIIGC8Y1R12",
        "7LTWFZYICNSX8D621K86",
        "969500193UZB79PV3N74",
        "2138000KYLEGFCD44P43",
        "391200V3PHWME86CR376",
    ] {
        assert!(validators::lei(valid), "{valid}");
    }
    for invalid in [
        // check digits fail
        "529900T8BM49AURSDO56",
        "5493001KJTIIGC8Y1R21",
        "7LTWFZYICNSX8D621K68",
        // form: two digits at the end, length, case
        "529900T8BM49AURSDO5A",
        "529900T8BM49AURSDO5",
        "529900T8BM49AURSDO550",
        "529900t8bm49aursdo55",
        "00000000000000000000",
    ] {
        assert!(!validators::lei(invalid), "{invalid}");
    }
}

#[test]
fn pzn_validator_checks_the_weighted_mod_11_digit() {
    for valid in [
        "01126111", "02532876", "43230555", "64030027", "03502423", "15902501",
        // the seven-digit PZN of before 2013 is the same number
        "1126111", "2532876", "3502423",
    ] {
        assert!(validators::de_pzn(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "01126112",
        "43230556",
        "1126112",
        // the weighted sum leaves 10: never issued
        "00000019",
        // one repeated digit
        "00000000",
        "1111111",
        // form
        "123456",
        "123456789",
        "0112611A",
        "0112 6111",
    ] {
        assert!(!validators::de_pzn(invalid), "{invalid}");
    }
}

#[test]
fn the_fin_rules_have_their_label_validator_and_context() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    for (rule_id, label, check, strength) in [
        (
            VIN,
            "VIN",
            validators::vin_check_digit as fn(&str) -> bool,
            ValidatorStrength::Checksum,
        ),
        (
            VIN_FORMAT,
            "VIN",
            validators::vin,
            ValidatorStrength::Format,
        ),
        (ISIN, "ISIN", validators::isin, ValidatorStrength::Checksum),
        (LEI, "LEI", validators::lei, ValidatorStrength::Checksum),
        (
            PZN,
            "DE_PZN",
            validators::de_pzn,
            ValidatorStrength::Checksum,
        ),
    ] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, label, "{rule_id}");
        assert_eq!(rule.strength, strength, "{rule_id}");
        assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
        assert!(!rule.captured_value, "{rule_id}");
        assert!(!rule.scored_only, "{rule_id}");
        assert!(rule.requires_context, "{rule_id}");
        assert!(
            score::score(rule, Context::Support { gap: 48 }) >= balanced,
            "{rule_id}"
        );
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (VIN, "VIN: 1HGCM82633A004352", "1HGCM82633A004352"),
        (
            VIN,
            "The vehicle identification number is 1M8GDM9AXKP042788.",
            "1M8GDM9AXKP042788",
        ),
        (VIN, "{\"vin\": \"JH4KA7561PC008269\"}", "JH4KA7561PC008269"),
        (
            VIN,
            "Fahrzeug-Identifizierungsnummer: 2T1L6ARK0WR085116",
            "2T1L6ARK0WR085116",
        ),
        (
            VIN_FORMAT,
            "Fahrgestellnummer: WVWZZZ1JZXW000001",
            "WVWZZZ1JZXW000001",
        ),
        (
            VIN_FORMAT,
            "Chassis number WBA3A5C51CF256985 is registered.",
            "WBA3A5C51CF256985",
        ),
        (ISIN, "ISIN: US0378331005", "US0378331005"),
        (
            ISIN,
            "Die Aktie mit der ISIN DE0007164600 wurde verkauft.",
            "DE0007164600",
        ),
        (ISIN, "{\"isin\": \"DE000BAY0017\"}", "DE000BAY0017"),
        (LEI, "LEI: 529900T8BM49AURSDO55", "529900T8BM49AURSDO55"),
        (
            LEI,
            "The legal entity identifier of the issuer is 7LTWFZYICNSX8D621K86.",
            "7LTWFZYICNSX8D621K86",
        ),
        (
            LEI,
            "LEI-Code: 5493001KJTIIGC8Y1R12",
            "5493001KJTIIGC8Y1R12",
        ),
        (PZN, "PZN: 01126111", "01126111"),
        (PZN, "PZN-02532876", "02532876"),
        (
            PZN,
            "Die Pharmazentralnummer des Präparats lautet 43230555.",
            "43230555",
        ),
        (PZN, "{\"pzn\": \"64030027\"}", "64030027"),
        (PZN, "Pharmazentralnummer: 1126111", "1126111"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (VIN, "vin,km\n3VW7F2UY9EA028312,42000", "3VW7F2UY9EA028312"),
        (ISIN, "isin;stueck\nFR0000131104;120", "FR0000131104"),
        (
            LEI,
            "lei,rating\n969500193UZB79PV3N74,3",
            "969500193UZB79PV3N74",
        ),
        (PZN, "nr;pzn;menge\n1;03502423;2", "03502423"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // check fails or form breaks
        ("VIN", "VIN: 1HGCM82633I004352"),
        ("VIN", "VIN: 1HGCM82633A00435A"),
        ("ISIN", "ISIN: US0378331006"),
        ("LEI", "LEI: 529900T8BM49AURSDO56"),
        ("DE_PZN", "PZN: 01126112"),
        ("DE_PZN", "PZN: 00000000"),
        // no term, also in the scored modes
        ("VIN", "1HGCM82633A004352"),
        ("VIN", "Reference WVWZZZ1JZXW000001 was archived."),
        ("ISIN", "Order US0378331005 was shipped."),
        ("LEI", "Vorgang 529900T8BM49AURSDO55 wurde abgeschlossen."),
        ("DE_PZN", "Bestellnummer 01126111"),
        ("DE_PZN", "Vorgang 43230555 wurde abgeschlossen."),
        // part of a longer value
        ("VIN", "VIN: 1HGCM82633A004352-2"),
        ("ISIN", "ISIN: XUS0378331005"),
        ("DE_PZN", "PZN: 01126111-4"),
        ("DE_PZN", "PZN: 4/01126111"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

#[test]
fn a_pzn_after_the_drug_on_a_medication_line_stays_silent() {
    // The E05 doctor's letter lists `Medikation: <drug>, PZN <digits>` with
    // random digits as a hard negative: under the medication key the digits are
    // no value of their own.
    assert_silent(
        "Diagnose: Refluxösophagitis (K21.0)\nMedikation: Pantoprazol 40 mg, PZN 43230555\n",
        "DE_PZN",
        &MODES,
    );
}
