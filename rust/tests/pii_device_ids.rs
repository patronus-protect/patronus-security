// SPDX-License-Identifier: GPL-3.0-only
//! Mobile device and SIM identifiers (B-DEVID).
//!
//! The IMEI (`IMEI`) is fifteen digits, plain or grouped 2-6-6-1, the last a
//! Luhn check digit. The MEID (`MEID`) is fourteen upper-case hex digits led by
//! a regional code `A0`–`FF` and a check digit computed by Luhn in base 16. The
//! ICCID (`ICCID`) is 19 or 20 digits led by the telecom prefix `89`, plain or
//! in blocks of four, the last a Luhn check digit. The IMSI (`IMSI`) is fifteen
//! digits led by a mobile country code `2xx`–`7xx` and has no check digit. All
//! four are reported in every mode only when a term of their label stands near
//! them or is their key: one bare fifteen-digit number in ten passes Luhn.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const IMEI: &str = "pii_imei";
const MEID: &str = "pii_meid";
const ICCID: &str = "pii_iccid";
const IMSI: &str = "pii_imsi";
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

/// Text of every span with `label`.
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
fn imei_validator_checks_the_luhn_digit_and_the_form() {
    for valid in [
        "490154203237518",
        "356352080572311",
        "862927656242170",
        "015023733203876",
        "990226402188166",
        "35-635208-057231-1",
        "86 292765 624217 0",
    ] {
        assert!(validators::imei(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "490154203237519",
        "356352080572312",
        // one repeated digit
        "000000000000000",
        // form
        "35635208057231",
        "3563520805723115",
        "35-635208 057231-1",
        "356-35208-057231-1",
        "35.635208.057231.1",
        "35635208057231A",
    ] {
        assert!(!validators::imei(invalid), "{invalid}");
    }
}

#[test]
fn meid_validator_checks_the_hex_luhn_digit_and_the_regional_code() {
    for valid in [
        "AF0123450ABCDEC",
        "A1000000929602E",
        "A0000031FF6A115",
        "A10000370B1E426",
        "A000001D57B3085",
        "A1000012CA4F07D",
    ] {
        assert!(validators::meid(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "AF0123450ABCDED",
        "A1000000929602F",
        // a decimal regional code (00–99) is an IMEI
        "990000864321010",
        "35635208057231B",
        // form
        "A1000000929602",
        "A1000000929602E7",
        "a1000000929602e",
        "G1000000929602E",
    ] {
        assert!(!validators::meid(invalid), "{invalid}");
    }
}

#[test]
fn iccid_validator_checks_the_prefix_luhn_digit_and_the_form() {
    for valid in [
        "89495988234014706821",
        "8944184652734537308",
        "89014454193125595750",
        "8933762633143822658",
        "8941 9503 6778 5996 7302",
        "8944 1846 5273 4537 308",
    ] {
        assert!(validators::iccid(valid), "{valid}");
    }
    for invalid in [
        // check digit fails
        "89495988234014706822",
        "8944184652734537309",
        // no telecom prefix 89, Luhn-valid
        "79495988234014706823",
        // form
        "894959882340147068",
        "894959882340147068213",
        "8949 1819 3237 79737016",
        "8941-9503-6778-5996-7302",
        "8949598823401470682A",
    ] {
        assert!(!validators::iccid(invalid), "{invalid}");
    }
}

#[test]
fn imsi_validator_checks_the_mobile_country_code_and_the_form() {
    for valid in [
        "262011234567890",
        "310150123456789",
        "234302345678901",
        "440101234567890",
        "722070123456789",
    ] {
        assert!(validators::imsi(valid), "{valid}");
    }
    for invalid in [
        // no mobile country code
        "001010123456789",
        "162011234567891",
        "810150123456789",
        "962011234567890",
        // one repeated digit
        "333333333333333",
        // form
        "26201123456789",
        "2620112345678901",
        "26201 1234567890",
        "26201123456789A",
    ] {
        assert!(!validators::imsi(invalid), "{invalid}");
    }
}

#[test]
fn the_device_rules_have_their_label_validator_and_strength() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    for (rule_id, label, check, strength) in [
        (
            IMEI,
            "IMEI",
            validators::imei as fn(&str) -> bool,
            ValidatorStrength::Checksum,
        ),
        (MEID, "MEID", validators::meid, ValidatorStrength::Checksum),
        (
            ICCID,
            "ICCID",
            validators::iccid,
            ValidatorStrength::Checksum,
        ),
        (IMSI, "IMSI", validators::imsi, ValidatorStrength::Format),
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
        (IMEI, "IMEI: 490154203237518", "490154203237518"),
        (
            IMEI,
            "The IMEI of the lost phone is 86-292765-624217-0.",
            "86-292765-624217-0",
        ),
        (IMEI, "{\"imei\": \"015023733203876\"}", "015023733203876"),
        (
            IMEI,
            "IMEI-Nummer: 99 022640 218816 6",
            "99 022640 218816 6",
        ),
        (
            IMEI,
            "Die IMEI des gestohlenen Handys lautet 869962546895674.",
            "869962546895674",
        ),
        (MEID, "MEID: AF0123450ABCDEC", "AF0123450ABCDEC"),
        (
            MEID,
            "The MEID printed on the handset is A0000031FF6A115.",
            "A0000031FF6A115",
        ),
        (MEID, "{\"meid\": \"A10000370B1E426\"}", "A10000370B1E426"),
        (MEID, "MEID-Nummer: A000001D57B3085", "A000001D57B3085"),
        (ICCID, "ICCID: 89495988234014706821", "89495988234014706821"),
        (
            ICCID,
            "The SIM card number is 8944184652734537308.",
            "8944184652734537308",
        ),
        (
            ICCID,
            "SIM serial number 8941 9503 6778 5996 7302",
            "8941 9503 6778 5996 7302",
        ),
        (
            ICCID,
            "Die SIM-Kartennummer lautet 89014454193125595750.",
            "89014454193125595750",
        ),
        (IMSI, "IMSI: 310150123456789", "310150123456789"),
        (
            IMSI,
            "The subscriber's IMSI is 234302345678901.",
            "234302345678901",
        ),
        (IMSI, "{\"imsi\": \"310260987654321\"}", "310260987654321"),
        (
            IMSI,
            "Die IMSI der SIM-Karte lautet 262073901234567.",
            "262073901234567",
        ),
    ] {
        assert_reports(rule_id, text, value);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (IMEI, "imei,age\n356352080572311,42", "356352080572311"),
        (
            IMEI,
            "nr;gerät;imei\n1;iPhone 15;356726082749946",
            "356726082749946",
        ),
        (MEID, "meid,age\nA1000049A51C336,42", "A1000049A51C336"),
        (
            ICCID,
            "iccid,age\n89430370932852231108,42",
            "89430370932852231108",
        ),
        (IMSI, "imsi,age\n262011234567890,42", "262011234567890"),
    ] {
        assert_reports(rule_id, text, value);
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // check fails
        ("IMEI", "IMEI: 490154203237519"),
        ("IMEI", "IMEI-Nummer: 000000000000000"),
        ("MEID", "MEID: A1000000929602F"),
        ("MEID", "MEID: 990000864321010"),
        ("ICCID", "ICCID: 89495988234014706822"),
        ("ICCID", "ICCID: 79495988234014706823"),
        ("IMSI", "IMSI: 810150123456789"),
        ("IMSI", "IMSI: 333333333333333"),
        // no term
        ("IMEI", "490154203237518"),
        ("IMEI", "Order 490154203237518 was shipped."),
        ("MEID", "Commit A1000000929602E was merged."),
        ("ICCID", "Tracking 89495988234014706821 was delivered."),
        ("IMSI", "Vorgang 262011234567890 wurde abgeschlossen."),
        // part of a longer value
        ("IMEI", "IMEI: 4901542032375185"),
        ("IMEI", "IMEI: 490154203237518-2"),
        ("MEID", "MEID: 0xA000001D57B3085"),
        ("ICCID", "ICCID: 894959882340147068213"),
        ("IMSI", "IMSI: 3101501234567890"),
    ] {
        assert_silent(text, label);
    }
}

#[test]
fn each_device_term_binds_only_its_own_label() {
    // A Luhn-valid IMSI under an IMSI term is no IMEI, and an IMEI under an
    // IMEI term no IMSI.
    assert_reports(IMSI, "IMSI: 310150123456780", "310150123456780");
    assert_silent("IMSI: 310150123456780", "IMEI");
    assert_reports(IMEI, "IMEI: 356352080572311", "356352080572311");
    assert_silent("IMEI: 356352080572311", "IMSI");
}
