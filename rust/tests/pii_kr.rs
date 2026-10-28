// SPDX-License-Identifier: GPL-3.0-only
//! Korean identifiers (B-KR: A14, T12).
//!
//! Three numbering systems with a check digit, one label each: the resident
//! registration number (`KR_RRN`, 주민등록번호, sex and century digit 1–4), the
//! foreigner registration number (`KR_FRN`, 외국인등록번호, 5–8), both
//! `YYMMDD-GHHSSSC` with a birth date, a region code up to 95 and a check digit mod
//! 11, and the business registration number (`KR_BRN`, 사업자등록번호,
//! `NNN-NN-NNNNN`, weighted check digit mod 10). Each label has a rule that reports
//! the value in every mode when a term of the label stands near it or is its key.
//! In `balanced` and `recall` the hyphenated forms are also reported bare (K05);
//! thirteen or ten bare digits need the term in every mode.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const RRN: &str = "pii_rrn_kr";
const RRN_CONTEXT_FREE: &str = "pii_rrn_kr_context_free";
const FRN: &str = "pii_frn_kr";
const FRN_CONTEXT_FREE: &str = "pii_frn_kr_context_free";
const BRN: &str = "pii_brn_kr";
const BRN_CONTEXT_FREE: &str = "pii_brn_kr_context_free";
const CONTEXT_BOUND: [&str; 3] = [RRN, FRN, BRN];
const CONTEXT_FREE: [&str; 3] = [RRN_CONTEXT_FREE, FRN_CONTEXT_FREE, BRN_CONTEXT_FREE];
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

// ── validators ───────────────────────────────────────────────────────────────

#[test]
fn rrn_validator_checks_the_date_sex_region_and_check_digit() {
    for valid in [
        // presidio-analyzer test values
        "960121-1021413",
        "9601211021413",
        "660607-1248425",
        "740311-2150890",
        "190908-3734834",
        "121205-4019691",
        "0101163953668",
    ] {
        assert!(validators::kr_rrn(valid), "{valid}");
    }
    for invalid in [
        // check digit fails (presidio-analyzer: issued after October 2020 or wrong)
        "960121-1234567",
        "000505-3637892",
        "660607-1248426",
        // impossible date: month 13, 30 February, 2019-02-29
        "001332-1234567",
        "960230-1021413",
        "190229-3734834",
        // foreigner, or no sex and century digit
        "911124-5678906",
        "960121-0021413",
        "960121-9021413",
        // region code above 95
        "660607-1968425",
        // separators and lengths
        "960121+1021413",
        "96012-11021413",
        "960121-102141",
        "96012110214131",
        "960121-102141A",
    ] {
        assert!(!validators::kr_rrn(invalid), "{invalid}");
    }
}

#[test]
fn frn_validator_checks_the_date_sex_region_and_check_digit() {
    for valid in [
        // presidio-analyzer test values
        "911124-5678906",
        "050912-6000012",
        "0509126000012",
        "801221-5183058",
        "650222-6148847",
        "000222-7652089",
        "090816-8248985",
    ] {
        assert!(validators::kr_frn(valid), "{valid}");
    }
    for invalid in [
        // a resident, not a foreigner (presidio-analyzer negative)
        "760413-1212134",
        "960121-1021413",
        // check digit fails
        "911124-5678907",
        "801221-5183059",
        // impossible date, region code above 95
        "001332-5678906",
        "801221-5963058",
        // separators and lengths
        "960121+5021413",
        "911124-567890",
        "911124-567890A",
    ] {
        assert!(!validators::kr_frn(invalid), "{invalid}");
    }
}

#[test]
fn brn_validator_checks_the_weighted_check_digit() {
    for valid in [
        // presidio-analyzer test values
        "1048656659",
        "104-82-13138",
        "534-57-86882",
        "250-39-98996",
        "0809124253",
        "942-81-10860",
    ] {
        assert!(validators::kr_brn(valid), "{valid}");
    }
    for invalid in [
        // presidio-analyzer negatives
        "110-81-412722",
        "110-81-4127A",
        "123-45-67890",
        // check digit fails
        "104-82-13139",
        "1048656658",
        // one repeated digit, other groupings
        "0000000000",
        "000-00-00000",
        "10-482-13138",
        "1048-2-13138",
        "104 82 13138",
        "104-8213138",
    ] {
        assert!(!validators::kr_brn(invalid), "{invalid}");
    }
}

#[test]
fn the_korean_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check) in [
        (
            [RRN, RRN_CONTEXT_FREE],
            "KR_RRN",
            validators::kr_rrn as fn(&str) -> bool,
        ),
        ([FRN, FRN_CONTEXT_FREE], "KR_FRN", validators::kr_frn),
        ([BRN, BRN_CONTEXT_FREE], "KR_BRN", validators::kr_brn),
    ] {
        for rule_id in rule_ids {
            let rule = pattern(rule_id);
            assert_eq!(rule.entity_group, label, "{rule_id}");
            assert_eq!(rule.strength, ValidatorStrength::Checksum, "{rule_id}");
            assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
            assert!(!rule.captured_value, "{rule_id}");
        }
    }
    let balanced = PiiMode::Balanced.min_score().unwrap();
    let recall = PiiMode::Recall.min_score().unwrap();
    for rule_id in CONTEXT_BOUND {
        let rule = pattern(rule_id);
        assert!(rule.requires_context && !rule.scored_only, "{rule_id}");
        // The farthest term still clears the balanced threshold.
        assert!(
            score::score(rule, Context::Support { gap: 48 }) >= balanced,
            "{rule_id}"
        );
    }
    for rule_id in CONTEXT_FREE {
        let rule = pattern(rule_id);
        assert!(rule.scored_only && !rule.requires_context, "{rule_id}");
        // Bare, the check digit reaches the balanced threshold; a nearer
        // counter-context term drops it below the recall threshold.
        assert_eq!(score::rule_score(rule), 0.55, "{rule_id}");
        assert!(score::score(rule, Context::Counter) < recall, "{rule_id}");
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (RRN, "His RRN is 9601211021413", "9601211021413"),
        (
            RRN,
            "Resident Registration Number: 660607-1248425",
            "660607-1248425",
        ),
        (RRN, "주민등록번호: 740311-2150890", "740311-2150890"),
        (RRN, "{\"rrn\": \"190908-3734834\"}", "190908-3734834"),
        (
            RRN,
            "Die koreanische Bürgernummer lautet 1212054019691.",
            "1212054019691",
        ),
        (
            FRN,
            "Foreigner Registration Number: 801221-5183058",
            "801221-5183058",
        ),
        (FRN, "외국인등록번호 0509126000012", "0509126000012"),
        (FRN, "Please quote FRN 650222-6148847.", "650222-6148847"),
        (
            FRN,
            "Koreanische Ausländerregistrierungsnummer: 000222-7652089",
            "000222-7652089",
        ),
        (
            BRN,
            "Business Registration Number: 1048656659",
            "1048656659",
        ),
        (BRN, "사업자등록번호: 104-82-13138", "104-82-13138"),
        (BRN, "My BRN is 534-57-86882.", "534-57-86882"),
        (
            BRN,
            "Koreanische Geschäftsregistrierungsnummer: 2503998996",
            "2503998996",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (RRN, "rrn,age\n6606071248425,42", "6606071248425"),
        (FRN, "frn,age\n8012215183058,46", "8012215183058"),
        (BRN, "brn,staff\n1048656659,120", "1048656659"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
    // A cell that holds more than the value is still part of a longer number.
    assert_silent("brn,staff\n1048656659-4,120", "KR_BRN", &MODES);
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // no term: the bare forms that are never context-free
        ("KR_RRN", "Reference 6606071248425"),
        ("KR_FRN", "Order 8012215183058 shipped."),
        ("KR_BRN", "Reference 1048656659"),
        // check fails
        ("KR_RRN", "RRN: 960121-1234567"),
        ("KR_RRN", "Resident Registration Number: 001332-1234567"),
        ("KR_FRN", "FRN: 911124-5678907"),
        ("KR_FRN", "Foreigner Registration Number: 760413-1212134"),
        ("KR_BRN", "BRN: 123-45-67890"),
        ("KR_BRN", "Business Registration Number: 000-00-00000"),
        // part of a longer value
        ("KR_RRN", "RRN: 660607-1248425-1"),
        ("KR_FRN", "FRN 8012215183058 0"),
        ("KR_BRN", "BRN: 110-81-412722"),
        // a nearer counter-context term
        ("KR_BRN", "BRN letter, invoice number 1048656659"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare values, scored modes only ───────────────────────────────────────────

#[test]
fn bare_values_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (RRN_CONTEXT_FREE, "960121-1021413", "960121-1021413"),
        (
            RRN_CONTEXT_FREE,
            "Applicant 570516-1185690 has been approved.",
            "570516-1185690",
        ),
        (FRN_CONTEXT_FREE, "911124-5678906", "911124-5678906"),
        (
            FRN_CONTEXT_FREE,
            "Bewerber 830201-6459457 wurde angenommen.",
            "830201-6459457",
        ),
        (BRN_CONTEXT_FREE, "104-82-13138", "104-82-13138"),
        (
            BRN_CONTEXT_FREE,
            "Supplier 646-84-14125 from Seoul",
            "646-84-14125",
        ),
    ] {
        assert_reports(rule_id, text, value, &SCORED);
        let label = pattern(rule_id).entity_group;
        assert_silent(text, label, &[PiiMode::Strict]);
        assert_eq!(
            spans(text, PiiMode::Balanced, label),
            [(value.to_owned(), 0.55)],
            "{text}"
        );
    }
}

#[test]
fn bare_lookalikes_stay_silent_in_every_mode() {
    for (label, text) in [
        // the check digit alone is too weak for thirteen or ten bare digits
        ("KR_RRN", "9601211021413"),
        ("KR_FRN", "0509126000012"),
        ("KR_BRN", "1048656659"),
        // presidio-analyzer negatives: invalid date, `+`, wrong check, a resident
        ("KR_RRN", "001332-1234567"),
        ("KR_RRN", "960121+1021413"),
        ("KR_FRN", "760413-1212134"),
        ("KR_BRN", "110-81-4127A"),
        ("KR_BRN", "123-45-67890"),
        // the other registration number
        ("KR_FRN", "960121-1021413"),
        ("KR_RRN", "911124-5678906"),
        // part of a longer value
        ("KR_RRN", "Part 960121-1021413-2 is in stock."),
        ("KR_BRN", "Teil 104-82-13138-1 ist lieferbar."),
        // a nearer counter-context term
        ("KR_RRN", "Invoice number 960121-1021413"),
        ("KR_BRN", "Bestellnummer 104-82-13138"),
    ] {
        assert_silent(text, label, &MODES);
    }
}
