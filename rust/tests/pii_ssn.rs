// SPDX-License-Identifier: GPL-3.0-only
//! US Social Security Number beyond the field name (B-SSN: T25, F07).
//!
//! `pii_ssn_us` binds a value right after its field name. Two rules add the rest:
//! `pii_ssn_us_proximity` reports `AAA-GG-SSSS` (hyphens, dots or spaces) and nine
//! digits without separators in every mode when an SSN term stands near the value
//! (`Social Security Number (SSN) …`, `Als SSN ist … hinterlegt`) or is its structural
//! key (`"ssn": …`, `ssn=…`, `<SSN>`, a CSV column); `pii_ssn_us_context_free`
//! reports the grouped form without any term, but only in `balanced` and `recall`.
//! A grouped value without an SSN term stays negative in `strict`, a nearer
//! counter-context term (order, reference, part number) drops it in every mode, and
//! nine bare digits need an SSN term in every mode. The SSA range validator is
//! unchanged.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const LABEL: &str = "SSN";
const PROXIMITY: &str = "pii_ssn_us_proximity";
const CONTEXT_FREE: &str = "pii_ssn_us_context_free";
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

/// `(text, score)` of every SSN span.
fn ssn_spans(text: &str, mode: PiiMode) -> Vec<(String, f64)> {
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

/// `rule_id` reports exactly `value` as the only SSN span in each of `modes`.
fn assert_reports(rule_id: &str, text: &str, value: &str, modes: &[PiiMode]) {
    for &mode in modes {
        let found = rules(text, mode);
        assert!(
            found
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report {value:?} in {text:?}: {found:?}"
        );
        let spans = ssn_spans(text, mode);
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

fn assert_silent(text: &str, modes: &[PiiMode]) {
    for &mode in modes {
        let spans = ssn_spans(text, mode);
        assert!(spans.is_empty(), "{mode}: no SSN in {text:?}: {spans:?}");
    }
}

#[test]
fn the_new_rules_check_the_ssa_ranges_without_a_field_name() {
    for rule_id in [PROXIMITY, CONTEXT_FREE] {
        let pattern = pattern(rule_id);
        assert_eq!(pattern.entity_group, LABEL, "{rule_id}");
        assert!(!pattern.captured_value, "{rule_id} binds no field name");
        assert_eq!(pattern.strength, ValidatorStrength::Format, "{rule_id}");
        assert_eq!(
            pattern.validator.map(|validator| validator as usize),
            Some(validators::us_ssn as fn(&str) -> bool as usize),
            "{rule_id} keeps the SSA range validator"
        );
    }
    let proximity = pattern(PROXIMITY);
    assert!(proximity.requires_context && !proximity.scored_only);
    let context_free = pattern(CONTEXT_FREE);
    assert!(!context_free.requires_context && context_free.scored_only);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    // The farthest SSN term still clears the balanced threshold ...
    assert!(score::score(proximity, Context::Support { gap: 48 }) >= balanced);
    // ... a bare grouped value just reaches it, and a nearer counter-context term
    // drops it below the recall threshold.
    assert_eq!(score::rule_score(context_free), balanced);
    assert!(score::score(context_free, Context::Counter) < PiiMode::Recall.min_score().unwrap());
    // Field-bound first: the field name keeps its span and score.
    let position = |rule_id: &str| {
        PII_PATTERNS
            .iter()
            .position(|pattern| pattern.name == rule_id)
            .unwrap()
    };
    assert!(position("pii_ssn_us") < position(PROXIMITY));
    assert!(position(PROXIMITY) < position(CONTEXT_FREE));
}

#[test]
fn ssa_range_vectors_are_unchanged() {
    for valid in [
        "123-45-6789",
        "861-18-8883",
        "078.05.1123",
        "078 05 1123",
        "078051121",
        "857016921",
        "219-09-9998",
        "665-12-3456",
        "899-99-9999",
    ] {
        assert!(validators::us_ssn(valid), "{valid}");
    }
    for invalid in [
        "000-12-3456", // area 000
        "666-12-3456", // area 666
        "900-12-3456", // area 9xx (ITIN range)
        "987-65-4322", // area 9xx (presidio-analyzer test value)
        "123-00-4567", // group 00
        "123-45-0000", // serial 0000
        "078-05-1120", // Woolworth wallet sample
        "219-09-9999", // advertised sample
        "666000000",   // presidio-analyzer hard negative
        "12345678",    // eight digits
        "1234567890",  // ten digits
    ] {
        assert!(!validators::us_ssn(invalid), "{invalid}");
    }
}

#[test]
fn an_ssn_term_near_the_value_reports_it_in_every_mode() {
    for (text, value) in [
        // Gretel finance: the abbreviation in parentheses, the value in parentheses.
        (
            "Note: The Social Security Number (SSN) 861-18-8883 is not required for this application.",
            "861-18-8883",
        ),
        (
            "The applicant consents to the processing of their Social Security Number (800-40-3880) for payroll.",
            "800-40-3880",
        ),
        ("Our records list the Social Security number as 404 15 2700.", "404 15 2700"),
        ("SSN No.: 078.05.1123", "078.05.1123"),
        ("536-90-4421 is my SSN.", "536-90-4421"),
        ("Als SSN ist 422-68-7360 hinterlegt.", "422-68-7360"),
        ("Die SSN des US-Mitarbeiters ist 532-87-1094.", "532-87-1094"),
        ("Sozialversicherungsnummer (USA): 212.34.5678", "212.34.5678"),
        ("SSN-Nr. 401 12 7788 liegt vor.", "401 12 7788"),
    ] {
        assert_reports(PROXIMITY, text, value, &MODES);
    }
}

#[test]
fn nine_digits_need_an_ssn_term_or_key() {
    // F07: nine digits without separators, only with SSN context.
    for (text, value) in [
        ("ssn=857016921", "857016921"),
        (
            "includes the following PII values: date_time=13 May 1997 19:05:18, ssn=857016921, name=Lucho",
            "857016921",
        ),
        ("My SSN is 401127789, please keep it on file.", "401127789"),
        ("Seine SSN lautet 401127789.", "401127789"),
        (r#"{"ssn": "401127789"}"#, "401127789"),
        (r#"{"ssn_nummer": "401127789"}"#, "401127789"),
        ("<SSN>401127789</SSN>", "401127789"),
        ("name,ssn,city\nJane Doe,401127789,Boston", "401127789"),
        ("Social Security Number: 401127789", "401127789"),
    ] {
        assert_reports(PROXIMITY, text, value, &MODES);
    }
    for text in [
        // No SSN term: bare digits stay negative in every mode.
        "401127789",
        "078051121",
        "Send the form for 401127789 today.",
        "35=D|55=TradingSessionStatus|432=857016921|437=Lucho",
        "<AcctID>790245863</AcctID>",
        "Artikelnummer 401127789",
        // A nearer counter-context term wins over the SSN term.
        "The SSN request is under order number 401127789.",
        "Die SSN folgt, Bestellnummer 401127789.",
        // Outside the SSA ranges or not nine digits.
        "SSN: 666000000",
        "SSN: 900123456",
        "SSN: 40112778",
        "SSN: 4011277890",
        "SSN: 401127789012",
    ] {
        assert_silent(text, &MODES);
    }
}

#[test]
fn structural_keys_bind_grouped_values_the_field_rule_does_not_take() {
    for (text, value) in [
        (
            r#"{"social_security_number": "078.05.1123"}"#,
            "078.05.1123",
        ),
        ("<ssn>212.34.5678</ssn>", "212.34.5678"),
        ("nr;name;ssn\n1;Jonas Weber;078.05.1123", "078.05.1123"),
    ] {
        assert_reports(PROXIMITY, text, value, &MODES);
    }
}

#[test]
fn grouped_values_without_an_ssn_term_stay_negative_in_strict() {
    for text in [
        "123-45-6789",
        "078 05 1123",
        "078.05.1123",
        "Release 123-45-6789",
        "Ticket 532-87-1094 was closed.",
        "Artikel 401-12-7788 ist lieferbar.",
        "From Account: 226-33-7819, To Account: 334-82-1956",
        "NAD+SU+341-33-4328::735 Kyle Camp+Apt 3+Anytown+CA+12345+US",
        "<identification><id>566-66-2655</id></identification>",
    ] {
        assert_silent(text, &[PiiMode::Strict]);
    }
}

#[test]
fn counter_context_keeps_grouped_values_negative_in_every_mode() {
    for text in [
        "Order number 123-45-6789 has shipped.",
        "Reference number 523-41-1234",
        "Part number 401-12-7788",
        "Invoice no 523-41-1234 is overdue.",
        "Tracking number 401-12-7788 is in transit.",
        "Serial number 219-45-7781",
        "Bestellnummer 123-45-6789 ist versandt.",
        "Referenznummer 523-41-1234",
        "Teilenummer 401-12-7788",
        "Rechnungsnummer 523-41-1234 ist offen.",
        "Sendungsnummer 532-87-1094",
        "Seriennummer 219-45-7781",
        r#"{"order_id": "123-45-6789"}"#,
        "The SSN request is under order number 123-45-6789.",
    ] {
        assert_silent(text, &MODES);
    }
}

#[test]
fn balanced_reports_a_grouped_value_without_a_term() {
    for (text, value) in [
        // presidio-analyzer recognizer tests.
        ("078 05 1123", "078 05 1123"),
        ("abc 078 05 1123 abc", "078 05 1123"),
        ("078.05.1123", "078.05.1123"),
        // Gretel finance: EDIFACT elements, SWIFT MT subfields, XML elements.
        (
            "NAD+SU+341-33-4328::735 Kyle Camp+Apt 3+Anytown+CA+12345+US",
            "341-33-4328",
        ),
        ("LIN+1++341-33-4328:IN+++123456++10.50+EA", "341-33-4328"),
        (":19A:20211115/00001/USD/399-38-9646", "399-38-9646"),
        (
            "<identification><id>566-66-2655</id></identification>",
            "566-66-2655",
        ),
        ("Release 123-45-6789", "123-45-6789"),
        ("Angaben zum US-Mitarbeiter: 219-09-9998", "219-09-9998"),
    ] {
        assert_reports(CONTEXT_FREE, text, value, &SCORED);
        for mode in SCORED {
            assert_eq!(ssn_spans(text, mode)[0].1, 0.5, "{mode}: {text}");
        }
    }
}

#[test]
fn a_bare_grouped_value_stands_alone() {
    for text in [
        // Values outside the SSA ranges.
        "900-12-3456",
        "666-12-3456",
        "078-05-1120",
        "219-09-9999",
        // Part of a longer number, a range or a phone number.
        "+341-33-4328",
        "12/341-33-4328",
        "341-33-4328-7",
        "Range 341-33-4328/2026",
        "Gruppe 12 341 33 4328",
        "1341-33-4328",
        "341-33-43281",
        // Mixed separators are no SSN grouping.
        "341-33 4328",
        "341.33-4328",
    ] {
        assert_silent(text, &MODES);
    }
}

#[test]
fn scores_follow_the_context() {
    let proximity = pattern(PROXIMITY);
    for (text, context) in [
        (
            "The SSN on file is 401-12-7788",
            Context::Support { gap: 12 },
        ),
        (
            "The Social Security Number we keep in the payroll file is 401-12-7788",
            Context::Support { gap: 32 },
        ),
        (r#"{"ssn": "401127789"}"#, Context::Field),
    ] {
        for mode in SCORED {
            let spans = ssn_spans(text, mode);
            assert_eq!(spans.len(), 1, "{mode}: {text}: {spans:?}");
            assert_eq!(
                spans[0].1,
                score::score(proximity, context),
                "{mode}: {text}"
            );
        }
        assert_eq!(ssn_spans(text, PiiMode::Strict)[0].1, 1.0, "{text}");
    }
    // After its field name the field-bound rule keeps its span and score.
    for mode in SCORED {
        assert_eq!(
            ssn_spans("SSN: 123-45-6789", mode),
            [(
                "123-45-6789".to_owned(),
                score::rule_score(pattern("pii_ssn_us"))
            )],
            "{mode}"
        );
    }
}
