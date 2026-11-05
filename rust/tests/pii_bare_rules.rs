// SPDX-License-Identifier: GPL-3.0-only
//! Opt-in bare-format PII rules (D-BARE).
//!
//! Every value that the default rules report only with a term of its label or
//! after its field name (`known_gaps` with `bare: true`) has a `*_bare` rule. It is
//! off in every mode until the `rules` gate enables it; then it reports the bare
//! value with the validator of its id, in every mode, and drops a value inside a
//! longer number, under a field that names another value or nearer a
//! counter-context term. Its low base score ranks it below the labelled rules in
//! `balanced` and `recall`.

use patronus_ark::detectors::pii::pii::PII_PATTERNS;
use patronus_ark::{
    NativeGates, ScanGateMatrix, ScoreMode, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};

/// `(rule, label, valid bare value, invalid value, labelled text, model score)`.
/// The invalid value fails the validator of the id: a check digit where one
/// exists, else the format.
const CASES: &[(&str, &str, &str, &str, &str, f64)] = &[
    ("pii_steuer_id_de_bare", "STEUERID", "86095742719", "86095742718", "Steuer-ID: 86095742719", 0.50),
    ("pii_steuernummer_de_bare", "TAX_NUMBER_DE", "1121081508150", "2893181508152", "Steuernummer: 1121081508150", 0.30),
    ("pii_physician_number_lanr_de_bare", "PHYSICIAN_NUMBER_LANR", "987654401", "987654402", "LANR: 987654401", 0.50),
    ("pii_facility_number_bsnr_de_bare", "FACILITY_NUMBER_BSNR", "711234567", "000000000", "BSNR 711234567 der Praxis.", 0.30),
    ("pii_driver_license_number_de_bare", "DRIVER_LICENSE_NUMBER", "B072RRE2A57", "INFORMATION", "Führerscheinnummer: B072RRE2A57", 0.30),
    ("pii_ssn_us_bare", "SSN", "422687360", "987654320", "SSN: 422-68-7360", 0.30),
    ("pii_sin_ca_bare", "CA_SIN", "435418165", "435418166", "My social insurance number is 435418165.", 0.50),
    ("pii_aadhaar_in_bare", "IN_AADHAAR", "599979610811", "599979610812", "My Aadhaar is 599979610811.", 0.50),
    ("pii_npi_us_bare", "US_NPI", "1565277724", "1072090843", "NPI: 1565277724", 0.50),
    ("pii_pesel_pl_bare", "PL_PESEL", "02070803628", "02130803627", "PESEL: 02070803628", 0.50),
    ("pii_acn_au_bare", "AU_ACN", "006 249 976", "135 506 072", "ACN: 006 249 976", 0.50),
    ("pii_brn_kr_bare", "KR_BRN", "1048656659", "0899614156", "Business Registration Number: 1048656659", 0.50),
    ("pii_pan_in_bare", "IN_PAN", "AFZPK7190K", "DKLQR3307N", "Indische PAN: DKLPR3307N", 0.30),
    ("pii_voter_id_in_bare", "IN_VOTER", "KLT4471920", "KLT0000000", "Voter ID: KLT4471920", 0.30),
    ("pii_vehicle_registration_ng_bare", "LICENSEPLATE", "APP-456CV", "APP 456 CV", "Kennzeichen: APP-456CV", 0.30),
];

/// Bare carriers per language: no term of any label, no counter-context term.
const BARE: [&str; 2] = ["Bitte {} eintragen.", "Please put {} there."];

/// Hard negatives per language: a counter-context term next to a valid value, a
/// value inside a longer number, a field that names another value.
const NEGATIVE: [&str; 6] = [
    "Bestellnummer {} wurde versandt.",
    "Vorgang {} wurde abgeschlossen.",
    "Order {} has shipped.",
    "Reference {} was archived.",
    "Rechnung 77-{}-3",
    "{\"order_id\": \"{}\"}",
];

fn scanner(gates: ScanGateMatrix) -> SecurityGateway {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(gates);
    scanner
}

fn gates(rule: Option<&str>, mode: ScoreMode) -> ScanGateMatrix {
    let mut gates = ScanGateMatrix {
        native: NativeGates {
            pii_mode: mode,
            ..Default::default()
        },
        ..Default::default()
    };
    if let Some(rule) = rule {
        gates.set_rule(rule, true);
    }
    gates
}

fn scan(scanner: &SecurityGateway, text: &str) -> SecurityScanResult {
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

/// Score of the `rule` entry in `matched_rules`, `Some(1.0)` without a score.
fn rule_score(result: &SecurityScanResult, rule: &str) -> Option<f64> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .and_then(|rules| rules.iter().find(|entry| entry["rule_id"] == rule))
        .map(|entry| entry["score"].as_f64().unwrap_or(1.0))
}

fn bare_rule_ids() -> Vec<&'static str> {
    PII_PATTERNS
        .iter()
        .map(|pattern| pattern.name)
        .filter(|name| name.ends_with("_bare"))
        .collect()
}

#[test]
fn every_bare_rule_is_tested_and_off_by_default() {
    let mut tested: Vec<_> = CASES.iter().map(|case| case.0).collect();
    tested.sort_unstable();
    let mut registered = bare_rule_ids();
    registered.sort_unstable();
    assert_eq!(tested, registered);
    for rule in registered {
        assert!(!NativeGates::default().allows_rule(rule), "{rule}");
        assert!(NativeGates::default().allows_rule(rule.trim_end_matches("_bare")));
        assert!(NativeGates::all_enabled().allows_rule(rule), "{rule}");
    }
}

#[test]
fn bare_values_stay_silent_with_the_default_gates_in_every_mode() {
    for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
        let scanner = scanner(gates(None, mode));
        for &(rule, _, value, ..) in CASES {
            for template in BARE {
                let text = template.replace("{}", value);
                let result = scan(&scanner, &text);
                assert_eq!(rule_score(&result, rule), None, "{rule} {mode}: {text}");
            }
        }
    }
}

#[test]
fn an_enabled_bare_rule_reports_the_valid_bare_value_in_every_mode() {
    for &(rule, label, value, _, _, score) in CASES {
        for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
            if mode.min_score().is_some_and(|min| score < min) {
                continue;
            }
            let scanner = scanner(gates(Some(rule), mode));
            for template in BARE {
                let text = template.replace("{}", value);
                let result = scan(&scanner, &text);
                let expected = if mode == ScoreMode::Strict { 1.0 } else { score };
                assert_eq!(rule_score(&result, rule), Some(expected), "{rule} {mode}: {text}");
                let start = text.find(value).unwrap();
                assert!(
                    result.evidence_spans.iter().any(|span| span.label == label
                        && span.start_byte == start
                        && span.end_byte == start + value.len()),
                    "{rule} {mode}: {text} -> {:?}",
                    result.evidence_spans
                );
            }
        }
    }
}

#[test]
fn a_format_only_bare_value_stays_below_the_balanced_threshold() {
    for &(rule, _, value, _, _, score) in CASES.iter().filter(|case| case.5 < 0.5) {
        let scanner = scanner(gates(Some(rule), ScoreMode::Balanced));
        let result = scan(&scanner, &BARE[1].replace("{}", value));
        assert_eq!(rule_score(&result, rule), None, "{rule} {score}");
    }
}

#[test]
fn an_enabled_bare_rule_keeps_the_validator_of_its_id() {
    for &(rule, _, _, invalid, ..) in CASES {
        let scanner = scanner(gates(Some(rule), ScoreMode::Recall));
        for template in BARE {
            let text = template.replace("{}", invalid);
            assert_eq!(rule_score(&scan(&scanner, &text), rule), None, "{rule}: {text}");
        }
    }
}

#[test]
fn an_enabled_bare_rule_drops_counter_context_fragments_and_foreign_fields() {
    for &(rule, _, value, ..) in CASES {
        let scanner = scanner(gates(Some(rule), ScoreMode::Strict));
        for template in NEGATIVE {
            let text = template.replace("{}", value);
            assert_eq!(rule_score(&scan(&scanner, &text), rule), None, "{rule}: {text}");
        }
    }
}

#[test]
fn an_enabled_bare_rule_ranks_below_and_leaves_the_labelled_hit_unchanged() {
    for &(rule, _, _, _, labelled, score) in CASES {
        for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
            let off = scan(&scanner(gates(None, mode)), labelled);
            let on = scan(&scanner(gates(Some(rule), mode)), labelled);
            assert!(!off.evidence_spans.is_empty(), "{rule} {mode}: {labelled}");
            assert_eq!(on.evidence_spans, off.evidence_spans, "{rule} {mode}: {labelled}");
            if mode != ScoreMode::Strict {
                assert!(
                    off.evidence_spans.iter().all(|span| span.score > score),
                    "{rule} {mode}: {labelled}"
                );
            }
        }
    }
}

#[test]
fn the_example_profile_enables_exactly_the_bare_rules() {
    let profile: ScanGateMatrix = serde_json::from_str(include_str!(
        "../../docs/how-to/pii-bare-formats.gates.json"
    ))
    .unwrap();
    let mut enabled: Vec<_> = profile
        .native
        .rules
        .iter()
        .filter(|(_, on)| **on)
        .map(|(rule, _)| rule.as_str())
        .collect();
    enabled.sort_unstable();
    let mut expected = bare_rule_ids();
    expected.sort_unstable();
    assert_eq!(enabled, expected);
    assert_eq!(profile.native.rules.len(), expected.len());
}
