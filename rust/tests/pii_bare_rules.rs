// SPDX-License-Identifier: GPL-3.0-only
//! Opt-in bare-format PII rules (D-BARE).
//!
//! Every value that the default rules report only with a term of its label or
//! after its field name (`known_gaps` with `bare: true`) has a `*_bare` rule. It is
//! off in every mode until the `rules` gate enables it; then it reports the bare
//! value with the validator of its id, in every mode, and drops a value inside a
//! longer number, under a field that names another value or nearer a
//! counter-context term. It scores the `balanced` threshold `0.50`, below the
//! labelled rules of its id in `balanced` and `recall`.

use patronus_ark::detectors::pii::pii::{PiiPipeline, PII_PATTERNS};
use patronus_ark::{
    NativeGates, ScanGateMatrix, ScoreMode, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};

/// `(rule, label, valid bare value, invalid value, labelled text)`. The invalid
/// value matches the pattern and fails the validator of the id: a check digit
/// where one exists, else the format.
const CASES: &[(&str, &str, &str, &str, &str)] = &[
    (
        "pii_steuer_id_de_bare",
        "STEUERID",
        "86095742719",
        "86095742718",
        "Steuer-ID: 86095742719",
    ),
    (
        "pii_steuernummer_de_bare",
        "TAX_NUMBER_DE",
        "1121081508150",
        "2893181508152",
        "Steuernummer: 1121081508150",
    ),
    (
        "pii_physician_number_lanr_de_bare",
        "PHYSICIAN_NUMBER_LANR",
        "987654401",
        "987654501",
        "LANR: 987654401",
    ),
    (
        "pii_facility_number_bsnr_de_bare",
        "FACILITY_NUMBER_BSNR",
        "711234567",
        "000000000",
        "BSNR 711234567 der Praxis.",
    ),
    (
        "pii_driver_license_number_de_bare",
        "DRIVER_LICENSE_NUMBER",
        "B072RRE2A57",
        "INFORMATION",
        "Führerscheinnummer: B072RRE2A57",
    ),
    (
        "pii_ssn_us_bare",
        "SSN",
        "422687360",
        "987654320",
        "SSN: 422-68-7360",
    ),
    (
        "pii_sin_ca_bare",
        "CA_SIN",
        "435418165",
        "435418166",
        "My social insurance number is 435418165.",
    ),
    (
        "pii_aadhaar_in_bare",
        "IN_AADHAAR",
        "599979610811",
        "599979610812",
        "My Aadhaar is 599979610811.",
    ),
    (
        "pii_npi_us_bare",
        "US_NPI",
        "1565277724",
        "1072090843",
        "NPI: 1565277724",
    ),
    (
        "pii_pesel_pl_bare",
        "PL_PESEL",
        "02070803628",
        "02130803627",
        "PESEL: 02070803628",
    ),
    (
        "pii_acn_au_bare",
        "AU_ACN",
        "006 249 976",
        "135 506 072",
        "ACN: 006 249 976",
    ),
    (
        "pii_brn_kr_bare",
        "KR_BRN",
        "1048656659",
        "0899614156",
        "Business Registration Number: 1048656659",
    ),
    (
        "pii_pan_in_bare",
        "IN_PAN",
        "AFZPK7190K",
        "DKLQR3307N",
        "Indische PAN: DKLPR3307N",
    ),
    (
        "pii_voter_id_in_bare",
        "IN_VOTER",
        "KLT4471920",
        "KLT0000000",
        "Voter ID: KLT4471920",
    ),
    (
        "pii_vehicle_registration_ng_bare",
        "LICENSEPLATE",
        "APP-456CV",
        "APP-000CV",
        "Kennzeichen: APP-456CV",
    ),
];

/// Model score of every bare hit without context: the `balanced` threshold.
const BARE_SCORE: f64 = 0.50;

/// Bare carriers per language: no term of any label, no counter-context term.
const BARE: [&str; 2] = ["Bitte {} eintragen.", "Please put {} there."];

/// Hard negatives per language: a counter-context term next to a valid value, a
/// value inside a longer number, a field that names another value.
const NEGATIVE: [&str; 6] = [
    "Bestellnummer {} wurde versandt.",
    "Rechnungsnummer: {}",
    "Order number {} has shipped.",
    "Booking reference {} was archived.",
    "Beleg 77-{}-3",
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
fn the_unfiltered_pipeline_keeps_the_bare_rules_off() {
    let pipeline = PiiPipeline::new();
    let texts: Vec<String> = CASES
        .iter()
        .flat_map(|case| BARE.map(|template| template.replace("{}", case.2)))
        .collect();
    let mut reported: Vec<_> = texts
        .iter()
        .zip(pipeline.evaluate_batch(&texts))
        .map(|(text, result)| (text, result.class_name))
        .filter(|(_, class)| class != "safe")
        .collect();
    reported.extend(
        texts
            .iter()
            .map(|text| (text, pipeline.evaluate(text).class_name))
            .filter(|(_, class)| class != "safe"),
    );
    assert!(reported.is_empty(), "{reported:#?}");
}

#[test]
fn an_enabled_bare_rule_reports_the_valid_bare_value_in_every_mode() {
    for &(rule, label, value, ..) in CASES {
        for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
            let scanner = scanner(gates(Some(rule), mode));
            for template in BARE {
                let text = template.replace("{}", value);
                let result = scan(&scanner, &text);
                let expected = if mode == ScoreMode::Strict {
                    1.0
                } else {
                    BARE_SCORE
                };
                assert_eq!(
                    rule_score(&result, rule),
                    Some(expected),
                    "{rule} {mode}: {text}"
                );
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
fn an_enabled_bare_rule_keeps_the_validator_of_its_id() {
    let mut reported = Vec::new();
    for &(rule, _, _, invalid, ..) in CASES {
        let pattern = PII_PATTERNS.iter().find(|p| p.name == rule).unwrap();
        // The invalid value reaches the validator: the pattern matches it whole.
        let regex = regex::Regex::new(&format!("^(?:{})$", pattern.pattern)).unwrap();
        assert!(
            regex.is_match(invalid),
            "{rule}: the pattern rejects the invalid value"
        );
        let scanner = scanner(gates(Some(rule), ScoreMode::Recall));
        for template in BARE {
            let text = template.replace("{}", invalid);
            if rule_score(&scan(&scanner, &text), rule).is_some() {
                reported.push(format!("{rule}: {text}"));
            }
        }
    }
    assert!(reported.is_empty(), "{reported:#?}");
}

#[test]
fn an_enabled_bare_rule_drops_counter_context_fragments_and_foreign_fields() {
    let mut reported = Vec::new();
    for &(rule, _, value, ..) in CASES {
        let scanner = scanner(gates(Some(rule), ScoreMode::Strict));
        for template in NEGATIVE {
            let text = template.replace("{}", value);
            if rule_score(&scan(&scanner, &text), rule).is_some() {
                reported.push(format!("{rule}: {text}"));
            }
        }
    }
    assert!(reported.is_empty(), "{reported:#?}");
}

#[test]
fn an_enabled_bare_rule_ranks_below_and_leaves_the_labelled_hit_unchanged() {
    let mut changed = Vec::new();
    for &(rule, _, _, _, labelled) in CASES {
        for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
            let off = scan(&scanner(gates(None, mode)), labelled);
            let on = scan(&scanner(gates(Some(rule), mode)), labelled);
            // A labelled rule that only scores (the Nigerian plate) leaves strict
            // to the bare rule.
            let scored_only = mode == ScoreMode::Strict && off.evidence_spans.is_empty();
            if (mode != ScoreMode::Strict && off.evidence_spans.is_empty())
                || (!scored_only && on.evidence_spans != off.evidence_spans)
                || (mode != ScoreMode::Strict
                    && off
                        .evidence_spans
                        .iter()
                        .any(|span| span.score <= BARE_SCORE))
            {
                changed.push(format!(
                    "{rule} {mode}: {labelled}: {:?} -> {:?}",
                    off.evidence_spans
                        .iter()
                        .map(|span| (&span.label, span.score))
                        .collect::<Vec<_>>(),
                    on.evidence_spans
                        .iter()
                        .map(|span| (&span.label, span.score))
                        .collect::<Vec<_>>()
                ));
            }
        }
    }
    assert!(changed.is_empty(), "{changed:#?}");
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
    // Every listed rule reports in the mode of the profile.
    let scanner = scanner(profile);
    for &(rule, _, value, ..) in CASES {
        for template in BARE {
            let text = template.replace("{}", value);
            assert_eq!(
                rule_score(&scan(&scanner, &text), rule),
                Some(BARE_SCORE),
                "{rule}: {text}"
            );
        }
    }
}

/// Hard negatives of the PII goldens and of the bilingual fixture.
fn hard_negatives() -> Vec<String> {
    let goldens = include_str!("../../python/patronus_ark/benchmark_data/pii_l1.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|row| row["case_type"] == "hard_negative")
        .map(|row| row["text"].as_str().unwrap().to_owned());
    let fixture: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../ark-core/tests/fixtures/l1_bilingual_rules.json"
    ))
    .unwrap();
    let fixture = fixture
        .into_iter()
        .filter(|rule| rule["category"] == "pii")
        .flat_map(|rule| {
            ["de", "en"].map(|language| rule["hard_negatives"][language].as_array().cloned())
        })
        .flatten()
        .flatten()
        .map(|text| text.as_str().unwrap().to_owned());
    goldens.chain(fixture).collect()
}

/// `text` of every row of the JSONL files in the directory that the environment
/// variable names (the benign corpora of `scripts/l1_dlp/prepare_corpora.py`).
fn benign_corpus(variable: &str) -> Vec<String> {
    let dir = std::env::var(variable).unwrap_or_else(|_| panic!("{variable} is not set"));
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    files
        .iter()
        .flat_map(|path| {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| {
                    let row: serde_json::Value = serde_json::from_str(line).unwrap();
                    row["text"].as_str().unwrap().to_owned()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

type Spans = std::collections::BTreeSet<(usize, usize)>;

fn spans(scanner: &SecurityGateway, text: &str) -> Spans {
    scan(scanner, text)
        .evidence_spans
        .iter()
        .map(|span| (span.start_byte, span.end_byte))
        .collect()
}

/// Spans of `on` that the default gates (`off`, one set per text) do not report.
fn new_spans(on: &SecurityGateway, texts: &[String], off: &[Spans]) -> usize {
    texts
        .iter()
        .zip(off)
        .map(|(text, off)| spans(on, text).difference(off).count())
        .sum()
}

/// False-positive report per bare rule, each enabled alone, against the default
/// gates (PR #284): new spans on the PII hard negatives and per MB of the pinned
/// benign code and docs corpora (dev split).
///
/// ```text
/// ARK_BENIGN_CODE=~/ark-dlp/data/dev/benign_code ARK_BENIGN_DOCS=~/ark-dlp/data/dev/benign_docs \
///   cargo test --release -p patronus-ark --test pii_bare_rules -- --ignored --nocapture
/// ```
#[test]
#[ignore = "requires ARK_BENIGN_CODE and ARK_BENIGN_DOCS"]
fn bare_rule_false_positive_report() {
    let corpora = [
        hard_negatives(),
        benign_corpus("ARK_BENIGN_CODE"),
        benign_corpus("ARK_BENIGN_DOCS"),
    ];
    let megabytes = corpora
        .each_ref()
        .map(|texts| texts.iter().map(String::len).sum::<usize>() as f64 / 1e6);
    println!(
        "hard negatives: {}; benign code: {:.2} MB; benign docs: {:.2} MB",
        corpora[0].len(),
        megabytes[1],
        megabytes[2]
    );
    println!("| Rule | Hard-negative spans strict / balanced | Code FP per MB strict / balanced | Docs FP per MB strict / balanced |");
    println!("|---|---:|---:|---:|");
    let modes = [ScoreMode::Strict, ScoreMode::Balanced];
    let off = modes.map(|mode| {
        let scanner = scanner(gates(None, mode));
        corpora.each_ref().map(|texts| {
            texts
                .iter()
                .map(|text| spans(&scanner, text))
                .collect::<Vec<_>>()
        })
    });
    for rule in bare_rule_ids() {
        let counts = modes.map(|mode| {
            let on = scanner(gates(Some(rule), mode));
            let off = &off[usize::from(mode == ScoreMode::Balanced)];
            [0, 1, 2].map(|i| new_spans(&on, &corpora[i], &off[i]))
        });
        let per_mb =
            |i: usize| [0, 1].map(|m| format!("{:.2}", counts[m][i] as f64 / megabytes[i]));
        let (code, docs) = (per_mb(1), per_mb(2));
        println!(
            "| `{rule}` | {} / {} | {} / {} | {} / {} |",
            counts[0][0], counts[1][0], code[0], code[1], docs[0], docs[1]
        );
    }
}
