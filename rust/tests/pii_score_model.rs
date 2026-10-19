//! PII score model and modes (K02).
//!
//! A span score is the rule base plus the validator strength (checksum,
//! format, none) plus a context bonus for a field name bound by the rule.
//! `strict` stays the default and keeps the previous output bit for bit
//! (every span 1.0); `balanced` and `recall` are opt-in, report the model
//! score and drop candidates below their threshold.

use patronus_ark::detectors::pii::{
    pii::PII_PATTERNS,
    score::{self, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

fn scanner(gates: Option<ScanGateMatrix>) -> SecurityGateway {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    if let Some(gates) = gates {
        scanner.set_execution_gates(gates);
    }
    scanner
}

fn scan(scanner: &SecurityGateway, text: &str) -> SecurityScanResult {
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

fn pii_result(text: &str, gates: Option<ScanGateMatrix>) -> SecurityScanResult {
    scan(&scanner(gates), text)
}

fn with_mode(mode: PiiMode) -> Option<ScanGateMatrix> {
    Some(ScanGateMatrix {
        pii_mode: mode,
        ..Default::default()
    })
}

fn spans(result: &SecurityScanResult) -> Vec<(String, usize, usize)> {
    result
        .evidence_spans
        .iter()
        .map(|span| (span.label.clone(), span.start_char, span.end_char))
        .collect()
}

fn comparable(result: &SecurityScanResult) -> serde_json::Value {
    serde_json::json!({
        "class_name": result.class_name,
        "confidence": result.confidence,
        "evidence_spans": result.evidence_spans,
        "details": result.layers[0].details,
    })
}

fn corpus() -> Vec<String> {
    let mut texts = Vec::new();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    for case in fixture.as_array().unwrap() {
        if case["category"] == "pii" {
            for language in ["de", "en"] {
                texts.push(case[language].as_str().unwrap().to_string());
            }
        }
    }
    let goldens = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/pii_l1.jsonl");
    for line in std::fs::read_to_string(goldens).unwrap().lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        texts.push(row["text"].as_str().unwrap().to_string());
    }
    texts
}

fn rule_score(rule_id: &str) -> f64 {
    let pattern = PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"));
    score::rule_score(pattern)
}

#[test]
fn strict_is_the_default_mode() {
    assert_eq!(PiiMode::default(), PiiMode::Strict);
    assert_eq!(ScanGateMatrix::default().pii_mode, PiiMode::Strict);
    assert_eq!(
        ScanGateMatrix::levels(true, false, false).pii_mode,
        PiiMode::Strict
    );
    assert_eq!(ScanGateMatrix::all_enabled().pii_mode, PiiMode::Strict);
}

#[test]
fn modes_parse_from_their_public_names_only() {
    for (name, mode) in [
        ("strict", PiiMode::Strict),
        ("balanced", PiiMode::Balanced),
        ("recall", PiiMode::Recall),
    ] {
        assert_eq!(name.parse::<PiiMode>().unwrap(), mode);
        assert_eq!(mode.as_str(), name);
        assert_eq!(serde_json::to_value(mode).unwrap(), name);
        assert_eq!(
            serde_json::from_value::<PiiMode>(serde_json::json!(name)).unwrap(),
            mode
        );
    }
    for invalid in ["", "Strict", "precision", "balanced "] {
        assert!(invalid.parse::<PiiMode>().is_err(), "{invalid:?}");
    }
    assert!(serde_json::from_value::<PiiMode>(serde_json::json!("fast")).is_err());
}

#[test]
fn mode_thresholds_order_strict_balanced_recall() {
    assert_eq!(PiiMode::Strict.min_score(), None);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    let recall = PiiMode::Recall.min_score().unwrap();
    assert_eq!(balanced, 0.5);
    assert_eq!(recall, 0.3);
    assert!(recall < balanced);
}

#[test]
fn strict_explicit_and_default_are_bit_identical_on_every_golden() {
    let default_scanner = scanner(None);
    let strict_scanner = scanner(with_mode(PiiMode::Strict));
    for text in corpus() {
        let default = scan(&default_scanner, &text);
        let strict = scan(&strict_scanner, &text);
        assert_eq!(comparable(&default), comparable(&strict), "{text}");
        assert_eq!(default.confidence, 1.0, "{text}");
        for span in &default.evidence_spans {
            assert_eq!(span.score, 1.0, "{text}: {span:?}");
        }
        if let Some(rules) = default.layers[0].details.get("matched_rules") {
            for rule in rules.as_array().unwrap() {
                assert!(rule.get("score").is_none(), "{text}: {rule}");
            }
        }
    }
}

#[test]
fn balanced_and_recall_keep_the_strict_spans_and_report_model_scores() {
    // K02 adds no candidates: every rule scores at least the balanced threshold,
    // so both opt-in modes return the strict spans with their model scores.
    let strict_scanner = scanner(None);
    for mode in [PiiMode::Balanced, PiiMode::Recall] {
        let scored_scanner = scanner(with_mode(mode));
        for text in corpus() {
            let strict = scan(&strict_scanner, &text);
            let scored = scan(&scored_scanner, &text);
            assert_eq!(spans(&strict), spans(&scored), "{mode:?}: {text}");
            assert_eq!(strict.class_name, scored.class_name, "{mode:?}: {text}");
            let rules = scored.layers[0]
                .details
                .get("matched_rules")
                .map(|rules| rules.as_array().unwrap().clone())
                .unwrap_or_default();
            for span in &scored.evidence_spans {
                assert!(
                    span.score >= mode.min_score().unwrap() && span.score <= 1.0,
                    "{mode:?}: {text}: {span:?}"
                );
                // The span carries the score of the rule that emitted it.
                assert!(
                    rules.iter().any(|rule| {
                        rule["start_byte"] == span.start_byte
                            && rule["end_byte"] == span.end_byte
                            && rule["score"] == span.score
                            && score::rule_score(
                                PII_PATTERNS
                                    .iter()
                                    .find(|pattern| pattern.name == rule["rule_id"])
                                    .unwrap(),
                            ) == span.score
                    }),
                    "{mode:?}: {text}: {span:?} not in {rules:?}"
                );
            }
            let best = scored
                .evidence_spans
                .iter()
                .map(|span| span.score)
                .reduce(f64::max);
            match best {
                Some(best) => assert_eq!(scored.confidence, best, "{mode:?}: {text}"),
                None if scored.class_name == "safe" => {
                    assert_eq!(scored.confidence, 1.0, "{mode:?}: {text}")
                }
                // Post-prediction hooks (e.g. link-local addresses) removed every
                // span; the confidence stays with the finding that set class_name.
                None => assert!(
                    scored.confidence >= mode.min_score().unwrap() && scored.confidence <= 1.0,
                    "{mode:?}: {text}"
                ),
            }
            assert_eq!(
                scored.layers[0].confidence, scored.confidence,
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn score_is_base_plus_validator_strength_plus_field_context() {
    assert_eq!(ValidatorStrength::Checksum.points(), 35);
    assert_eq!(ValidatorStrength::Format.points(), 15);
    assert_eq!(ValidatorStrength::None.points(), 0);
    assert_eq!(score::FIELD_CONTEXT_POINTS, 25);
    for pattern in PII_PATTERNS {
        let context = if pattern.captured_value {
            score::FIELD_CONTEXT_POINTS
        } else {
            0
        };
        let points = (u16::from(pattern.base_score)
            + u16::from(pattern.strength.points())
            + u16::from(context))
        .min(100);
        assert_eq!(
            score::rule_score(pattern),
            f64::from(points) / 100.0,
            "{}",
            pattern.name
        );
        assert!(
            (1..=100).contains(&pattern.base_score),
            "{}: base {}",
            pattern.name,
            pattern.base_score
        );
        assert!(
            score::rule_score(pattern) >= PiiMode::Balanced.min_score().unwrap(),
            "{} would change balanced output",
            pattern.name
        );
        assert_eq!(
            pattern.validator.is_none(),
            pattern.strength == ValidatorStrength::None,
            "{}: strength {:?}",
            pattern.name,
            pattern.strength
        );
    }
}

#[test]
fn checksum_strength_is_reserved_for_real_check_digits() {
    // Same classification as `checksums.ark` in research/l1-pii/entity_map.yaml
    // (enforced there by count_validated.py check).
    let checksum: Vec<_> = PII_PATTERNS
        .iter()
        .filter(|pattern| pattern.strength == ValidatorStrength::Checksum)
        .map(|pattern| pattern.name)
        .collect();
    assert_eq!(
        checksum,
        [
            "pii_iban_de",
            "pii_iban_generic",
            "pii_credit_card",
            "pii_steuer_id_de"
        ]
    );
}

#[test]
fn reference_scores_per_rule() {
    for (rule_id, expected) in [
        ("pii_email", 0.70),
        ("pii_ipv4", 0.65),
        ("pii_phone_us", 0.50),
        ("pii_phone_de_national_context", 0.70),
        ("pii_iban_de", 0.90),
        ("pii_iban_generic", 0.80),
        ("pii_credit_card", 0.75),
        ("pii_credit_card_cvv", 0.60),
        ("pii_steuer_id_de", 1.00),
        ("pii_rentenversicherung_de", 0.90),
        ("pii_kfz_kennzeichen_de", 0.65),
        ("pii_ssn_us", 0.85),
    ] {
        assert_eq!(rule_score(rule_id), expected, "{rule_id}");
    }
}

#[test]
fn checksum_vectors_decide_emission_in_every_mode() {
    // Valid and invalid check digits: the score model never relaxes a validator.
    for (valid, invalid, label, validator) in [
        (
            "Card: 4111 1111 1111 1111",
            "Card: 4111 1111 1111 1112",
            "CREDITCARD",
            validators::luhn as fn(&str) -> bool,
        ),
        (
            "IBAN: DE89370400440532013000",
            "IBAN: DE88370400440532013000",
            "IBAN",
            validators::mod97,
        ),
        (
            "Steuer-ID: 86095742719",
            "Steuer-ID: 86095742718",
            "STEUERID",
            validators::steuer_id,
        ),
    ] {
        let value = |text: &str| text.split_once(": ").unwrap().1.to_string();
        assert!(validator(&value(valid)), "{valid}");
        assert!(!validator(&value(invalid)), "{invalid}");
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            let found = pii_result(valid, with_mode(mode));
            assert!(
                found.evidence_spans.iter().any(|span| span.label == label),
                "{mode:?}: {valid}"
            );
            let rejected = pii_result(invalid, with_mode(mode));
            assert!(
                rejected
                    .evidence_spans
                    .iter()
                    .all(|span| span.label != label),
                "{mode:?}: {invalid}"
            );
        }
    }
}

#[test]
fn balanced_scores_rank_checksum_values_above_format_values() {
    let text = "Steuer-ID: 86095742719, IBAN: DE89370400440532013000, Kennzeichen: B-AB 1234, Tel. +1 415 555 0101";
    let result = pii_result(text, with_mode(PiiMode::Balanced));
    let score_of = |label: &str| {
        result
            .evidence_spans
            .iter()
            .find(|span| span.label == label)
            .unwrap_or_else(|| panic!("{label} missing: {:?}", result.evidence_spans))
            .score
    };
    assert_eq!(score_of("STEUERID"), 1.0);
    assert_eq!(score_of("IBAN"), 0.9);
    assert_eq!(score_of("LICENSEPLATE"), 0.65);
    assert!(score_of("STEUERID") > score_of("LICENSEPLATE"));
    assert!(score_of("IBAN") > score_of("PHONE"));
    assert_eq!(result.confidence, 1.0);

    let strict = pii_result(text, None);
    assert!(strict.evidence_spans.iter().all(|span| span.score == 1.0));
}

#[test]
fn safe_text_stays_safe_in_every_mode() {
    for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
        let result = pii_result("The quarterly report is attached.", with_mode(mode));
        assert_eq!(result.class_name, "safe");
        assert_eq!(result.confidence, 1.0);
        assert!(result.evidence_spans.is_empty());
    }
}
