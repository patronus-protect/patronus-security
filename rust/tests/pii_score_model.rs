//! PII score model and modes (K02).
//!
//! A span score is the rule base plus the validator strength (checksum,
//! format, none) plus its context: a field name bound by the rule, else the
//! proximity context of the K03 engine (support terms add, a nearer counter
//! term subtracts; `pii_context_engine.rs`). `strict` stays the default and
//! scores every span 1.0; `balanced` and `recall` are opt-in, report the
//! model score and drop candidates below their threshold.

use patronus_ark::detectors::pii::{
    context,
    pii::PII_PATTERNS,
    score::{self, Context, PiiMode, ValidatorStrength},
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

/// Model score of a `matched_rules` entry: field context for field rules,
/// otherwise the structural key of the matched value (K04), else its proximity
/// context.
/// Whether only the `recall` normalization (K06: spelled-out separators, spaced
/// characters) revealed the match of `rule`.
fn recall_obfuscation(rule: &serde_json::Value) -> bool {
    rule["obfuscation"].as_array().is_some_and(|kinds| {
        kinds
            .iter()
            .any(|kind| kind == "spelled_out" || kind == "spaced_digits")
    })
}

fn expected_score(text: &str, rule: &serde_json::Value) -> (f64, Context) {
    let pattern = PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule["rule_id"])
        .unwrap();
    if recall_obfuscation(rule) {
        let (plain, context) = expected_score_of(text, rule, pattern);
        let points = (plain * 100.0).round() - f64::from(score::SPELLED_OUT_PENALTY_POINTS);
        return (points.max(0.0) / 100.0, context);
    }
    expected_score_of(text, rule, pattern)
}

fn expected_score_of(
    text: &str,
    rule: &serde_json::Value,
    pattern: &patronus_ark::detectors::pii::pii::PiiPattern,
) -> (f64, Context) {
    let context = if pattern.captured_value {
        Context::Field
    } else {
        let start = rule["start_byte"].as_u64().unwrap() as usize;
        let end = rule["end_byte"].as_u64().unwrap() as usize;
        context::key_context(text, (start, end), pattern.entity_group)
            .unwrap_or_else(|| context::proximity(text, (start, end), pattern.entity_group))
    };
    (score::score(pattern, context), context)
}

#[test]
fn balanced_and_recall_keep_the_strict_spans_unless_counter_context_outranks() {
    // K03: scored modes drop a strict span only when a counter-context term is
    // nearer than any support term; every other strict span stays, with the
    // score of its rule in its context. K05: scored-only rules may add spans.
    // K06: in recall, so may spelled-out or spaced values (10 points lower).
    // K07: a span of a competing label may yield to an overlapping one.
    let strict_scanner = scanner(None);
    for mode in [PiiMode::Balanced, PiiMode::Recall] {
        let scored_scanner = scanner(with_mode(mode));
        for text in corpus() {
            let strict = scan(&strict_scanner, &text);
            let scored = scan(&scored_scanner, &text);
            if spans(&scored) == spans(&strict) {
                assert_eq!(strict.class_name, scored.class_name, "{mode:?}: {text}");
            }
            let rules = scored.layers[0]
                .details
                .get("matched_rules")
                .map(|rules| rules.as_array().unwrap().clone())
                .unwrap_or_default();
            let strict_rules = strict.layers[0]
                .details
                .get("matched_rules")
                .map(|rules| rules.as_array().unwrap().clone())
                .unwrap_or_default();
            let scored_spans = spans(&scored);
            for (span, strict_span) in strict.evidence_spans.iter().zip(spans(&strict)) {
                if scored_spans.contains(&strict_span) {
                    continue;
                }
                // K07: or it yielded to an overlapping finding of a competing label.
                if rules.iter().any(|rule| {
                    rule["start_byte"] == span.start_byte
                        && rule["end_byte"] == span.end_byte
                        && rule.get("overlap").is_some()
                }) {
                    continue;
                }
                // Every rule that reported the dropped span saw a nearer counter term.
                let reporting: Vec<_> = strict_rules
                    .iter()
                    .filter(|rule| {
                        rule["start_byte"] == span.start_byte && rule["end_byte"] == span.end_byte
                    })
                    .collect();
                assert!(!reporting.is_empty(), "{mode:?}: {text}: {span:?}");
                for rule in reporting {
                    let (score, context) = expected_score(&text, rule);
                    assert_eq!(context, Context::Counter, "{mode:?}: {text}: {rule}");
                    assert!(
                        score < mode.min_score().unwrap(),
                        "{mode:?}: {text}: {rule}"
                    );
                }
            }
            for span in &scored.evidence_spans {
                // K05: only a scored-only rule (a bare checksum value, B-SSN: a grouped
                // SSN) adds a span; K06: or the recall normalization.
                let scored_only = rules.iter().any(|rule| {
                    rule["start_byte"] == span.start_byte
                        && rule["end_byte"] == span.end_byte
                        && (PII_PATTERNS
                            .iter()
                            .any(|pattern| pattern.name == rule["rule_id"] && pattern.scored_only)
                            || (mode == PiiMode::Recall && recall_obfuscation(rule)))
                });
                assert!(
                    scored_only
                        || spans(&strict).contains(&(
                            span.label.clone(),
                            span.start_char,
                            span.end_char
                        )),
                    "{mode:?}: {text}: {span:?} not in strict"
                );
                assert!(
                    span.score >= mode.min_score().unwrap() && span.score <= 1.0,
                    "{mode:?}: {text}: {span:?}"
                );
                // The span carries the score of the rule that emitted it, and the
                // rule's context explains that score.
                assert!(
                    rules.iter().any(|rule| {
                        let points = |key: &str| rule["context"][key].as_u64().unwrap() as u8;
                        rule["start_byte"] == span.start_byte
                            && rule["end_byte"] == span.end_byte
                            && rule["score"] == span.score
                            && expected_score(&text, rule).0 == span.score
                            && i16::from(points("bonus")) - i16::from(points("penalty"))
                                == expected_score(&text, rule).1.points()
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
        let field = if pattern.captured_value {
            Context::Field
        } else {
            Context::None
        };
        assert_eq!(
            score::rule_score(pattern),
            score::score(pattern, field),
            "{}",
            pattern.name
        );
        // Counter-context floors at 0 and never exceeds the context-free score.
        let counter = score::score(pattern, Context::Counter);
        assert!(
            (0.0..=score::rule_score(pattern)).contains(&counter),
            "{}",
            pattern.name
        );
        assert!(
            (1..=100).contains(&pattern.base_score),
            "{}: base {}",
            pattern.name,
            pattern.base_score
        );
        // Context-bound rules emit only with support (pii_context_engine.rs).
        assert!(
            pattern.requires_context
                || score::rule_score(pattern) >= PiiMode::Balanced.min_score().unwrap(),
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
            "pii_steuer_id_de",
            "pii_steuer_id_de_context_free",
            "pii_vat_id_de",
            "pii_vat_id_at",
            "pii_vat_id_ch",
            "pii_vat_id_fr",
            "pii_vat_id_nl",
            "pii_vat_id_be",
            "pii_vat_id_it",
            "pii_vat_id_it_proximity",
            "pii_vat_id_es",
            "pii_vat_id_lu",
            "pii_vat_id_lv",
            "pii_vat_id_mt",
            "pii_vat_id_pl",
            "pii_vat_id_pt",
            "pii_vat_id_ro",
            "pii_vat_id_se",
            "pii_vat_id_si",
            "pii_vat_id_sk",
            "pii_vat_id_no",
            "pii_vat_id_gb",
            "pii_passport_number_de_context_free",
            "pii_passport_number_de_legacy",
            "pii_identity_card_number_de_context_free",
            "pii_identity_card_number_de_legacy",
            "pii_vat_id_bg",
            "pii_vat_id_cy",
            "pii_vat_id_cz",
            "pii_vat_id_dk",
            "pii_vat_id_ee",
            "pii_vat_id_el",
            "pii_vat_id_fi",
            "pii_vat_id_hr",
            "pii_vat_id_hu",
            "pii_vat_id_ie",
            "pii_vat_id_lt"
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
        ("pii_steuer_id_de_context_free", 0.55),
        ("pii_rentenversicherung_de", 0.90),
        ("pii_kfz_kennzeichen_de", 0.65),
        ("pii_ssn_us", 0.85),
        ("pii_ssn_us_context_free", 0.50),
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
    // 0.90 without context; the "IBAN" term right before it adds 25 (K03).
    assert_eq!(score_of("IBAN"), 1.0);
    assert_eq!(score_of("LICENSEPLATE"), 0.65);
    // 0.55 without context; "Tel." right before it adds 25.
    assert_eq!(score_of("PHONE"), 0.8);
    assert!(score_of("STEUERID") > score_of("LICENSEPLATE"));
    assert!(score_of("IBAN") > score_of("PHONE"));
    assert_eq!(result.confidence, 1.0);

    // Without field names the checksum value still outranks the format value.
    let bare = pii_result(
        "DE89370400440532013000 und +1 415 555 0101",
        with_mode(PiiMode::Balanced),
    );
    let bare_score = |label: &str| {
        bare.evidence_spans
            .iter()
            .find(|span| span.label == label)
            .unwrap_or_else(|| panic!("{label} missing: {:?}", bare.evidence_spans))
            .score
    };
    assert_eq!(bare_score("IBAN"), 0.9);
    assert_eq!(bare_score("PHONE"), 0.55);

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
