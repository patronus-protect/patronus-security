//! DLP score model and modes (K04), on the PII score model (PII K02/K03).
//!
//! A span score is the rule base plus the validator strength (checksum,
//! structure, format, none) plus its context: the field name a value-capturing
//! rule binds, else for secrets without a field name the nearest DE/EN term on
//! the line (a credential term adds, a nearer digest/hash/ID term subtracts).
//! `strict` stays the default and scores every span 1.0; `balanced` and
//! `recall` are opt-in, report the model score and drop candidates below the
//! PII thresholds.

use std::{path::Path, sync::OnceLock};

use patronus_ark::detectors::dlp::{
    context::{self, ContextSource},
    dlp::{ValidatorStrength, DLP_PATTERNS},
    score::{self, DlpMode},
};
use patronus_ark::detectors::pii::score::{
    Context, PiiMode, ValidatorStrength as PiiStrength, COUNTER_CONTEXT_POINTS,
    FIELD_CONTEXT_POINTS,
};
use patronus_ark::golden_recipes::{
    materialize, materialize_fragments, GeneratorSet, SecretRecipe,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;

/// Default-on credential/secret groups (`dlp.rs`).
const SECRET_GROUPS: &[&str] = &[
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
];

fn scanner(gates: Option<ScanGateMatrix>) -> SecurityGateway {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
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
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

fn with_mode(mode: DlpMode) -> ScanGateMatrix {
    ScanGateMatrix {
        dlp_mode: mode,
        ..ScanGateMatrix::all_enabled()
    }
}

/// One gateway per mode for the whole test binary: building one compiles every regex.
fn mode_scanner(mode: DlpMode) -> &'static SecurityGateway {
    static SCANNERS: OnceLock<[SecurityGateway; 3]> = OnceLock::new();
    let scanners = SCANNERS.get_or_init(|| {
        [DlpMode::Strict, DlpMode::Balanced, DlpMode::Recall]
            .map(|mode| scanner(Some(with_mode(mode))))
    });
    &scanners[mode as usize]
}

fn dlp_result(text: &str, mode: DlpMode) -> SecurityScanResult {
    scan(mode_scanner(mode), text)
}

fn matched_rules(result: &SecurityScanResult) -> Vec<serde_json::Value> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .cloned()
        .unwrap_or_default()
}

fn rule<'a>(rules: &'a [serde_json::Value], rule_id: &str) -> Option<&'a serde_json::Value> {
    rules.iter().find(|rule| rule["rule_id"] == rule_id)
}

fn span_of(result: &SecurityScanResult, rule: &serde_json::Value) -> Option<f64> {
    let (start, end) = (
        rule["start_byte"].as_u64().unwrap() as usize,
        rule["end_byte"].as_u64().unwrap() as usize,
    );
    result
        .evidence_spans
        .iter()
        .find(|span| span.start_byte == start && span.end_byte == end)
        .map(|span| span.score)
}

fn comparable(result: &SecurityScanResult) -> serde_json::Value {
    serde_json::json!({
        "class_name": result.class_name,
        "confidence": result.confidence,
        "evidence_spans": result.evidence_spans,
        "details": result.layers[0].details,
    })
}

fn generators() -> GeneratorSet {
    GeneratorSet::load(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../python/patronus_ark/dlp_synth/generators.json"),
    )
    .expect("generator spec must load")
}

fn value(generators: &GeneratorSet, template: &str, generator: &str, seed: u64) -> String {
    materialize(generators, template, &[SecretRecipe::new(generator, seed)])
        .unwrap()
        .0
}

#[derive(Deserialize)]
struct Probes {
    de: String,
    en: String,
}

#[derive(Deserialize)]
struct BalancedProbes {
    context: Probes,
    counter: Option<Probes>,
}

#[derive(Deserialize)]
struct Case {
    category: String,
    rule_id: String,
    de: String,
    en: String,
    #[serde(default)]
    secrets: Vec<SecretRecipe>,
    #[serde(default)]
    hard_negatives: std::collections::BTreeMap<String, Vec<String>>,
    balanced: Option<BalancedProbes>,
}

fn fixture() -> Vec<Case> {
    serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap()
}

fn materialized(generators: &GeneratorSet, case: &Case, template: &str) -> String {
    if case.secrets.is_empty() {
        return template.to_owned();
    }
    materialize(generators, template, &case.secrets)
        .unwrap_or_else(|error| panic!("{}: {error}", case.rule_id))
        .0
}

#[derive(Deserialize)]
struct GoldenRow {
    text: Option<String>,
    template: Option<String>,
    secrets: Option<Vec<SecretRecipe>>,
}

/// DLP texts of the bilingual rule fixture (rules, lookalikes, probes) and of
/// every `dlp_l1` golden, materialized from their recipes.
fn corpus() -> Vec<String> {
    let generators = generators();
    let mut texts = Vec::new();
    for case in fixture().iter().filter(|case| case.category == "dlp") {
        let mut templates = vec![case.de.clone(), case.en.clone()];
        // Hard negatives are plain text, also in cases with secret recipes.
        texts.extend(case.hard_negatives.values().flatten().cloned());
        if let Some(probes) = &case.balanced {
            templates.extend([probes.context.de.clone(), probes.context.en.clone()]);
            if let Some(counter) = &probes.counter {
                templates.extend([counter.de.clone(), counter.en.clone()]);
            }
        }
        texts.extend(
            templates
                .iter()
                .map(|template| materialized(&generators, case, template)),
        );
    }
    let goldens = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/dlp_l1.jsonl");
    for line in std::fs::read_to_string(goldens).unwrap().lines() {
        let row: GoldenRow = serde_json::from_str(line).unwrap();
        texts.push(match (row.text, row.template, row.secrets) {
            (Some(text), None, None) => text,
            (None, Some(template), Some(secrets)) => {
                materialize_fragments(&generators, &template, &secrets)
                    .unwrap()
                    .0
            }
            _ => panic!("golden row needs text or template + secrets"),
        });
    }
    texts
}

fn pattern(rule_id: &str) -> &'static patronus_ark::detectors::dlp::dlp::DlpPattern {
    DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

#[test]
fn strict_is_the_default_mode() {
    assert_eq!(DlpMode::default(), DlpMode::Strict);
    assert_eq!(ScanGateMatrix::default().dlp_mode, DlpMode::Strict);
    assert_eq!(
        ScanGateMatrix::levels(true, false, false).dlp_mode,
        DlpMode::Strict
    );
    assert_eq!(ScanGateMatrix::all_enabled().dlp_mode, DlpMode::Strict);
}

#[test]
fn modes_parse_explicitly_and_share_the_pii_thresholds() {
    for (name, mode) in [
        ("strict", DlpMode::Strict),
        ("balanced", DlpMode::Balanced),
        ("recall", DlpMode::Recall),
    ] {
        assert_eq!(name.parse::<DlpMode>().unwrap(), mode);
        assert_eq!(mode.as_str(), name);
        assert_eq!(
            serde_json::from_value::<DlpMode>(serde_json::json!(name)).unwrap(),
            mode
        );
        assert_eq!(serde_json::to_value(mode).unwrap(), serde_json::json!(name));
    }
    for invalid in ["", "Strict", "precision", "balanced "] {
        assert!(invalid.parse::<DlpMode>().is_err(), "{invalid:?}");
    }
    assert!(serde_json::from_value::<DlpMode>(serde_json::json!("fast")).is_err());
    assert_eq!(DlpMode::Strict.min_score(), None);
    assert_eq!(DlpMode::Balanced.min_score(), PiiMode::Balanced.min_score());
    assert_eq!(DlpMode::Recall.min_score(), PiiMode::Recall.min_score());
    assert_eq!(DlpMode::Balanced.min_score(), Some(0.5));
    assert_eq!(DlpMode::Recall.min_score(), Some(0.3));
}

#[test]
fn strict_output_is_the_unscored_rule_acceptance() {
    let default = scanner(Some(ScanGateMatrix::all_enabled()));
    let strict = mode_scanner(DlpMode::Strict);
    let unset = scanner(None);
    let explicit = scanner(Some(ScanGateMatrix {
        dlp_mode: DlpMode::Strict,
        ..ScanGateMatrix::default()
    }));
    let texts = corpus();
    assert!(texts.len() > 700, "{} texts", texts.len());
    for text in &texts {
        let result = scan(strict, text);
        assert_eq!(
            comparable(&scan(&default, text)),
            comparable(&result),
            "{text}"
        );
        assert_eq!(
            comparable(&scan(&unset, text)),
            comparable(&scan(&explicit, text)),
            "{text}"
        );
        assert!(
            result.evidence_spans.iter().all(|span| span.score == 1.0),
            "{text}"
        );
        assert!(
            matched_rules(&result)
                .iter()
                .all(|rule| rule.get("score").is_none() && rule.get("context").is_none()),
            "{text}"
        );
    }
}

#[test]
fn scored_modes_keep_strict_spans_and_report_the_model_score() {
    for text in corpus() {
        let strict = dlp_result(&text, DlpMode::Strict);
        let strict_spans: Vec<_> = strict
            .evidence_spans
            .iter()
            .map(|span| (span.label.clone(), span.start_byte, span.end_byte))
            .collect();
        for mode in [DlpMode::Balanced, DlpMode::Recall] {
            let threshold = mode.min_score().unwrap();
            let scored = dlp_result(&text, mode);
            let rules = matched_rules(&scored);
            for span in &scored.evidence_spans {
                assert!(
                    strict_spans.contains(&(span.label.clone(), span.start_byte, span.end_byte)),
                    "{mode:?}: {text}: {span:?} not in strict"
                );
                assert!(span.score >= threshold, "{mode:?}: {text}: {span:?}");
            }
            for entry in &rules {
                let pattern = pattern(entry["rule_id"].as_str().unwrap());
                let entry_score = entry["score"].as_f64().unwrap();
                let points = |field: &str| entry["context"][field].as_u64().unwrap() as i16;
                let context_points = points("bonus") - points("penalty");
                let expected = (i16::from(pattern.base_score)
                    + i16::from(pattern.meta.validator_strength.points())
                    + context_points)
                    .clamp(0, 100);
                assert_eq!(
                    entry_score,
                    f64::from(expected) / 100.0,
                    "{mode:?}: {text}: {entry}"
                );
                assert!(entry_score >= threshold, "{mode:?}: {text}: {entry}");
                if let Some(span_score) = span_of(&scored, entry) {
                    // Several rules may report one span; it keeps the first rule's score.
                    assert!(span_score >= threshold, "{mode:?}: {text}");
                }
                if context::source(pattern) == ContextSource::Field {
                    assert_eq!(entry["context"]["anchor"], "field", "{text}: {entry}");
                }
            }
            match scored
                .evidence_spans
                .iter()
                .map(|span| span.score)
                .reduce(f64::max)
            {
                Some(best) => assert_eq!(scored.confidence, best, "{mode:?}: {text}"),
                None => assert_eq!(scored.class_name, "safe", "{mode:?}: {text}"),
            }
            assert_eq!(
                scored.layers[0].confidence, scored.confidence,
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn score_is_base_plus_validator_strength_plus_context() {
    assert_eq!(
        ValidatorStrength::Checksum.points(),
        PiiStrength::Checksum.points()
    );
    assert_eq!(
        ValidatorStrength::Format.points(),
        PiiStrength::Format.points()
    );
    assert_eq!(ValidatorStrength::None.points(), PiiStrength::None.points());
    assert_eq!(ValidatorStrength::Structure.points(), 25);
    assert!(ValidatorStrength::Structure.points() > ValidatorStrength::Format.points());
    assert!(ValidatorStrength::Structure.points() < ValidatorStrength::Checksum.points());
    let balanced = DlpMode::Balanced.min_score().unwrap();
    let recall = DlpMode::Recall.min_score().unwrap();
    for pattern in DLP_PATTERNS {
        assert!(
            (1..=100).contains(&pattern.base_score),
            "{}: base {}",
            pattern.name,
            pattern.base_score
        );
        let source = context::source(pattern);
        let context = if source == ContextSource::Field {
            FIELD_CONTEXT_POINTS
        } else {
            0
        };
        let points = (u16::from(pattern.base_score)
            + u16::from(pattern.meta.validator_strength.points())
            + u16::from(context))
        .min(100);
        assert_eq!(
            score::rule_score(pattern),
            f64::from(points) / 100.0,
            "{}",
            pattern.name
        );
        let counter = score::score(pattern, Context::Counter);
        assert!(
            (0.0..=score::rule_score(pattern)).contains(&counter),
            "{}",
            pattern.name
        );
        match source {
            // A field name or a content class keeps every strict finding in balanced.
            ContextSource::Field | ContextSource::None => assert!(
                score::rule_score(pattern) >= balanced,
                "{} would change balanced output",
                pattern.name
            ),
            // Without a field name: recall keeps every finding without counter
            // context, and a nearer counter term drops every provider token
            // from balanced; only a complete PEM block outweighs it.
            ContextSource::Proximity => {
                assert!(
                    score::rule_score(pattern) >= recall,
                    "{} would change recall output",
                    pattern.name
                );
                assert_eq!(
                    counter < balanced,
                    pattern.name != "dlp_private_key_block",
                    "{}",
                    pattern.name
                );
                assert!(
                    score::score(pattern, Context::Support { gap: 0 }) >= balanced,
                    "{}",
                    pattern.name
                );
            }
        }
    }
    assert_eq!(COUNTER_CONTEXT_POINTS, 30);
}

#[test]
fn context_source_follows_the_rule_shape() {
    for pattern in DLP_PATTERNS {
        let content = pattern.entity_group.starts_with("dlp.content.")
            || pattern.entity_group.starts_with("dlp.internal.");
        let expected = if content {
            ContextSource::None
        } else if pattern.span_group.is_some() {
            ContextSource::Field
        } else if SECRET_GROUPS.contains(&pattern.entity_group) {
            ContextSource::Proximity
        } else {
            ContextSource::None
        };
        assert_eq!(context::source(pattern), expected, "{}", pattern.name);
    }
    for (rule_id, expected) in [
        ("dlp_password_assignment", ContextSource::Field),
        ("dlp_aws_secret_key", ContextSource::Field),
        ("dlp_url_userinfo_password", ContextSource::Field),
        ("dlp_github_token", ContextSource::Proximity),
        ("dlp_eth_private_key", ContextSource::Proximity),
        ("dlp_private_key_block", ContextSource::Proximity),
        ("dlp_jwt_token", ContextSource::Proximity),
        ("dlp_sql_statement", ContextSource::None),
        ("dlp_source_code_fence", ContextSource::None),
    ] {
        assert_eq!(context::source(pattern(rule_id)), expected, "{rule_id}");
    }
}

#[test]
fn proximity_decides_secrets_without_a_field_name() {
    let generators = generators();
    let eth = |template: &str| value(&generators, template, "eth_private_key_hex", 11);
    let eth_rule = pattern("dlp_eth_private_key");
    let score_of = |text: &str, mode: DlpMode| {
        rule(
            &matched_rules(&dlp_result(text, mode)),
            "dlp_eth_private_key",
        )
        // Strict entries carry no score.
        .map(|rule| {
            (
                rule["score"].as_f64().unwrap_or(1.0),
                rule["context"].clone(),
            )
        })
    };

    // Bare: no key context, so F01 drops it in every mode.
    let bare = eth("<<secret:0>>");
    for mode in [DlpMode::Strict, DlpMode::Balanced, DlpMode::Recall] {
        assert!(score_of(&bare, mode).is_none(), "{mode:?}");
    }
    // A bare WIF key: its Base58Check checksum (F02) carries it into balanced
    // without any context term.
    let wif = value(
        &generators,
        "<<secret:0>>",
        "btc_wif_mainnet_compressed",
        11,
    );
    let wif_score = |mode: DlpMode| {
        rule(&matched_rules(&dlp_result(&wif, mode)), "dlp_btc_wif").map(|rule| {
            (
                rule["score"].as_f64().unwrap_or(1.0),
                rule["context"].clone(),
            )
        })
    };
    assert!(wif_score(DlpMode::Strict).is_some());
    for mode in [DlpMode::Balanced, DlpMode::Recall] {
        let (score, context) = wif_score(mode).unwrap();
        assert_eq!(score, score::score(pattern("dlp_btc_wif"), Context::None));
        assert_eq!(context, serde_json::json!({"bonus": 0, "penalty": 0}));
    }

    // A credential term before or after the value supports it.
    for (template, anchor, side, distance) in [
        (
            "Wallet private key: <<secret:0>>",
            "dlp.private_key",
            "before",
            2,
        ),
        (
            "Privater Schlüssel der Wallet: <<secret:0>>",
            "dlp.private_key",
            "before",
            13,
        ),
        (
            "<<secret:0>> (privater Schlüssel)",
            "dlp.private_key",
            "after",
            2,
        ),
    ] {
        let text = eth(template);
        let (balanced, context) = score_of(&text, DlpMode::Balanced).expect(template);
        let gap = Context::Support { gap: distance };
        assert_eq!(balanced, score::score(eth_rule, gap), "{template}");
        assert_eq!(context["anchor"], anchor, "{template}");
        assert_eq!(context["side"], side, "{template}");
        assert_eq!(context["distance"], distance, "{template}");
        assert_eq!(context["bonus"], gap.points(), "{template}");
    }

    // A nearer digest/hash term marks a hash, not a key: dropped in every mode (F01).
    for template in [
        "tx hash: <<secret:0>>",
        "Transaktionshash <<secret:0>>",
        "Prüfsumme der Datei: <<secret:0>>",
        "<<secret:0>> (sha256 checksum)",
        "private key? no, block hash: <<secret:0>>",
    ] {
        let text = eth(template);
        assert!(score_of(&text, DlpMode::Strict).is_none(), "{template}");
        assert!(score_of(&text, DlpMode::Balanced).is_none(), "{template}");
        assert!(score_of(&text, DlpMode::Recall).is_none(), "{template}");
        let result = dlp_result(&text, DlpMode::Recall);
        assert!(result.evidence_spans.is_empty(), "{template}");
    }
    // A hex hash dropped for its context does not free its range for a
    // shorter match inside it, in no mode.
    for seed in (1..=48).chain([8016]) {
        let text = value(
            &generators,
            "Transaktionshash: <<secret:0>>",
            "eth_private_key_hex",
            seed,
        );
        for mode in [DlpMode::Strict, DlpMode::Balanced, DlpMode::Recall] {
            let scored = dlp_result(&text, mode);
            assert!(scored.evidence_spans.is_empty(), "{mode:?}: {text}");
            assert_eq!(scored.class_name, "safe", "{mode:?}: {text}");
            // As in strict, `matched_rules` keeps a match that lost the overlap.
            assert!(
                rule(&matched_rules(&scored), "dlp_eth_private_key").is_none(),
                "{mode:?}: {text}"
            );
        }
    }

    // A support term nearer than the counter term wins.
    let text = eth("checksum ok, private key <<secret:0>>");
    let (_, context) = score_of(&text, DlpMode::Balanced).unwrap();
    assert_eq!(context["anchor"], "dlp.private_key");

    // A provider token keeps balanced without context, and only a counter term drops it.
    let token = |template: &str| value(&generators, template, "openai_project_key", 5);
    let openai = |text: &str, mode: DlpMode| {
        rule(&matched_rules(&dlp_result(text, mode)), "dlp_openai_key")
            .map(|rule| rule["score"].as_f64().unwrap_or(1.0))
    };
    let plain = token("model: gpt\nkey <<secret:0>>");
    assert_eq!(openai(&plain, DlpMode::Balanced), Some(0.7));
    let counter = token("request id <<secret:0>>");
    assert_eq!(openai(&counter, DlpMode::Balanced), None);
    assert_eq!(openai(&counter, DlpMode::Recall), Some(0.4));
    assert!(openai(&counter, DlpMode::Strict).is_some());
}

#[test]
fn field_rules_score_their_field_name() {
    let text = "db:\n  password: Sommer2026!x\n";
    for mode in [DlpMode::Balanced, DlpMode::Recall] {
        let result = dlp_result(text, mode);
        let rules = matched_rules(&result);
        let entry = rule(&rules, "dlp_password_assignment").expect("password");
        assert_eq!(
            entry["score"].as_f64().unwrap(),
            score::rule_score(pattern("dlp_password_assignment"))
        );
        assert_eq!(
            entry["context"],
            serde_json::json!({"bonus": FIELD_CONTEXT_POINTS, "penalty": 0, "anchor": "field"})
        );
        // Rule metadata v2 stays next to the score.
        assert_eq!(entry["validator_strength"], "none");
        assert_eq!(result.confidence, 0.6);
    }
    // A counter term next to a field-bound value does not count: the key names it.
    let text = "checksum password = Sommer2026!x";
    let rules = matched_rules(&dlp_result(text, DlpMode::Balanced));
    assert!(rule(&rules, "dlp_password_assignment").is_some());
}

#[test]
fn bilingual_rule_fixture_probes_context_and_counter_context() {
    let generators = generators();
    let cases = fixture();
    let probed: Vec<_> = cases
        .iter()
        .filter(|case| case.category == "dlp")
        .filter_map(|case| case.balanced.as_ref().map(|probes| (case, probes)))
        .collect();
    assert!(probed.len() >= 5, "{} probed rules", probed.len());
    assert!(probed.iter().any(|(_, probes)| probes.counter.is_some()));
    for (case, probes) in probed {
        for template in [&probes.context.de, &probes.context.en] {
            let text = materialized(&generators, case, template);
            let result = dlp_result(&text, DlpMode::Balanced);
            let rules = matched_rules(&result);
            let matched =
                rule(&rules, &case.rule_id).unwrap_or_else(|| panic!("{}: {text}", case.rule_id));
            assert!(
                matched["context"]["bonus"].as_u64().unwrap() > 0,
                "{}: {text}: {matched}",
                case.rule_id
            );
        }
        if let Some(counter) = &probes.counter {
            for template in [&counter.de, &counter.en] {
                let text = materialized(&generators, case, template);
                // F01: a rule with a context gate drops it already in strict.
                let gated = pattern(&case.rule_id).meta.context_gate.is_some();
                let strict = matched_rules(&dlp_result(&text, DlpMode::Strict));
                assert_eq!(
                    rule(&strict, &case.rule_id).is_some(),
                    !gated,
                    "strict {}: {text}",
                    case.rule_id
                );
                let balanced = matched_rules(&dlp_result(&text, DlpMode::Balanced));
                assert!(
                    rule(&balanced, &case.rule_id).is_none(),
                    "balanced {}: {text}",
                    case.rule_id
                );
            }
        }
    }
}
