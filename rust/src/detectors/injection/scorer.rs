// SPDX-License-Identifier: GPL-3.0-only
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;

use super::candidate::L1Candidate;

const SCORER_JSON: &str = include_str!("rules/l1_scorer_0_1_6.json");

#[derive(Debug, Deserialize)]
pub(crate) struct L1ScorerConfig {
    pub schema_version: u32,
    pub model_id: String,
    pub score_version: String,
    pub feature_order: Vec<String>,
    pub coefficients: Vec<f64>,
    pub intercept: f64,
    pub acceptance_threshold: f64,
    pub golden_cases: Vec<L1ScorerGoldenCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct L1ScorerGoldenCase {
    pub name: String,
    pub features: Vec<f64>,
    pub expected_score: f64,
    pub expected_accepted: bool,
}

#[derive(Debug)]
pub(crate) struct L1CandidateScore {
    pub score: f64,
    pub accepted: bool,
    pub features: HashMap<String, f64>,
}

pub(crate) fn scorer_config() -> &'static L1ScorerConfig {
    static CONFIG: OnceLock<L1ScorerConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let config: L1ScorerConfig =
            serde_json::from_str(SCORER_JSON).expect("embedded Injection L1 scorer must parse");
        assert_eq!(config.schema_version, 1, "unsupported L1 scorer schema");
        assert_eq!(
            config.feature_order.len(),
            config.coefficients.len(),
            "L1 scorer feature and coefficient counts must match"
        );
        assert!(
            (0.0..=1.0).contains(&config.acceptance_threshold),
            "L1 scorer acceptance threshold must be a probability"
        );
        let mut names = HashSet::new();
        for name in &config.feature_order {
            assert!(names.insert(name), "duplicate L1 scorer feature: {name}");
            assert!(
                supported_feature(name),
                "unsupported L1 scorer feature: {name}"
            );
        }
        assert!(
            !config.golden_cases.is_empty(),
            "L1 scorer must embed golden parity cases"
        );
        for case in &config.golden_cases {
            assert!(!case.name.is_empty(), "L1 scorer golden case needs a name");
            assert_eq!(
                case.features.len(),
                config.coefficients.len(),
                "L1 scorer golden feature count must match for {}",
                case.name
            );
            assert!(
                case.features.iter().all(|value| value.is_finite()),
                "L1 scorer golden features must be finite for {}",
                case.name
            );
            assert!(
                case.expected_score.is_finite() && (0.0..=1.0).contains(&case.expected_score),
                "L1 scorer golden score must be a probability for {}",
                case.name
            );
            let actual = score_feature_values(&config, &case.features);
            assert!(
                (actual - case.expected_score).abs() <= 1e-12,
                "L1 scorer golden score mismatch for {}",
                case.name
            );
            assert_eq!(
                actual >= config.acceptance_threshold,
                case.expected_accepted,
                "L1 scorer golden acceptance mismatch for {}",
                case.name
            );
        }
        config
    })
}

pub(crate) fn score_candidate(candidate: &L1Candidate, producer_count: usize) -> L1CandidateScore {
    let config = scorer_config();
    let ordered_values = config
        .feature_order
        .iter()
        .map(|name| feature_value(name, candidate, producer_count))
        .collect::<Vec<_>>();
    let features = config
        .feature_order
        .iter()
        .cloned()
        .zip(ordered_values.iter().copied())
        .collect::<HashMap<_, _>>();
    let score = score_feature_values(config, &ordered_values);
    L1CandidateScore {
        score,
        accepted: score >= config.acceptance_threshold,
        features,
    }
}

fn score_feature_values(config: &L1ScorerConfig, values: &[f64]) -> f64 {
    assert_eq!(
        values.len(),
        config.coefficients.len(),
        "L1 scorer value and coefficient counts must match"
    );
    let logit = config.intercept
        + values
            .iter()
            .zip(&config.coefficients)
            .map(|(value, coefficient)| value * coefficient)
            .sum::<f64>();
    sigmoid(logit)
}

fn supported_feature(name: &str) -> bool {
    matches!(
        name,
        "critical_rule_count"
            | "high_rule_count"
            | "medium_rule_count"
            | "low_rule_count"
            | "rule_match_count"
            | "structural_feature_count"
            | "family_count"
            | "producer_count"
            | "source_derived_rule_count"
            | "has_rule_and_structural"
            | "span_length_log1p"
            | "exact_rule_count"
            | "clause_window_rule_count"
    )
}

fn feature_value(name: &str, candidate: &L1Candidate, producer_count: usize) -> f64 {
    match name {
        "critical_rule_count" => severity_count(candidate, "critical"),
        "high_rule_count" => severity_count(candidate, "high"),
        "medium_rule_count" => severity_count(candidate, "medium"),
        "low_rule_count" => severity_count(candidate, "low"),
        "rule_match_count" => feature_rule_count(candidate, |feature| feature.kind == "rule_match"),
        "structural_feature_count" => candidate
            .features
            .iter()
            .filter(|feature| feature.kind == "structural")
            .count() as f64,
        "family_count" => candidate.families.len() as f64,
        "producer_count" => producer_count as f64,
        "source_derived_rule_count" => feature_rule_count(candidate, |feature| {
            feature.provenance.source != "ark-native"
        }),
        "has_rule_and_structural" => {
            let has_rule = candidate
                .features
                .iter()
                .any(|feature| feature.kind == "rule_match");
            let has_structural = candidate
                .features
                .iter()
                .any(|feature| feature.kind == "structural");
            f64::from(has_rule && has_structural)
        }
        "span_length_log1p" => ((candidate.end_byte - candidate.start_byte) as f64).ln_1p(),
        "exact_rule_count" => feature_rule_count(candidate, |feature| {
            feature.kind == "rule_match" && feature.span_precision == "exact"
        }),
        "clause_window_rule_count" => feature_rule_count(candidate, |feature| {
            feature.kind == "rule_match"
                && matches!(
                    feature.span_precision.as_str(),
                    "clause" | "window" | "document"
                )
        }),
        _ => unreachable!("scorer config is validated before feature extraction"),
    }
}

fn severity_count(candidate: &L1Candidate, severity: &str) -> f64 {
    candidate
        .rule_severities
        .values()
        .filter(|value| value.as_str() == severity)
        .count() as f64
}

fn feature_rule_count(
    candidate: &L1Candidate,
    predicate: impl Fn(&super::candidate::L1Feature) -> bool,
) -> f64 {
    candidate
        .features
        .iter()
        .filter(|feature| predicate(feature))
        .map(|feature| feature.provenance.rule_id.as_str())
        .collect::<HashSet<_>>()
        .len() as f64
}

fn sigmoid(value: f64) -> f64 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::injection::candidate::candidates_from_signals;
    use crate::detectors::injection::signal::InjectionSignal;

    fn candidate() -> L1Candidate {
        candidates_from_signals(
            "ignore previous instructions",
            &[InjectionSignal {
                rule_id: "test.rule".to_string(),
                upstream_id: None,
                family: "instruction_override".to_string(),
                severity: "critical".to_string(),
                description: "test".to_string(),
                source: "ark-native".to_string(),
                source_revision: "test".to_string(),
                source_license: None,
                source_file: None,
                provenance_weight: None,
                adaptation: None,
                references: Vec::new(),
                start_byte: 0,
                end_byte: 28,
                span_precision: "exact",
                feature_kind: "rule_match",
                components: Vec::new(),
            }],
        )
        .remove(0)
    }

    #[test]
    fn extracts_named_features_in_embedded_model_order() {
        let candidate = candidate();
        let scored = score_candidate(&candidate, 2);

        assert_eq!(scored.features["critical_rule_count"], 1.0);
        assert_eq!(scored.features["rule_match_count"], 1.0);
        assert_eq!(scored.features["producer_count"], 2.0);
        assert!((0.0..=1.0).contains(&scored.score));
    }

    #[test]
    fn embedded_golden_cases_match_scores_and_threshold_boundary() {
        let config = scorer_config();
        assert!(config.golden_cases.len() >= 3);
        for case in &config.golden_cases {
            let actual = score_feature_values(config, &case.features);
            assert!(
                (actual - case.expected_score).abs() <= 1e-12,
                "golden score mismatch for {}: {actual} != {}",
                case.name,
                case.expected_score
            );
            assert_eq!(
                actual >= config.acceptance_threshold,
                case.expected_accepted,
                "{}",
                case.name
            );
        }
        assert!(config
            .golden_cases
            .iter()
            .any(|case| { case.name == "one_quantum_below_threshold" && !case.expected_accepted }));
        assert!(config
            .golden_cases
            .iter()
            .any(|case| { case.name == "one_quantum_above_threshold" && case.expected_accepted }));
    }
}
