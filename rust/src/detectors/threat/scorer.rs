// SPDX-License-Identifier: GPL-3.0-only
//! Embedded document-level Threat logistic scorer, independently calibrated.
use serde::Deserialize;
use serde_json::Value;
use std::{collections::HashSet, sync::OnceLock};
#[derive(Deserialize)]
pub(super) struct Config {
    schema_version: u32,
    pub score_version: String,
    rule_ids: Vec<String>,
    feature_order: Vec<String>,
    coefficients: Vec<f64>,
    intercept: f64,
    pub acceptance_threshold: f64,
    golden_cases: Vec<Golden>,
}
#[derive(Deserialize)]
struct Golden {
    features: Vec<f64>,
    expected_score: f64,
    expected_accepted: bool,
}
pub(super) fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let c: Config = serde_json::from_str(include_str!("l1_scorer_0_1_7.json"))
            .expect("valid Threat scorer");
        assert_eq!(c.schema_version, 1);
        let order: Vec<_> = c
            .rule_ids
            .iter()
            .map(|id| format!("rule:{id}"))
            .chain(["rule_count_log1p", "max_span_log1p", "class_count"].map(str::to_string))
            .collect();
        assert_eq!(c.feature_order, order);
        assert_eq!(c.coefficients.len(), order.len());
        assert!(c.intercept.is_finite() && c.coefficients.iter().all(|v| v.is_finite()));
        assert!((0.0..1.0).contains(&c.acceptance_threshold));
        assert!(!c.golden_cases.is_empty());
        for g in &c.golden_cases {
            let score = probability(&c, &g.features);
            assert!((score - g.expected_score).abs() <= 1e-12);
            assert_eq!(score >= c.acceptance_threshold, g.expected_accepted);
        }
        c
    })
}
fn probability(c: &Config, features: &[f64]) -> f64 {
    assert_eq!(features.len(), c.coefficients.len());
    let value = c.intercept
        + features
            .iter()
            .zip(&c.coefficients)
            .map(|(x, w)| x * w)
            .sum::<f64>();
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        value.exp() / (1.0 + value.exp())
    }
}
pub(super) fn score(findings: &[Value]) -> (f64, bool) {
    let c = config();
    if findings.is_empty() {
        return (0.0, false);
    }
    let rules: HashSet<_> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    let classes: HashSet<_> = findings
        .iter()
        .filter_map(|f| f["class_name"].as_str())
        .collect();
    let length = findings
        .iter()
        .map(|f| f["end_byte"].as_u64().unwrap() - f["start_byte"].as_u64().unwrap())
        .max()
        .unwrap_or(0);
    let mut features: Vec<_> = c
        .rule_ids
        .iter()
        .map(|id| f64::from(rules.contains(id.as_str())))
        .collect();
    features.extend([
        (rules.len() as f64).ln_1p(),
        (length as f64).ln_1p(),
        classes.len() as f64,
    ]);
    let score = probability(c, &features);
    (score, score >= c.acceptance_threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_covers_exactly_the_current_rule_catalog() {
        let rules: Value = serde_json::from_str(include_str!("rules.json")).unwrap();
        let mut ids: Vec<_> = rules["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| rule["id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        assert_eq!(config().rule_ids, ids);
    }

    #[test]
    fn scores_match_python_training_goldens() {
        let c = config();
        assert!(c.golden_cases.iter().any(|g| g.expected_accepted));
        assert!(c.golden_cases.iter().any(|g| !g.expected_accepted));
        for g in &c.golden_cases {
            assert!((probability(c, &g.features) - g.expected_score).abs() < 1e-12);
        }
    }

    #[test]
    fn no_findings_cannot_be_accepted() {
        assert_eq!(score(&[]), (0.0, false));
    }
    #[test]
    fn repeated_rule_matches_do_not_reduce_score() {
        let finding = serde_json::json!({"rule_id": config().rule_ids[0], "class_name": "tool_abuse", "start_byte": 0, "end_byte": 30});
        assert_eq!(
            score(std::slice::from_ref(&finding)),
            score(&vec![finding; 256])
        );
    }
}
