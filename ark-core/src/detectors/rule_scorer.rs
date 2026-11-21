// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rule-feature logistic scorer of the attack-class L1 aggregations: a
//! binary logistic regression over named rule features, embedded as JSON with
//! golden parity cases from the Python training run. The injection
//! aggregation (`injection/rules/l1_scorer_*.json`) and the threat rules
//! (`threat/l1_scorer_*.json`) each embed one; feature extraction stays with
//! the caller, loading, the golden check and scoring live here.
//!
//! A scorer's `acceptance_threshold` is the default of its acceptance cut;
//! hosts may override it ([`crate::cascade::ScanGateMatrix`]).

use std::collections::HashSet;

use serde::Deserialize;

/// One embedded scorer.
#[derive(Debug, Deserialize)]
pub struct RuleScorer {
    pub schema_version: u32,
    pub model_id: String,
    pub score_version: String,
    /// Rule ids whose presence the scorer reads (threat form); empty when the
    /// features name their rules themselves (injection form).
    #[serde(default)]
    pub rule_ids: Vec<String>,
    pub feature_order: Vec<String>,
    pub coefficients: Vec<f64>,
    pub intercept: f64,
    /// Default acceptance cut on the probability.
    pub acceptance_threshold: f64,
    pub golden_cases: Vec<GoldenCase>,
}

/// A feature vector with the score and acceptance the training run computed.
#[derive(Debug, Deserialize)]
pub struct GoldenCase {
    #[serde(default)]
    pub name: Option<String>,
    pub features: Vec<f64>,
    pub expected_score: f64,
    pub expected_accepted: bool,
}

impl RuleScorer {
    /// Parse and validate an embedded scorer: schema 1, one finite coefficient
    /// per unique feature, a probability as acceptance threshold, and golden
    /// cases that reproduce their score (to 1e-12) and acceptance. `label`
    /// names the scorer in the panic of a broken build.
    pub fn load(json: &str, label: &str) -> Self {
        let scorer: Self = serde_json::from_str(json)
            .unwrap_or_else(|error| panic!("embedded {label} scorer must parse: {error}"));
        assert_eq!(
            scorer.schema_version, 1,
            "unsupported {label} scorer schema"
        );
        assert_eq!(
            scorer.feature_order.len(),
            scorer.coefficients.len(),
            "{label} scorer feature and coefficient counts must match"
        );
        let mut names = HashSet::new();
        for name in &scorer.feature_order {
            assert!(
                names.insert(name),
                "duplicate {label} scorer feature: {name}"
            );
        }
        assert!(
            scorer.intercept.is_finite() && scorer.coefficients.iter().all(|v| v.is_finite()),
            "{label} scorer weights must be finite"
        );
        assert!(
            (0.0..=1.0).contains(&scorer.acceptance_threshold),
            "{label} scorer acceptance threshold must be a probability"
        );
        assert!(
            !scorer.golden_cases.is_empty(),
            "{label} scorer must embed golden parity cases"
        );
        for (index, case) in scorer.golden_cases.iter().enumerate() {
            let name = case.name.clone().unwrap_or_else(|| index.to_string());
            assert!(
                case.features.len() == scorer.coefficients.len()
                    && case.features.iter().all(|v| v.is_finite()),
                "{label} scorer golden case {name} needs one finite value per feature"
            );
            let actual = scorer.probability(&case.features);
            assert!(
                (actual - case.expected_score).abs() <= 1e-12,
                "{label} scorer golden score mismatch for {name}"
            );
            assert_eq!(
                actual >= scorer.acceptance_threshold,
                case.expected_accepted,
                "{label} scorer golden acceptance mismatch for {name}"
            );
        }
        scorer
    }

    /// Probability of `features`, given in [`Self::feature_order`].
    pub fn probability(&self, features: &[f64]) -> f64 {
        assert_eq!(
            features.len(),
            self.coefficients.len(),
            "scorer value and coefficient counts must match"
        );
        let logit = self.intercept
            + features
                .iter()
                .zip(&self.coefficients)
                .map(|(value, coefficient)| value * coefficient)
                .sum::<f64>();
        sigmoid(logit)
    }
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

    fn scorer(threshold: f64, expected_score: f64, expected_accepted: bool) -> String {
        serde_json::json!({
            "schema_version": 1, "model_id": "test", "score_version": "test-1",
            "feature_order": ["a", "b"], "coefficients": [1.0, -2.0], "intercept": 0.0,
            "acceptance_threshold": threshold,
            "golden_cases": [{"features": [0.0, 0.0], "expected_score": expected_score,
                "expected_accepted": expected_accepted}],
        })
        .to_string()
    }

    #[test]
    fn scores_with_a_stable_sigmoid() {
        let scorer = RuleScorer::load(&scorer(0.5, 0.5, true), "test");
        assert_eq!(scorer.probability(&[0.0, 0.0]), 0.5);
        assert!((scorer.probability(&[1.0, 0.0]) - 0.731_058_578_630_004_9).abs() < 1e-15);
        assert!(scorer.probability(&[0.0, 1e6]) >= 0.0);
        assert_eq!(scorer.probability(&[1e6, 0.0]), 1.0);
    }

    #[test]
    #[should_panic(expected = "golden score mismatch")]
    fn refuses_a_golden_score_mismatch() {
        RuleScorer::load(&scorer(0.5, 0.4, true), "test");
    }

    #[test]
    #[should_panic(expected = "golden acceptance mismatch")]
    fn refuses_a_golden_acceptance_mismatch() {
        RuleScorer::load(&scorer(0.6, 0.5, true), "test");
    }

    #[test]
    #[should_panic(expected = "must be a probability")]
    fn refuses_a_threshold_outside_zero_one() {
        RuleScorer::load(&scorer(1.5, 0.5, false), "test");
    }

    #[test]
    fn both_embedded_scorers_load() {
        let injection = crate::detectors::injection::scorer::scorer_config();
        let threat = crate::detectors::threat::scorer::config();
        assert_eq!(injection.acceptance_threshold, 0.96);
        assert_eq!(threat.acceptance_threshold, 0.1);
        assert!(injection.rule_ids.is_empty() && !threat.rule_ids.is_empty());
    }
}
