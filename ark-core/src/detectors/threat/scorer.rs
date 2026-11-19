// SPDX-License-Identifier: MIT OR Apache-2.0
//! Embedded document-level Threat logistic scorer, independently calibrated.
use serde_json::Value;
use std::{collections::HashSet, sync::OnceLock};

use crate::detectors::rule_scorer::RuleScorer;

/// The embedded scorer; its features are one presence flag per rule id, then
/// the rule count, the longest span and the scorer class count.
pub(crate) fn config() -> &'static RuleScorer {
    static CONFIG: OnceLock<RuleScorer> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let c = RuleScorer::load(include_str!("l1_scorer_0_1_7.json"), "Threat");
        let order: Vec<_> = c
            .rule_ids
            .iter()
            .map(|id| format!("rule:{id}"))
            .chain(["rule_count_log1p", "max_span_log1p", "class_count"].map(str::to_string))
            .collect();
        assert_eq!(c.feature_order, order);
        c
    })
}
/// Scores the findings of the rules the model was trained on against the
/// model's acceptance cut; findings of points rules are not features of
/// the model.
pub(super) fn score(findings: &[Value]) -> (f64, bool) {
    let c = config();
    let findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f["rule_id"]
                .as_str()
                .is_some_and(|id| c.rule_ids.iter().any(|known| known == id))
        })
        .collect();
    if findings.is_empty() {
        return (0.0, false);
    }
    let rules: HashSet<_> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    let classes: HashSet<_> = findings
        .iter()
        .filter_map(|f| f["scorer_class"].as_str())
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
    let score = c.probability(&features);
    (score, score >= c.acceptance_threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_covers_exactly_the_rules_without_points() {
        let rules: Value = serde_json::from_str(include_str!("rules.json")).unwrap();
        let mut ids: Vec<_> = rules["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| rule.get("points").is_none())
            .map(|rule| rule["id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        assert_eq!(config().rule_ids, ids);
    }

    #[test]
    fn goldens_cover_both_decisions() {
        let c = config();
        assert!(c.golden_cases.iter().any(|g| g.expected_accepted));
        assert!(c.golden_cases.iter().any(|g| !g.expected_accepted));
    }

    #[test]
    fn no_findings_cannot_be_accepted() {
        assert_eq!(score(&[]), (0.0, false));
    }
    #[test]
    fn findings_of_points_rules_do_not_change_the_model_score() {
        let finding = serde_json::json!({"rule_id": config().rule_ids[0], "scorer_class": "tool_abuse", "start_byte": 0, "end_byte": 30});
        let points = serde_json::json!({"rule_id": "ark.threat.ua_destructive_request", "class_name": "unsafe_action", "start_byte": 0, "end_byte": 300});
        assert_eq!(
            score(std::slice::from_ref(&finding)),
            score(&[finding, points.clone()])
        );
        assert_eq!(score(&[points]), (0.0, false));
    }

    #[test]
    fn repeated_rule_matches_do_not_reduce_score() {
        let finding = serde_json::json!({"rule_id": config().rule_ids[0], "scorer_class": "tool_abuse", "start_byte": 0, "end_byte": 30});
        assert_eq!(
            score(std::slice::from_ref(&finding)),
            score(&vec![finding; 256])
        );
    }
}
