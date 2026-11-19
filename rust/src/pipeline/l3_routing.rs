// SPDX-License-Identifier: GPL-3.0-only
//! Ark's L3 model table: priority, timeout and cost defaults per category or
//! model. A configured `l3_policy` entry overrides the table per key.
use crate::{EffectiveL3PipelinePolicy, L3SchedulerPolicy};

/// Default L3 order when the policy configures none.
const DEFAULT_PRIORITY: &[&str] = &[
    "injection",
    "wolf-defender-small",
    "unsafe_action",
    "unified-v3-threat",
    "dynamic-pii",
    "gliner_small-v2.5-edge",
    "sensitive_document",
    "orca-sonar-document-classifier",
    "tool_class",
    "tool_action",
    "tool_tags",
    "routing",
    "unified-multitask-model-augmented-v3",
];

/// Unified-model heads and their legacy category names.
const UNIFIED_HEADS: &[&str] = &[
    "tool_class",
    "tool_action",
    "tool_tags",
    "routing",
    "unsafe_action",
    "unified-v3-tool-class",
    "unified-v3-tool-action",
    "unified-v3-tool-tags",
    "unified-v3-routing",
    "unified-v3-threat",
];

/// `(timeout ms, initial cost estimate ms)` of a known category or model.
fn default_ttl_and_cost(name: &str) -> Option<(u64, u64)> {
    match name {
        "injection" | "wolf-defender-small" => Some((15_000, 200)),
        "dynamic-pii" | "gliner_small-v2.5-edge" => Some((12_000, 240)),
        "sensitive_document" | "orca-sonar-document-classifier" => Some((12_000, 150)),
        "unified-multitask-model-augmented-v3" => Some((15_000, 200)),
        name if UNIFIED_HEADS.contains(&name) => Some((10_500, 150)),
        _ => None,
    }
}

pub fn priority_index(policy: &L3SchedulerPolicy, category: &str, model: &str) -> usize {
    let matches = |item: &str| item == category || item == model;
    if policy.priority.is_empty() {
        DEFAULT_PRIORITY
            .iter()
            .position(|item| matches(item))
            .unwrap_or(DEFAULT_PRIORITY.len())
    } else {
        policy
            .priority
            .iter()
            .position(|item| matches(item))
            .unwrap_or(policy.priority.len())
    }
}

pub fn ttl_ms(policy: &L3SchedulerPolicy, category: &str, model: &str) -> u64 {
    policy
        .ttl_ms
        .get(model)
        .copied()
        .or_else(|| default_ttl_and_cost(model).map(|(ttl, _)| ttl))
        .or_else(|| policy.ttl_ms.get(category).copied())
        .or_else(|| default_ttl_and_cost(category).map(|(ttl, _)| ttl))
        .unwrap_or(7_500)
}

pub fn estimated_cost_ms(policy: &L3SchedulerPolicy, category: &str, model: &str) -> u64 {
    policy
        .estimated_cost_ms
        .get(model)
        .copied()
        .or_else(|| default_ttl_and_cost(model).map(|(_, cost)| cost))
        .or_else(|| policy.estimated_cost_ms.get(category).copied())
        .or_else(|| default_ttl_and_cost(category).map(|(_, cost)| cost))
        .unwrap_or(40)
        .max(1)
}

/// The resolved L3 policy of one pipeline. Attack detectors (`injection`,
/// `unsafe_action`, Wolf and the unified threat head) stop the whole request
/// on a stable positive.
pub fn pipeline_policy(
    policy: &L3SchedulerPolicy,
    category: &str,
    model: &str,
) -> EffectiveL3PipelinePolicy {
    let request_wide_positive = matches!(category, "injection" | "unsafe_action")
        || matches!(model, "wolf-defender-small" | "unified-v3-threat");
    policy.pipeline_policy(category, model, request_wide_positive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::L3PipelineEarlyExit;

    #[test]
    fn model_table_fills_what_the_policy_leaves_open() {
        let mut policy = L3SchedulerPolicy::default();
        assert_eq!(ttl_ms(&policy, "injection", "wolf-defender-small"), 15_000);
        assert_eq!(
            ttl_ms(&policy, "tool_class", "unified-v3-tool-class"),
            10_500
        );
        assert_eq!(ttl_ms(&policy, "other", "other"), 7_500);
        assert_eq!(estimated_cost_ms(&policy, "dynamic-pii", "x"), 240);
        assert_eq!(estimated_cost_ms(&policy, "other", "other"), 40);
        assert_eq!(priority_index(&policy, "injection", "x"), 0);
        assert_eq!(priority_index(&policy, "x", "routing"), 11);
        assert_eq!(priority_index(&policy, "x", "y"), DEFAULT_PRIORITY.len());

        // A configured key wins for that key only; model keys beat category keys.
        policy.ttl_ms.insert("injection".into(), 99);
        assert_eq!(ttl_ms(&policy, "injection", "other-model"), 99);
        assert_eq!(ttl_ms(&policy, "injection", "wolf-defender-small"), 15_000);
        policy.priority = vec!["routing".into()];
        assert_eq!(priority_index(&policy, "routing", "x"), 0);
        assert_eq!(priority_index(&policy, "injection", "x"), 1);
    }

    #[test]
    fn attack_pipelines_stop_the_request_on_a_stable_positive() {
        let policy = L3SchedulerPolicy::default();
        assert_eq!(
            pipeline_policy(&policy, "threat", "unified-v3-threat").early_exit,
            L3PipelineEarlyExit::RequestWidePositive
        );
        assert_eq!(
            pipeline_policy(&policy, "injection", "x").early_exit,
            L3PipelineEarlyExit::RequestWidePositive
        );
        assert_eq!(
            pipeline_policy(&policy, "tool_class", "unified-v3-tool-class").early_exit,
            L3PipelineEarlyExit::HeadStable
        );
    }
}
