// SPDX-License-Identifier: GPL-3.0-only
use serde_json::Value;

use crate::{GateExpression, GateResult, ScanExecution, SecurityLevel};

pub(crate) fn pipeline_allowed(
    execution: &ScanExecution,
    level: SecurityLevel,
    pipeline: &str,
    metadata: &Value,
    results: &[GateResult],
) -> bool {
    execution
        .gates()
        .conditional
        .iter()
        .filter(|gate| {
            gate.level == level
                && gate.l3_policy.is_none()
                && gate
                    .pipeline
                    .as_deref()
                    .is_none_or(|target| target == pipeline)
        })
        .all(|gate| expression_matches(&gate.when, metadata, results))
}

pub(crate) fn apply_l3_policy_overrides(
    execution: &ScanExecution,
    metadata: &Value,
    results: &[GateResult],
) -> ScanExecution {
    let mut effective = execution.clone();
    let mut gates = execution.gates().clone();
    let mut changed = false;
    let conditional = gates.conditional.clone();
    for gate in &conditional {
        let (Some(pipeline), Some(override_policy)) =
            (gate.pipeline.as_ref(), gate.l3_policy.as_ref())
        else {
            continue;
        };
        if gate.level != SecurityLevel::L3 || !expression_matches(&gate.when, metadata, results) {
            continue;
        }
        gates
            .l3_policy
            .pipelines
            .entry(pipeline.clone())
            .or_default()
            .apply_override(override_policy);
        changed = true;
    }
    if changed {
        effective.set_gates(gates);
    }
    effective
}

fn expression_matches(
    expression: &GateExpression,
    metadata: &Value,
    results: &[GateResult],
) -> bool {
    match expression {
        GateExpression::All(items) => items
            .iter()
            .all(|item| expression_matches(item, metadata, results)),
        GateExpression::Any(items) => items
            .iter()
            .any(|item| expression_matches(item, metadata, results)),
        GateExpression::Not(item) => !expression_matches(item, metadata, results),
        GateExpression::Metadata(condition) => {
            let value = value_at_path(metadata, &condition.path);
            if let Some(expected) = condition.exists {
                return value.is_some() == expected;
            }
            let Some(value) = value else {
                return false;
            };
            if let Some(expected) = &condition.equals {
                return value == expected;
            }
            condition
                .in_values
                .as_ref()
                .is_some_and(|values| values.contains(value))
        }
        GateExpression::Result(condition) => results.iter().any(|result| {
            result.pipeline == condition.pipeline
                && if condition.classes.is_empty() {
                    true
                } else {
                    condition.classes.contains(&result.class_name)
                }
                && condition
                    .min_confidence
                    .is_none_or(|minimum| result.confidence >= minimum)
        }),
    }
}

fn value_at_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(root, |value, segment| {
        value.as_object().and_then(|object| object.get(segment))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConditionalPipelineGate, MetadataCondition, ResultCondition, ScanGateMatrix};

    #[test]
    fn evaluates_nested_metadata_and_result_conditions() {
        let mut gates = ScanGateMatrix::all_enabled();
        gates
            .set_conditional(vec![ConditionalPipelineGate {
                level: SecurityLevel::L3,
                pipeline: Some("dynamic-pii".to_string()),
                when: GateExpression::All(vec![
                    GateExpression::Metadata(MetadataCondition {
                        path: "tool.action".to_string(),
                        equals: Some(Value::String("list".to_string())),
                        in_values: None,
                        exists: None,
                    }),
                    GateExpression::Not(Box::new(GateExpression::Result(ResultCondition {
                        pipeline: "routing".to_string(),
                        classes: vec!["code_development_request".to_string()],
                        min_confidence: Some(0.8),
                    }))),
                ]),
                l3_policy: None,
            }])
            .unwrap();
        let execution = ScanExecution::with_gates(SecurityLevel::L3, gates);
        let metadata = serde_json::json!({"tool": {"action": "list"}});

        assert!(pipeline_allowed(
            &execution,
            SecurityLevel::L3,
            "dynamic-pii",
            &metadata,
            &[]
        ));
        assert!(!pipeline_allowed(
            &execution,
            SecurityLevel::L3,
            "dynamic-pii",
            &metadata,
            &[GateResult {
                pipeline: "routing".to_string(),
                class_name: "code_development_request".to_string(),
                confidence: 0.9,
                level: SecurityLevel::L2,
            }]
        ));
    }

    #[test]
    fn matching_policy_gate_overrides_l3_policy_without_suppressing_on_miss() {
        let mut gates = ScanGateMatrix::all_enabled();
        gates
            .set_conditional(vec![ConditionalPipelineGate {
                level: SecurityLevel::L3,
                pipeline: Some("injection".to_string()),
                when: GateExpression::Result(ResultCondition {
                    pipeline: "routing".to_string(),
                    classes: vec!["source_code".to_string()],
                    min_confidence: Some(0.8),
                }),
                l3_policy: Some(crate::L3PipelinePolicy {
                    clustering: Some(crate::L3ClusteringStrategy::Representative),
                    early_exit: Some(crate::L3PipelineEarlyExit::Disabled),
                    ..crate::L3PipelinePolicy::default()
                }),
            }])
            .unwrap();
        let execution = ScanExecution::with_gates(SecurityLevel::L3, gates);
        let source_code = GateResult {
            pipeline: "routing".to_string(),
            class_name: "source_code".to_string(),
            confidence: 0.9,
            level: SecurityLevel::L2,
        };

        let matched = apply_l3_policy_overrides(&execution, &Value::Null, &[source_code]);
        let matched_policy = matched
            .l3_policy()
            .pipeline_policy("injection", "wolf-defender-small");
        assert_eq!(
            matched_policy.clustering,
            crate::L3ClusteringStrategy::Representative
        );
        assert_eq!(
            matched_policy.early_exit,
            crate::L3PipelineEarlyExit::Disabled
        );

        let missed = apply_l3_policy_overrides(&execution, &Value::Null, &[]);
        assert!(pipeline_allowed(
            &missed,
            SecurityLevel::L3,
            "injection",
            &Value::Null,
            &[]
        ));
        assert_eq!(
            missed
                .l3_policy()
                .pipeline_policy("injection", "wolf-defender-small")
                .clustering,
            crate::L3ClusteringStrategy::RankOnly
        );
    }
}
