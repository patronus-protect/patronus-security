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
                && gate
                    .pipeline
                    .as_deref()
                    .is_none_or(|target| target == pipeline)
        })
        .all(|gate| expression_matches(&gate.when, metadata, results))
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
                && condition
                    .classes
                    .is_empty()
                    .then_some(true)
                    .unwrap_or_else(|| condition.classes.contains(&result.class_name))
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
}
