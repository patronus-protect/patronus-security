use super::*;
use crate::{native::ScoreMode, SecurityCategory};

fn gates(value: Value) -> Result<ScanGateMatrix, String> {
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[test]
fn one_gate_schema_reads_every_key() {
    let gates = gates(serde_json::json!({
        "rules": {"pii_email": false, "cat.core.remote_to_exec": false},
        "models": {"native:pii": false},
        "pii_mode": "recall",
        "dlp_mode": "balanced",
        "unsafe_action_mode": "recall",
        "explain": true,
        "l1": true,
        "l2": false,
        "l3": false,
        "conditional": [{
            "level": "l3",
            "pipeline": "injection",
            "when": {"metadata": {"path": "tenant", "equals": "a"}},
            "l3_policy": {"clustering": "representative"}
        }],
        "l3_policy": {
            "enabled": false,
            "priority": ["tool_class"],
            "ttl_ms": {"tool_class": 1234},
            "estimated_cost_ms": {"tool_class": 30},
            "fairness_quantum_ms": 10,
            "max_wait_ms": 100,
            "degraded_factor": 0.5,
            "early_exit": "disabled",
            "progress": "provisional",
            "clustering": "verify_representative",
            "representatives_per_cluster": 2,
            "verify_representatives_per_cluster": 2,
            "min_cluster_similarity": 0.8,
            "max_cluster_size": 4,
            "pipelines": {"injection": {
                "clustering": "representative",
                "aggregation": {"type": "any_positive_or_highest", "positive_class": "attack", "threshold": 0.93},
                "early_exit": "request_wide_positive"
            }}
        }
    }))
    .unwrap();
    assert!(!gates.native.allows_rule("cat.core.remote_to_exec"));
    assert!(!gates.native.allows_model("native:pii"));
    assert_eq!(gates.native.pii_mode, ScoreMode::Recall);
    assert_eq!(
        gates.native.mode(SecurityCategory::UnsafeAction),
        ScoreMode::Recall
    );
    assert_eq!(
        gates.native.mode(SecurityCategory::Injection),
        ScoreMode::Strict
    );
    assert!(gates.native.explain);
    assert_eq!(
        (gates.l1, gates.l2, gates.l3),
        (Some(true), Some(false), Some(false))
    );
    assert_eq!(gates.conditional.len(), 1);
    let policy = &gates.l3_policy;
    assert!(!policy.enabled);
    assert_eq!(policy.priority, ["tool_class"]);
    // Core ships no model table: only the configured entries are present.
    assert_eq!(policy.ttl_ms, HashMap::from([("tool_class".into(), 1234)]));
    assert_eq!(policy.estimated_cost_ms["tool_class"], 30);
    assert_eq!(
        policy.clustering,
        L3ClusteringStrategy::VerifyRepresentative
    );
    assert_eq!(policy.max_cluster_size, 4);
    assert_eq!(
        policy.pipelines["injection"].clustering,
        Some(L3ClusteringStrategy::Representative)
    );
    let default = self::gates(serde_json::json!({})).unwrap();
    assert!(default.l3_policy.priority.is_empty());
    assert!(default.l3_policy.ttl_ms.is_empty());
    assert!(default.native.allows_rule("pii_email"));
}

#[test]
fn gate_schema_refuses_old_keys_and_bad_values() {
    for invalid in [
        serde_json::json!({"levels": {"l1": true}}),
        serde_json::json!({"model_areas": {"native:pii": false}}),
        serde_json::json!({"policy": {"enabled": true}}),
        serde_json::json!({"l3": {"enabled": true}}),
        serde_json::json!({"l3_policy": {"execution": "rank_only"}}),
        serde_json::json!({"l3_policy": {"min_similarity": 0.9}}),
        serde_json::json!({"l3_policy": {"pipelines": {"injection": {"execution": "representative"}}}}),
        serde_json::json!({"rules": {"pii_email": "no"}}),
        serde_json::json!({"l1": "yes"}),
        serde_json::json!({"pii_mode": "fast"}),
        serde_json::json!({"l3_policy": {"priority": "injection"}}),
        serde_json::json!({"l3_policy": {"ttl_ms": {"injection": "soon"}}}),
        serde_json::json!({"l3_policy": {"estimated_cost_ms": {"pii": 0}}}),
        serde_json::json!({"l3_policy": {"fairness_quantum_ms": 0}}),
        serde_json::json!({"l3_policy": {"max_wait_ms": -1}}),
        serde_json::json!({"l3_policy": {"degraded_factor": 2.0}}),
        serde_json::json!({"l3_policy": {"min_cluster_similarity": 1.5}}),
        serde_json::json!({"l3_policy": {"early_exit": "sometimes"}}),
        serde_json::json!({"l3_policy": {"progress": "verbose"}}),
        serde_json::json!({"l3_policy": {"clustering": "aggressive"}}),
        serde_json::json!({"l3_policy": {"representatives_per_cluster": 0}}),
        serde_json::json!({"l3_policy": {"max_cluster_size": 0}}),
        serde_json::json!({"l3_policy": {"pipelines": {"": {}}}}),
        serde_json::json!({"l3_policy": {"pipelines": {"injection": {"max_cluster_size": 0}}}}),
        serde_json::json!({"l3_policy": {"pipelines": {"injection": {"min_cluster_similarity": 1.5}}}}),
        serde_json::json!({"l3_policy": {"pipelines": {"injection": {"aggregation": {"type": "any_positive_or_highest", "positive_class": " ", "threshold": 0.5}}}}}),
        serde_json::json!({"conditional": [{"level": "l1", "when": {"metadata": {"path": "a", "exists": true}}}]}),
        serde_json::json!({"conditional": [{"level": "l3", "pipeline": "injection", "when": {"metadata": {"path": "a", "exists": true}}, "l3_policy": {"max_cluster_size": 0}}]}),
    ] {
        assert!(gates(invalid.clone()).is_err(), "{invalid} must be refused");
    }
}

#[test]
fn l3_pipeline_policy_overrides_request_defaults_by_category() {
    let mut policy = L3SchedulerPolicy {
        clustering: L3ClusteringStrategy::RankOnly,
        ..L3SchedulerPolicy::default()
    };
    policy.pipelines.insert(
        "injection".to_string(),
        L3PipelinePolicy {
            clustering: Some(L3ClusteringStrategy::VerifyRepresentative),
            representatives_per_cluster: Some(2),
            verify_representatives_per_cluster: Some(1),
            min_cluster_similarity: Some(0.96),
            max_cluster_size: Some(4),
            aggregation: Some(L3AggregationStrategy::AnyPositiveOrHighest {
                positive_class: "attack".to_string(),
                threshold: 0.9,
            }),
            early_exit: Some(L3PipelineEarlyExit::RequestWidePositive),
        },
    );

    let resolved = policy.pipeline_policy("injection", "model-a", false);

    assert_eq!(
        resolved.clustering,
        L3ClusteringStrategy::VerifyRepresentative
    );
    assert_eq!(resolved.representatives_per_cluster, 2);
    assert_eq!(resolved.min_cluster_similarity, 0.96);
    assert_eq!(resolved.max_cluster_size, 4);
    assert_eq!(
        resolved.early_exit,
        L3PipelineEarlyExit::RequestWidePositive
    );
}

#[test]
fn l3_pipeline_policy_uses_model_override_when_category_is_absent() {
    let mut policy = L3SchedulerPolicy::default();
    policy.pipelines.insert(
        "model-b".to_string(),
        L3PipelinePolicy {
            clustering: Some(L3ClusteringStrategy::Representative),
            ..L3PipelinePolicy::default()
        },
    );

    assert_eq!(
        policy
            .pipeline_policy("tool_class", "model-b", false)
            .clustering,
        L3ClusteringStrategy::Representative
    );
}

#[test]
fn l3_inherited_early_exit_scope_follows_the_pipeline_kind() {
    let policy = L3SchedulerPolicy::default();
    assert_eq!(
        policy.pipeline_policy("threat", "m", true).early_exit,
        L3PipelineEarlyExit::RequestWidePositive
    );
    assert_eq!(
        policy.pipeline_policy("tool_class", "m", false).early_exit,
        L3PipelineEarlyExit::HeadStable
    );
    let disabled = L3SchedulerPolicy {
        early_exit: L3EarlyExitMode::Disabled,
        ..L3SchedulerPolicy::default()
    };
    assert_eq!(
        disabled.pipeline_policy("threat", "m", true).early_exit,
        L3PipelineEarlyExit::Disabled
    );
}

#[test]
fn security_level_serde_accepts_from_str_names_and_writes_canonical_names() {
    for (name, level) in [
        ("L1", SecurityLevel::L1),
        ("l2", SecurityLevel::L2),
        ("3", SecurityLevel::L3),
    ] {
        let parsed: SecurityLevel = serde_json::from_value(serde_json::json!(name)).unwrap();
        assert_eq!(parsed, level);
        assert_eq!(serde_json::to_value(level).unwrap(), level.as_str());
    }
    assert!(serde_json::from_value::<SecurityLevel>(serde_json::json!("L4")).is_err());
}

#[test]
fn evaluates_nested_metadata_and_result_conditions() {
    let mut gates = ScanGateMatrix::all_enabled();
    gates
        .set_conditional(vec![ConditionalPipelineGate {
            level: SecurityLevel::L3,
            pipeline: Some("pii".to_string()),
            when: GateExpression::All(vec![
                GateExpression::Metadata(MetadataCondition {
                    path: "tool.action".to_string(),
                    equals: Some(Value::String("list".to_string())),
                    in_values: None,
                    exists: None,
                }),
                GateExpression::Not(Box::new(GateExpression::Result(ResultCondition {
                    pipeline: "dlp".to_string(),
                    classes: vec!["source_code".to_string()],
                    min_confidence: Some(0.8),
                }))),
            ]),
            l3_policy: None,
        }])
        .unwrap();
    let metadata = serde_json::json!({"tool": {"action": "list"}});

    assert!(pipeline_allowed(
        &gates.conditional,
        SecurityLevel::L3,
        "pii",
        &metadata,
        &[]
    ));
    assert!(pipeline_allowed(
        &gates.conditional,
        SecurityLevel::L2,
        "pii",
        &Value::Null,
        &[]
    ));
    assert!(!pipeline_allowed(
        &gates.conditional,
        SecurityLevel::L3,
        "pii",
        &Value::Null,
        &[]
    ));
    assert!(!pipeline_allowed(
        &gates.conditional,
        SecurityLevel::L3,
        "pii",
        &metadata,
        &[GateResult {
            pipeline: "dlp".to_string(),
            class_name: "source_code".to_string(),
            confidence: 0.9,
            level: SecurityLevel::L2,
        }]
    ));
}

#[test]
fn metadata_in_and_exists_predicates() {
    let any = GateExpression::Any(vec![
        GateExpression::Metadata(MetadataCondition {
            path: "tenant".into(),
            equals: None,
            in_values: Some(vec![serde_json::json!("a"), serde_json::json!("b")]),
            exists: None,
        }),
        GateExpression::Metadata(MetadataCondition {
            path: "debug".into(),
            equals: None,
            in_values: None,
            exists: Some(true),
        }),
    ]);
    assert!(any.matches(&serde_json::json!({"tenant": "b"}), &[]));
    assert!(any.matches(&serde_json::json!({"debug": false}), &[]));
    assert!(!any.matches(&serde_json::json!({"tenant": "c"}), &[]));
}

#[test]
fn matching_policy_gate_overrides_l3_policy_without_suppressing_on_miss() {
    let mut gates = ScanGateMatrix::all_enabled();
    gates
        .set_conditional(vec![ConditionalPipelineGate {
            level: SecurityLevel::L3,
            pipeline: Some("injection".to_string()),
            when: GateExpression::Result(ResultCondition {
                pipeline: "dlp".to_string(),
                classes: vec!["source_code".to_string()],
                min_confidence: Some(0.8),
            }),
            l3_policy: Some(L3PipelinePolicy {
                clustering: Some(L3ClusteringStrategy::Representative),
                early_exit: Some(L3PipelineEarlyExit::Disabled),
                ..L3PipelinePolicy::default()
            }),
        }])
        .unwrap();
    let source_code = GateResult {
        pipeline: "dlp".to_string(),
        class_name: "source_code".to_string(),
        confidence: 0.9,
        level: SecurityLevel::L2,
    };

    let mut matched = gates.clone();
    matched.apply_l3_policy_overrides(&Value::Null, &[source_code]);
    let matched_policy = matched.l3_policy.pipeline_policy("injection", "m", true);
    assert_eq!(
        matched_policy.clustering,
        L3ClusteringStrategy::Representative
    );
    assert_eq!(matched_policy.early_exit, L3PipelineEarlyExit::Disabled);

    let mut missed = gates;
    missed.apply_l3_policy_overrides(&Value::Null, &[]);
    assert!(pipeline_allowed(
        &missed.conditional,
        SecurityLevel::L3,
        "injection",
        &Value::Null,
        &[]
    ));
    assert_eq!(
        missed
            .l3_policy
            .pipeline_policy("injection", "m", true)
            .clustering,
        L3ClusteringStrategy::RankOnly
    );
}

#[test]
fn layer_execution_caps_levels_by_max_level_and_gates() {
    let mut execution =
        LayerExecution::with_gates(SecurityLevel::L2, ScanGateMatrix::levels(true, false, true));
    assert!(execution.allows_level(SecurityLevel::L1));
    assert!(!execution.allows_level(SecurityLevel::L2));
    assert!(!execution.allows_level(SecurityLevel::L3));
    execution.set_max_level(SecurityLevel::L3);
    assert!(execution.allows_level(SecurityLevel::L3));
    execution.gates_mut().set_level(SecurityLevel::L3, false);
    assert!(!execution.allows_level(SecurityLevel::L3));
    assert_eq!(execution.max_level(), SecurityLevel::L3);
}

#[test]
fn the_gate_cascade_takes_only_modules_and_is_off_by_default() {
    let gates: ScanGateMatrix = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(gates.cascade.is_none());
    let gates: ScanGateMatrix = serde_json::from_value(serde_json::json!({
        "l2": false,
        "cascade": {"modules": {"injection": {"detect_threshold": 0.9, "clear_threshold": 0.1}}}
    }))
    .unwrap();
    assert!(gates.cascade.is_some() && !gates.allows_level(SecurityLevel::L2));
    for invalid in [
        serde_json::json!({"cascade": {"l2": false}}),
        serde_json::json!({"cascade": {"max_level": "l1"}}),
        serde_json::json!({"cascade": {"modules": {"injection": {"l1_model": {"bundle_dir": "m", "manifest_sha256": "ab"}}}}}),
        serde_json::json!({"cascade": {"modules": {"injection": {"clear_threshold": 2.0}}}}),
    ] {
        assert!(
            serde_json::from_value::<ScanGateMatrix>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}
