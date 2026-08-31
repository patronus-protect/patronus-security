//! Unit tests for internal pipeline building blocks, reached through the
//! `test-util` feature surface (enabled for the test suite via dev-dependencies).

mod l3_results {
    use std::collections::HashMap;

    use patronus_ark::pipeline::{
        degraded_error_result, degraded_timeout_result, has_l3_pending, l3_pending_layer,
    };
    use patronus_ark::{
        EvaluationResult, LayerResult, NtdbOperatingPoint, ScanExecution, SecurityLevel,
        SecurityScanResult,
    };

    #[test]
    fn ntdb_decision_threshold_point_is_separate_from_promote_point() {
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        assert_eq!(
            execution.ntdb_operating_point(),
            NtdbOperatingPoint::BestPromote
        );
        assert_eq!(
            execution.ntdb_decision_threshold_point(),
            NtdbOperatingPoint::BestF1
        );

        execution.set_ntdb_decision_threshold_point(NtdbOperatingPoint::BestFprInF1);

        assert_eq!(
            execution.ntdb_operating_point(),
            NtdbOperatingPoint::BestPromote
        );
        assert_eq!(
            execution.ntdb_decision_threshold_point(),
            NtdbOperatingPoint::BestFprInF1
        );
    }

    fn fallback_result() -> SecurityScanResult {
        SecurityScanResult {
            category: "injection".to_string(),
            class_name: "benign".to_string(),
            confidence: 0.80,
            level: "L2".to_string(),
            model: "wolf-defender-small".to_string(),
            duration_ms: 4.0,
            layers: vec![
                LayerResult {
                    level: "L2".to_string(),
                    layer_type: "veto_consensus".to_string(),
                    class_name: "benign".to_string(),
                    confidence: 0.80,
                    matched: true,
                    duration_ms: 4.0,
                    thresholds: HashMap::new(),
                    details: HashMap::new(),
                },
                LayerResult {
                    level: "L3".to_string(),
                    layer_type: "l3_pending".to_string(),
                    class_name: "benign".to_string(),
                    confidence: 0.0,
                    matched: false,
                    duration_ms: 0.0,
                    thresholds: HashMap::new(),
                    details: HashMap::new(),
                },
            ],
            internal_l2_chunk_outputs: Vec::new(),
            evidence_spans: Vec::new(),
            label_scores: Vec::new(),
            decision: None,
        }
    }

    #[test]
    fn l3_pending_layer_records_fallback_and_execution_metadata() {
        let result = EvaluationResult {
            class_name: "benign".to_string(),
            confidence: 0.42,
            level: "L2".to_string(),
        };
        let execution = ScanExecution::new(SecurityLevel::L3);

        let layer = l3_pending_layer(&result, &execution);

        assert_eq!(layer.level, "L3");
        assert_eq!(layer.layer_type, "l3_pending");
        assert!(!layer.matched);
        assert_eq!(layer.details.get("queued"), Some(&serde_json::json!(true)));
        assert_eq!(
            layer.details.get("fallback_level"),
            Some(&serde_json::json!("L2"))
        );
        assert_eq!(
            layer.details.get("fallback_confidence"),
            Some(&serde_json::json!(0.42))
        );
        assert_eq!(
            layer.details.get("batch_mode"),
            Some(&serde_json::json!("lazy_batches"))
        );
    }

    #[test]
    fn degraded_timeout_result_marks_l2_fallback_and_appends_timeout_layer() {
        let degraded = degraded_timeout_result(fallback_result(), 125.0, 100, 0.5);

        assert_eq!(degraded.confidence, 0.40);
        assert_eq!(degraded.duration_ms, 4.0);
        let fallback_layer = degraded
            .layers
            .iter()
            .find(|layer| layer.layer_type == "veto_consensus")
            .unwrap();
        assert!(fallback_layer.matched);
        assert_eq!(fallback_layer.confidence, 0.40);
        assert_eq!(
            fallback_layer.details.get("degraded_reason"),
            Some(&serde_json::json!("l3_timeout"))
        );

        let timeout_layer = degraded.layers.last().unwrap();
        assert_eq!(timeout_layer.level, "L3");
        assert_eq!(timeout_layer.layer_type, "degraded_timeout");
        assert_eq!(
            timeout_layer.details.get("fallback_due_to_timeout"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn degraded_error_result_marks_l2_fallback_and_preserves_error() {
        let degraded = degraded_error_result(
            fallback_result(),
            50.0,
            100,
            0.25,
            "model unavailable".to_string(),
        );

        assert_eq!(degraded.confidence, 0.20);
        let fallback_layer = degraded
            .layers
            .iter()
            .find(|layer| layer.layer_type == "veto_consensus")
            .unwrap();
        assert_eq!(
            fallback_layer.details.get("degraded_reason"),
            Some(&serde_json::json!("l3_error"))
        );

        let error_layer = degraded.layers.last().unwrap();
        assert_eq!(error_layer.level, "L3");
        assert_eq!(error_layer.layer_type, "degraded_error");
        assert_eq!(
            error_layer.details.get("fallback_due_to_error"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            error_layer.details.get("error"),
            Some(&serde_json::json!("model unavailable"))
        );
    }

    #[test]
    fn has_l3_pending_detects_pending_layer_only() {
        let pending = fallback_result();
        assert!(has_l3_pending(&pending));

        let without_pending = SecurityScanResult {
            layers: pending
                .layers
                .into_iter()
                .filter(|layer| layer.layer_type != "l3_pending")
                .collect(),
            ..pending
        };
        assert!(!has_l3_pending(&without_pending));
    }
}

mod public_strategy_types {
    use patronus_ark::{L3Strategy, NtdbOperatingPoint};

    #[test]
    fn ntdb_operating_point_defaults_to_best_promote_and_parses_all_variants() {
        assert_eq!(
            NtdbOperatingPoint::default(),
            NtdbOperatingPoint::BestPromote
        );
        for name in [
            "best_f1",
            "best_promote",
            "best_fpr_in_f1",
            "best_fnr_in_f1",
            "best_latency_in_f1",
        ] {
            assert_eq!(name.parse::<NtdbOperatingPoint>().unwrap().as_str(), name);
        }
    }

    #[test]
    fn l3_strategy_defaults_to_dedicated_and_parses_multi() {
        assert_eq!(L3Strategy::default(), L3Strategy::Dedicated);
        assert_eq!("multi".parse::<L3Strategy>().unwrap(), L3Strategy::Multi);
        assert_eq!(
            "dedicated".parse::<L3Strategy>().unwrap(),
            L3Strategy::Dedicated
        );
    }
}

mod long_text {
    use std::collections::HashMap;

    use patronus_ark::pipeline::test_util::{
        aggregate_chunk_outputs, candidate_selection, l3_metadata, ChunkAggregation,
    };
    use patronus_ark::{EvaluationResult, LayerResult};

    fn result(class_name: &str, confidence: f64, level: &str) -> EvaluationResult {
        EvaluationResult {
            class_name: class_name.to_string(),
            confidence,
            level: level.to_string(),
        }
    }

    fn layer(
        level: &str,
        class_name: &str,
        confidence: f64,
        matched: bool,
        duration_ms: f64,
    ) -> LayerResult {
        LayerResult {
            level: level.to_string(),
            layer_type: "test".to_string(),
            class_name: class_name.to_string(),
            confidence,
            matched,
            duration_ms,
            thresholds: HashMap::new(),
            details: HashMap::new(),
        }
    }

    #[test]
    fn candidate_selection_dedupes_contiguous_same_class_by_best_confidence() {
        let chunk_outputs = vec![
            (
                result("secret", 0.60, "L2"),
                vec![layer("L2", "secret", 0.60, true, 1.0)],
            ),
            (
                result("secret", 0.90, "L2"),
                vec![layer("L2", "secret", 0.90, true, 1.0)],
            ),
            (
                result("credential", 0.80, "L2"),
                vec![layer("L2", "credential", 0.80, true, 1.0)],
            ),
            (
                result("safe", 1.0, "L1"),
                vec![layer("L1", "safe", 1.0, true, 1.0)],
            ),
        ];

        let selection =
            candidate_selection(&chunk_outputs, |result, _| result.class_name != "safe");

        assert_eq!(selection.raw_count, 3);
        assert_eq!(selection.deduped_count, 2);
        assert_eq!(selection.indexes, vec![1, 2]);
        assert_eq!(selection.strategy, "contiguous_same_class_best_confidence");
    }

    #[test]
    fn aggregate_chunk_outputs_selects_highest_risk_and_summarizes_omitted_work() {
        let full_text_layers = vec![layer("L1", "safe", 0.0, false, 0.5)];
        let chunk_outputs = vec![
            (
                result("safe", 0.99, "L1"),
                vec![layer("L1", "safe", 0.99, true, 1.0)],
            ),
            (
                result("secret", 0.70, "L2"),
                vec![layer("L2", "secret", 0.70, true, 2.0)],
            ),
            (
                result("credential", 0.95, "L2"),
                vec![layer("L2", "credential", 0.95, true, 3.0)],
            ),
        ];

        let aggregate = aggregate_chunk_outputs(
            full_text_layers,
            chunk_outputs,
            3,
            "safe",
            ChunkAggregation::HighestRiskAboveThresholdOrConfidence { threshold: 0.93 },
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "credential");
        assert_eq!(aggregate.result.confidence, 0.95);
        let selected_chunk_layer = aggregate
            .layers
            .iter()
            .find(|layer| {
                layer.class_name == "credential"
                    && layer.details.get("chunk_id") == Some(&serde_json::json!(2))
            })
            .expect("selected chunk layer should be retained");
        assert_eq!(
            selected_chunk_layer.details.get("chunk_count"),
            Some(&serde_json::json!(3))
        );

        let l2_summary = aggregate
            .layers
            .iter()
            .find(|layer| layer.level == "L2" && layer.layer_type == "chunked_batch_summary")
            .expect("omitted L2 work should be summarized");
        assert_eq!(l2_summary.duration_ms, 2.0);
        assert_eq!(
            l2_summary.details.get("total_chunk_layer_count"),
            Some(&serde_json::json!(2))
        );
    }

    #[test]
    fn aggregate_chunk_outputs_ignores_risk_below_threshold() {
        let chunk_outputs = vec![
            (result("safe", 0.99, "L3"), vec![]),
            (result("credential", 0.92, "L3"), vec![]),
        ];

        let aggregate = aggregate_chunk_outputs(
            vec![],
            chunk_outputs,
            2,
            "safe",
            ChunkAggregation::HighestRiskAboveThresholdOrConfidence { threshold: 0.93 },
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "safe");
        assert_eq!(aggregate.result.confidence, 0.99);
    }

    #[test]
    fn l3_metadata_records_runtime_backend_and_batch_shape() {
        let metadata = l3_metadata(
            Some("fp16"),
            Some(std::path::Path::new("/tmp/model.onnx")),
            "demo-model",
            Some("CPUExecutionProvider"),
            "tensor_batch",
            4,
        );

        assert_eq!(
            metadata.get("runtime"),
            Some(&serde_json::json!("onnxruntime"))
        );
        assert_eq!(metadata.get("precision"), Some(&serde_json::json!("fp16")));
        assert_eq!(
            metadata.get("model_name"),
            Some(&serde_json::json!("demo-model"))
        );
        assert_eq!(
            metadata.get("batch_mode"),
            Some(&serde_json::json!("tensor_batch"))
        );
        assert_eq!(metadata.get("batch_size"), Some(&serde_json::json!(4)));
    }

    #[test]
    fn binary_any_positive_threshold_wins_before_highest_confidence() {
        let chunk_outputs = vec![
            (result("benign", 0.99, "L3"), vec![]),
            (result("attack", 0.94, "L3"), vec![]),
        ];

        let aggregate = aggregate_chunk_outputs(
            vec![],
            chunk_outputs,
            2,
            "benign",
            ChunkAggregation::AnyPositiveOrHighest {
                positive_class: "attack".to_string(),
                threshold: 0.93,
            },
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "attack");
        assert_eq!(aggregate.result.confidence, 0.94);
    }

    #[test]
    fn binary_any_positive_falls_back_to_highest_confidence_below_threshold() {
        let chunk_outputs = vec![
            (result("benign", 0.99, "L3"), vec![]),
            (result("attack", 0.92, "L3"), vec![]),
        ];

        let aggregate = aggregate_chunk_outputs(
            vec![],
            chunk_outputs,
            2,
            "benign",
            ChunkAggregation::AnyPositiveOrHighest {
                positive_class: "attack".to_string(),
                threshold: 0.93,
            },
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "benign");
        assert_eq!(aggregate.result.confidence, 0.99);
    }

    #[test]
    fn majority_vote_ignores_safe_labels_when_non_safe_exists() {
        let mut chunk_outputs = (0..9)
            .map(|_| (result("benign", 0.99, "L3"), vec![]))
            .collect::<Vec<_>>();
        chunk_outputs.push((result("legal", 0.65, "L3"), vec![]));

        let aggregate = aggregate_chunk_outputs(
            vec![],
            chunk_outputs,
            10,
            "benign",
            ChunkAggregation::MajorityVoteOrHighest,
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "legal");
    }

    #[test]
    fn majority_vote_still_prefers_largest_non_safe_class() {
        let mut chunk_outputs = (0..9)
            .map(|_| (result("hr", 0.70, "L3"), vec![]))
            .collect::<Vec<_>>();
        chunk_outputs.push((result("legal", 0.99, "L3"), vec![]));

        let aggregate = aggregate_chunk_outputs(
            vec![],
            chunk_outputs,
            10,
            "safe",
            ChunkAggregation::MajorityVoteOrHighest,
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "hr");
    }
}

mod decision_cache {
    use std::collections::HashMap;

    use patronus_ark::pipeline::test_util::{DecisionCache, DecisionCacheConfig};
    use patronus_ark::{EvaluationResult, LayerResult, ScanExecution, SecurityLevel};

    fn result(class_name: &str) -> EvaluationResult {
        EvaluationResult {
            class_name: class_name.to_string(),
            confidence: 0.9,
            level: "L2".to_string(),
        }
    }

    fn layers(class_name: &str) -> Vec<LayerResult> {
        vec![LayerResult {
            level: "L2".to_string(),
            layer_type: "ntdb_l2".to_string(),
            class_name: class_name.to_string(),
            confidence: 0.9,
            matched: true,
            duration_ms: 12.0,
            thresholds: HashMap::new(),
            details: HashMap::new(),
        }]
    }

    #[test]
    fn does_not_cache_l3_pending_layers() {
        let cache = DecisionCache::default();
        let execution = ScanExecution::new(SecurityLevel::L3);
        let result = EvaluationResult {
            class_name: "benign".to_string(),
            confidence: 0.8,
            level: "L2".to_string(),
        };
        let mut layers = layers("benign");
        layers.push(LayerResult {
            level: "L3".to_string(),
            layer_type: "l3_pending".to_string(),
            class_name: "benign".to_string(),
            confidence: 0.0,
            matched: false,
            duration_ms: 0.0,
            thresholds: HashMap::new(),
            details: HashMap::new(),
        });

        cache.insert("pending", "same text", &execution, &result, &layers);

        assert!(cache.get("pending", "same text", &execution).is_none());
    }

    #[test]
    fn cache_hit_returns_zeroed_decision_with_hit_metadata() {
        let cache = DecisionCache::default();
        let execution = ScanExecution::new(SecurityLevel::L2);
        let result = result("secret");
        let layers = layers("secret");

        cache.insert("model-a", "repeat me", &execution, &result, &layers);
        let (cached, cached_layers) = cache
            .get("model-a", "repeat me", &execution)
            .expect("decision should be cached");

        assert_eq!(cached.class_name, "secret");
        assert!(cached_layers[0].duration_ms < 5.0);
        assert_eq!(
            cached_layers[0].details.get("decision_cache_hit"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn cache_scope_includes_execution_policy() {
        let cache = DecisionCache::default();
        let mut execution = ScanExecution::new(SecurityLevel::L2);
        let result = result("secret");
        let layers = layers("secret");

        cache.insert("model-a", "repeat me", &execution, &result, &layers);
        execution.set_defer_l3(true);

        assert!(cache.get("model-a", "repeat me", &execution).is_none());
    }

    #[test]
    fn cache_prunes_to_entry_cap() {
        let cache = DecisionCache::with_config(DecisionCacheConfig {
            max_entries: 1,
            max_bytes: usize::MAX,
        });
        let execution = ScanExecution::new(SecurityLevel::L2);
        let result = result("secret");
        let layers = layers("secret");

        cache.insert("model-a", "first", &execution, &result, &layers);
        cache.insert("model-a", "second", &execution, &result, &layers);

        assert!(cache.get("model-a", "first", &execution).is_none());
        assert!(cache.get("model-a", "second", &execution).is_some());
    }
}

mod ntdb_l2_results {
    use patronus_ark::ml::ntdb_executor::{ByteSpan, L2ChunkOutput, L3Candidate, NtdbDecision};
    use patronus_ark::pipeline::test_util::{
        ntdb_l2_enabled_for_category, ntdb_l2_model_config_for_id,
        ntdb_l2_model_configs_for_category, ntdb_l2_scan_result,
    };
    use patronus_ark::{
        L3SchedulerPolicy, ScanExecution, ScanGateMatrix, SecurityCategory, SecurityLevel,
    };

    #[test]
    fn ntdb_l2_promote_result_preserves_old_api_model_and_queues_l3() {
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        execution.set_defer_l3(true);
        let decision = NtdbDecision {
            model_id: "injection".to_string(),
            aggregator_id: "router".to_string(),
            task: "binary_promote".to_string(),
            labels: vec![
                "benign".to_string(),
                "attack".to_string(),
                "promote".to_string(),
            ],
            fallback_label: "attack".to_string(),
            fallback_confidence: 0.91,
            route_to_l3: true,
            promote_score: Some(0.82),
            promote_threshold: Some(0.7),
            class_scores: vec![0.01, 0.91, 0.82],
            class_logits: vec![0.0, 2.0, 1.0],
            chunks: 3,
            chunk_promote_scores: vec![Some(0.1), Some(0.8), Some(0.2)],
            l3_candidate_spans: vec![ByteSpan {
                start: 256,
                end: 512,
            }],
            l3_candidates: vec![L3Candidate {
                span: ByteSpan {
                    start: 256,
                    end: 512,
                },
                promote_score: 0.8,
                promote_threshold: 0.7,
                source_pipeline: String::new(),
                source_model: "injection".to_string(),
                l2_class: "attack".to_string(),
            }],
            l2_chunk_outputs: vec![
                L2ChunkOutput {
                    span: ByteSpan { start: 0, end: 256 },
                    class_name: "benign".to_string(),
                    confidence: 0.9,
                    promoted: false,
                    promote_score: Some(0.1),
                    promote_threshold: Some(0.7),
                    source_pipeline: String::new(),
                    source_model: "injection".to_string(),
                    embedding: Vec::new(),
                    embedding_space: String::new(),
                    token_ids: Vec::new(),
                    tokenizer_family: String::new(),
                    class_probabilities: Vec::new(),
                    joint_v3_decision: None,
                },
                L2ChunkOutput {
                    span: ByteSpan {
                        start: 256,
                        end: 512,
                    },
                    class_name: "attack".to_string(),
                    confidence: 0.91,
                    promoted: true,
                    promote_score: Some(0.8),
                    promote_threshold: Some(0.7),
                    source_pipeline: String::new(),
                    source_model: "injection".to_string(),
                    embedding: Vec::new(),
                    embedding_space: String::new(),
                    token_ids: Vec::new(),
                    tokenizer_family: String::new(),
                    class_probabilities: Vec::new(),
                    joint_v3_decision: None,
                },
            ],
        };

        let config = ntdb_l2_model_config_for_id("injection").unwrap();
        let result = ntdb_l2_scan_result(config, &decision, &execution, 4.0);

        assert_eq!(result.category, "injection");
        assert_eq!(result.model, "wolf-defender-small");
        assert_eq!(result.class_name, "attack");
        assert_eq!(result.level, "L2");
        assert_eq!(
            result.layers[0].details.get("ntdb_model_id"),
            Some(&serde_json::json!("injection"))
        );
        assert_eq!(
            result.layers[0].details.get("aggregator_id"),
            Some(&serde_json::json!("router"))
        );
        assert_eq!(
            result.layers[0].details.get("decision_cache_hit"),
            None,
            "cache metadata is added by the gateway around the pure L2 result builder"
        );
        let chunk_outputs = result.layers[0]
            .details
            .get("l2_chunk_outputs")
            .and_then(serde_json::Value::as_array)
            .expect("L2 chunk outputs should be transported");
        assert_eq!(chunk_outputs.len(), 2);
        assert_eq!(chunk_outputs[0]["class_name"], serde_json::json!("benign"));
        assert_eq!(chunk_outputs[0]["promoted"], serde_json::json!(false));
        assert_eq!(
            chunk_outputs[0]["source_pipeline"],
            serde_json::json!("injection")
        );
        assert_eq!(chunk_outputs[1]["class_name"], serde_json::json!("attack"));
        assert_eq!(chunk_outputs[1]["promoted"], serde_json::json!(true));
        assert!(result.layers[0].matched);
        assert!(result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));
    }

    #[test]
    fn ntdb_l2_multiclass_result_maps_sensitive_documents_without_l3_pending() {
        let execution = ScanExecution::new(SecurityLevel::L3);
        let decision = NtdbDecision {
            model_id: "sensitive_document".to_string(),
            aggregator_id: "doc_router".to_string(),
            task: "multiclass".to_string(),
            labels: vec![
                "source_code".to_string(),
                "other".to_string(),
                "legal".to_string(),
            ],
            fallback_label: "source_code".to_string(),
            fallback_confidence: 0.73,
            route_to_l3: false,
            promote_score: None,
            promote_threshold: None,
            class_scores: vec![0.73, 0.1, 0.17],
            class_logits: vec![1.2, 0.0, 0.4],
            chunks: 1,
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };

        let config = ntdb_l2_model_config_for_id("sensitive_document").unwrap();
        let result = ntdb_l2_scan_result(config, &decision, &execution, 2.5);

        assert_eq!(result.category, "sensitive_document");
        assert_eq!(result.model, "orca-sonar-document-classifier");
        assert_eq!(result.class_name, "source_code");
        assert!((result.confidence - 0.73).abs() < 1e-6);
        assert_eq!(result.layers.len(), 1);
        assert_eq!(result.layers[0].layer_type, "ntdb_l2");
        assert!(result.layers[0].matched);
    }

    #[test]
    fn ntdb_l2_injection_result_uses_accepted_attack_candidate_from_label_scores() {
        let execution = ScanExecution::new(SecurityLevel::L2);
        let decision = NtdbDecision {
            model_id: "injection".to_string(),
            aggregator_id: "router".to_string(),
            task: "binary_promote".to_string(),
            labels: vec![
                "benign".to_string(),
                "attack".to_string(),
                "promote".to_string(),
            ],
            fallback_label: "benign".to_string(),
            fallback_confidence: 0.1,
            route_to_l3: false,
            promote_score: Some(0.1),
            promote_threshold: Some(0.7),
            class_scores: vec![0.1, 0.9, 0.1],
            class_logits: vec![0.0, 2.0, 0.0],
            chunks: 1,
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };

        let config = ntdb_l2_model_config_for_id("injection").unwrap();
        let result = ntdb_l2_scan_result(config, &decision, &execution, 1.0);

        assert_eq!(result.class_name, "attack");
        assert!((result.confidence - 0.9).abs() < 1e-6);
        let decision = result
            .decision
            .expect("L2-only result should carry a decision envelope");
        assert_eq!(decision.final_result.class_name, "attack");
        assert!((decision.final_result.confidence - 0.9).abs() < 1e-6);
        assert_eq!(decision.final_result.source, "l2");
        assert!(decision.recommendation.accepted);
        assert_eq!(decision.candidates.len(), 1);
        assert_eq!(decision.candidates[0].source, "l2");
        assert_eq!(decision.candidates[0].class_name, "attack");
        assert!((decision.candidates[0].confidence - 0.9).abs() < 1e-6);

        let candidate = decision
            .decision_candidate
            .expect("L2 final label should expose the L2 policy candidate");
        assert_eq!(candidate.source, "l2");
        assert_eq!(candidate.class_name, "attack");
        assert!((candidate.confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn ntdb_l2_tool_class_result_thresholds_fallback_and_queues_l3() {
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        execution.set_defer_l3(true);
        let decision = NtdbDecision {
            model_id: "tool_class".to_string(),
            aggregator_id: "main".to_string(),
            task: "multiclass".to_string(),
            labels: vec![
                "unknown".to_string(),
                "tool_class.web.search".to_string(),
                "tool_class.file.read".to_string(),
            ],
            fallback_label: "tool_class.web.search".to_string(),
            fallback_confidence: 0.88,
            route_to_l3: true,
            promote_score: Some(0.91),
            promote_threshold: Some(0.7),
            class_scores: vec![0.02, 0.88, 0.1],
            class_logits: vec![0.0, 2.0, 0.2],
            chunks: 1,
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };

        let config = ntdb_l2_model_config_for_id("tool_class").unwrap();
        let result = ntdb_l2_scan_result(config, &decision, &execution, 1.5);

        assert_eq!(result.category, "tool_class");
        assert_eq!(result.model, "unified-v3-tool-class");
        assert_eq!(result.class_name, "unknown");
        assert!((result.confidence - 0.02).abs() < 1e-6);
        assert!(
            result.decision.is_none(),
            "queued L2 results with l3_pending are not authoritative policy inputs"
        );
        assert_eq!(result.layers.len(), 2);
        assert_eq!(result.layers[0].layer_type, "ntdb_l2");
        assert!(result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));
    }

    #[test]
    fn ntdb_l2_respects_max_level_and_injection_model_gates() {
        let l1_only = ScanExecution::new(SecurityLevel::L1);
        assert!(!ntdb_l2_enabled_for_category(
            &l1_only,
            SecurityCategory::Injection
        ));
        assert!(!ntdb_l2_enabled_for_category(
            &l1_only,
            SecurityCategory::SensitiveDocument
        ));
        assert!(
            ntdb_l2_model_configs_for_category(&l1_only, SecurityCategory::ToolClass).is_empty()
        );

        let mut execution = ScanExecution::new(SecurityLevel::L2);
        assert!(ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::Injection
        ));

        let l2_only = ScanExecution::with_gates(
            SecurityLevel::L2,
            ScanGateMatrix::levels(false, true, false),
        );
        assert!(!l2_only.allows_level(SecurityLevel::L1));
        assert!(ntdb_l2_enabled_for_category(
            &l2_only,
            SecurityCategory::Injection
        ));

        execution.set_gates(ScanGateMatrix::all_enabled().with_model("injection", false));
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::Injection
        ));

        execution.set_gates(ScanGateMatrix::all_enabled().with_model("wolf-defender-small", false));
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::Injection
        ));
    }

    #[test]
    fn ntdb_l2_l3_pending_respects_l3_gate_and_scheduler_policy() {
        let decision = NtdbDecision {
            model_id: "injection".to_string(),
            aggregator_id: "router".to_string(),
            task: "binary_promote".to_string(),
            labels: vec![
                "benign".to_string(),
                "attack".to_string(),
                "promote".to_string(),
            ],
            fallback_label: "attack".to_string(),
            fallback_confidence: 0.91,
            route_to_l3: true,
            promote_score: Some(0.82),
            promote_threshold: Some(0.7),
            class_scores: vec![0.01, 0.91, 0.82],
            class_logits: vec![0.0, 2.0, 1.0],
            chunks: 1,
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };
        let config = ntdb_l2_model_config_for_id("injection").unwrap();

        let mut enabled = ScanExecution::new(SecurityLevel::L3);
        enabled.set_defer_l3(true);
        let result = ntdb_l2_scan_result(config, &decision, &enabled, 1.0);
        assert!(result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));

        let mut l3_level_closed =
            ScanExecution::with_gates(SecurityLevel::L3, ScanGateMatrix::levels(true, true, false));
        l3_level_closed.set_defer_l3(true);
        let result = ntdb_l2_scan_result(config, &decision, &l3_level_closed, 1.0);
        assert!(!result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));

        let policy = L3SchedulerPolicy {
            enabled: false,
            ..L3SchedulerPolicy::default()
        };
        let mut gates = ScanGateMatrix::all_enabled();
        gates.set_l3_policy(policy);
        let mut scheduler_disabled = ScanExecution::with_gates(SecurityLevel::L3, gates);
        scheduler_disabled.set_defer_l3(true);
        let result = ntdb_l2_scan_result(config, &decision, &scheduler_disabled, 1.0);
        assert!(!result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));

        let mut l2_only = ScanExecution::new(SecurityLevel::L2);
        l2_only.set_defer_l3(true);
        let result = ntdb_l2_scan_result(config, &decision, &l2_only, 1.0);
        assert!(!result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));

        let mut multi_disabled = ScanExecution::new(SecurityLevel::L3);
        multi_disabled.set_l3_strategy(patronus_ark::L3Strategy::Multi);
        multi_disabled.set_defer_l3(true);
        multi_disabled.set_gates(
            ScanGateMatrix::all_enabled().with_model("unified-multitask-model-augmented-v3", false),
        );
        let result = ntdb_l2_scan_result(config, &decision, &multi_disabled, 1.0);
        assert!(!result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));
    }

    #[test]
    fn ntdb_l2_respects_sensitive_documents_model_gates() {
        let mut execution = ScanExecution::new(SecurityLevel::L2);

        assert!(ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocument
        ));

        execution.set_gates(
            ScanGateMatrix::all_enabled().with_model("orca-sonar-document-classifier", false),
        );
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocument
        ));

        execution.set_gates(ScanGateMatrix::all_enabled().with_model("sensitive_document", false));
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocument
        ));

        execution.set_gates(ScanGateMatrix::levels(true, false, true));
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocument
        ));
    }

    #[test]
    fn ntdb_l2_respects_pipeline_and_model_gates() {
        let mut execution = ScanExecution::new(SecurityLevel::L2);
        let model_ids = ntdb_l2_model_configs_for_category(&execution, SecurityCategory::ToolClass)
            .into_iter()
            .map(|config| config.model_id)
            .collect::<Vec<_>>();
        assert_eq!(model_ids, vec!["tool_class"]);

        execution
            .set_gates(ScanGateMatrix::all_enabled().with_model("unified-v3-tool-class", false));
        let model_ids = ntdb_l2_model_configs_for_category(&execution, SecurityCategory::ToolClass)
            .into_iter()
            .map(|config| config.model_id)
            .collect::<Vec<_>>();
        assert!(model_ids.is_empty());
    }
}

mod download_policy {
    use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};

    #[test]
    fn download_categories_limit_asset_downloads() {
        let gateway = SecurityGateway::with_download_categories(
            vec![SecurityCategory::Injection, SecurityCategory::Pii],
            SecurityLevel::L2,
            None,
            true,
            Some(vec![SecurityCategory::Injection]),
        );

        assert!(gateway.should_download_assets_for(SecurityCategory::Injection));
        assert!(!gateway.should_download_assets_for(SecurityCategory::Pii));
    }

    #[test]
    fn download_files_false_disables_even_selected_categories() {
        let gateway = SecurityGateway::with_download_categories(
            vec![SecurityCategory::Injection],
            SecurityLevel::L2,
            None,
            false,
            Some(vec![SecurityCategory::Injection]),
        );

        assert!(!gateway.should_download_assets_for(SecurityCategory::Injection));
    }

    #[test]
    fn missing_download_categories_preserves_global_download_behavior() {
        let gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::Injection],
            SecurityLevel::L2,
            None,
            true,
        );

        assert!(gateway.should_download_assets_for(SecurityCategory::Injection));
    }
}
