//! Unit tests for internal pipeline building blocks, reached through the
//! `test-util` feature surface (enabled for the test suite via dev-dependencies).

mod strategy {
    use patronus_security::pipeline::test_util::{PipelineInput, PipelineScope, PipelineStrategy};
    use patronus_security::LongTextPolicy;

    #[test]
    fn global_text_pipelines_use_global_chunk_policy() {
        let policy = LongTextPolicy {
            enabled: true,
            no_full_l2_byte_limit: 1,
            chunk_size_bytes: 256,
            overlap_bytes: 96,
            verify_non_benign_l2: true,
        };

        assert_eq!(
            PipelineStrategy::sensitive_documents()
                .long_text_policy(policy)
                .chunk_size_bytes,
            512
        );
        assert_eq!(
            PipelineStrategy::user_intent()
                .long_text_policy(policy)
                .overlap_bytes,
            128
        );
        assert_eq!(
            PipelineStrategy::sensitive_documents().scope(),
            PipelineScope::Global
        );
        assert!(
            !PipelineStrategy::sensitive_documents().should_skip_full_l2(&"x".repeat(4096), policy)
        );
    }

    #[test]
    fn local_text_pipeline_can_skip_full_l2_for_long_text() {
        let policy = LongTextPolicy {
            enabled: true,
            no_full_l2_byte_limit: 1024,
            chunk_size_bytes: 512,
            overlap_bytes: 128,
            verify_non_benign_l2: true,
        };

        let strategy = PipelineStrategy::prompt_injection();

        assert_eq!(strategy.scope(), PipelineScope::Local);
        assert_eq!(strategy.input(), PipelineInput::Text);
        assert!(strategy.should_skip_full_l2(&"x".repeat(4096), policy));
        assert!(!strategy.should_skip_full_l2("short", policy));
    }

    #[test]
    fn structural_tool_pipeline_uses_local_chunk_policy_but_never_skips_full_l2() {
        let strategy = PipelineStrategy::tool_classifier_executions();
        let policy = LongTextPolicy {
            enabled: true,
            no_full_l2_byte_limit: 1,
            chunk_size_bytes: 512,
            overlap_bytes: 128,
            verify_non_benign_l2: true,
        };

        assert_eq!(
            strategy.long_text_policy(policy).chunk_size_bytes,
            PipelineStrategy::LOCAL_CHUNK_SIZE_BYTES
        );
        assert_eq!(strategy.scope(), PipelineScope::Local);
        assert_eq!(strategy.input(), PipelineInput::Structural);
        assert!(!strategy.should_skip_full_l2(&"x".repeat(4096), policy));
        assert!(!strategy.l3_allowed_for_text(&"x".repeat(2049)));
        assert!(strategy.l3_allowed_for_text(&"x".repeat(2048)));
    }
}

mod l3_results {
    use std::collections::HashMap;

    use patronus_security::pipeline::{
        degraded_error_result, degraded_timeout_result, has_l3_pending, l3_pending_layer,
    };
    use patronus_security::{
        EvaluationResult, LayerResult, ScanExecution, SecurityLevel, SecurityScanResult,
    };

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

mod long_text {
    use std::collections::HashMap;

    use patronus_security::pipeline::test_util::{
        aggregate_chunk_outputs, candidate_selection, chunk_text_bytes, l3_metadata,
        ChunkAggregation,
    };
    use patronus_security::{EvaluationResult, LayerResult, TextChunking};

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
    fn chunk_text_bytes_preserves_tail_and_overlap() {
        let chunking = TextChunking::new(5, 2).unwrap();

        let chunks = chunk_text_bytes("abcdefghijkl", chunking);

        assert_eq!(chunks, vec!["abcde", "defgh", "ghijk", "jkl"]);
        assert_eq!(chunks.last().unwrap(), "jkl");
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
            true,
            ChunkAggregation::HighestRiskOrConfidence,
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
            true,
            ChunkAggregation::AnyPositiveOrHighest {
                positive_class: "attack",
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
            true,
            ChunkAggregation::AnyPositiveOrHighest {
                positive_class: "attack",
                threshold: 0.93,
            },
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "benign");
        assert_eq!(aggregate.result.confidence, 0.99);
    }

    #[test]
    fn first_positive_aggregation_keeps_first_non_safe_chunk() {
        let chunk_outputs = vec![
            (result("safe", 0.99, "L2"), vec![]),
            (
                result("EMAIL", 0.60, "L2"),
                vec![layer("L2", "EMAIL", 0.60, true, 1.0)],
            ),
            (
                result("CREDIT_CARD", 0.95, "L2"),
                vec![layer("L2", "CREDIT_CARD", 0.95, true, 1.0)],
            ),
        ];

        let aggregate = aggregate_chunk_outputs(
            vec![],
            chunk_outputs,
            3,
            "safe",
            true,
            ChunkAggregation::FirstPositive,
        )
        .unwrap();

        assert_eq!(aggregate.result.class_name, "EMAIL");
        let selected_layer = aggregate
            .layers
            .iter()
            .find(|layer| layer.details.get("chunk_id") == Some(&serde_json::json!(1)))
            .expect("selected positive chunk layer should be retained");
        assert_eq!(selected_layer.class_name, "EMAIL");
        assert_eq!(
            selected_layer.details.get("chunk_id"),
            Some(&serde_json::json!(1))
        );
    }
}

mod decision_cache {
    use std::collections::HashMap;

    use patronus_security::pipeline::test_util::{DecisionCache, DecisionCacheConfig};
    use patronus_security::{EvaluationResult, LayerResult, ScanExecution, SecurityLevel};

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
    use patronus_security::ml::ntdb_executor::{ByteSpan, NtdbDecision};
    use patronus_security::pipeline::test_util::{
        ntdb_l2_enabled_for_category, ntdb_l2_model_config_for_id,
        ntdb_l2_model_configs_for_category, ntdb_l2_scan_result, NTDB_TOOL_DESCRIPTIONS_MODEL_ID,
        NTDB_TOOL_EXECUTIONS_MODEL_ID, NTDB_TOOL_PROMPTS_MODEL_ID, TOOL_PROMPTS_MODEL,
    };
    use patronus_security::{
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
        assert_eq!(
            result.layers[0].details.get("l3_candidate_spans"),
            Some(&serde_json::json!([{"start": 256, "end": 512}]))
        );
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
            model_id: "sensitive_documents".to_string(),
            aggregator_id: "doc_router".to_string(),
            task: "multiclass".to_string(),
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
        };

        let config = ntdb_l2_model_config_for_id("sensitive_documents").unwrap();
        let result = ntdb_l2_scan_result(config, &decision, &execution, 2.5);

        assert_eq!(result.category, "sensitive_documents");
        assert_eq!(result.model, "orca-sonar-document-classifier");
        assert_eq!(result.class_name, "source_code");
        assert_eq!(result.confidence, 0.73);
        assert_eq!(result.layers.len(), 1);
        assert_eq!(result.layers[0].layer_type, "ntdb_l2");
        assert!(result.layers[0].matched);
    }

    #[test]
    fn ntdb_l2_tool_multiclass_result_uses_old_api_model_without_l3_pending() {
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        execution.set_defer_l3(true);
        let decision = NtdbDecision {
            model_id: NTDB_TOOL_PROMPTS_MODEL_ID.to_string(),
            aggregator_id: "main".to_string(),
            task: "multiclass".to_string(),
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
        };

        let config = ntdb_l2_model_config_for_id(NTDB_TOOL_PROMPTS_MODEL_ID).unwrap();
        let result = ntdb_l2_scan_result(config, &decision, &execution, 1.5);

        assert_eq!(result.category, "tool_classifier");
        assert_eq!(result.model, TOOL_PROMPTS_MODEL);
        assert_eq!(result.class_name, "tool_class.web.search");
        assert_eq!(result.layers.len(), 1);
        assert_eq!(result.layers[0].layer_type, "ntdb_l2");
        assert!(!result
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
            SecurityCategory::SensitiveDocuments
        ));
        assert!(
            ntdb_l2_model_configs_for_category(&l1_only, SecurityCategory::ToolClassifier)
                .is_empty()
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

        let mut policy = L3SchedulerPolicy::default();
        policy.enabled = false;
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
    }

    #[test]
    fn ntdb_l2_respects_sensitive_documents_model_gates() {
        let mut execution = ScanExecution::new(SecurityLevel::L2);

        assert!(ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocuments
        ));

        execution.set_gates(
            ScanGateMatrix::all_enabled().with_model("orca-sonar-document-classifier", false),
        );
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocuments
        ));

        execution.set_gates(ScanGateMatrix::all_enabled().with_model("sensitive_documents", false));
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocuments
        ));

        execution.set_gates(ScanGateMatrix::levels(true, false, true));
        assert!(!ntdb_l2_enabled_for_category(
            &execution,
            SecurityCategory::SensitiveDocuments
        ));
    }

    #[test]
    fn ntdb_l2_respects_tool_classifier_submodel_gates() {
        let mut execution = ScanExecution::new(SecurityLevel::L2);
        let model_ids =
            ntdb_l2_model_configs_for_category(&execution, SecurityCategory::ToolClassifier)
                .into_iter()
                .map(|config| config.model_id)
                .collect::<Vec<_>>();
        assert_eq!(
            model_ids,
            vec![
                NTDB_TOOL_PROMPTS_MODEL_ID,
                NTDB_TOOL_EXECUTIONS_MODEL_ID,
                NTDB_TOOL_DESCRIPTIONS_MODEL_ID,
            ]
        );

        execution.set_gates(
            ScanGateMatrix::all_enabled()
                .with_model(TOOL_PROMPTS_MODEL, false)
                .with_model("tool_classifier.description", false),
        );
        let model_ids =
            ntdb_l2_model_configs_for_category(&execution, SecurityCategory::ToolClassifier)
                .into_iter()
                .map(|config| config.model_id)
                .collect::<Vec<_>>();
        assert_eq!(model_ids, vec![NTDB_TOOL_EXECUTIONS_MODEL_ID]);
    }
}

mod download_policy {
    use patronus_security::{SecurityCategory, SecurityGateway, SecurityLevel};

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
