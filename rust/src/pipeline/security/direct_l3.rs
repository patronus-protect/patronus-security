// SPDX-License-Identifier: GPL-3.0-only
//! Prepare classifier requests when no L2 inference stage is enabled.

use super::{ntdb_l2::classifier_model_configs_for_category, scan_result, SecurityGateway};
use crate::{
    ml::{ntdb_executor::L2ChunkOutput, tokenizer::RuntimeTokenizer},
    EvaluationResult, ExternalL1Input, ScanExecution, SecurityLevel, SecurityScanResult,
};

impl SecurityGateway {
    pub(super) fn direct_l3_results(
        &self,
        inputs: &[ExternalL1Input],
        execution: &ScanExecution,
        metadata: &serde_json::Value,
        gate_results: &[crate::GateResult],
    ) -> Vec<SecurityScanResult> {
        if !execution.allows_level(SecurityLevel::L3) || !execution.l3_policy().enabled {
            return Vec::new();
        }
        if execution.l3_strategy() == crate::L3Strategy::Multi
            && !execution.allows_model(crate::ml::unified_onnx::UNIFIED_MODEL)
        {
            return Vec::new();
        }
        let mut results = Vec::new();
        for input in inputs {
            let configs = classifier_model_configs_for_category(execution, input.category)
                .into_iter()
                .filter(|config| {
                    [
                        input.category.as_str(),
                        config.public_model,
                        config.model_id,
                    ]
                    .into_iter()
                    .all(|pipeline| {
                        crate::pipeline::conditional_gate::pipeline_allowed(
                            execution,
                            SecurityLevel::L3,
                            pipeline,
                            metadata,
                            gate_results,
                        )
                    })
                })
                .collect::<Vec<_>>();
            if configs.is_empty() {
                continue;
            }
            let tokenizer = self.model_base_dir().and_then(|base| {
                let dir = if execution.l3_strategy() == crate::L3Strategy::Multi {
                    base.join(crate::assets::UNIFIED_L3_ASSET.destination_path)
                } else {
                    crate::assets::dedicated_l3_asset(input.category)
                        .map(|asset| base.join(asset.destination_path))
                        .unwrap_or_else(|| base.join(input.category.as_str()))
                };
                RuntimeTokenizer::load(dir).map_err(Into::into)
            });
            for config in configs {
                let tokenizer = match &tokenizer {
                    Ok(tokenizer) => tokenizer,
                    Err(error) => {
                        let mut failure = super::scanner_error_scan_result(
                            input.category,
                            config.public_model.to_string(),
                            error.to_string(),
                        );
                        failure.level = "L3".to_string();
                        failure.layers[0].level = "L3".to_string();
                        results.push(failure);
                        continue;
                    }
                };
                let evaluation = EvaluationResult {
                    class_name: "pending".to_string(),
                    confidence: 0.0,
                    level: "L3".to_string(),
                };
                let pending = crate::pipeline::l3_pending_layer(&evaluation, execution);
                let mut result = scan_result(
                    input.category,
                    config.public_model,
                    evaluation,
                    vec![pending],
                );
                // Reuse the token handoff transport, without inventing L2 scores or embeddings.
                result.internal_l2_chunk_outputs = tokenizer
                    .token_chunks_with_overlap(&input.text, execution.chunk_overlap_tokens())
                    .expect("ScanExecution contains a validated chunk overlap")
                    .into_iter()
                    .map(|chunk| L2ChunkOutput {
                        span: crate::ml::ntdb_executor::ByteSpan {
                            start: chunk.byte_span.0,
                            end: chunk.byte_span.1,
                        },
                        class_name: String::new(),
                        confidence: 0.0,
                        promoted: true,
                        promote_score: None,
                        promote_threshold: None,
                        source_pipeline: config.model_id.to_string(),
                        source_model: config.public_model.to_string(),
                        embedding: Vec::new(),
                        embedding_space: String::new(),
                        token_ids: chunk.token_ids,
                        tokenizer_family: crate::ml::tokenizer::TOKENIZER_FAMILY.to_string(),
                        class_probabilities: Vec::new(),
                        joint_v3_decision: None,
                    })
                    .collect();
                results.push(result);
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{L3Strategy, ScanGateMatrix, SecurityCategory};

    fn gateway() -> SecurityGateway {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "ark-direct-l3-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let bundle = base.join(crate::assets::UNIFIED_L3_ASSET.destination_path);
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tokenizer.mmbpe"),
            bundle.join("tokenizer.mmbpe"),
        )
        .unwrap();
        let gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::Injection, SecurityCategory::ToolTags],
            SecurityLevel::L3,
            Some(base),
            false,
        );
        gateway.set_l3_strategy(L3Strategy::Multi);
        gateway.set_execution_gates(ScanGateMatrix::levels(false, false, true));
        gateway
    }

    #[test]
    fn l3_only_prepares_every_chunk_without_l2_scores() {
        let gateway = gateway();
        let text = "hello world ".repeat(800);
        let inputs = vec![ExternalL1Input::new(
            SecurityCategory::Injection,
            text.as_str(),
        )];
        let results = gateway.scan_l2_inputs(
            &inputs,
            &gateway.scan_execution(),
            &serde_json::json!({}),
            &[],
        );
        assert_eq!(results.len(), 1);
        assert!(crate::pipeline::has_l3_pending(&results[0]));
        assert!(results[0].layers.iter().all(|layer| layer.level == "L3"));
        let chunks = &results[0].internal_l2_chunk_outputs;
        assert!(chunks.len() > 1);
        let expected = crate::ml::tokenizer::fixture_tokenizer().token_chunks(&text);
        assert_eq!(chunks.len(), expected.len());
        for (chunk, expected) in chunks.iter().zip(expected) {
            assert_eq!(chunk.token_ids, expected.token_ids);
            assert_eq!((chunk.span.start, chunk.span.end), expected.byte_span);
            assert!(chunk.class_probabilities.is_empty());
            assert!(chunk.embedding.is_empty());
            assert!(chunk.token_ids.len() <= 254);
        }
    }

    #[test]
    fn l3_only_uses_request_chunk_overlap() {
        let gateway = gateway();
        let text = "hello world ".repeat(800);
        let inputs = vec![ExternalL1Input::new(
            SecurityCategory::Injection,
            text.as_str(),
        )];
        let mut execution = gateway.scan_execution();
        execution.set_chunk_overlap_tokens(64).unwrap();

        let results = gateway.scan_l2_inputs(&inputs, &execution, &serde_json::json!({}), &[]);
        let actual = &results[0].internal_l2_chunk_outputs;
        let expected = crate::ml::tokenizer::fixture_tokenizer()
            .token_chunks_with_overlap(&text, 64)
            .unwrap();

        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            assert_eq!(actual.token_ids, expected.token_ids);
            assert_eq!((actual.span.start, actual.span.end), expected.byte_span);
        }
    }

    #[test]
    fn l3_only_keeps_tool_properties_and_model_gates() {
        let gateway = gateway();
        let inputs = vec![ExternalL1Input::new(SecurityCategory::ToolTags, "hello")];
        let mut execution = gateway.scan_execution();
        let results = gateway.direct_l3_results(&inputs, &execution, &serde_json::json!({}), &[]);
        assert_eq!(results.len(), 3);
        let heads = results
            .iter()
            .map(|r| r.internal_l2_chunk_outputs[0].source_pipeline.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(heads.len(), 3);
        for result in &results {
            let candidates = super::super::request_queue::l3_candidates(result);
            assert_eq!(candidates.len(), result.internal_l2_chunk_outputs.len());
            for (candidate, chunk) in candidates.iter().zip(&result.internal_l2_chunk_outputs) {
                assert_eq!(candidate.span, chunk.span);
                assert_eq!(candidate.source_pipeline, chunk.source_pipeline);
                assert!(candidate.source_pipeline.starts_with("tool_tags_"));
            }
        }
        let mut gates = execution.gates().clone();
        gates.set_model("tool_tags_sink_external", false);
        execution.set_gates(gates);
        assert_eq!(
            gateway
                .direct_l3_results(&inputs, &execution, &serde_json::json!({}), &[])
                .len(),
            2
        );
        execution.set_gates(ScanGateMatrix::levels(false, false, false));
        assert!(gateway
            .direct_l3_results(&inputs, &execution, &serde_json::json!({}), &[])
            .is_empty());
    }

    #[test]
    fn l3_only_conditional_gate_does_not_publish_pending() {
        let gateway = gateway();
        let mut gates = gateway.scan_execution().gates().clone();
        gates
            .set_conditional(vec![crate::ConditionalPipelineGate {
                level: SecurityLevel::L3,
                pipeline: Some("injection".to_string()),
                when: crate::GateExpression::Metadata(crate::MetadataCondition {
                    path: "run_l3".to_string(),
                    equals: Some(serde_json::json!(true)),
                    in_values: None,
                    exists: None,
                }),
                l3_policy: None,
            }])
            .unwrap();
        let mut execution = gateway.scan_execution();
        execution.set_gates(gates);
        let inputs = vec![ExternalL1Input::new(SecurityCategory::Injection, "hello")];
        assert!(gateway
            .scan_l2_inputs(&inputs, &execution, &serde_json::json!({}), &[])
            .is_empty());
        assert_eq!(
            gateway
                .scan_l2_inputs(
                    &inputs,
                    &execution,
                    &serde_json::json!({"run_l3": true}),
                    &[]
                )
                .len(),
            1
        );
    }

    #[test]
    fn l3_only_conditional_gate_keeps_tool_property_identity() {
        let gateway = gateway();
        let mut gates = gateway.scan_execution().gates().clone();
        gates
            .set_conditional(vec![crate::ConditionalPipelineGate {
                level: SecurityLevel::L3,
                pipeline: Some("tool_tags_sink_external".to_string()),
                when: crate::GateExpression::Metadata(crate::MetadataCondition {
                    path: "run_sink".to_string(),
                    equals: Some(serde_json::json!(true)),
                    in_values: None,
                    exists: None,
                }),
                l3_policy: None,
            }])
            .unwrap();
        let mut execution = gateway.scan_execution();
        execution.set_gates(gates);
        let inputs = vec![ExternalL1Input::new(SecurityCategory::ToolTags, "hello")];
        let results = gateway.scan_l2_inputs(&inputs, &execution, &serde_json::json!({}), &[]);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| result
            .internal_l2_chunk_outputs
            .iter()
            .all(|chunk| chunk.source_pipeline != "tool_tags_sink_external")));
        assert_eq!(
            gateway
                .scan_l2_inputs(
                    &inputs,
                    &execution,
                    &serde_json::json!({"run_sink": true}),
                    &[]
                )
                .len(),
            3
        );
    }

    #[test]
    fn l3_only_readiness_requires_the_unified_model() {
        let gateway = gateway();
        assert!(matches!(
            gateway.runtime_readiness().l3,
            crate::SecurityLevelReadiness::NotReady { .. }
        ));
    }
}
