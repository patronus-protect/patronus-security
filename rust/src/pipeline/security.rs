// SPDX-License-Identifier: GPL-3.0-only
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc, Arc, Mutex, OnceLock,
};
use std::time::Instant;

use super::decision_cache::DecisionCache;
use crate::{
    assets::DYNAMIC_PII_ASSET,
    detectors::{
        dlp::{destructive_operation, dlp, secret_transfer, sensitive_material},
        injection::{
            agentic_control_abuse, authority_escalation, binary_smuggling, covert_instruction,
            cross_tool_instruction, encoded_instruction, guardrail_tamper, hidden_html_instruction,
            instruction_boundary, instruction_leak, instruction_override, jailbreak_framing,
            multi_turn_escalation, output_manipulation, rule_catalog, signal, structural,
            tool_call_injection, tool_output_instruction, unicode_confusable,
            zero_width_obfuscation,
        },
        mcp::{mcp_policy, mcp_runtime_risk},
        pii::pii,
        threat::ThreatPipeline,
        NativeDetection, NativeRegexDetector,
    },
    diagnostics::PhaseMetricScope,
    ml::ntdb_executor::{NtdbExecutor, NtdbModelChunkInferences, PreparedNtdbChunk},
    pipeline::{L3Worker, RequestRegistry},
    post_prediction::filter_evidence,
    DynamicPiiConfig, EvaluationResult, ExecutionBackend, ExternalL1Detector, ExternalL1Input,
    LayerResult, NtdbOperatingPoint, OnnxBatchMode, ScanExecution, ScanGateMatrix,
    SecurityCategory, SecurityFailure, SecurityFailureKind, SecurityFailureStage, SecurityLevel,
    SecurityLevelReadiness, SecurityRuntimeReadiness, SecurityScanResult,
};

mod injection_l1;
mod ntdb_l2;
mod request_queue;
mod warmup;

use ntdb_l2::{ntdb_l2_cache_namespace, ntdb_l2_error_scan_result};
#[cfg(feature = "test-util")]
pub use ntdb_l2::{ntdb_l2_enabled_for_category, ntdb_l2_model_config_for_id, NtdbL2ModelConfig};
pub use ntdb_l2::{ntdb_l2_model_configs_for_category, ntdb_l2_scan_result};

const DEFAULT_QUEUE_WORKER_COUNT: usize = 2;

fn distributed_unified_l3_fingerprint(base_dir: &std::path::Path) -> Result<String, String> {
    use std::io::Read;

    let asset = crate::assets::UNIFIED_L3_ASSET;
    let bundle_dir = base_dir.join(asset.destination_path);
    let mut files = crate::assets::selected_pipeline_model_files(asset)
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    for generated in ["tokenizer.mmbpe", ".patronus-revision"] {
        if bundle_dir.join(generated).is_file() {
            files.push(generated.to_string());
        }
    }
    files.sort();
    files.dedup();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"patronus-unified-l3-assets-v1\0");
    for relative in files {
        let path = bundle_dir.join(&relative);
        let file = std::fs::File::open(&path).map_err(|error| {
            format!("failed to fingerprint L3 asset {}: {error}", path.display())
        })?;
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        let mut reader = std::io::BufReader::new(file);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(|error| {
                format!("failed to fingerprint L3 asset {}: {error}", path.display())
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod distributed_fingerprint_tests {
    use super::distributed_unified_l3_fingerprint;

    #[test]
    fn unified_l3_fingerprint_tracks_selected_file_contents() {
        let root = std::env::temp_dir().join(format!(
            "ark-l3-fingerprint-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let bundle = root.join(crate::assets::UNIFIED_L3_ASSET.destination_path);
        let selected =
            crate::assets::selected_pipeline_model_files(crate::assets::UNIFIED_L3_ASSET);
        for relative in &selected {
            let path = bundle.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, format!("fixture:{relative}")).unwrap();
        }
        std::fs::write(bundle.join(".patronus-revision"), "revision-a").unwrap();
        let before = distributed_unified_l3_fingerprint(&root).unwrap();
        std::fs::write(bundle.join(selected[0]), "changed").unwrap();
        let after = distributed_unified_l3_fingerprint(&root).unwrap();
        assert_ne!(before, after);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod distributed_plan_tests {
    use super::*;

    #[test]
    fn tool_tags_plan_preserves_all_canonical_model_bindings() {
        let gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::ToolTags],
            SecurityLevel::L2,
            None,
            false,
        );
        let execution = ScanExecution::new(SecurityLevel::L2);
        let pipelines = gateway.distributed_l2_pipelines(&[SecurityCategory::ToolTags], &execution);

        assert_eq!(pipelines.len(), 3);
        assert!(pipelines
            .iter()
            .all(|pipeline| pipeline.category == SecurityCategory::ToolTags));
        assert_eq!(
            pipelines
                .iter()
                .map(|pipeline| pipeline.model_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "tool_tags_sink_external",
                "tool_tags_source_sensitive",
                "tool_tags_source_untrusted",
            ]
        );
    }

    #[test]
    fn distributed_l2_plan_marks_l3_as_deferred_for_central_aggregation() {
        let gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::Injection],
            SecurityLevel::L3,
            None,
            false,
        );
        let execution = ScanExecution::new(SecurityLevel::L3);
        let inputs = [ExternalL1Input::new(
            SecurityCategory::Injection,
            "ordinary prose",
        )];

        let plan = gateway.plan_distributed_l2(&inputs, &serde_json::json!({}), &execution);

        assert!(plan.execution.defer_l3());
    }
}

fn run_measured_l1_detector<F>(
    category: SecurityCategory,
    model: &str,
    text_bytes: usize,
    evaluate: F,
) -> SecurityScanResult
where
    F: FnOnce() -> SecurityScanResult,
{
    let mut metrics = PhaseMetricScope::new(
        "security_l1_detector",
        format!(
            "category={} model={} text_bytes={}",
            category.as_str(),
            model,
            text_bytes
        ),
    );
    let result = evaluate();
    metrics.checkpoint(
        "after_evaluate",
        format!("category={} model={model}", category.as_str()),
    );
    result
}

/// Main scanner gateway for native and model-backed security categories.
pub struct SecurityGateway {
    core: Arc<SecurityGatewayCore>,
    queue_sender: OnceLock<mpsc::Sender<request_queue::QueueWork>>,
}

#[derive(Debug, Clone)]
pub struct DistributedL2Plan {
    pub l1_results: Vec<SecurityScanResult>,
    pub l1_failures: Vec<SecurityFailure>,
    pub categories: Vec<SecurityCategory>,
    pub model_ids: Vec<String>,
    pub pipelines: Vec<DistributedL2Pipeline>,
    pub execution: ScanExecution,
    pub gate_results: Vec<crate::GateResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedL2Pipeline {
    pub pipeline_id: String,
    pub category: SecurityCategory,
    pub model_id: String,
    pub public_model: String,
    pub has_l3: bool,
}

#[derive(Debug, Clone)]
pub struct DistributedL3Plan {
    pub categories: Vec<SecurityCategory>,
    pub execution: ScanExecution,
    pub gate_results: Vec<crate::GateResult>,
}

#[doc(hidden)]
pub struct SecurityGatewayCore {
    /// Categories configured for `scan_all`.
    categories: Vec<SecurityCategory>,
    /// Maximum layer to evaluate for configured categories.
    max_level: SecurityLevel,
    /// Optional asset root. Defaults to the platform cache directory.
    model_dir: Option<PathBuf>,
    /// Whether missing model assets may be downloaded during `warmup`.
    download_files: bool,
    /// Optional allowlist of categories that may download missing assets.
    download_categories: Option<Vec<SecurityCategory>>,
    /// Execution gates consumed by scan methods.
    execution: Mutex<ScanExecution>,
    /// Application-provided L1 heuristics, grouped in registration order by category.
    external_l1: Mutex<HashMap<SecurityCategory, Vec<Arc<dyn ExternalL1Detector>>>>,
    /// Request-independent configuration for the L3-only dynamic entity pipeline.
    dynamic_pii_config: Mutex<DynamicPiiConfig>,
    queue_worker_count: AtomicUsize,

    ntdb_executor: Option<Mutex<NtdbExecutor>>,
    distributed_fingerprints: OnceLock<(String, String)>,

    // Instantiated native rule-based pipelines
    dlp_pipeline: Option<dlp::DlpPipeline>,
    pii_pipeline: Option<pii::PiiPipeline>,
    threat_pipeline: Option<ThreatPipeline>,
    cross_tool_instruction_pipeline: Option<cross_tool_instruction::CrossToolInstructionPipeline>,
    instruction_leak_pipeline: Option<instruction_leak::InstructionLeakPipeline>,
    secret_transfer_pipeline: Option<secret_transfer::SecretTransferPipeline>,
    sensitive_material_pipeline: Option<sensitive_material::SensitiveMaterialPipeline>,
    encoded_instruction_pipeline: Option<encoded_instruction::EncodedInstructionPipeline>,
    multi_turn_escalation_pipeline: Option<multi_turn_escalation::MultiTurnEscalationPipeline>,
    guardrail_tamper_pipeline: Option<guardrail_tamper::GuardrailTamperPipeline>,
    destructive_operation_pipeline: Option<destructive_operation::DestructiveOperationPipeline>,
    agentic_control_abuse_pipeline: Option<agentic_control_abuse::AgenticControlAbusePipeline>,
    binary_smuggling_pipeline: Option<binary_smuggling::BinarySmugglingPipeline>,
    tool_output_instruction_pipeline:
        Option<tool_output_instruction::ToolOutputInstructionPipeline>,
    mcp_runtime_risk_pipeline: Option<mcp_runtime_risk::McpRuntimeRiskPipeline>,
    hidden_html_instruction_pipeline:
        Option<hidden_html_instruction::HiddenHtmlInstructionPipeline>,
    unicode_confusable_pipeline: Option<unicode_confusable::UnicodeConfusablePipeline>,
    zero_width_obfuscation_pipeline: Option<zero_width_obfuscation::ZeroWidthObfuscationPipeline>,
    injection_rule_catalog_pipeline: Option<rule_catalog::InjectionRuleCatalogPipeline>,
    injection_structural_pipeline: Option<structural::InjectionStructuralPipeline>,
    instruction_override_pipeline: Option<instruction_override::InstructionOverridePipeline>,
    jailbreak_framing_pipeline: Option<jailbreak_framing::JailbreakFramingPipeline>,
    covert_instruction_pipeline: Option<covert_instruction::CovertInstructionPipeline>,
    instruction_boundary_pipeline: Option<instruction_boundary::InstructionBoundaryPipeline>,
    authority_escalation_pipeline: Option<authority_escalation::AuthorityEscalationPipeline>,
    tool_call_injection_pipeline: Option<tool_call_injection::ToolCallInjectionPipeline>,
    output_manipulation_pipeline: Option<output_manipulation::OutputManipulationPipeline>,
    mcp_policy_pipeline: Option<mcp_policy::McpPolicyPipeline>,

    request_counter: AtomicU64,
    requests: Arc<RequestRegistry>,
    l3_worker: L3Worker,
    ntdb_decision_cache: DecisionCache,
}

impl Deref for SecurityGateway {
    type Target = SecurityGatewayCore;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl DerefMut for SecurityGateway {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::get_mut(&mut self.core).expect("warmup must run before queue processing starts")
    }
}

fn scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    result: EvaluationResult,
    layers: Vec<LayerResult>,
) -> SecurityScanResult {
    let duration_ms = layers.iter().map(|layer| layer.duration_ms).sum();
    SecurityScanResult {
        category: category.as_str().to_string(),
        class_name: result.class_name,
        confidence: result.confidence,
        level: result.level,
        model: model.into(),
        duration_ms,
        layers,
        internal_l2_chunk_outputs: Vec::new(),
        evidence_spans: Vec::new(),
        label_scores: Vec::new(),
        decision: None,
    }
}

pub(super) fn dynamic_pii_pending_result(execution: &ScanExecution) -> SecurityScanResult {
    let result = EvaluationResult {
        class_name: "pending".to_string(),
        confidence: 0.0,
        level: SecurityLevel::L3.as_str().to_string(),
    };
    scan_result(
        SecurityCategory::DynamicPii,
        DYNAMIC_PII_ASSET.model,
        result.clone(),
        vec![crate::pipeline::l3_pending_layer(&result, execution)],
    )
}

fn l1_scan_result_with_duration(
    category: SecurityCategory,
    model: impl Into<String>,
    layer_type: &str,
    result: EvaluationResult,
    duration_ms: f64,
) -> SecurityScanResult {
    let layer = LayerResult {
        level: result.level.clone(),
        layer_type: layer_type.to_string(),
        class_name: result.class_name.clone(),
        confidence: result.confidence,
        matched: true,
        duration_ms,
        thresholds: HashMap::new(),
        details: HashMap::new(),
    };
    scan_result(category, model, result, vec![layer])
}

fn timed_native_regex_scan_result<T: NativeRegexDetector>(
    category: SecurityCategory,
    model: impl Into<String>,
    detector: &T,
    prepared: &crate::threat::NativeText<'_>,
    execution: &ScanExecution,
) -> SecurityScanResult {
    let text = prepared.text();
    timed_native_detection_scan_result(category, model, text, || {
        detector.detect_prepared_with_options(
            prepared,
            |rule_id| execution.allows_rule(rule_id),
            execution.gates().explain,
        )
    })
}

fn timed_native_detection_scan_result<F>(
    category: SecurityCategory,
    model: impl Into<String>,
    text: &str,
    detect: F,
) -> SecurityScanResult
where
    F: FnOnce() -> NativeDetection,
{
    let model = model.into();
    let started = Instant::now();
    match catch_unwind(AssertUnwindSafe(detect)) {
        Ok(detection) => {
            let mut result = l1_scan_result_with_duration(
                category,
                model,
                "native",
                detection.result,
                started.elapsed().as_secs_f64() * 1000.0,
            );
            result.evidence_spans = filter_evidence(category, text, detection.evidence_spans);
            result.layers[0].details = detection.details;
            result
        }
        Err(payload) => scanner_error_scan_result(category, model, panic_message(payload)),
    }
}

fn scanner_error_scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    message: String,
) -> SecurityScanResult {
    let model = model.into();
    let result = EvaluationResult {
        class_name: "error".to_string(),
        confidence: 0.0,
        level: SecurityLevel::L1.as_str().to_string(),
    };
    let layer = LayerResult {
        level: result.level.clone(),
        layer_type: "scanner_error".to_string(),
        class_name: result.class_name.clone(),
        confidence: 0.0,
        matched: false,
        duration_ms: 0.0,
        thresholds: HashMap::new(),
        details: HashMap::from([("error".to_string(), serde_json::json!(message))]),
    };
    scan_result(category, model, result, vec![layer])
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "scanner panicked".to_string()
    }
}

impl SecurityGateway {
    /// Flush queued persistent cache writes. Memory-only gateways are a no-op.
    pub fn flush_cache(&self) -> Result<(), crate::CacheError> {
        self.l3_worker.flush_cache()
    }

    /// Flush queued persistent cache writes and reopen storage on the next cache access.
    pub fn reset_cache_connections(&self) -> Result<(), crate::CacheError> {
        self.l3_worker.reset_cache_connections()
    }

    /// Remove hot and persistent cache records created before `until_unix_ms`.
    pub fn reset_cache(&self, until_unix_ms: u64) -> Result<usize, crate::CacheError> {
        self.l3_worker.reset_cache(until_unix_ms)
    }

    /// Explicit persistent cache location configured for this gateway.
    pub fn cache_storage_location(&self) -> Option<PathBuf> {
        self.l3_worker.cache_storage_location()
    }

    /// Set the number of Ark queue workers spawned on first queued request.
    pub fn set_queue_worker_count(&self, worker_count: usize) {
        self.core
            .queue_worker_count
            .store(worker_count.max(1), Ordering::Relaxed);
    }

    /// Set ONNX Runtime session options for subsequent scans.
    pub fn set_onnx_runtime_options(&self, options: crate::OnnxRuntimeOptions) {
        self.execution
            .lock()
            .expect("scan execution mutex poisoned")
            .set_onnx_runtime_options(options);
    }

    /// Create a gateway with `SecurityLevel::L2` as the maximum level.
    pub fn new(
        categories: Vec<SecurityCategory>,
        model_dir: Option<PathBuf>,
        download_files: bool,
    ) -> Self {
        Self::with_max_level(categories, SecurityLevel::L2, model_dir, download_files)
    }

    /// Create a gateway with an explicit maximum security level.
    pub fn with_max_level(
        categories: Vec<SecurityCategory>,
        max_level: SecurityLevel,
        model_dir: Option<PathBuf>,
        download_files: bool,
    ) -> Self {
        Self::with_download_categories(categories, max_level, model_dir, download_files, None)
    }

    /// Create a gateway with an optional per-category asset download allowlist.
    ///
    /// When `download_categories` is `None`, all configured categories may
    /// download missing assets if `download_files` is `true`.
    pub fn with_download_categories(
        categories: Vec<SecurityCategory>,
        max_level: SecurityLevel,
        model_dir: Option<PathBuf>,
        download_files: bool,
        download_categories: Option<Vec<SecurityCategory>>,
    ) -> Self {
        Self::try_with_download_categories_and_cache(
            categories,
            max_level,
            model_dir,
            download_files,
            download_categories,
            crate::ExactCacheConfig::default(),
        )
        .expect("memory-only exact cache must initialize")
    }

    /// Create a gateway with lifecycle-scoped exact-cache configuration.
    ///
    /// Persistent caching is enabled only when `cache_config.persistent`
    /// contains an explicit storage location. Requests cannot override it.
    pub fn try_with_download_categories_and_cache(
        categories: Vec<SecurityCategory>,
        max_level: SecurityLevel,
        model_dir: Option<PathBuf>,
        download_files: bool,
        download_categories: Option<Vec<SecurityCategory>>,
        cache_config: crate::ExactCacheConfig,
    ) -> Result<Self, crate::CacheError> {
        let requests = Arc::new(RequestRegistry::default());
        let l3_worker = L3Worker::start_with_cache(Arc::clone(&requests), cache_config)?;
        let mut core = SecurityGatewayCore {
            categories,
            max_level,
            model_dir,
            download_files,
            download_categories,
            execution: Mutex::new(ScanExecution::new(max_level)),
            external_l1: Mutex::new(HashMap::new()),
            dynamic_pii_config: Mutex::new(DynamicPiiConfig::default()),
            queue_worker_count: AtomicUsize::new(DEFAULT_QUEUE_WORKER_COUNT),
            ntdb_executor: None,
            distributed_fingerprints: OnceLock::new(),
            dlp_pipeline: None,
            pii_pipeline: None,
            threat_pipeline: None,
            cross_tool_instruction_pipeline: None,
            instruction_leak_pipeline: None,
            secret_transfer_pipeline: None,
            sensitive_material_pipeline: None,
            encoded_instruction_pipeline: None,
            multi_turn_escalation_pipeline: None,
            guardrail_tamper_pipeline: None,
            destructive_operation_pipeline: None,
            agentic_control_abuse_pipeline: None,
            binary_smuggling_pipeline: None,
            tool_output_instruction_pipeline: None,
            mcp_runtime_risk_pipeline: None,
            hidden_html_instruction_pipeline: None,
            unicode_confusable_pipeline: None,
            zero_width_obfuscation_pipeline: None,
            injection_rule_catalog_pipeline: None,
            injection_structural_pipeline: None,
            instruction_override_pipeline: None,
            jailbreak_framing_pipeline: None,
            covert_instruction_pipeline: None,
            instruction_boundary_pipeline: None,
            authority_escalation_pipeline: None,
            tool_call_injection_pipeline: None,
            output_manipulation_pipeline: None,
            mcp_policy_pipeline: None,
            request_counter: AtomicU64::new(1),
            requests,
            l3_worker,
            ntdb_decision_cache: DecisionCache::default(),
        };

        // Immediately instantiate native rule pipelines for configured categories
        for cat in &core.categories {
            match cat {
                SecurityCategory::Injection => {
                    core.cross_tool_instruction_pipeline =
                        Some(cross_tool_instruction::CrossToolInstructionPipeline::new());
                    core.instruction_leak_pipeline =
                        Some(instruction_leak::InstructionLeakPipeline::new());
                    core.encoded_instruction_pipeline =
                        Some(encoded_instruction::EncodedInstructionPipeline::new());
                    core.multi_turn_escalation_pipeline =
                        Some(multi_turn_escalation::MultiTurnEscalationPipeline::new());
                    core.guardrail_tamper_pipeline =
                        Some(guardrail_tamper::GuardrailTamperPipeline::new());
                    core.tool_output_instruction_pipeline =
                        Some(tool_output_instruction::ToolOutputInstructionPipeline::new());
                    core.hidden_html_instruction_pipeline =
                        Some(hidden_html_instruction::HiddenHtmlInstructionPipeline::new());
                    core.unicode_confusable_pipeline =
                        Some(unicode_confusable::UnicodeConfusablePipeline::new());
                    core.zero_width_obfuscation_pipeline =
                        Some(zero_width_obfuscation::ZeroWidthObfuscationPipeline::new());
                    core.injection_rule_catalog_pipeline =
                        Some(rule_catalog::InjectionRuleCatalogPipeline::new());
                    core.injection_structural_pipeline =
                        Some(structural::InjectionStructuralPipeline::new());
                    core.agentic_control_abuse_pipeline =
                        Some(agentic_control_abuse::AgenticControlAbusePipeline::new());
                    core.binary_smuggling_pipeline =
                        Some(binary_smuggling::BinarySmugglingPipeline::new());
                    core.instruction_override_pipeline =
                        Some(instruction_override::InstructionOverridePipeline::new());
                    core.jailbreak_framing_pipeline =
                        Some(jailbreak_framing::JailbreakFramingPipeline::new());
                    core.covert_instruction_pipeline =
                        Some(covert_instruction::CovertInstructionPipeline::new());
                    core.instruction_boundary_pipeline =
                        Some(instruction_boundary::InstructionBoundaryPipeline::new());
                    core.authority_escalation_pipeline =
                        Some(authority_escalation::AuthorityEscalationPipeline::new());
                    core.tool_call_injection_pipeline =
                        Some(tool_call_injection::ToolCallInjectionPipeline::new());
                    core.output_manipulation_pipeline =
                        Some(output_manipulation::OutputManipulationPipeline::new());
                }
                SecurityCategory::Dlp => {
                    core.dlp_pipeline = Some(dlp::DlpPipeline::new());
                    core.sensitive_material_pipeline =
                        Some(sensitive_material::SensitiveMaterialPipeline::new());
                    core.secret_transfer_pipeline =
                        Some(secret_transfer::SecretTransferPipeline::new());
                    core.mcp_runtime_risk_pipeline =
                        Some(mcp_runtime_risk::McpRuntimeRiskPipeline::new());
                    core.mcp_policy_pipeline = Some(mcp_policy::McpPolicyPipeline::new());
                    core.destructive_operation_pipeline =
                        Some(destructive_operation::DestructiveOperationPipeline::new());
                }
                SecurityCategory::Threat => {
                    core.threat_pipeline = Some(ThreatPipeline::new());
                }
                SecurityCategory::Pii => {
                    core.pii_pipeline = Some(pii::PiiPipeline::new());
                }
                _ => {}
            }
        }

        Ok(SecurityGateway {
            core: Arc::new(core),
            queue_sender: OnceLock::new(),
        })
    }

    /// Categories configured for `scan_all`.
    pub fn categories(&self) -> &[SecurityCategory] {
        &self.categories
    }

    /// Maximum level evaluated for configured categories.
    pub fn max_level(&self) -> SecurityLevel {
        self.max_level
    }

    /// Return runtime readiness for the currently configured levels and models.
    pub fn runtime_readiness(&self) -> SecurityRuntimeReadiness {
        let execution = self.scan_execution();
        let external_l1 = self
            .external_l1
            .lock()
            .expect("external L1 registry mutex poisoned");
        let has_l1_category = self.categories.iter().any(|category| {
            matches!(
                category,
                SecurityCategory::Injection
                    | SecurityCategory::Dlp
                    | SecurityCategory::Pii
                    | SecurityCategory::Threat
            ) || external_l1
                .get(category)
                .is_some_and(|detectors| !detectors.is_empty())
        });
        let l1 = if execution.allows_level(SecurityLevel::L1) && has_l1_category {
            SecurityLevelReadiness::Ready
        } else {
            SecurityLevelReadiness::NotConfigured
        };

        let l2_configs = self
            .categories
            .iter()
            .copied()
            .flat_map(|category| ntdb_l2_model_configs_for_category(&execution, category))
            .collect::<Vec<_>>();
        let l2 = if l2_configs.is_empty() {
            SecurityLevelReadiness::NotConfigured
        } else if self.ntdb_executor.is_some() {
            SecurityLevelReadiness::Ready
        } else {
            SecurityLevelReadiness::NotReady {
                failures: l2_configs
                    .iter()
                    .map(|config| SecurityFailure {
                        stage: SecurityFailureStage::Inference,
                        level: Some(SecurityLevel::L2),
                        detector_id: Some(config.public_model.to_string()),
                        kind: SecurityFailureKind::NotReady,
                        retryable: true,
                        message: format!("{} L2 runtime is not initialized", config.public_model),
                    })
                    .collect(),
            }
        };

        let has_classifier_l3 = l2_configs
            .iter()
            .any(|config| config.has_l3 && execution.allows_level(SecurityLevel::L3));
        let mut l3_models = match execution.l3_strategy() {
            crate::L3Strategy::Multi
                if has_classifier_l3
                    && execution.allows_model(crate::ml::unified_onnx::UNIFIED_MODEL) =>
            {
                vec![crate::ml::unified_onnx::UNIFIED_MODEL]
            }
            crate::L3Strategy::Multi => Vec::new(),
            crate::L3Strategy::Dedicated => l2_configs
                .iter()
                .filter(|config| config.has_l3 && execution.allows_level(SecurityLevel::L3))
                .map(|config| config.public_model)
                .collect::<Vec<_>>(),
        };
        if self.categories.contains(&SecurityCategory::DynamicPii)
            && execution.allows_level(SecurityLevel::L3)
            && execution.allows_model(DYNAMIC_PII_ASSET.model)
        {
            l3_models.push(DYNAMIC_PII_ASSET.model);
        }
        let l3_failures = l3_models
            .iter()
            .filter(|model| !self.l3_worker.has_model(model))
            .map(|model| SecurityFailure {
                stage: SecurityFailureStage::Worker,
                level: Some(SecurityLevel::L3),
                detector_id: Some((*model).to_string()),
                kind: SecurityFailureKind::NotReady,
                retryable: true,
                message: format!("{model} L3 worker model is not registered"),
            })
            .collect::<Vec<_>>();
        let l3 = if l3_models.is_empty() {
            SecurityLevelReadiness::NotConfigured
        } else if l3_failures.is_empty() {
            SecurityLevelReadiness::Ready
        } else {
            SecurityLevelReadiness::NotReady {
                failures: l3_failures,
            }
        };

        SecurityRuntimeReadiness { l1, l2, l3 }
    }

    /// Register an external L1 heuristic for the category returned by the detector.
    ///
    /// Detectors run after the built-in L1 heuristics in registration order.
    pub fn register_external_l1(
        &self,
        detector: Arc<dyn ExternalL1Detector>,
    ) -> Result<(), String> {
        let category = detector.category();
        let id = detector.id();
        if id.is_empty() {
            return Err("external L1 detector id must not be empty".to_string());
        }

        let mut registry = self
            .external_l1
            .lock()
            .expect("external L1 registry mutex poisoned");
        let detectors = registry.entry(category).or_default();
        if detectors.iter().any(|registered| registered.id() == id) {
            return Err(format!(
                "external L1 detector '{id}' is already registered for {}",
                category.as_str()
            ));
        }
        detectors.push(detector);
        Ok(())
    }

    #[doc(hidden)]
    pub fn should_download_assets_for(&self, category: SecurityCategory) -> bool {
        if !self.download_files {
            return false;
        }

        match &self.download_categories {
            Some(categories) => categories.contains(&category),
            None => true,
        }
    }

    /// Replace the execution gate matrix used by subsequent scans.
    pub fn set_execution_gates(&self, gates: ScanGateMatrix) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_gates(gates);
    }

    /// Replace the ONNX batch mode used by subsequent batch scans.
    pub fn set_onnx_batch_mode(&self, mode: OnnxBatchMode) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_onnx_batch_mode(mode);
    }

    /// Replace the execution backend and apply its default L3 mode.
    pub fn set_execution_backend(&self, backend: ExecutionBackend) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_backend(backend);
    }

    /// Select the calibrated NTDB operating point used by subsequent scans.
    pub fn set_ntdb_operating_point(&self, point: NtdbOperatingPoint) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_ntdb_operating_point(point);
    }

    /// Select the calibrated NTDB final-decision threshold set used by subsequent scans.
    pub fn set_ntdb_decision_threshold_point(&self, point: NtdbOperatingPoint) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_ntdb_decision_threshold_point(point);
    }

    /// Select dedicated per-pipeline L3 models or the shared multi-head model.
    pub fn set_l3_strategy(&self, strategy: crate::L3Strategy) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_l3_strategy(strategy);
    }

    /// Unload resident L3 model sessions while keeping registered model metadata.
    ///
    /// Subsequent L3 scans can reload the same configured models without another
    /// gateway construction or asset warmup.
    pub fn stop_l3_models(&self) {
        self.l3_worker.stop_models();
    }

    /// Return the active global L3 model strategy.
    pub fn l3_strategy(&self) -> crate::L3Strategy {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .l3_strategy()
    }

    /// Return the calibrated NTDB operating point used by subsequent scans.
    pub fn ntdb_operating_point(&self) -> NtdbOperatingPoint {
        self.scan_execution().ntdb_operating_point()
    }

    /// Runtime identities used to reject incompatible distributed batches.
    pub fn distributed_ntdb_fingerprints(&self) -> Result<(String, String), String> {
        if let Some(fingerprints) = self.distributed_fingerprints.get() {
            return Ok(fingerprints.clone());
        }
        let executor = self
            .ntdb_executor
            .as_ref()
            .ok_or_else(|| "NTDB L2 runtime is not initialized".to_string())?
            .lock()
            .map_err(|error| format!("NTDB executor mutex poisoned: {error}"))?;
        let (tokenizer, ntdb_models) = executor
            .distributed_fingerprints()
            .map_err(|error| error.to_string())?;
        let mut models = blake3::Hasher::new();
        models.update(b"patronus-distributed-models-v1\0");
        models.update(ntdb_models.as_bytes());
        models.update(&[0]);
        if self
            .l3_worker
            .has_model(crate::ml::unified_onnx::UNIFIED_MODEL)
        {
            let base_dir = self.model_base_dir().map_err(|error| error.to_string())?;
            models.update(distributed_unified_l3_fingerprint(&base_dir)?.as_bytes());
        } else {
            models.update(b"unified-l3-not-loaded");
        }
        let fingerprints = (tokenizer, models.finalize().to_hex().to_string());
        let _ = self.distributed_fingerprints.set(fingerprints.clone());
        Ok(self
            .distributed_fingerprints
            .get()
            .cloned()
            .unwrap_or(fingerprints))
    }

    /// Tokenize a document once for distributed Package-v4 execution.
    pub fn prepare_distributed_ntdb_chunks(
        &self,
        text: &str,
    ) -> Result<Vec<PreparedNtdbChunk>, String> {
        self.ntdb_executor
            .as_ref()
            .ok_or_else(|| "NTDB L2 runtime is not initialized".to_string())?
            .lock()
            .map_err(|error| format!("NTDB executor mutex poisoned: {error}"))?
            .prepare_chunks(text)
            .map_err(|error| error.to_string())
    }

    /// Infer independent, pre-tokenized NTDB chunks without L1 or document aggregation.
    pub fn infer_distributed_ntdb_chunks(
        &self,
        model_ids: HashSet<String>,
        chunks: &[PreparedNtdbChunk],
        document_chunk_count: usize,
        operating_point: NtdbOperatingPoint,
    ) -> Result<Vec<NtdbModelChunkInferences>, String> {
        self.ntdb_executor
            .as_ref()
            .ok_or_else(|| "NTDB L2 runtime is not initialized".to_string())?
            .lock()
            .map_err(|error| format!("NTDB executor mutex poisoned: {error}"))?
            .infer_prepared_chunks_for_models(
                model_ids,
                chunks,
                document_chunk_count,
                operating_point,
            )
            .map_err(|error| error.to_string())
    }

    /// Run immediate unified L3 inference for promoted chunks without document aggregation.
    pub fn infer_distributed_unified_l3_chunks(
        &self,
        chunks: &[crate::ml::ntdb_executor::NtdbChunkInference],
        execution: &ScanExecution,
    ) -> Result<Vec<crate::pipeline::DistributedL3ChunkInference>, String> {
        self.l3_worker
            .infer_distributed_unified_chunks(chunks, execution)
    }

    /// Aggregate all unified L3 chunk outputs with the normal final result mapping.
    pub fn aggregate_distributed_unified_l3_chunks(
        &self,
        chunks: &[crate::pipeline::DistributedL3ChunkInference],
        l2_fallbacks: &[SecurityScanResult],
        execution: &ScanExecution,
        duration_ms: f64,
    ) -> Result<Vec<SecurityScanResult>, String> {
        self.l3_worker.aggregate_distributed_unified_chunks(
            chunks,
            l2_fallbacks,
            execution,
            duration_ms,
        )
    }

    /// Aggregate all worker L2 evidence and map it through the normal gateway thresholds.
    pub fn aggregate_distributed_ntdb_chunks(
        &self,
        inferred: &[NtdbModelChunkInferences],
        categories: &[SecurityCategory],
        execution: &ScanExecution,
        duration_ms: f64,
    ) -> Result<Vec<SecurityScanResult>, String> {
        let decisions = self
            .ntdb_executor
            .as_ref()
            .ok_or_else(|| "NTDB L2 runtime is not initialized".to_string())?
            .lock()
            .map_err(|error| format!("NTDB executor mutex poisoned: {error}"))?
            .aggregate_chunk_inferences(inferred, execution.ntdb_operating_point())
            .map_err(|error| error.to_string())?;
        let configs = categories
            .iter()
            .copied()
            .flat_map(|category| ntdb_l2_model_configs_for_category(execution, category))
            .collect::<Vec<_>>();
        Ok(decisions
            .iter()
            .filter_map(|decision| {
                configs
                    .iter()
                    .find(|config| config.model_id == decision.model_id)
                    .map(|config| ntdb_l2_scan_result(*config, decision, execution, duration_ms))
            })
            .collect())
    }

    /// Execute only the normal L1 portion with the gateway's effective configuration.
    pub fn distributed_execution(&self) -> ScanExecution {
        self.scan_execution()
    }

    pub fn scan_distributed_l1(
        &self,
        inputs: &[ExternalL1Input],
        execution: &ScanExecution,
    ) -> Vec<SecurityScanResult> {
        self.scan_l1_inputs(inputs, execution)
    }

    /// Resolve canonical distributed pipeline bindings without executing scanners.
    pub fn distributed_l2_pipelines(
        &self,
        categories: &[SecurityCategory],
        execution: &ScanExecution,
    ) -> Vec<DistributedL2Pipeline> {
        categories
            .iter()
            .flat_map(|category| ntdb_l2_model_configs_for_category(execution, *category))
            .map(|config| DistributedL2Pipeline {
                pipeline_id: config.model_id.to_string(),
                category: config.category,
                model_id: config.model_id.to_string(),
                public_model: config.public_model.to_string(),
                has_l3: config.has_l3,
            })
            .collect()
    }

    /// Run L1 and resolve the exact conditional-gate/model plan for distributed L2.
    pub fn plan_distributed_l2(
        &self,
        inputs: &[ExternalL1Input],
        metadata: &serde_json::Value,
        execution: &ScanExecution,
    ) -> DistributedL2Plan {
        let (l1_results, l1_failures) =
            request_queue::split_results(self.scan_l1_inputs(inputs, execution));
        let mut gate_results = l1_results
            .iter()
            .filter_map(request_queue::gate_result)
            .collect::<Vec<_>>();
        gate_results.extend(request_queue::rejected_l1_candidate_gate_results(
            &l1_results,
        ));
        let categories = inputs
            .iter()
            .filter(|input| {
                crate::pipeline::conditional_gate::pipeline_allowed(
                    execution,
                    SecurityLevel::L2,
                    input.category.as_str(),
                    metadata,
                    &gate_results,
                )
            })
            .map(|input| input.category)
            .collect::<Vec<_>>();
        let mut l2_execution = execution.clone();
        let mut gates = l2_execution.gates().clone();
        for category in &categories {
            for config in ntdb_l2_model_configs_for_category(&l2_execution, *category) {
                if ![config.model_id, config.public_model]
                    .into_iter()
                    .all(|model| {
                        crate::pipeline::conditional_gate::pipeline_allowed(
                            execution,
                            SecurityLevel::L2,
                            model,
                            metadata,
                            &gate_results,
                        )
                    })
                {
                    gates.set_model(config.model_id, false);
                    gates.set_model(config.public_model, false);
                }
            }
        }
        l2_execution.set_gates(gates);
        if l2_execution.allows_level(SecurityLevel::L3) && l2_execution.l3_policy().enabled {
            l2_execution.set_defer_l3(true);
        }
        let pipelines = self.distributed_l2_pipelines(&categories, &l2_execution);
        let model_ids = pipelines
            .iter()
            .map(|pipeline| pipeline.model_id.clone())
            .collect();
        DistributedL2Plan {
            l1_results,
            l1_failures,
            categories,
            model_ids,
            pipelines,
            execution: l2_execution,
            gate_results,
        }
    }

    /// Resolve L3 policy overrides and eligibility after distributed L2 aggregation.
    pub fn plan_distributed_l3(
        &self,
        l1_gate_results: &[crate::GateResult],
        l2_results: &[SecurityScanResult],
        metadata: &serde_json::Value,
        execution: &ScanExecution,
    ) -> DistributedL3Plan {
        let mut gate_results = l1_gate_results.to_vec();
        gate_results.extend(l2_results.iter().filter_map(request_queue::gate_result));
        let execution = crate::pipeline::conditional_gate::apply_l3_policy_overrides(
            execution,
            metadata,
            &gate_results,
        );
        let categories = l2_results
            .iter()
            .filter(|result| crate::pipeline::has_l3_pending(result))
            .filter(|result| {
                crate::pipeline::conditional_gate::pipeline_allowed(
                    &execution,
                    SecurityLevel::L3,
                    &result.category,
                    metadata,
                    &gate_results,
                ) && crate::pipeline::conditional_gate::pipeline_allowed(
                    &execution,
                    SecurityLevel::L3,
                    &result.model,
                    metadata,
                    &gate_results,
                )
            })
            .filter_map(|result| result.category.parse().ok())
            .collect();
        DistributedL3Plan {
            categories,
            execution,
            gate_results,
        }
    }

    /// Return the calibrated NTDB final-decision threshold set used by subsequent scans.
    pub fn ntdb_decision_threshold_point(&self) -> NtdbOperatingPoint {
        self.scan_execution().ntdb_decision_threshold_point()
    }

    /// Replace the pipeline-specific `dynamic-pii` configuration.
    pub fn set_dynamic_pii_config(&self, config: DynamicPiiConfig) -> Result<(), String> {
        let config = config.validated()?;
        *self
            .dynamic_pii_config
            .lock()
            .expect("dynamic-pii config mutex poisoned") = config;
        Ok(())
    }

    /// Return the currently configured `dynamic-pii` settings.
    pub fn dynamic_pii_config(&self) -> DynamicPiiConfig {
        self.dynamic_pii_config
            .lock()
            .expect("dynamic-pii config mutex poisoned")
            .clone()
    }

    /// Return the execution state that should be consumed by this scan.
    fn scan_execution(&self) -> ScanExecution {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .clone()
            .with_max_level(self.max_level)
    }

    fn level_enabled(&self, execution: &ScanExecution, level: SecurityLevel) -> bool {
        execution.allows_level(level)
    }

    fn model_enabled(&self, execution: &ScanExecution, model: &str) -> bool {
        execution.allows_model(model)
    }

    #[cfg(test)]
    fn scan_category_with_execution(
        &self,
        input: &ExternalL1Input,
        execution: &ScanExecution,
    ) -> Vec<SecurityScanResult> {
        self.scan_category_prepared(
            input,
            execution,
            &crate::threat::NativeText::new(input.text.as_ref()),
        )
    }

    fn scan_category_prepared(
        &self,
        input: &ExternalL1Input,
        execution: &ScanExecution,
        prepared: &crate::threat::NativeText<'_>,
    ) -> Vec<SecurityScanResult> {
        let category = input.category;
        let text = input.text.as_ref();
        let mut results = Vec::new();
        macro_rules! push_native {
            ($pipeline:expr, $model:literal, $rule:literal) => {
                if self.level_enabled(&execution, SecurityLevel::L1)
                    && self.model_enabled(&execution, $model)
                    && execution.allows_rule($rule)
                {
                    if let Some(ref pipe) = $pipeline {
                        results.push(run_measured_l1_detector(
                            category,
                            $model,
                            text.len(),
                            || {
                                timed_native_detection_scan_result(category, $model, text, || {
                                    pipe.detect_prepared(prepared)
                                })
                            },
                        ));
                    }
                }
            };
        }
        macro_rules! push_native_injection {
            ($target:expr, $pipeline:expr, $model:literal) => {
                if self.level_enabled(&execution, SecurityLevel::L1)
                    && self.model_enabled(&execution, "native:injection_l1")
                    && self.model_enabled(&execution, $model)
                    && execution.allows_rule(signal::native_rule_id($model))
                {
                    if let Some(ref pipe) = $pipeline {
                        $target.push(run_measured_l1_detector(
                            category,
                            $model,
                            text.len(),
                            || {
                                timed_native_detection_scan_result(category, $model, text, || {
                                    pipe.detect_prepared(prepared)
                                })
                            },
                        ));
                    }
                }
            };
        }

        match category {
            SecurityCategory::Injection => {
                let mut native_results = Vec::new();
                if self.level_enabled(execution, SecurityLevel::L1)
                    && self.model_enabled(execution, "native:injection_l1")
                    && self.model_enabled(execution, "native:injection_rule_catalog")
                {
                    if let Some(ref catalog) = self.injection_rule_catalog_pipeline {
                        native_results.push(run_measured_l1_detector(
                            category,
                            "native:injection_rule_catalog",
                            text.len(),
                            || {
                                timed_native_detection_scan_result(
                                    category,
                                    "native:injection_rule_catalog",
                                    text,
                                    || {
                                        catalog.detect_prepared(prepared, |rule_id| {
                                            execution.allows_rule(rule_id)
                                        })
                                    },
                                )
                            },
                        ));
                    }
                }
                if self.level_enabled(execution, SecurityLevel::L1)
                    && self.model_enabled(execution, "native:injection_l1")
                    && self.model_enabled(execution, "native:injection_structural")
                    && execution
                        .allows_rule("ark.injection.structure.override_sensitive_disclosure")
                {
                    if let Some(ref structural) = self.injection_structural_pipeline {
                        native_results.push(run_measured_l1_detector(
                            category,
                            "native:injection_structural",
                            text.len(),
                            || {
                                timed_native_detection_scan_result(
                                    category,
                                    "native:injection_structural",
                                    text,
                                    || structural.detect_prepared(prepared),
                                )
                            },
                        ));
                    }
                }
                push_native_injection!(
                    native_results,
                    self.cross_tool_instruction_pipeline,
                    "native:cross_tool_instruction"
                );
                push_native_injection!(
                    native_results,
                    self.instruction_leak_pipeline,
                    "native:instruction_leak"
                );
                push_native_injection!(
                    native_results,
                    self.encoded_instruction_pipeline,
                    "native:encoded_instruction"
                );
                push_native_injection!(
                    native_results,
                    self.multi_turn_escalation_pipeline,
                    "native:multi_turn_escalation"
                );
                push_native_injection!(
                    native_results,
                    self.guardrail_tamper_pipeline,
                    "native:guardrail_tamper"
                );
                push_native_injection!(
                    native_results,
                    self.tool_output_instruction_pipeline,
                    "native:tool_output_instruction"
                );
                push_native_injection!(
                    native_results,
                    self.hidden_html_instruction_pipeline,
                    "native:hidden_html_instruction"
                );
                push_native_injection!(
                    native_results,
                    self.unicode_confusable_pipeline,
                    "native:unicode_confusable"
                );
                push_native_injection!(
                    native_results,
                    self.zero_width_obfuscation_pipeline,
                    "native:zero_width_obfuscation"
                );
                push_native_injection!(
                    native_results,
                    self.agentic_control_abuse_pipeline,
                    "native:agentic_control_abuse"
                );
                push_native_injection!(
                    native_results,
                    self.binary_smuggling_pipeline,
                    "native:binary_smuggling"
                );
                push_native_injection!(
                    native_results,
                    self.instruction_override_pipeline,
                    "native:instruction_override"
                );
                push_native_injection!(
                    native_results,
                    self.jailbreak_framing_pipeline,
                    "native:jailbreak_framing"
                );
                push_native_injection!(
                    native_results,
                    self.covert_instruction_pipeline,
                    "native:covert_instruction"
                );
                push_native_injection!(
                    native_results,
                    self.instruction_boundary_pipeline,
                    "native:instruction_boundary"
                );
                push_native_injection!(
                    native_results,
                    self.authority_escalation_pipeline,
                    "native:authority_escalation"
                );
                push_native_injection!(
                    native_results,
                    self.tool_call_injection_pipeline,
                    "native:tool_call_injection"
                );
                push_native_injection!(
                    native_results,
                    self.output_manipulation_pipeline,
                    "native:output_manipulation"
                );
                if !native_results.is_empty() {
                    results.push(injection_l1::aggregate(text, native_results));
                }
            }
            SecurityCategory::Dlp => {
                if self.level_enabled(execution, SecurityLevel::L1)
                    && self.model_enabled(execution, "native:dlp")
                {
                    if let Some(ref native) = self.dlp_pipeline {
                        results.push(run_measured_l1_detector(
                            category,
                            "native:dlp",
                            text.len(),
                            || {
                                timed_native_regex_scan_result(
                                    category,
                                    "native:dlp",
                                    native,
                                    prepared,
                                    execution,
                                )
                            },
                        ));
                    }
                }
                push_native!(
                    self.sensitive_material_pipeline,
                    "native:sensitive_material",
                    "dlp_sensitive_material"
                );
                push_native!(
                    self.secret_transfer_pipeline,
                    "native:secret_transfer",
                    "dlp_secret_transfer"
                );
                push_native!(
                    self.mcp_runtime_risk_pipeline,
                    "native:mcp_runtime_risk",
                    "dlp_mcp_runtime_risk"
                );
                push_native!(
                    self.mcp_policy_pipeline,
                    "native:mcp_policy",
                    "dlp_mcp_policy"
                );
                push_native!(
                    self.destructive_operation_pipeline,
                    "native:destructive_operation",
                    "dlp_destructive_operation"
                );
            }
            SecurityCategory::Pii => {
                let native_enabled = self.level_enabled(execution, SecurityLevel::L1)
                    && self.model_enabled(execution, "native:pii");
                if native_enabled {
                    if let Some(ref native) = self.pii_pipeline {
                        results.push(run_measured_l1_detector(
                            category,
                            "native:pii",
                            text.len(),
                            || {
                                timed_native_regex_scan_result(
                                    category,
                                    "native:pii",
                                    native,
                                    prepared,
                                    execution,
                                )
                            },
                        ));
                    }
                }
            }
            SecurityCategory::Threat => {
                if self.level_enabled(execution, SecurityLevel::L1)
                    && self.model_enabled(execution, "native:threat_l1")
                {
                    if let Some(ref native) = self.threat_pipeline {
                        results.push(run_measured_l1_detector(
                            category,
                            "native:threat_l1",
                            text.len(),
                            || {
                                timed_native_detection_scan_result(
                                    category,
                                    "native:threat_l1",
                                    text,
                                    || native.detect_prepared(prepared, |id| execution.allows_rule(id)),
                                )
                            },
                        ));
                    }
                }
            }
            SecurityCategory::DynamicPii => {}
            SecurityCategory::SensitiveDocument
            | SecurityCategory::ToolClass
            | SecurityCategory::ToolAction
            | SecurityCategory::ToolTags
            | SecurityCategory::Routing => {}
        }

        if self.level_enabled(execution, SecurityLevel::L1) {
            let detectors = self
                .external_l1
                .lock()
                .expect("external L1 registry mutex poisoned")
                .get(&category)
                .cloned()
                .unwrap_or_default();
            for detector in detectors {
                let model = format!("external:{}", detector.id());
                if !self.model_enabled(execution, &model) {
                    continue;
                }
                results.push(run_measured_l1_detector(
                    category,
                    &model,
                    text.len(),
                    || {
                        let started = Instant::now();
                        match catch_unwind(AssertUnwindSafe(|| detector.evaluate(input))) {
                            Ok(mut result) => {
                                result.level = SecurityLevel::L1.as_str().to_string();
                                l1_scan_result_with_duration(
                                    category,
                                    model.clone(),
                                    "external_l1",
                                    result,
                                    started.elapsed().as_secs_f64() * 1000.0,
                                )
                            }
                            Err(payload) => scanner_error_scan_result(
                                category,
                                model.clone(),
                                panic_message(payload),
                            ),
                        }
                    },
                ));
            }
        }
        results
    }

    fn scan_ntdb_l2_categories(
        &self,
        categories: &[SecurityCategory],
        text: &str,
        execution: &ScanExecution,
    ) -> Vec<SecurityScanResult> {
        let mut metrics = PhaseMetricScope::new(
            "security_ntdb_l2_categories",
            format!("categories={} text_bytes={}", categories.len(), text.len()),
        );
        let requested = categories
            .iter()
            .copied()
            .flat_map(|category| ntdb_l2_model_configs_for_category(execution, category))
            .collect::<Vec<_>>();
        if requested.is_empty() {
            return Vec::new();
        }

        let Some(executor_mutex) = &self.ntdb_executor else {
            return requested
                .into_iter()
                .map(|config| {
                    ntdb_l2_error_scan_result(config, "NTDB L2 runtime is not initialized")
                })
                .collect();
        };

        let mut cached_results: HashMap<&'static str, Vec<SecurityScanResult>> = HashMap::new();
        let mut missing_configs = Vec::new();
        {
            let executor = match executor_mutex.lock() {
                Ok(executor) => executor,
                Err(err) => {
                    return requested
                        .into_iter()
                        .map(|config| {
                            ntdb_l2_error_scan_result(
                                config,
                                format!("NTDB executor mutex poisoned: {err}"),
                            )
                        })
                        .collect();
                }
            };

            for config in &requested {
                let Some(aggregator_ids) = executor.model_aggregator_ids(config.model_id) else {
                    missing_configs.push(*config);
                    continue;
                };

                let mut cached_for_category = Vec::with_capacity(aggregator_ids.len());
                let mut all_cached = true;
                for aggregator_id in aggregator_ids {
                    let namespace = ntdb_l2_cache_namespace(config.model_id, &aggregator_id);
                    if let Some((result, layers)) =
                        self.ntdb_decision_cache.get(&namespace, text, execution)
                    {
                        cached_for_category.push(scan_result(
                            config.category,
                            config.public_model,
                            result,
                            layers,
                        ));
                    } else {
                        all_cached = false;
                        break;
                    }
                }

                if all_cached {
                    cached_results.insert(config.model_id, cached_for_category);
                } else {
                    missing_configs.push(*config);
                }
            }
        }
        metrics.checkpoint(
            "after_cache_check",
            format!(
                "requested={} cached_models={} missing={}",
                requested.len(),
                cached_results.len(),
                missing_configs.len()
            ),
        );
        let mut scored_results = cached_results;
        if !missing_configs.is_empty() {
            let model_ids = missing_configs
                .iter()
                .map(|config| config.model_id)
                .collect::<Vec<_>>();
            let scoring_started = Instant::now();
            metrics.checkpoint(
                "before_executor_score",
                format!("model_ids={}", model_ids.len()),
            );
            let decisions = match executor_mutex.lock() {
                Ok(mut executor) => executor.score_models(
                    model_ids.iter().copied(),
                    text,
                    execution.ntdb_operating_point(),
                ),
                Err(err) => Err(Box::new(std::io::Error::other(format!(
                    "NTDB executor mutex poisoned: {err}"
                )))
                    as Box<dyn std::error::Error + Send + Sync>),
            };
            metrics.checkpoint(
                "after_executor_score",
                format!("model_ids={}", model_ids.len()),
            );
            let duration_ms = scoring_started.elapsed().as_secs_f64() * 1000.0;

            match decisions {
                Ok(decisions) => {
                    for decision in decisions {
                        let Some(config) = missing_configs
                            .iter()
                            .find(|config| config.model_id == decision.model_id)
                            .copied()
                        else {
                            continue;
                        };
                        let mut result =
                            ntdb_l2_scan_result(config, &decision, execution, duration_ms);
                        for layer in &mut result.layers {
                            layer
                                .details
                                .entry("decision_cache_hit".to_string())
                                .or_insert_with(|| serde_json::json!(false));
                        }
                        let evaluation = EvaluationResult {
                            class_name: result.class_name.clone(),
                            confidence: result.confidence,
                            level: result.level.clone(),
                        };
                        let namespace =
                            ntdb_l2_cache_namespace(&decision.model_id, &decision.aggregator_id);
                        self.ntdb_decision_cache.insert(
                            &namespace,
                            text,
                            execution,
                            &evaluation,
                            &result.layers,
                        );
                        scored_results
                            .entry(config.model_id)
                            .or_default()
                            .push(result);
                    }
                    metrics.checkpoint("after_result_build", "");
                }
                Err(err) => {
                    let message = err.to_string();
                    for config in &missing_configs {
                        scored_results
                            .entry(config.model_id)
                            .or_default()
                            .push(ntdb_l2_error_scan_result(*config, message.clone()));
                    }
                }
            }
        }

        let mut results = Vec::new();
        for config in requested {
            if let Some(mut scored) = scored_results.remove(config.model_id) {
                results.append(&mut scored);
            }
        }
        metrics.checkpoint("after_result_mapping", format!("results={}", results.len()));
        results
    }

    fn scan_l1_inputs(
        &self,
        inputs: &[ExternalL1Input],
        execution: &ScanExecution,
    ) -> Vec<SecurityScanResult> {
        use rayon::prelude::*;

        let mut execution = execution.clone();
        if execution.allows_level(SecurityLevel::L3) && execution.l3_policy().enabled {
            execution.set_defer_l3(true);
        }

        // Equal text supplied for different categories shares request-local views.
        // Distinct external inputs retain independent preparation and offsets.
        let mut prepared = HashMap::new();
        for input in inputs {
            let text = input.text.as_ref();
            prepared
                .entry(text)
                .or_insert_with(|| crate::threat::NativeText::new(text));
        }
        inputs
            .par_iter()
            .map(|input| {
                self.scan_category_prepared(input, &execution, &prepared[input.text.as_ref()])
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect()
    }

    fn scan_l2_inputs(
        &self,
        inputs: &[ExternalL1Input],
        execution: &ScanExecution,
        metadata: &serde_json::Value,
        gate_results: &[crate::GateResult],
    ) -> Vec<SecurityScanResult> {
        let mut metrics = PhaseMetricScope::new(
            "security_scan_l2_inputs",
            format!(
                "inputs={} gate_results={}",
                inputs.len(),
                gate_results.len()
            ),
        );
        let mut execution = execution.clone();
        if execution.allows_level(SecurityLevel::L3) && execution.l3_policy().enabled {
            execution.set_defer_l3(true);
        }
        let allowed_categories = inputs
            .iter()
            .filter(|input| {
                crate::pipeline::conditional_gate::pipeline_allowed(
                    &execution,
                    SecurityLevel::L2,
                    input.category.as_str(),
                    metadata,
                    gate_results,
                )
            })
            .collect::<Vec<_>>();
        metrics.checkpoint(
            "after_allowed_categories",
            format!("allowed={}", allowed_categories.len()),
        );
        let mut l2_execution = execution.clone();
        let mut l2_gates = l2_execution.gates().clone();
        for input in &allowed_categories {
            for config in ntdb_l2_model_configs_for_category(&l2_execution, input.category) {
                let model_allowed =
                    [config.model_id, config.public_model]
                        .into_iter()
                        .all(|model| {
                            crate::pipeline::conditional_gate::pipeline_allowed(
                                &execution,
                                SecurityLevel::L2,
                                model,
                                metadata,
                                gate_results,
                            )
                        });
                if !model_allowed {
                    l2_gates.set_model(config.model_id, false);
                    l2_gates.set_model(config.public_model, false);
                }
            }
        }
        l2_execution.set_gates(l2_gates);
        metrics.checkpoint("after_gate_filtering", "");
        let mut results = Vec::new();
        if let Some(first) = allowed_categories.first() {
            if allowed_categories
                .iter()
                .all(|input| input.text == first.text)
            {
                let categories = allowed_categories
                    .iter()
                    .map(|input| input.category)
                    .collect::<Vec<_>>();
                metrics.checkpoint(
                    "before_shared_ntdb_l2",
                    format!("categories={}", categories.len()),
                );
                results.extend(self.scan_ntdb_l2_categories(
                    &categories,
                    &first.text,
                    &l2_execution,
                ));
                metrics.checkpoint("after_shared_ntdb_l2", format!("results={}", results.len()));
            } else {
                for input in allowed_categories {
                    metrics.checkpoint(
                        "before_single_ntdb_l2",
                        format!("category={}", input.category.as_str()),
                    );
                    results.extend(self.scan_ntdb_l2_categories(
                        &[input.category],
                        &input.text,
                        &l2_execution,
                    ));
                    metrics
                        .checkpoint("after_single_ntdb_l2", format!("results={}", results.len()));
                }
            }
        }
        metrics.checkpoint("done", format!("results={}", results.len()));
        results
    }
}
