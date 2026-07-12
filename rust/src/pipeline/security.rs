use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{atomic::AtomicU64, mpsc, Arc, Mutex, OnceLock};
use std::time::Instant;

use super::decision_cache::DecisionCache;
use crate::{
    detectors::{
        dlp::{destructive_operation, dlp, secret_transfer, sensitive_material},
        injection::{
            agentic_control_abuse, binary_smuggling, cross_tool_instruction, encoded_instruction,
            guardrail_tamper, hidden_html_instruction, instruction_leak, multi_turn_escalation,
            tool_output_instruction, unicode_confusable, zero_width_obfuscation,
        },
        mcp::{mcp_policy, mcp_runtime_risk},
        pii::pii,
    },
    ml::ntdb_executor::NtdbExecutor,
    pipeline::{L3Worker, Pipeline, RequestRegistry},
    EvaluationResult, ExecutionBackend, LayerResult, LongTextPolicy, NtdbOperatingPoint,
    OnnxBatchMode, ScanExecution, ScanGateMatrix, SecurityCategory, SecurityLevel,
    SecurityScanResult,
};

mod ntdb_l2;
mod request_queue;
mod warmup;

#[cfg(feature = "test-util")]
pub use ntdb_l2::TOOL_PROMPTS_MODEL;
#[cfg(not(feature = "test-util"))]
use ntdb_l2::TOOL_PROMPTS_MODEL;
use ntdb_l2::{
    ntdb_l2_cache_namespace, ntdb_l2_error_scan_result, tool_classifier_area_enabled,
    TOOL_CLASSIFIER_DESCRIPTIONS_MODEL, TOOL_EXECUTIONS_MODEL,
};
#[cfg(feature = "test-util")]
pub use ntdb_l2::{
    ntdb_l2_enabled_for_category, ntdb_l2_model_config_for_id, NtdbL2ModelConfig,
    NTDB_TOOL_DESCRIPTIONS_MODEL_ID, NTDB_TOOL_EXECUTIONS_MODEL_ID, NTDB_TOOL_PROMPTS_MODEL_ID,
};
pub use ntdb_l2::{ntdb_l2_model_configs_for_category, ntdb_l2_scan_result};

/// Main scanner gateway for native and model-backed security categories.
pub struct SecurityGateway {
    core: Arc<SecurityGatewayCore>,
    queue_sender: OnceLock<mpsc::Sender<request_queue::QueueWork>>,
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

    // Lazy-loaded L1 rule pipelines. Model-backed L2 is NTDB-only.
    tool_classifier_prompts: Option<Pipeline>,
    tool_classifier_executions: Option<Pipeline>,
    tool_classifier_descriptions: Option<Pipeline>,
    user_intent_prompts: Option<Pipeline>,
    sensitive_documents_prompts: Option<Pipeline>,
    ntdb_executor: Option<Mutex<NtdbExecutor>>,

    // Instantiated native rule-based pipelines
    dlp_pipeline: Option<dlp::DlpPipeline>,
    pii_pipeline: Option<pii::PiiPipeline>,
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
    }
}

fn native_scan_result_with_duration(
    category: SecurityCategory,
    model: impl Into<String>,
    result: EvaluationResult,
    duration_ms: f64,
) -> SecurityScanResult {
    let layer = LayerResult {
        level: result.level.clone(),
        layer_type: "native".to_string(),
        class_name: result.class_name.clone(),
        confidence: result.confidence,
        matched: true,
        duration_ms,
        thresholds: HashMap::new(),
        details: HashMap::new(),
    };
    scan_result(category, model, result, vec![layer])
}

fn timed_into_scan_result<F>(
    category: SecurityCategory,
    model: impl Into<String>,
    evaluate: F,
) -> SecurityScanResult
where
    F: FnOnce() -> EvaluationResult,
{
    let started = Instant::now();
    let result = evaluate();
    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    native_scan_result_with_duration(category, model, result, duration_ms)
}

fn model_scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    output: (EvaluationResult, Vec<LayerResult>),
) -> SecurityScanResult {
    let (result, layers) = output;
    scan_result(category, model, result, layers)
}

fn l1_rule_scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    pipe: &Pipeline,
    text: &str,
    execution: &ScanExecution,
) -> Option<SecurityScanResult> {
    let l1_execution = execution.clone().with_max_level(SecurityLevel::L1);
    pipe.evaluate_with_execution(text, &l1_execution)
        .map(|output| model_scan_result(category, model, output))
}

impl SecurityGateway {
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
        let requests = Arc::new(RequestRegistry::default());
        let l3_worker = L3Worker::start(Arc::clone(&requests));
        let mut core = SecurityGatewayCore {
            categories,
            max_level,
            model_dir,
            download_files,
            download_categories,
            execution: Mutex::new(ScanExecution::new(max_level)),
            tool_classifier_prompts: None,
            tool_classifier_executions: None,
            tool_classifier_descriptions: None,
            user_intent_prompts: None,
            sensitive_documents_prompts: None,
            ntdb_executor: None,
            dlp_pipeline: None,
            pii_pipeline: None,
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
                    core.agentic_control_abuse_pipeline =
                        Some(agentic_control_abuse::AgenticControlAbusePipeline::new());
                    core.binary_smuggling_pipeline =
                        Some(binary_smuggling::BinarySmugglingPipeline::new());
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
                SecurityCategory::Pii => {
                    core.pii_pipeline = Some(pii::PiiPipeline::new());
                }
                _ => {}
            }
        }

        SecurityGateway {
            core: Arc::new(core),
            queue_sender: OnceLock::new(),
        }
    }

    /// Categories configured for `scan_all`.
    pub fn categories(&self) -> &[SecurityCategory] {
        &self.categories
    }

    /// Maximum level evaluated for configured categories.
    pub fn max_level(&self) -> SecurityLevel {
        self.max_level
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

    /// Replace the long-text routing policy.
    pub fn set_long_text_policy(&self, policy: LongTextPolicy) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_long_text_policy(policy);
    }

    /// Select the calibrated NTDB operating point used by subsequent scans.
    pub fn set_ntdb_operating_point(&self, point: NtdbOperatingPoint) {
        self.execution
            .lock()
            .expect("execution mutex poisoned")
            .set_ntdb_operating_point(point);
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

    /// Download allowed missing assets and initialize model-backed pipelines.

    fn scan_category_with_execution(
        &self,
        category: SecurityCategory,
        text: &str,
        execution: &ScanExecution,
    ) -> Vec<SecurityScanResult> {
        let mut results = Vec::new();
        macro_rules! push_native {
            ($pipeline:expr, $model:literal) => {
                if self.level_enabled(&execution, SecurityLevel::L1)
                    && self.model_enabled(&execution, $model)
                {
                    if let Some(ref pipe) = $pipeline {
                        results.push(timed_into_scan_result(category, $model, || {
                            pipe.evaluate(text)
                        }));
                    }
                }
            };
        }

        match category {
            SecurityCategory::Injection => {
                push_native!(
                    self.cross_tool_instruction_pipeline,
                    "native:cross_tool_instruction"
                );
                push_native!(self.instruction_leak_pipeline, "native:instruction_leak");
                push_native!(
                    self.encoded_instruction_pipeline,
                    "native:encoded_instruction"
                );
                push_native!(
                    self.multi_turn_escalation_pipeline,
                    "native:multi_turn_escalation"
                );
                push_native!(self.guardrail_tamper_pipeline, "native:guardrail_tamper");
                push_native!(
                    self.tool_output_instruction_pipeline,
                    "native:tool_output_instruction"
                );
                push_native!(
                    self.hidden_html_instruction_pipeline,
                    "native:hidden_html_instruction"
                );
                push_native!(
                    self.unicode_confusable_pipeline,
                    "native:unicode_confusable"
                );
                push_native!(
                    self.zero_width_obfuscation_pipeline,
                    "native:zero_width_obfuscation"
                );
                push_native!(
                    self.agentic_control_abuse_pipeline,
                    "native:agentic_control_abuse"
                );
                push_native!(self.binary_smuggling_pipeline, "native:binary_smuggling");
            }
            SecurityCategory::Dlp => {
                push_native!(self.dlp_pipeline, "native:dlp");
                push_native!(
                    self.sensitive_material_pipeline,
                    "native:sensitive_material"
                );
                push_native!(self.secret_transfer_pipeline, "native:secret_transfer");
                push_native!(self.mcp_runtime_risk_pipeline, "native:mcp_runtime_risk");
                push_native!(self.mcp_policy_pipeline, "native:mcp_policy");
                push_native!(
                    self.destructive_operation_pipeline,
                    "native:destructive_operation"
                );
            }
            SecurityCategory::Pii => {
                let native_enabled = self.level_enabled(&execution, SecurityLevel::L1)
                    && self.model_enabled(&execution, "native:pii");
                if native_enabled {
                    if let Some(ref native) = self.pii_pipeline {
                        let native_started = Instant::now();
                        let native_res = native.evaluate(text);
                        let native_duration_ms = native_started.elapsed().as_secs_f64() * 1000.0;
                        results.push(native_scan_result_with_duration(
                            category,
                            "native:pii",
                            native_res,
                            native_duration_ms,
                        ));
                    }
                }
            }
            SecurityCategory::ToolClassifier => {
                if tool_classifier_area_enabled(
                    execution,
                    TOOL_PROMPTS_MODEL,
                    &[
                        "tool_classifier.prompt",
                        "tool_classifier.prompts",
                        "tool_classifier_prompt",
                        "tool_classifier_prompts",
                    ],
                ) {
                    if let Some(ref pipe) = self.tool_classifier_prompts {
                        if let Some(result) =
                            l1_rule_scan_result(category, TOOL_PROMPTS_MODEL, pipe, text, execution)
                        {
                            results.push(result);
                        }
                    }
                }
                if tool_classifier_area_enabled(
                    execution,
                    TOOL_EXECUTIONS_MODEL,
                    &[
                        "tool_classifier.execution",
                        "tool_classifier.executions",
                        "tool_classifier_execution",
                        "tool_classifier_executions",
                    ],
                ) {
                    if let Some(ref pipe) = self.tool_classifier_executions {
                        if let Some(result) = l1_rule_scan_result(
                            category,
                            TOOL_EXECUTIONS_MODEL,
                            pipe,
                            text,
                            execution,
                        ) {
                            results.push(result);
                        }
                    }
                }
                if tool_classifier_area_enabled(
                    execution,
                    TOOL_CLASSIFIER_DESCRIPTIONS_MODEL,
                    &[
                        "tool_classifier.description",
                        "tool_classifier.descriptions",
                        "tool_classifier_description",
                        "tool_classifier_descriptions",
                    ],
                ) {
                    if let Some(ref pipe) = self.tool_classifier_descriptions {
                        if let Some(result) = l1_rule_scan_result(
                            category,
                            TOOL_CLASSIFIER_DESCRIPTIONS_MODEL,
                            pipe,
                            text,
                            execution,
                        ) {
                            results.push(result);
                        }
                    }
                }
            }
            SecurityCategory::SensitiveDocuments => {
                if self.model_enabled(&execution, "orca-sonar-document-classifier") {
                    if let Some(ref pipe) = self.sensitive_documents_prompts {
                        if let Some(result) = l1_rule_scan_result(
                            category,
                            "orca-sonar-document-classifier",
                            pipe,
                            text,
                            execution,
                        ) {
                            results.push(result);
                        }
                    }
                }
            }
            SecurityCategory::UserIntent => {
                if self.model_enabled(&execution, "user-intent-model") {
                    if let Some(ref pipe) = self.user_intent_prompts {
                        if let Some(result) = l1_rule_scan_result(
                            category,
                            "user-intent-model",
                            pipe,
                            text,
                            execution,
                        ) {
                            results.push(result);
                        }
                    }
                }
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
        let requested = categories
            .iter()
            .copied()
            .flat_map(|category| ntdb_l2_model_configs_for_category(execution, category))
            .collect::<Vec<_>>();
        if requested.is_empty() {
            return Vec::new();
        }

        let Some(executor_mutex) = &self.ntdb_executor else {
            return Vec::new();
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

        let mut scored_results = cached_results;
        if !missing_configs.is_empty() {
            let model_ids = missing_configs
                .iter()
                .map(|config| config.model_id)
                .collect::<Vec<_>>();
            let scoring_started = Instant::now();
            let decisions = match executor_mutex.lock() {
                Ok(mut executor) => executor.score_models(
                    model_ids.iter().copied(),
                    text,
                    execution.ntdb_operating_point(),
                ),
                Err(err) => Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("NTDB executor mutex poisoned: {err}"),
                ))
                    as Box<dyn std::error::Error + Send + Sync>),
            };
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
        results
    }

    fn scan_categories_direct(
        &self,
        categories: &[SecurityCategory],
        text: &str,
    ) -> Vec<SecurityScanResult> {
        use rayon::prelude::*;

        let mut execution = self.scan_execution();
        if execution.allows_level(SecurityLevel::L3) && execution.l3_policy().enabled {
            execution.set_defer_l3(true);
        }

        let mut results: Vec<SecurityScanResult> = categories
            .par_iter()
            .map(|cat| self.scan_category_with_execution(*cat, text, &execution))
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();
        results.extend(self.scan_ntdb_l2_categories(categories, text, &execution));
        results
    }
}
