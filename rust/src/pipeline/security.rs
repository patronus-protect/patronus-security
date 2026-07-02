use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{atomic::AtomicU64, Arc};
use std::time::Instant;

use crate::{
    assets,
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
    pipeline::{L3Worker, Pipeline, PromptInjectionPipeline, RequestRegistry},
    EvaluationResult, ExecutionBackend, LayerResult, LongTextPolicy, OnnxBatchMode, ScanExecution,
    ScanGateMatrix, SecurityCategory, SecurityLevel, SecurityScanResult,
};

mod request_queue;

/// Main scanner gateway for native and model-backed security categories.
pub struct PatronusSecurity {
    /// Categories configured for `scan_all`.
    pub categories: Vec<SecurityCategory>,
    /// Maximum layer to evaluate for configured categories.
    pub max_level: SecurityLevel,
    /// Optional asset root. Defaults to the platform cache directory.
    pub use_dir: Option<PathBuf>,
    /// Whether missing model assets may be downloaded during `warmup`.
    pub download_files: bool,
    /// Optional allowlist of categories that may download missing assets.
    pub download_categories: Option<Vec<SecurityCategory>>,
    /// Execution gates consumed by scan methods.
    pub execution: ScanExecution,

    // Lazy-loaded model-based pipelines
    pub injection_pipeline: Option<PromptInjectionPipeline>,
    pub tool_classifier_prompts: Option<Pipeline>,
    pub tool_classifier_executions: Option<Pipeline>,
    pub user_intent_prompts: Option<Pipeline>,
    pub sensitive_documents_prompts: Option<Pipeline>,
    pub tool_description_prompts: Option<Pipeline>,
    pub pii_model_pipeline: Option<Pipeline>,

    // Instantiated native rule-based pipelines
    pub dlp_pipeline: Option<dlp::DlpPipeline>,
    pub pii_pipeline: Option<pii::PiiPipeline>,
    pub cross_tool_instruction_pipeline:
        Option<cross_tool_instruction::CrossToolInstructionPipeline>,
    pub instruction_leak_pipeline: Option<instruction_leak::InstructionLeakPipeline>,
    pub secret_transfer_pipeline: Option<secret_transfer::SecretTransferPipeline>,
    pub sensitive_material_pipeline: Option<sensitive_material::SensitiveMaterialPipeline>,
    pub encoded_instruction_pipeline: Option<encoded_instruction::EncodedInstructionPipeline>,
    pub multi_turn_escalation_pipeline: Option<multi_turn_escalation::MultiTurnEscalationPipeline>,
    pub guardrail_tamper_pipeline: Option<guardrail_tamper::GuardrailTamperPipeline>,
    pub destructive_operation_pipeline: Option<destructive_operation::DestructiveOperationPipeline>,
    pub agentic_control_abuse_pipeline: Option<agentic_control_abuse::AgenticControlAbusePipeline>,
    pub binary_smuggling_pipeline: Option<binary_smuggling::BinarySmugglingPipeline>,
    pub tool_output_instruction_pipeline:
        Option<tool_output_instruction::ToolOutputInstructionPipeline>,
    pub mcp_runtime_risk_pipeline: Option<mcp_runtime_risk::McpRuntimeRiskPipeline>,
    pub hidden_html_instruction_pipeline:
        Option<hidden_html_instruction::HiddenHtmlInstructionPipeline>,
    pub unicode_confusable_pipeline: Option<unicode_confusable::UnicodeConfusablePipeline>,
    pub zero_width_obfuscation_pipeline:
        Option<zero_width_obfuscation::ZeroWidthObfuscationPipeline>,
    pub mcp_policy_pipeline: Option<mcp_policy::McpPolicyPipeline>,

    request_counter: AtomicU64,
    requests: Arc<RequestRegistry>,
    l3_worker: L3Worker,
}

/// Preferred public name for the security scanner gateway.
pub type SecurityGateway = PatronusSecurity;

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

fn pii_model_scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    pipe: &Pipeline,
    text: &str,
) -> Option<SecurityScanResult> {
    let execution = ScanExecution::with_gates(
        SecurityLevel::L2,
        ScanGateMatrix::levels(false, true, false),
    );
    pipe.evaluate_with_execution(text, &execution)
        .map(|output| model_scan_result(category, model, output))
}

fn generic_model_scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    pipe: &Pipeline,
    text: &str,
    execution: &ScanExecution,
) -> Option<SecurityScanResult> {
    pipe.evaluate_with_execution(text, execution)
        .map(|output| model_scan_result(category, model, output))
}

fn injection_model_scan_result(
    category: SecurityCategory,
    pipe: &PromptInjectionPipeline,
    text: &str,
    execution: &ScanExecution,
) -> Option<SecurityScanResult> {
    pipe.evaluate_with_execution(text, execution)
        .map(|output| model_scan_result(category, "wolf-defender-small", output))
}

#[derive(Clone, Copy)]
enum WarmupPipelineKind {
    Injection,
    SensitiveDocumentsPrompts,
    ToolClassifierPrompts,
    ToolClassifierExecutions,
    ToolDescriptionPrompts,
    UserIntentPrompts,
    PiiPrompts,
}

struct WarmupPipelineTask {
    kind: WarmupPipelineKind,
    label: &'static str,
    path: PathBuf,
}

enum WarmupPipeline {
    Injection(PromptInjectionPipeline),
    Generic(Pipeline),
}

fn log_pipeline_warmup(label: &str, started: Instant, has_l3: bool, l3_loaded: bool) {
    let l3_state = if has_l3 {
        if l3_loaded {
            "loaded"
        } else {
            "lazy-present/session-not-loaded"
        }
    } else {
        "not-present"
    };
    println!(
        "[warmup] {label} initialized in {:.2} ms; l3={l3_state}",
        started.elapsed().as_secs_f64() * 1000.0
    );
}

impl PatronusSecurity {
    /// Create a gateway with `SecurityLevel::L2` as the maximum level.
    pub fn new(
        categories: Vec<SecurityCategory>,
        use_dir: Option<PathBuf>,
        download_files: bool,
    ) -> Self {
        Self::with_max_level(categories, SecurityLevel::L2, use_dir, download_files)
    }

    /// Create a gateway with an explicit maximum security level.
    pub fn with_max_level(
        categories: Vec<SecurityCategory>,
        max_level: SecurityLevel,
        use_dir: Option<PathBuf>,
        download_files: bool,
    ) -> Self {
        Self::with_download_categories(categories, max_level, use_dir, download_files, None)
    }

    /// Create a gateway with an optional per-category asset download allowlist.
    ///
    /// When `download_categories` is `None`, all configured categories may
    /// download missing assets if `download_files` is `true`.
    pub fn with_download_categories(
        categories: Vec<SecurityCategory>,
        max_level: SecurityLevel,
        use_dir: Option<PathBuf>,
        download_files: bool,
        download_categories: Option<Vec<SecurityCategory>>,
    ) -> Self {
        let requests = Arc::new(RequestRegistry::default());
        let l3_worker = L3Worker::start(Arc::clone(&requests));
        let mut ps = PatronusSecurity {
            categories,
            max_level,
            use_dir,
            download_files,
            download_categories,
            execution: ScanExecution::new(max_level),
            injection_pipeline: None,
            tool_classifier_prompts: None,
            tool_classifier_executions: None,
            user_intent_prompts: None,
            sensitive_documents_prompts: None,
            tool_description_prompts: None,
            pii_model_pipeline: None,
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
        };

        // Immediately instantiate native rule pipelines for configured categories
        for cat in &ps.categories {
            match cat {
                SecurityCategory::Injection => {
                    ps.cross_tool_instruction_pipeline =
                        Some(cross_tool_instruction::CrossToolInstructionPipeline::new());
                    ps.instruction_leak_pipeline =
                        Some(instruction_leak::InstructionLeakPipeline::new());
                    ps.encoded_instruction_pipeline =
                        Some(encoded_instruction::EncodedInstructionPipeline::new());
                    ps.multi_turn_escalation_pipeline =
                        Some(multi_turn_escalation::MultiTurnEscalationPipeline::new());
                    ps.guardrail_tamper_pipeline =
                        Some(guardrail_tamper::GuardrailTamperPipeline::new());
                    ps.tool_output_instruction_pipeline =
                        Some(tool_output_instruction::ToolOutputInstructionPipeline::new());
                    ps.hidden_html_instruction_pipeline =
                        Some(hidden_html_instruction::HiddenHtmlInstructionPipeline::new());
                    ps.unicode_confusable_pipeline =
                        Some(unicode_confusable::UnicodeConfusablePipeline::new());
                    ps.zero_width_obfuscation_pipeline =
                        Some(zero_width_obfuscation::ZeroWidthObfuscationPipeline::new());
                    ps.agentic_control_abuse_pipeline =
                        Some(agentic_control_abuse::AgenticControlAbusePipeline::new());
                    ps.binary_smuggling_pipeline =
                        Some(binary_smuggling::BinarySmugglingPipeline::new());
                }
                SecurityCategory::Dlp => {
                    ps.dlp_pipeline = Some(dlp::DlpPipeline::new());
                    ps.sensitive_material_pipeline =
                        Some(sensitive_material::SensitiveMaterialPipeline::new());
                    ps.secret_transfer_pipeline =
                        Some(secret_transfer::SecretTransferPipeline::new());
                    ps.mcp_runtime_risk_pipeline =
                        Some(mcp_runtime_risk::McpRuntimeRiskPipeline::new());
                    ps.mcp_policy_pipeline = Some(mcp_policy::McpPolicyPipeline::new());
                    ps.destructive_operation_pipeline =
                        Some(destructive_operation::DestructiveOperationPipeline::new());
                }
                SecurityCategory::Pii => {
                    ps.pii_pipeline = Some(pii::PiiPipeline::new());
                }
                _ => {}
            }
        }

        ps
    }

    fn should_download_assets_for(&self, category: SecurityCategory) -> bool {
        if !self.download_files {
            return false;
        }

        match &self.download_categories {
            Some(categories) => categories.contains(&category),
            None => true,
        }
    }

    /// Replace the execution gate matrix used by subsequent scans.
    pub fn set_execution_gates(&mut self, gates: ScanGateMatrix) {
        self.execution.set_gates(gates);
    }

    /// Replace the ONNX batch mode used by subsequent batch scans.
    pub fn set_onnx_batch_mode(&mut self, mode: OnnxBatchMode) {
        self.execution.set_onnx_batch_mode(mode);
    }

    /// Replace the execution backend and apply its default L3 mode.
    pub fn set_execution_backend(&mut self, backend: ExecutionBackend) {
        self.execution.set_backend(backend);
    }

    /// Replace the long-text routing policy.
    pub fn set_long_text_policy(&mut self, policy: LongTextPolicy) {
        self.execution.set_long_text_policy(policy);
    }

    /// Return the execution state that should be consumed by this scan.
    fn scan_execution(&self) -> ScanExecution {
        self.execution.clone().with_max_level(self.max_level)
    }

    fn level_enabled(&self, execution: &ScanExecution, level: SecurityLevel) -> bool {
        execution.allows_level(level)
    }

    fn model_enabled(&self, execution: &ScanExecution, model: &str) -> bool {
        execution.allows_model(model)
    }

    /// Download allowed missing assets and initialize model-backed pipelines.
    pub fn warmup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let base_dir = match &self.use_dir {
            Some(path) => path.clone(),
            None => dirs::cache_dir()
                .ok_or("Could not resolve cache directory")?
                .join("patronus_security"),
        };

        println!(
            "[warmup] model_dir={}; max_level={}",
            base_dir.display(),
            self.max_level.as_str()
        );
        let onnx_started = Instant::now();
        let configured_onnx_runtime = crate::ml::onnx::warmup_runtime();
        println!(
            "[warmup] onnx runtime initialized in {:.2} ms; configured_now={}; model_sessions_loaded=false",
            onnx_started.elapsed().as_secs_f64() * 1000.0,
            configured_onnx_runtime
        );

        let mut init_tasks = Vec::new();

        for cat in &self.categories {
            let cat_dir = match cat {
                SecurityCategory::Injection => base_dir.join("injection"),
                SecurityCategory::SensitiveDocuments => base_dir.join("sensitive_documents"),
                SecurityCategory::ToolClassifier => base_dir.join("tool_classifier"),
                SecurityCategory::ToolDescription => base_dir.join("tool_description"),
                SecurityCategory::UserIntent => base_dir.join("user_intent"),
                SecurityCategory::Pii => base_dir.join("pii"),
                SecurityCategory::Dlp => {
                    println!("[warmup] dlp native-only; no model assets");
                    continue;
                }
            };

            let config_check_file = match cat {
                SecurityCategory::Injection => cat_dir.join("cascade_config.json"),
                SecurityCategory::ToolClassifier => cat_dir.join("prompts").join("l2_config.json"),
                _ => cat_dir.join("prompts").join("l2_config.json"),
            };

            let assets_present = assets::required_assets_present(*cat, self.max_level, &cat_dir);
            if !assets_present {
                if self.should_download_assets_for(*cat) {
                    println!(
                        "[warmup] {} required assets missing; downloading required assets",
                        cat.as_str()
                    );
                    assets::download_category_assets(*cat, self.max_level, &cat_dir)?;
                } else {
                    println!(
                        "[warmup] {} required assets missing; downloads disabled",
                        cat.as_str()
                    );
                }
            } else {
                println!(
                    "[warmup] {} required assets present at {}",
                    cat.as_str(),
                    cat_dir.display()
                );
            }

            match cat {
                SecurityCategory::Injection => {
                    if self.max_level >= SecurityLevel::L2 && config_check_file.exists() {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::Injection,
                            label: "injection",
                            path: cat_dir.clone(),
                        });
                    }
                }
                SecurityCategory::SensitiveDocuments => {
                    let prompts_path = cat_dir.join("prompts");
                    if self.max_level >= SecurityLevel::L2
                        && prompts_path.join("l2_config.json").exists()
                    {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::SensitiveDocumentsPrompts,
                            label: "sensitive_documents/prompts",
                            path: prompts_path,
                        });
                    }
                }
                SecurityCategory::ToolClassifier => {
                    let prompts_path = cat_dir.join("prompts");
                    if self.max_level >= SecurityLevel::L2
                        && prompts_path.join("l2_config.json").exists()
                    {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::ToolClassifierPrompts,
                            label: "tool_classifier/prompts",
                            path: prompts_path,
                        });
                    }
                    let executions_path = cat_dir.join("executions");
                    if self.max_level >= SecurityLevel::L2
                        && executions_path.join("l2_config.json").exists()
                    {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::ToolClassifierExecutions,
                            label: "tool_classifier/executions",
                            path: executions_path,
                        });
                    }
                }
                SecurityCategory::ToolDescription => {
                    let prompts_path = cat_dir.join("prompts");
                    if self.max_level >= SecurityLevel::L2
                        && prompts_path.join("l2_config.json").exists()
                    {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::ToolDescriptionPrompts,
                            label: "tool_description/prompts",
                            path: prompts_path,
                        });
                    }
                }
                SecurityCategory::UserIntent => {
                    let prompts_path = cat_dir.join("prompts");
                    if self.max_level >= SecurityLevel::L2
                        && prompts_path.join("l2_config.json").exists()
                    {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::UserIntentPrompts,
                            label: "user_intent/prompts",
                            path: prompts_path,
                        });
                    }
                }
                SecurityCategory::Pii => {
                    let prompts_path = cat_dir.join("prompts");
                    if self.max_level >= SecurityLevel::L2
                        && prompts_path.join("l2_config.json").exists()
                    {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::PiiPrompts,
                            label: "pii/prompts",
                            path: prompts_path,
                        });
                    }
                }
                SecurityCategory::Dlp => {}
            }
        }

        use rayon::prelude::*;
        let init_results: Result<Vec<_>, String> = init_tasks
            .into_par_iter()
            .map(|task| {
                let started = Instant::now();
                let pipeline = match task.kind {
                    WarmupPipelineKind::Injection => {
                        let pipeline = PromptInjectionPipeline::new(&task.path)
                            .map_err(|err| format!("{}: {}", task.label, err))?;
                        log_pipeline_warmup(
                            task.label,
                            started,
                            pipeline.has_l3_model(),
                            pipeline.is_l3_loaded(),
                        );
                        WarmupPipeline::Injection(pipeline)
                    }
                    _ => {
                        let pipeline = Pipeline::new(&task.path)
                            .map_err(|err| format!("{}: {}", task.label, err))?;
                        log_pipeline_warmup(
                            task.label,
                            started,
                            pipeline.has_l3_model(),
                            pipeline.is_l3_loaded(),
                        );
                        WarmupPipeline::Generic(pipeline)
                    }
                };
                Ok((task.kind, task.path, pipeline))
            })
            .collect();

        for (kind, _path, pipeline) in
            init_results.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
        {
            self.register_l3_worker_pipeline(kind, &pipeline);
            match (kind, pipeline) {
                (WarmupPipelineKind::Injection, WarmupPipeline::Injection(pipeline)) => {
                    self.injection_pipeline = Some(pipeline);
                }
                (
                    WarmupPipelineKind::SensitiveDocumentsPrompts,
                    WarmupPipeline::Generic(pipeline),
                ) => {
                    self.sensitive_documents_prompts = Some(pipeline);
                }
                (WarmupPipelineKind::ToolClassifierPrompts, WarmupPipeline::Generic(pipeline)) => {
                    self.tool_classifier_prompts = Some(pipeline);
                }
                (
                    WarmupPipelineKind::ToolClassifierExecutions,
                    WarmupPipeline::Generic(pipeline),
                ) => {
                    self.tool_classifier_executions = Some(pipeline);
                }
                (WarmupPipelineKind::ToolDescriptionPrompts, WarmupPipeline::Generic(pipeline)) => {
                    self.tool_description_prompts = Some(pipeline);
                }
                (WarmupPipelineKind::UserIntentPrompts, WarmupPipeline::Generic(pipeline)) => {
                    self.user_intent_prompts = Some(pipeline);
                }
                (WarmupPipelineKind::PiiPrompts, WarmupPipeline::Generic(pipeline)) => {
                    self.pii_model_pipeline = Some(pipeline);
                }
                _ => unreachable!("warmup task produced mismatched pipeline type"),
            }
        }

        Ok(())
    }

    fn register_l3_worker_pipeline(&self, kind: WarmupPipelineKind, pipeline: &WarmupPipeline) {
        let model = match pipeline {
            WarmupPipeline::Injection(pipeline) => pipeline.l3_worker_model(),
            WarmupPipeline::Generic(pipeline) => pipeline.l3_worker_model(),
        };
        let Some(model) = model else {
            return;
        };

        match kind {
            WarmupPipelineKind::Injection => {
                self.l3_worker.register_model("wolf-defender-small", model);
            }
            WarmupPipelineKind::ToolClassifierPrompts => {
                self.l3_worker.register_model("tool-prompts-model", model);
            }
            WarmupPipelineKind::ToolClassifierExecutions => {
                self.l3_worker
                    .register_model("tool-executions-model", model);
            }
            WarmupPipelineKind::UserIntentPrompts => {
                self.l3_worker.register_model("user-intent-model", model);
            }
            WarmupPipelineKind::SensitiveDocumentsPrompts => {
                self.l3_worker
                    .register_model("orca-sonar-document-classifier", model);
            }
            WarmupPipelineKind::ToolDescriptionPrompts => {
                self.l3_worker
                    .register_model("tool-description-model", model);
            }
            WarmupPipelineKind::PiiPrompts => {}
        }
    }

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
                if self.model_enabled(&execution, "wolf-defender-small") {
                    if let Some(ref pipe) = self.injection_pipeline {
                        if let Some(result) =
                            injection_model_scan_result(category, pipe, text, execution)
                        {
                            results.push(result);
                        }
                    }
                }
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
                let model_enabled = self.level_enabled(&execution, SecurityLevel::L2)
                    && self.model_enabled(&execution, "pii-model");
                if native_enabled {
                    if let Some(ref native) = self.pii_pipeline {
                        let native_started = Instant::now();
                        let native_res = native.evaluate(text);
                        let native_duration_ms = native_started.elapsed().as_secs_f64() * 1000.0;
                        if native_res.class_name != "safe" {
                            results.push(native_scan_result_with_duration(
                                category,
                                "native:pii",
                                native_res,
                                native_duration_ms,
                            ));
                        } else if model_enabled {
                            if let Some(ref model) = self.pii_model_pipeline {
                                if let Some(result) =
                                    pii_model_scan_result(category, "pii-model", model, text)
                                {
                                    results.push(result);
                                }
                            } else {
                                results.push(native_scan_result_with_duration(
                                    category,
                                    "native:pii",
                                    native_res,
                                    native_duration_ms,
                                ));
                            }
                        } else {
                            results.push(native_scan_result_with_duration(
                                category,
                                "native:pii",
                                native_res,
                                native_duration_ms,
                            ));
                        }
                    }
                } else if model_enabled {
                    if let Some(ref model) = self.pii_model_pipeline {
                        if let Some(result) =
                            pii_model_scan_result(category, "pii-model", model, text)
                        {
                            results.push(result);
                        }
                    }
                }
            }
            SecurityCategory::ToolClassifier => {
                if self.model_enabled(&execution, "tool-prompts-model") {
                    if let Some(ref pipe) = self.tool_classifier_prompts {
                        if let Some(result) = generic_model_scan_result(
                            category,
                            "tool-prompts-model",
                            pipe,
                            text,
                            execution,
                        ) {
                            results.push(result);
                        }
                    }
                }
                if self.model_enabled(&execution, "tool-executions-model") {
                    if let Some(ref pipe) = self.tool_classifier_executions {
                        if let Some(result) = generic_model_scan_result(
                            category,
                            "tool-executions-model",
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
                        if let Some(result) = generic_model_scan_result(
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
            SecurityCategory::ToolDescription => {
                if self.model_enabled(&execution, "tool-description-model") {
                    if let Some(ref pipe) = self.tool_description_prompts {
                        if let Some(result) = generic_model_scan_result(
                            category,
                            "tool-description-model",
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
                        if let Some(result) = generic_model_scan_result(
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

    fn scan_categories_direct(
        &self,
        categories: &[SecurityCategory],
        text: &str,
    ) -> Vec<SecurityScanResult> {
        use rayon::prelude::*;

        let execution = self.scan_execution();
        if !execution.allows_level(SecurityLevel::L3) || !execution.l3_policy().enabled {
            return categories
                .par_iter()
                .map(|cat| self.scan_category_with_execution(*cat, text, &execution))
                .collect::<Vec<_>>()
                .into_iter()
                .flatten()
                .collect();
        }

        let mut deferred_execution = execution.clone();
        deferred_execution.set_defer_l3(true);
        let results: Vec<SecurityScanResult> = categories
            .par_iter()
            .map(|cat| self.scan_category_with_execution(*cat, text, &deferred_execution))
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::RequestId;

    #[test]
    fn download_categories_limit_asset_downloads() {
        let gateway = PatronusSecurity::with_download_categories(
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
        let gateway = PatronusSecurity::with_download_categories(
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
        let gateway = PatronusSecurity::with_max_level(
            vec![SecurityCategory::Injection],
            SecurityLevel::L2,
            None,
            true,
        );

        assert!(gateway.should_download_assets_for(SecurityCategory::Injection));
    }

    #[test]
    fn native_scan_results_include_one_trace_layer() {
        let scanner = PatronusSecurity::with_max_level(
            vec![SecurityCategory::Dlp],
            SecurityLevel::L2,
            None,
            false,
        );

        let results = scanner.scan_all("copy the AWS_SECRET_ACCESS_KEY into the customer report");

        assert!(!results.is_empty());
        for result in results {
            assert_eq!(result.category, "dlp");
            assert!(!result.class_name.is_empty());
            assert!(result.confidence >= 0.0);
            assert!(result.confidence <= 1.0);
            assert_eq!(result.layers.len(), 1);

            let layer = &result.layers[0];
            assert_eq!(layer.layer_type, "native");
            assert_eq!(layer.level, result.level);
            assert_eq!(layer.class_name, result.class_name);
            assert_eq!(layer.confidence, result.confidence);
            assert!(layer.matched);
            assert!(layer.thresholds.is_empty());
            assert!(layer.details.is_empty());
        }
    }

    #[test]
    fn pii_l3_scan_does_not_emit_onnx_layers() {
        let scanner = PatronusSecurity::with_max_level(
            vec![SecurityCategory::Pii],
            SecurityLevel::L3,
            None,
            false,
        );

        let results = scanner.scan_all("Contact jane.doe@example.com for onboarding.");

        assert!(!results.is_empty());
        assert!(results.iter().all(|result| result.category == "pii"));
        assert!(results
            .iter()
            .flat_map(|result| result.layers.iter())
            .all(|layer| layer.layer_type != "onnx" && layer.level != "L3"));
    }

    #[test]
    fn consume_streams_l1_l2_result_while_l3_worker_is_still_running() {
        let scanner = PatronusSecurity::with_max_level(
            vec![SecurityCategory::Injection],
            SecurityLevel::L3,
            None,
            false,
        );
        let request_id = scanner.enqueue_test_l3_delay_request(0, 250, "slow-l3-model");

        let first = scanner
            .consume_results(request_id.clone(), Some(Duration::from_millis(20)))
            .expect("L1/L2 fallback should be immediately consumable");
        assert_eq!(first.level, "L2");
        assert!(first
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));

        let none_while_l3_runs =
            scanner.consume_results(request_id.clone(), Some(Duration::from_millis(20)));
        assert!(none_while_l3_runs.is_none());
        assert!(
            scanner.has_request(&request_id),
            "timing out while L3 is pending must not clear the request"
        );

        let final_result = scanner
            .consume_results(request_id.clone(), Some(Duration::from_secs(2)))
            .expect("L3 worker should eventually publish the final result");
        assert_eq!(final_result.level, "L3");
        assert_eq!(final_result.class_name, "test_l3");
        assert!(final_result.layers.iter().any(|layer| {
            layer.level == "L3"
                && layer.matched
                && layer.details.get("l3_worker") == Some(&serde_json::json!("rust_l3_worker"))
        }));
        assert!(scanner
            .consume_results(request_id.clone(), Some(Duration::from_millis(20)))
            .is_none());
        assert!(
            !scanner.has_request(&request_id),
            "fully drained requests should be removed from the registry"
        );
    }

    #[test]
    fn ingress_can_enqueue_while_egress_thread_waits_for_l3() {
        let scanner = std::sync::Arc::new(PatronusSecurity::with_max_level(
            vec![SecurityCategory::Injection],
            SecurityLevel::L3,
            None,
            false,
        ));
        let request_a = scanner.enqueue_test_l3_delay_request(0, 300, "blocking-l3-a");
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let consumer_scanner = std::sync::Arc::clone(&scanner);

        let consumer = std::thread::spawn(move || {
            let mut levels = Vec::new();
            if let Some(first) =
                consumer_scanner.consume_results(request_a.clone(), Some(Duration::from_secs(1)))
            {
                first_tx.send(first.level.clone()).unwrap();
                levels.push(first.level);
            }
            while let Some(result) =
                consumer_scanner.consume_results(request_a.clone(), Some(Duration::from_secs(2)))
            {
                levels.push(result.level);
            }
            levels
        });

        assert_eq!(first_rx.recv_timeout(Duration::from_secs(1)).unwrap(), "L2");

        let request_b = scanner.enqueue_test_l3_delay_request(0, 10, "second-request-l3");
        let b_first = scanner
            .consume_results(request_b.clone(), Some(Duration::from_millis(20)))
            .expect("ingress should enqueue another request while egress waits on L3");
        assert_eq!(b_first.level, "L2");

        let b_final = scanner
            .consume_results(request_b, Some(Duration::from_secs(2)))
            .expect("second request L3 should eventually finish");
        assert_eq!(b_final.level, "L3");

        let levels = consumer.join().unwrap();
        assert_eq!(levels, vec!["L2".to_string(), "L3".to_string()]);
    }

    #[test]
    fn dispatcher_consumes_multiple_requests_while_ingress_adds_work() {
        let scanner = std::sync::Arc::new(PatronusSecurity::with_max_level(
            vec![SecurityCategory::Injection],
            SecurityLevel::L3,
            None,
            false,
        ));
        let (request_tx, request_rx) = std::sync::mpsc::channel::<RequestId>();
        let (result_tx, result_rx) = std::sync::mpsc::channel::<(RequestId, String, String)>();
        let dispatcher_scanner = std::sync::Arc::clone(&scanner);

        let dispatcher = std::thread::spawn(move || {
            let mut active = Vec::<RequestId>::new();
            let mut ingress_open = true;
            while ingress_open || !active.is_empty() {
                loop {
                    match request_rx.try_recv() {
                        Ok(request_id) => active.push(request_id),
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            ingress_open = false;
                            break;
                        }
                    }
                }

                let mut index = 0;
                while index < active.len() {
                    let request_id = active[index].clone();
                    match dispatcher_scanner
                        .consume_results(request_id.clone(), Some(Duration::from_millis(10)))
                    {
                        Some(result) => {
                            result_tx
                                .send((request_id, result.level, result.model))
                                .unwrap();
                            index += 1;
                        }
                        None if !dispatcher_scanner.has_request(&request_id) => {
                            active.swap_remove(index);
                        }
                        None => {
                            index += 1;
                        }
                    }
                }
            }
        });

        let request_a = scanner.enqueue_test_l3_delay_request(0, 300, "dispatcher-slow-l3");
        request_tx.send(request_a.clone()).unwrap();
        let first = result_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            (first.0.clone(), first.1.as_str()),
            (request_a.clone(), "L2")
        );

        let request_b = scanner.enqueue_test_l3_delay_request(0, 10, "dispatcher-fast-l3");
        request_tx.send(request_b.clone()).unwrap();
        let started = Instant::now();
        let mut saw_b_l2 = false;
        while started.elapsed() < Duration::from_millis(150) {
            let Ok((request_id, level, _model)) = result_rx.recv_timeout(Duration::from_millis(25))
            else {
                continue;
            };
            if request_id == request_b && level == "L2" {
                saw_b_l2 = true;
                break;
            }
        }
        assert!(
            saw_b_l2,
            "dispatcher should emit request B L1/L2 while request A L3 is still running"
        );

        drop(request_tx);
        dispatcher.join().unwrap();
    }

    #[test]
    fn l3_worker_processes_jobs_by_priority() {
        let scanner = PatronusSecurity::with_max_level(
            vec![SecurityCategory::Injection],
            SecurityLevel::L3,
            None,
            false,
        );
        let request_ids = scanner.enqueue_test_l3_delay_requests(&[
            (10, 10, "low-priority-l3"),
            (0, 10, "high-priority-l3"),
        ]);
        let low = request_ids[0].clone();
        let high = request_ids[1].clone();

        let _low_fallback = scanner.consume_results(low.clone(), Some(Duration::from_secs(1)));
        let _high_fallback = scanner.consume_results(high.clone(), Some(Duration::from_secs(1)));
        let high_final = scanner
            .consume_results(high.clone(), Some(Duration::from_secs(2)))
            .expect("high priority L3 job should finish first");
        assert_eq!(high_final.model, "high-priority-l3");
        let low_final = scanner
            .consume_results(low.clone(), Some(Duration::from_secs(2)))
            .expect("low priority L3 job should finish after high priority");
        assert_eq!(low_final.model, "low-priority-l3");
    }
}
