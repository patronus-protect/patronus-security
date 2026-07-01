use std::collections::HashMap;
use std::path::PathBuf;
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
    pipeline::{Pipeline, PromptInjectionPipeline},
    EvaluationResult, LayerResult, SecurityCategory, SecurityLevel, SecurityScanResult,
};

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

fn into_scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    result: EvaluationResult,
) -> SecurityScanResult {
    let layer = LayerResult {
        level: result.level.clone(),
        layer_type: "native".to_string(),
        class_name: result.class_name.clone(),
        confidence: result.confidence,
        matched: true,
        duration_ms: 0.0,
        thresholds: HashMap::new(),
        details: HashMap::new(),
    };
    scan_result(category, model, result, vec![layer])
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
) -> SecurityScanResult {
    model_scan_result(
        category,
        model,
        pipe.evaluate_with_layers(text, SecurityLevel::L2),
    )
}

fn generic_model_scan_result(
    category: SecurityCategory,
    model: impl Into<String>,
    pipe: &Pipeline,
    text: &str,
    max_level: SecurityLevel,
) -> SecurityScanResult {
    model_scan_result(category, model, pipe.evaluate_with_layers(text, max_level))
}

fn injection_model_scan_result(
    category: SecurityCategory,
    pipe: &PromptInjectionPipeline,
    text: &str,
    max_level: SecurityLevel,
) -> SecurityScanResult {
    model_scan_result(
        category,
        "wolf-defender-small",
        pipe.evaluate_with_layers(text, max_level),
    )
}

fn scan_result_batch(
    category: SecurityCategory,
    model: &str,
    outputs: Vec<(EvaluationResult, Vec<LayerResult>)>,
) -> Vec<SecurityScanResult> {
    outputs
        .into_iter()
        .map(|output| model_scan_result(category, model, output))
        .collect()
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

fn select_first_unsafe_or_model(
    mut results: Vec<SecurityScanResult>,
    preferred_model: &str,
) -> Option<SecurityScanResult> {
    if let Some(index) = results
        .iter()
        .position(|result| result.class_name != "safe")
    {
        Some(results.remove(index))
    } else {
        let preferred_index = results
            .iter()
            .position(|result| result.model == preferred_model);
        match preferred_index {
            Some(index) => Some(results.remove(index)),
            None => results.into_iter().next(),
        }
    }
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
        let mut ps = PatronusSecurity {
            categories,
            max_level,
            use_dir,
            download_files,
            download_categories,
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
                Ok((task.kind, pipeline))
            })
            .collect();

        for (kind, pipeline) in
            init_results.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
        {
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

    /// Scan text with a single category.
    pub fn scan_category(&self, category: SecurityCategory, text: &str) -> Vec<SecurityScanResult> {
        let mut results = Vec::new();
        match category {
            SecurityCategory::Injection => {
                if let Some(ref pipe) = self.injection_pipeline {
                    results.push(injection_model_scan_result(
                        category,
                        pipe,
                        text,
                        self.max_level,
                    ));
                }
                if let Some(ref pipe) = self.cross_tool_instruction_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:cross_tool_instruction",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.instruction_leak_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:instruction_leak",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.encoded_instruction_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:encoded_instruction",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.multi_turn_escalation_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:multi_turn_escalation",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.guardrail_tamper_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:guardrail_tamper",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.tool_output_instruction_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:tool_output_instruction",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.hidden_html_instruction_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:hidden_html_instruction",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.unicode_confusable_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:unicode_confusable",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.zero_width_obfuscation_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:zero_width_obfuscation",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.agentic_control_abuse_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:agentic_control_abuse",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.binary_smuggling_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:binary_smuggling",
                        || pipe.evaluate(text),
                    ));
                }
            }
            SecurityCategory::Dlp => {
                if let Some(ref pipe) = self.dlp_pipeline {
                    results.push(timed_into_scan_result(category, "native:dlp", || {
                        pipe.evaluate(text)
                    }));
                }
                if let Some(ref pipe) = self.sensitive_material_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:sensitive_material",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.secret_transfer_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:secret_transfer",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.mcp_runtime_risk_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:mcp_runtime_risk",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.mcp_policy_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:mcp_policy",
                        || pipe.evaluate(text),
                    ));
                }
                if let Some(ref pipe) = self.destructive_operation_pipeline {
                    results.push(timed_into_scan_result(
                        category,
                        "native:destructive_operation",
                        || pipe.evaluate(text),
                    ));
                }
            }
            SecurityCategory::Pii => {
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
                    } else if self.max_level >= SecurityLevel::L2 {
                        if let Some(ref model) = self.pii_model_pipeline {
                            results.push(pii_model_scan_result(category, "pii-model", model, text));
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
            }
            SecurityCategory::ToolClassifier => {
                if let Some(ref pipe) = self.tool_classifier_prompts {
                    results.push(generic_model_scan_result(
                        category,
                        "tool-prompts-model",
                        pipe,
                        text,
                        self.max_level,
                    ));
                }
                if let Some(ref pipe) = self.tool_classifier_executions {
                    results.push(generic_model_scan_result(
                        category,
                        "tool-executions-model",
                        pipe,
                        text,
                        self.max_level,
                    ));
                }
            }
            SecurityCategory::SensitiveDocuments => {
                if let Some(ref pipe) = self.sensitive_documents_prompts {
                    results.push(generic_model_scan_result(
                        category,
                        "orca-sonar-document-classifier",
                        pipe,
                        text,
                        self.max_level,
                    ));
                }
            }
            SecurityCategory::ToolDescription => {
                if let Some(ref pipe) = self.tool_description_prompts {
                    results.push(generic_model_scan_result(
                        category,
                        "tool-description-model",
                        pipe,
                        text,
                        self.max_level,
                    ));
                }
            }
            SecurityCategory::UserIntent => {
                if let Some(ref pipe) = self.user_intent_prompts {
                    results.push(generic_model_scan_result(
                        category,
                        "user-intent-model",
                        pipe,
                        text,
                        self.max_level,
                    ));
                }
            }
        }
        results
    }

    /// Evaluate a legacy-compatible pipeline name for one text.
    ///
    /// This returns one final result for the selected pipeline. For categories
    /// with multiple native subscanners, unsafe findings are preferred over the
    /// category's safe baseline result.
    pub fn evaluate_pipeline(&self, pipeline: &str, text: &str) -> Option<SecurityScanResult> {
        match pipeline {
            "tool_classifier_prompts" => self.tool_classifier_prompts.as_ref().map(|pipe| {
                generic_model_scan_result(
                    SecurityCategory::ToolClassifier,
                    "tool-prompts-model",
                    pipe,
                    text,
                    self.max_level,
                )
            }),
            "tool_classifier_executions" => self.tool_classifier_executions.as_ref().map(|pipe| {
                generic_model_scan_result(
                    SecurityCategory::ToolClassifier,
                    "tool-executions-model",
                    pipe,
                    text,
                    self.max_level,
                )
            }),
            "user_intent_prompts" => self.user_intent_prompts.as_ref().map(|pipe| {
                generic_model_scan_result(
                    SecurityCategory::UserIntent,
                    "user-intent-model",
                    pipe,
                    text,
                    self.max_level,
                )
            }),
            "sensitive_documents_prompts" => {
                self.sensitive_documents_prompts.as_ref().map(|pipe| {
                    generic_model_scan_result(
                        SecurityCategory::SensitiveDocuments,
                        "orca-sonar-document-classifier",
                        pipe,
                        text,
                        self.max_level,
                    )
                })
            }
            "tool_description_prompts" => self.tool_description_prompts.as_ref().map(|pipe| {
                generic_model_scan_result(
                    SecurityCategory::ToolDescription,
                    "tool-description-model",
                    pipe,
                    text,
                    self.max_level,
                )
            }),
            "injection" => self.injection_pipeline.as_ref().map(|pipe| {
                injection_model_scan_result(SecurityCategory::Injection, pipe, text, self.max_level)
            }),
            "dlp" => select_first_unsafe_or_model(
                self.scan_category(SecurityCategory::Dlp, text),
                "native:dlp",
            ),
            "pii" => select_first_unsafe_or_model(
                self.scan_category(SecurityCategory::Pii, text),
                "native:pii",
            ),
            _ => None,
        }
    }

    fn evaluate_dlp_batch(&self, texts: &[String]) -> Vec<SecurityScanResult> {
        let mut per_text = vec![Vec::<SecurityScanResult>::new(); texts.len()];

        if let Some(ref pipe) = self.dlp_pipeline {
            for (index, result) in pipe.evaluate_batch(texts).into_iter().enumerate() {
                per_text[index].push(into_scan_result(
                    SecurityCategory::Dlp,
                    "native:dlp",
                    result,
                ));
            }
        }
        if let Some(ref pipe) = self.sensitive_material_pipeline {
            for (index, result) in pipe.evaluate_batch(texts).into_iter().enumerate() {
                per_text[index].push(into_scan_result(
                    SecurityCategory::Dlp,
                    "native:sensitive_material",
                    result,
                ));
            }
        }
        if let Some(ref pipe) = self.secret_transfer_pipeline {
            for (index, result) in pipe.evaluate_batch(texts).into_iter().enumerate() {
                per_text[index].push(into_scan_result(
                    SecurityCategory::Dlp,
                    "native:secret_transfer",
                    result,
                ));
            }
        }
        if let Some(ref pipe) = self.mcp_runtime_risk_pipeline {
            for (index, result) in pipe.evaluate_batch(texts).into_iter().enumerate() {
                per_text[index].push(into_scan_result(
                    SecurityCategory::Dlp,
                    "native:mcp_runtime_risk",
                    result,
                ));
            }
        }
        if let Some(ref pipe) = self.mcp_policy_pipeline {
            for (index, result) in pipe.evaluate_batch(texts).into_iter().enumerate() {
                per_text[index].push(into_scan_result(
                    SecurityCategory::Dlp,
                    "native:mcp_policy",
                    result,
                ));
            }
        }
        if let Some(ref pipe) = self.destructive_operation_pipeline {
            for (index, result) in pipe.evaluate_batch(texts).into_iter().enumerate() {
                per_text[index].push(into_scan_result(
                    SecurityCategory::Dlp,
                    "native:destructive_operation",
                    result,
                ));
            }
        }

        per_text
            .into_iter()
            .filter_map(|results| select_first_unsafe_or_model(results, "native:dlp"))
            .collect()
    }

    fn evaluate_pii_batch(&self, texts: &[String]) -> Vec<SecurityScanResult> {
        let Some(ref native) = self.pii_pipeline else {
            return Vec::new();
        };

        let native_results = native.evaluate_batch(texts);
        let mut output = vec![None; texts.len()];
        let mut model_indices = Vec::new();
        let mut model_texts = Vec::new();
        let can_use_model =
            self.max_level >= SecurityLevel::L2 && self.pii_model_pipeline.is_some();

        for (index, native_result) in native_results.into_iter().enumerate() {
            if native_result.class_name != "safe" || !can_use_model {
                output[index] = Some(into_scan_result(
                    SecurityCategory::Pii,
                    "native:pii",
                    native_result,
                ));
            } else {
                model_indices.push(index);
                model_texts.push(texts[index].clone());
            }
        }

        if let Some(ref model) = self.pii_model_pipeline {
            let model_results = scan_result_batch(
                SecurityCategory::Pii,
                "pii-model",
                model.evaluate_batch_with_layers(&model_texts, SecurityLevel::L2),
            );
            for (index, result) in model_indices.into_iter().zip(model_results) {
                output[index] = Some(result);
            }
        }

        output.into_iter().flatten().collect()
    }

    /// Evaluate a legacy-compatible pipeline name for many texts.
    ///
    /// This is the optimized bulk path used by benchmarks and Python
    /// `evaluate_batch`. Native subscanners and model-backed pipelines are
    /// batched internally instead of looping through `evaluate_pipeline`.
    pub fn evaluate_pipeline_batch(
        &self,
        pipeline: &str,
        texts: &[String],
    ) -> Option<Vec<SecurityScanResult>> {
        match pipeline {
            "tool_classifier_prompts" => self.tool_classifier_prompts.as_ref().map(|pipe| {
                scan_result_batch(
                    SecurityCategory::ToolClassifier,
                    "tool-prompts-model",
                    pipe.evaluate_batch_with_layers(texts, self.max_level),
                )
            }),
            "tool_classifier_executions" => self.tool_classifier_executions.as_ref().map(|pipe| {
                scan_result_batch(
                    SecurityCategory::ToolClassifier,
                    "tool-executions-model",
                    pipe.evaluate_batch_with_layers(texts, self.max_level),
                )
            }),
            "user_intent_prompts" => self.user_intent_prompts.as_ref().map(|pipe| {
                scan_result_batch(
                    SecurityCategory::UserIntent,
                    "user-intent-model",
                    pipe.evaluate_batch_with_layers(texts, self.max_level),
                )
            }),
            "sensitive_documents_prompts" => {
                self.sensitive_documents_prompts.as_ref().map(|pipe| {
                    scan_result_batch(
                        SecurityCategory::SensitiveDocuments,
                        "orca-sonar-document-classifier",
                        pipe.evaluate_batch_with_layers(texts, self.max_level),
                    )
                })
            }
            "tool_description_prompts" => self.tool_description_prompts.as_ref().map(|pipe| {
                scan_result_batch(
                    SecurityCategory::ToolDescription,
                    "tool-description-model",
                    pipe.evaluate_batch_with_layers(texts, self.max_level),
                )
            }),
            "injection" => self.injection_pipeline.as_ref().map(|pipe| {
                scan_result_batch(
                    SecurityCategory::Injection,
                    "wolf-defender-small",
                    pipe.evaluate_batch_with_layers(texts, self.max_level),
                )
            }),
            "dlp" => Some(self.evaluate_dlp_batch(texts)),
            "pii" => Some(self.evaluate_pii_batch(texts)),
            _ => None,
        }
    }

    /// Scan text with a caller-provided category subset.
    pub fn scan_categories(
        &self,
        categories: &[SecurityCategory],
        text: &str,
    ) -> Vec<SecurityScanResult> {
        let mut results = Vec::new();
        for cat in categories {
            results.extend(self.scan_category(*cat, text));
        }
        results
    }

    /// Scan text with every category configured on this gateway.
    pub fn scan_all(&self, text: &str) -> Vec<SecurityScanResult> {
        self.scan_categories(&self.categories, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn selector_returns_first_safe_result_when_preferred_safe_model_is_absent() {
        let selected = select_first_unsafe_or_model(
            vec![SecurityScanResult {
                category: "pii".to_string(),
                class_name: "safe".to_string(),
                confidence: 0.99,
                level: "L2".to_string(),
                model: "pii-model".to_string(),
                duration_ms: 1.0,
                layers: vec![LayerResult {
                    level: "L2".to_string(),
                    layer_type: "fast_ml".to_string(),
                    class_name: "safe".to_string(),
                    confidence: 0.99,
                    matched: true,
                    duration_ms: 1.0,
                    thresholds: HashMap::new(),
                    details: HashMap::new(),
                }],
            }],
            "native:pii",
        )
        .unwrap();

        assert_eq!(selected.model, "pii-model");
        assert_eq!(selected.class_name, "safe");
    }
}
