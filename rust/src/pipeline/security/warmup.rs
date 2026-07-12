//! Asset verification, model downloads, and pipeline initialization.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use crate::{
    assets,
    ml::{
        ntdb_executor::{manifest::PackageManifest, NtdbExecutor},
        onnx::LazyOnnxTextClassifier,
    },
    pipeline::{Pipeline, PipelineStrategy},
    SecurityCategory, SecurityLevel,
};

use super::ntdb_l2::{
    model_explicitly_enabled, ntdb_l2_model_configs_for_category, ntdb_l2_package_dir,
    unsupported_ntdb_l2_models, validate_ntdb_l2_package, NtdbL2ModelConfig,
};
use super::SecurityGateway;

#[derive(Clone, Copy)]
enum WarmupPipelineKind {
    SensitiveDocumentsPrompts,
    ToolClassifierPrompts,
    ToolClassifierExecutions,
    ToolClassifierDescriptions,
    UserIntentPrompts,
}

struct WarmupPipelineTask {
    kind: WarmupPipelineKind,
    label: &'static str,
    path: PathBuf,
}

fn pipeline_strategy(kind: WarmupPipelineKind) -> PipelineStrategy {
    match kind {
        WarmupPipelineKind::SensitiveDocumentsPrompts => PipelineStrategy::sensitive_documents(),
        WarmupPipelineKind::ToolClassifierPrompts => PipelineStrategy::tool_classifier_prompts(),
        WarmupPipelineKind::ToolClassifierExecutions => {
            PipelineStrategy::tool_classifier_executions()
        }
        WarmupPipelineKind::ToolClassifierDescriptions => {
            PipelineStrategy::tool_classifier_descriptions()
        }
        WarmupPipelineKind::UserIntentPrompts => PipelineStrategy::user_intent(),
    }
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
    log::info!(
        "{label} initialized in {:.2} ms; l3={l3_state}",
        started.elapsed().as_secs_f64() * 1000.0
    );
}

fn l1_rules_present(path: &std::path::Path) -> bool {
    path.join("l1_rules.json").exists()
}

fn first_existing_l1_rules_path(paths: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    paths.into_iter().find(|path| l1_rules_present(path))
}

impl SecurityGateway {
    pub fn warmup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let base_dir = match &self.model_dir {
            Some(path) => path.clone(),
            None => dirs::cache_dir()
                .ok_or("Could not resolve cache directory")?
                .join("patronus_security"),
        };

        log::info!(
            "model_dir={}; max_level={}",
            base_dir.display(),
            self.max_level.as_str()
        );
        let onnx_started = Instant::now();
        let configured_onnx_runtime = crate::ml::onnx::warmup_runtime();
        log::info!(
            "onnx runtime initialized in {:.2} ms; configured_now={}; model_sessions_loaded=false",
            onnx_started.elapsed().as_secs_f64() * 1000.0,
            configured_onnx_runtime
        );

        let execution = self.scan_execution();
        let mut init_tasks = Vec::new();
        let mut ntdb_specs = Vec::new();

        for cat in &self.categories {
            if *cat == SecurityCategory::Pii
                && !model_explicitly_enabled(&execution, &["pii-model"])
            {
                log::info!("pii native-only; pii-model disabled by default");
                continue;
            }

            let cat_dir = match cat {
                SecurityCategory::Injection => base_dir.join("injection"),
                SecurityCategory::SensitiveDocuments => base_dir.join("sensitive_documents"),
                SecurityCategory::ToolClassifier => base_dir.join("tool_classifier"),
                SecurityCategory::UserIntent => base_dir.join("user_intent"),
                SecurityCategory::Pii => base_dir.join("pii"),
                SecurityCategory::Dlp => {
                    log::info!("dlp native-only; no model assets");
                    continue;
                }
            };

            let ntdb_l2_configs = ntdb_l2_model_configs_for_category(&execution, *cat);
            let unsupported_l2_models = unsupported_ntdb_l2_models(&execution, *cat);
            if !unsupported_l2_models.is_empty() {
                return Err(format!(
                    "missing NTDB v2 L2 export mapping for {}/{}; legacy L2 has been removed",
                    cat.as_str(),
                    unsupported_l2_models.join(",")
                )
                .into());
            }

            let mut validated_ntdb_l3 = Vec::new();
            for config in &ntdb_l2_configs {
                let env_override = std::env::var_os(config.env_key).is_some();
                let package_dir = ntdb_l2_package_dir(*config, &cat_dir);
                if !env_override
                    && !package_dir.join("manifest.json").exists()
                    && self.should_download_assets_for(*cat)
                {
                    log::info!(
                        "{}/{} NTDB v2 L2 package missing; downloading package",
                        cat.as_str(),
                        config.public_model
                    );
                    assets::download_ntdb_l2_package(
                        *cat,
                        self.max_level,
                        config.public_model,
                        &cat_dir,
                    )?;
                }
                let (spec, manifest) = validate_ntdb_l2_package(*config, package_dir.clone())?;
                log::info!(
                    "{}/{} NTDB v2 L2 package present at {}",
                    cat.as_str(),
                    config.public_model,
                    package_dir.display()
                );
                validated_ntdb_l3.push((*config, manifest));
                ntdb_specs.push(spec);
            }

            let assets_present = assets::required_assets_present(*cat, self.max_level, &cat_dir);
            if !assets_present {
                if self.should_download_assets_for(*cat) {
                    log::info!(
                        "{} required assets missing; downloading required assets",
                        cat.as_str()
                    );
                    assets::download_category_assets(*cat, self.max_level, &cat_dir)?;
                } else {
                    log::info!(
                        "{} required assets missing; downloads disabled",
                        cat.as_str()
                    );
                }
            } else {
                log::info!(
                    "{} required assets present at {}",
                    cat.as_str(),
                    cat_dir.display()
                );
            }

            for (config, manifest) in validated_ntdb_l3 {
                self.register_ntdb_l3_worker_model(config, &cat_dir, &manifest)?;
            }

            match cat {
                SecurityCategory::Injection => {}
                SecurityCategory::SensitiveDocuments => {
                    let prompts_path = cat_dir.join("prompts");
                    if l1_rules_present(&prompts_path) {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::SensitiveDocumentsPrompts,
                            label: "sensitive_documents/prompts",
                            path: prompts_path,
                        });
                    }
                }
                SecurityCategory::ToolClassifier => {
                    let prompts_path = cat_dir.join("prompts");
                    if l1_rules_present(&prompts_path) {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::ToolClassifierPrompts,
                            label: "tool_classifier/prompts",
                            path: prompts_path,
                        });
                    }
                    let executions_path = cat_dir.join("executions");
                    if l1_rules_present(&executions_path) {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::ToolClassifierExecutions,
                            label: "tool_classifier/executions",
                            path: executions_path,
                        });
                    }
                    if let Some(descriptions_path) = first_existing_l1_rules_path([
                        cat_dir.join("descriptions"),
                        base_dir.join("tool_description").join("prompts"),
                    ]) {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::ToolClassifierDescriptions,
                            label: "tool_classifier/descriptions",
                            path: descriptions_path,
                        });
                    }
                }
                SecurityCategory::UserIntent => {
                    let prompts_path = cat_dir.join("prompts");
                    if l1_rules_present(&prompts_path) {
                        init_tasks.push(WarmupPipelineTask {
                            kind: WarmupPipelineKind::UserIntentPrompts,
                            label: "user_intent/prompts",
                            path: prompts_path,
                        });
                    }
                }
                SecurityCategory::Pii => {}
                SecurityCategory::Dlp => {}
            }
        }

        use rayon::prelude::*;
        let init_results: Result<Vec<_>, String> = init_tasks
            .into_par_iter()
            .map(|task| {
                let started = Instant::now();
                let pipeline = Pipeline::new_with_strategy(
                    &task.path,
                    SecurityLevel::L1,
                    pipeline_strategy(task.kind),
                )
                .map_err(|err| format!("{}: {}", task.label, err))?;
                log_pipeline_warmup(
                    task.label,
                    started,
                    pipeline.has_l3_model(),
                    pipeline.is_l3_loaded(),
                );
                Ok((task.kind, task.path, pipeline))
            })
            .collect();

        for (kind, _path, pipeline) in
            init_results.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
        {
            match kind {
                WarmupPipelineKind::SensitiveDocumentsPrompts => {
                    self.sensitive_documents_prompts = Some(pipeline);
                }
                WarmupPipelineKind::ToolClassifierPrompts => {
                    self.tool_classifier_prompts = Some(pipeline);
                }
                WarmupPipelineKind::ToolClassifierExecutions => {
                    self.tool_classifier_executions = Some(pipeline);
                }
                WarmupPipelineKind::ToolClassifierDescriptions => {
                    self.tool_classifier_descriptions = Some(pipeline);
                }
                WarmupPipelineKind::UserIntentPrompts => {
                    self.user_intent_prompts = Some(pipeline);
                }
            }
        }

        if !ntdb_specs.is_empty() {
            let started = Instant::now();
            let executor = NtdbExecutor::load_specs(ntdb_specs)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
            log::info!(
                "ntdb_executor initialized with {} packages in {:.2} ms",
                executor.len(),
                started.elapsed().as_secs_f64() * 1000.0
            );
            self.ntdb_executor = Some(Mutex::new(executor));
        } else {
            self.ntdb_executor = None;
        }

        Ok(())
    }

    fn register_ntdb_l3_worker_model(
        &self,
        config: NtdbL2ModelConfig,
        category_dir: &std::path::Path,
        manifest: &PackageManifest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !config.has_l3 || self.max_level < SecurityLevel::L3 {
            return Ok(());
        }
        let model = match config.category {
            SecurityCategory::Injection => ntdb_injection_l3_worker_model(category_dir)?,
            SecurityCategory::SensitiveDocuments => LazyOnnxTextClassifier::from_dir(
                category_dir.join("prompts"),
                manifest.task.labels.clone(),
                config.public_model,
            )?,
            _ => return Ok(()),
        };
        let Some(model) = model else {
            log::info!(
                "{} NTDB L3 worker model not present at {}",
                config.category.as_str(),
                category_dir.display()
            );
            return Ok(());
        };
        log::info!(
            "{} NTDB L3 worker model registered from {}",
            config.category.as_str(),
            category_dir.display()
        );
        self.l3_worker.register_model(config.public_model, model);
        Ok(())
    }
}

fn ntdb_injection_l3_worker_model(
    category_dir: &std::path::Path,
) -> Result<Option<LazyOnnxTextClassifier>, Box<dyn std::error::Error>> {
    let labels = vec!["benign".to_string(), "attack".to_string()];
    LazyOnnxTextClassifier::from_dir_with_paths(
        category_dir,
        labels,
        "wolf-defender-small",
        &["l3/onnx/onnx_mixed/model_mixed.onnx"],
        "l3/tokenizer.json",
        256,
    )
}
