// SPDX-License-Identifier: GPL-3.0-only
//! Asset synchronization and model-runtime initialization.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use crate::{
    assets,
    ml::{
        dynamic_pii::DynamicPiiRuntime,
        ntdb_executor::{manifest::PackageManifest, NtdbExecutor, NtdbPackageSpec},
        onnx::LazyOnnxTextClassifier,
        unified_onnx::LazyUnifiedOnnxClassifier,
    },
    L3Strategy, SecurityAssetProgressCallback, SecurityAssetReadiness, SecurityCategory,
    SecurityFailure, SecurityFailureKind, SecurityFailureStage, SecurityLevel,
    SecurityLevelReadiness,
};

use super::ntdb_l2::{
    ntdb_l2_model_configs_for_category, ntdb_l2_package_dir, validate_ntdb_l2_package,
    NtdbL2ModelConfig,
};
use super::SecurityGateway;
use crate::detectors::shell::shell_risk::ShellRiskPipeline;

struct PreparedNtdbAssets {
    config: NtdbL2ModelConfig,
    category_dir: PathBuf,
    manifest: PackageManifest,
    spec: NtdbPackageSpec,
}

#[derive(Default)]
struct PreparedAssets {
    ntdb: Vec<PreparedNtdbAssets>,
}

impl SecurityGateway {
    /// Backwards-compatible combined lifecycle. New integrations should call
    /// `prepare_assets` in their delivery window and
    /// `warmup_from_local_assets` when starting their runtime.
    pub fn warmup(&mut self) -> Result<(), SecurityFailure> {
        self.prepare_assets()?;
        self.warmup_from_local_assets()
    }

    /// Download and verify configured model assets without initializing ONNX,
    /// tokenizers, executors, workers, or model sessions.
    pub fn prepare_assets(&self) -> Result<SecurityAssetReadiness, SecurityFailure> {
        self.prepare_assets_inner(true, None)
            .map_err(|error| asset_failure(error.to_string()))?;
        Ok(self.configured_asset_readiness())
    }

    /// Download and verify configured model assets while reporting per-model
    /// file progress. Callbacks may run concurrently on asset download threads.
    pub fn prepare_assets_with_progress(
        &self,
        progress: SecurityAssetProgressCallback,
    ) -> Result<SecurityAssetReadiness, SecurityFailure> {
        self.prepare_assets_inner(true, Some(&progress))
            .map_err(|error| asset_failure(error.to_string()))?;
        Ok(self.configured_asset_readiness())
    }

    /// Inspect configured model assets without downloading or warming them.
    pub fn asset_readiness(&self) -> SecurityAssetReadiness {
        match self.prepare_assets_inner(false, None) {
            Ok(_) => self.configured_asset_readiness(),
            Err(error) => self.failed_asset_readiness(asset_failure(error.to_string())),
        }
    }

    /// Initialize all configured model runtimes strictly from local assets.
    /// This method has no download path regardless of the gateway's download
    /// policy.
    pub fn warmup_from_local_assets(&mut self) -> Result<(), SecurityFailure> {
        self.warmup_from_local_assets_inner()
            .map_err(|error| warmup_failure(error.to_string()))
    }

    fn warmup_from_local_assets_inner(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut metrics = crate::diagnostics::PhaseMetricScope::new(
            "security_local_startup",
            format!("max_level={}", self.max_level.as_str()),
        );
        self.distributed_fingerprints.take();
        let base_dir = self.model_base_dir()?;
        let prepared = self.prepare_assets_inner(false, None)?;
        metrics.checkpoint("asset_validation", "downloads=false");
        self.l3_worker
            .configure_strategy(self.scan_execution().l3_strategy());

        log::info!(
            "model_dir={}; max_level={}; downloads=false",
            base_dir.display(),
            self.max_level.as_str()
        );
        let onnx_started = Instant::now();
        let configured_onnx_runtime = crate::ml::onnx::warmup_runtime();
        log::info!(
            "onnx runtime initialized in {:.2} ms; configured_now={}; model_sessions_loaded=true",
            onnx_started.elapsed().as_secs_f64() * 1000.0,
            configured_onnx_runtime
        );

        metrics.checkpoint("onnx_runtime", "");
        let mut ntdb_specs = Vec::with_capacity(prepared.ntdb.len());
        for assets in prepared.ntdb {
            self.register_ntdb_l3_worker_model(
                assets.config,
                &assets.category_dir,
                &assets.manifest,
            )?;
            ntdb_specs.push(assets.spec);
        }

        metrics.checkpoint("worker_registration", "");
        let execution = self.scan_execution();
        self.shell_command_pipeline = if self.shell_command_configured(&execution) {
            let shell = self.shell_command_config(&base_dir);
            let pipeline = ShellRiskPipeline::from_pinned_bundle_dir(
                &shell.bundle_dir,
                &shell.manifest_sha256,
            )
            .map_err(std::io::Error::other)?;
            pipeline
                .configure(&self.shell_command_policy_config())
                .map_err(std::io::Error::other)?;
            let (ask, block) = pipeline.model().cuts();
            log::info!(
                "shell_command model {} loaded from {}; cuts ask={ask} block={block}",
                patronus_ark_core::warmup::SHELL_MODEL,
                shell.bundle_dir.display(),
            );
            metrics.checkpoint("shell_command_l1", "");
            Some(pipeline)
        } else {
            None
        };
        if execution.l3_strategy() == L3Strategy::Multi
            && execution.allows_level(SecurityLevel::L3)
            && execution
                .gates()
                .native
                .allows_model(crate::ml::unified_onnx::UNIFIED_MODEL)
            && self.categories.iter().copied().any(|category| {
                super::ntdb_l2::classifier_model_configs_for_category(&execution, category)
                    .iter()
                    .any(|config| config.has_l3)
            })
        {
            let bundle_dir = base_dir.join(assets::UNIFIED_L3_ASSET.destination_path);
            let mut classifier = LazyUnifiedOnnxClassifier::from_dir(&bundle_dir)?;
            classifier.warmup_session(execution.backend(), execution.onnx_runtime_options())?;
            self.l3_worker.register_unified(classifier);
            metrics.checkpoint("unified_l3", "");
            log::info!(
                "unified multi-head L3 worker model warmed and registered from {}",
                bundle_dir.display()
            );
        }

        if self.categories.contains(&SecurityCategory::DynamicPii)
            && self.max_level >= SecurityLevel::L3
            && self.scan_execution().allows_level(SecurityLevel::L3)
            && self
                .scan_execution()
                .gates()
                .native
                .allows_model(assets::DYNAMIC_PII_ASSET.model)
        {
            let bundle_dir = base_dir.join(assets::DYNAMIC_PII_ASSET.destination_path);
            let mut runtime = DynamicPiiRuntime::from_path(&bundle_dir)?;
            runtime.warmup(&self.dynamic_pii_config())?;
            self.l3_worker
                .register_dynamic_pii(assets::DYNAMIC_PII_ASSET.model, runtime);
            metrics.checkpoint("dynamic_pii_l3", "");
            log::info!(
                "dynamic-pii L3 worker model registered from {}",
                bundle_dir.display()
            );
        }

        if ntdb_specs.is_empty() {
            self.ntdb_executor = None;
        } else {
            let started = Instant::now();
            let executor = NtdbExecutor::load_specs(ntdb_specs)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            log::info!(
                "ntdb_executor initialized with {} packages in {:.2} ms",
                executor.len(),
                started.elapsed().as_secs_f64() * 1000.0
            );
            self.ntdb_executor = Some(Mutex::new(executor));
            metrics.checkpoint("l2_executor", "");
            // L2 local inference does not need distributed export identities.
            // Keep the L3 identity bound to the just-loaded background runtime.
            if self.max_level >= SecurityLevel::L3 {
                self.distributed_ntdb_fingerprints()
                    .map_err(std::io::Error::other)?;
                metrics.checkpoint("distributed_fingerprints", "");
            }
        }

        metrics.checkpoint("ready", "");
        Ok(())
    }

    fn prepare_assets_inner(
        &self,
        allow_download: bool,
        progress: Option<&SecurityAssetProgressCallback>,
    ) -> Result<PreparedAssets, Box<dyn std::error::Error>> {
        let base_dir = self.model_base_dir()?;
        let execution = self.scan_execution();
        let mut prepared = PreparedAssets::default();
        let mut prepared_compact_tokenizers = HashSet::new();

        let unified_strategy_multi = execution.l3_strategy() == L3Strategy::Multi;
        let unified_l3_allowed = execution.allows_level(SecurityLevel::L3);
        let unified_model_allowed = execution
            .gates()
            .native
            .allows_model(crate::ml::unified_onnx::UNIFIED_MODEL);
        let unified_category_has_l3 = self.categories.iter().copied().any(|category| {
            super::ntdb_l2::classifier_model_configs_for_category(&execution, category)
                .iter()
                .any(|config| config.has_l3)
        });
        let unified_assets_present = assets::unified_l3_assets_present(&base_dir);
        log::debug!(
            "checked unified L3 asset preparation state; base_dir={}; allow_download={}; strategy_multi={}; l3_allowed={}; unified_model_allowed={}; category_has_l3={}; unified_assets_present={}",
            base_dir.display(),
            allow_download,
            unified_strategy_multi,
            unified_l3_allowed,
            unified_model_allowed,
            unified_category_has_l3,
            unified_assets_present
        );

        if unified_strategy_multi
            && unified_l3_allowed
            && unified_model_allowed
            && unified_category_has_l3
        {
            let bundle_dir = base_dir.join(assets::UNIFIED_L3_ASSET.destination_path);
            if !unified_assets_present {
                let may_download = allow_download
                    && self
                        .categories
                        .iter()
                        .copied()
                        .filter(|category| category.is_unified_classifier())
                        .any(|category| self.should_download_assets_for(category));
                log::debug!(
                    "unified L3 assets missing during preparation; bundle_dir={}; may_download={}",
                    bundle_dir.display(),
                    may_download
                );
                if may_download {
                    if let Some(progress) = progress {
                        assets::download_unified_l3_assets_with_progress(&base_dir, progress)?;
                    } else {
                        assets::download_unified_l3_assets(&base_dir)?;
                    }
                } else {
                    return Err(format!(
                        "missing unified L3 assets at {}; downloads disabled",
                        bundle_dir.display()
                    )
                    .into());
                }
            }
            // Runtime startup and readiness checks only consume prepared files.
            // Converting the source tokenizer and weights belongs to delivery.
            if allow_download {
                assets::prepare_cached_pipeline_model(assets::UNIFIED_L3_ASSET, &base_dir);
            }
        }

        for category in &self.categories {
            if *category == SecurityCategory::ShellCommand {
                if !self.shell_command_configured(&execution) {
                    continue;
                }
                let shell = self.shell_command_config(&base_dir);
                let download = allow_download && self.should_download_assets_for(*category);
                if !download && !patronus_ark_core::warmup::shell_assets_present(&shell) {
                    return Err(format!(
                        "missing shell_command assets at {}; downloads disabled",
                        shell.bundle_dir.display()
                    )
                    .into());
                }
                let report = progress.map(|progress| {
                    move |completed_files, total_files| {
                        progress(crate::SecurityAssetProgress {
                            category: SecurityCategory::ShellCommand,
                            model: patronus_ark_core::warmup::SHELL_MODEL.to_string(),
                            completed_files,
                            total_files,
                        })
                    }
                });
                patronus_ark_core::warmup::prepare_shell_assets_with_progress(
                    &shell,
                    &core_warmup_options(download),
                    report
                        .as_ref()
                        .map(|report| report as &(dyn Fn(usize, usize) + Send + Sync)),
                )?;
                continue;
            }
            if *category == SecurityCategory::DynamicPii {
                if self.max_level < SecurityLevel::L3
                    || !execution.allows_level(SecurityLevel::L3)
                    || !execution
                        .gates()
                        .native
                        .allows_model(assets::DYNAMIC_PII_ASSET.model)
                {
                    continue;
                }
                let bundle_dir = base_dir.join(assets::DYNAMIC_PII_ASSET.destination_path);
                if !assets::dynamic_pii_assets_present(&base_dir) {
                    if allow_download && self.should_download_assets_for(*category) {
                        if let Some(progress) = progress {
                            assets::download_dynamic_pii_assets_with_progress(&base_dir, progress)?;
                        } else {
                            assets::download_dynamic_pii_assets(&base_dir)?;
                        }
                    } else {
                        return Err(format!(
                            "missing dynamic-pii assets at {}; downloads disabled",
                            bundle_dir.display()
                        )
                        .into());
                    }
                }
                let missing_files = assets::DYNAMIC_PII_ASSET
                    .files
                    .iter()
                    .filter(|file| {
                        assets::selected_pipeline_model_files(assets::DYNAMIC_PII_ASSET)
                            .contains(file)
                    })
                    .filter(|file| !bundle_dir.join(file).is_file())
                    .copied()
                    .collect::<Vec<_>>();
                if !missing_files.is_empty() {
                    return Err(format!(
                        "missing dynamic-pii bundle files at {}: {}",
                        bundle_dir.display(),
                        missing_files.join(", ")
                    )
                    .into());
                }
                if allow_download {
                    assets::prepare_cached_pipeline_model(assets::DYNAMIC_PII_ASSET, &base_dir);
                }
                continue;
            }

            let category_dir = match category {
                SecurityCategory::Injection => base_dir.join("injection"),
                SecurityCategory::SensitiveDocument => base_dir.join("sensitive_document"),
                SecurityCategory::ToolClass => base_dir.join("tool_class"),
                SecurityCategory::ToolAction => base_dir.join("tool_action"),
                SecurityCategory::ToolTags => base_dir.join("tool_tags"),
                SecurityCategory::Routing => base_dir.join("routing"),
                SecurityCategory::UnsafeAction => base_dir.join("threat"),
                SecurityCategory::Dlp
                | SecurityCategory::Pii
                | SecurityCategory::Jailbreak
                | SecurityCategory::PromptExtraction
                | SecurityCategory::ToolPoisoning
                | SecurityCategory::AgentConfigTampering
                | SecurityCategory::MemoryPoisoning
                | SecurityCategory::Exfiltration
                | SecurityCategory::ResourceExhaustion
                | SecurityCategory::HarmfulContent
                | SecurityCategory::ToxicLanguage => continue,
                SecurityCategory::DynamicPii | SecurityCategory::ShellCommand => {
                    unreachable!("handled above")
                }
            };
            let configs = if execution.l3_strategy() == L3Strategy::Dedicated
                && execution.allows_level(SecurityLevel::L3)
            {
                super::ntdb_l2::classifier_model_configs_for_category(&execution, *category)
            } else {
                ntdb_l2_model_configs_for_category(&execution, *category)
            };
            if configs.is_empty() {
                continue;
            }

            for config in configs {
                let env_override = std::env::var_os(config.env_key).is_some();
                let package_dir = ntdb_l2_package_dir(config, &category_dir);
                let official_package_current = env_override
                    || assets::ntdb_l2_package_assets_present(
                        *category,
                        self.max_level,
                        config.asset_model,
                        &category_dir,
                    );
                if !official_package_current {
                    if allow_download && self.should_download_assets_for(*category) {
                        log::info!(
                            "{}/{} NTDB L2 package missing; downloading package",
                            category.as_str(),
                            config.public_model
                        );
                        if let Some(progress) = progress {
                            assets::download_ntdb_l2_package_with_progress(
                                *category,
                                self.max_level,
                                config.asset_model,
                                &category_dir,
                                progress,
                            )?;
                        } else {
                            assets::download_ntdb_l2_package(
                                *category,
                                self.max_level,
                                config.asset_model,
                                &category_dir,
                            )?;
                        }
                    } else {
                        return Err(format!(
                            "missing {} L2 package at {}, or cached revision is outdated; downloads disabled",
                            config.public_model,
                            package_dir.display()
                        )
                        .into());
                    }
                }

                let (spec, manifest) = validate_ntdb_l2_package(config, package_dir.clone())?;
                if allow_download && !env_override {
                    if let Err(error) = assets::prepare_cached_ntdb_l2_compact_tokenizer(
                        &manifest,
                        &package_dir,
                        &mut prepared_compact_tokenizers,
                    ) {
                        log::warn!(
                            "failed to prepare compact tokenizer for cached {}/{} package: {error}; tokenizer.json remains available",
                            category.as_str(),
                            config.public_model
                        );
                    }
                }
                prepared.ntdb.push(PreparedNtdbAssets {
                    config,
                    category_dir: category_dir.clone(),
                    manifest,
                    spec,
                });
            }

            let asset_level = if execution.l3_strategy() == L3Strategy::Multi {
                SecurityLevel::L2.min(self.max_level)
            } else {
                self.max_level
            };
            if execution.l3_strategy() == L3Strategy::Dedicated
                && execution.allows_level(SecurityLevel::L3)
            {
                let download = allow_download && self.should_download_assets_for(*category);
                if *category == SecurityCategory::Injection {
                    // Core pins, prepares and caches Wolf; ARK only picks the model.
                    let wolf = execution.wolf_selection();
                    let dir = patronus_ark_core::warmup::wolf_bundle_dir(&base_dir, wolf.model);
                    if !download
                        && !patronus_ark_core::warmup::wolf_assets_present(
                            &dir,
                            wolf.model,
                            wolf.precision,
                        )?
                    {
                        return Err(format!(
                            "missing injection dedicated L3 assets below {}; downloads disabled",
                            dir.display()
                        )
                        .into());
                    }
                    patronus_ark_core::warmup::prepare_wolf_cache(
                        &dir,
                        wolf.model,
                        wolf.precision,
                        &core_warmup_options(download),
                        None,
                    )?;
                } else if let Some(asset) = assets::dedicated_l3_asset(*category) {
                    if !assets::dedicated_l3_assets_present(*category, &base_dir) {
                        if !download {
                            return Err(format!(
                                "missing {} dedicated L3 assets below {}; downloads disabled",
                                category.as_str(),
                                base_dir.display()
                            )
                            .into());
                        }
                        assets::download_dedicated_l3_assets(*category, &base_dir)?;
                    }
                    if allow_download {
                        assets::prepare_cached_pipeline_model(asset, &base_dir);
                    }
                }
            }
            if !assets::required_assets_present(*category, asset_level, &category_dir) {
                if allow_download && self.should_download_assets_for(*category) {
                    assets::download_category_assets(*category, asset_level, &category_dir)?;
                } else {
                    return Err(format!(
                        "missing {} assets at {}; downloads disabled",
                        category.as_str(),
                        category_dir.display()
                    )
                    .into());
                }
            }
        }

        Ok(prepared)
    }

    fn configured_asset_readiness(&self) -> SecurityAssetReadiness {
        let execution = self.scan_execution();
        let l2_configured =
            self.categories.iter().copied().any(|category| {
                !ntdb_l2_model_configs_for_category(&execution, category).is_empty()
            });
        let classifier_l3 = if execution.l3_strategy() == L3Strategy::Multi {
            execution
                .gates()
                .native
                .allows_model(crate::ml::unified_onnx::UNIFIED_MODEL)
                && self.categories.iter().copied().any(|category| {
                    super::ntdb_l2::classifier_model_configs_for_category(&execution, category)
                        .iter()
                        .any(|config| config.has_l3)
                })
        } else {
            self.categories.iter().copied().any(|category| {
                super::ntdb_l2::classifier_model_configs_for_category(&execution, category)
                    .iter()
                    .any(|config| config.has_l3)
            })
        };
        let l3_configured = execution.allows_level(SecurityLevel::L3)
            && (classifier_l3
                || (self.categories.contains(&SecurityCategory::DynamicPii)
                    && execution
                        .gates()
                        .native
                        .allows_model(assets::DYNAMIC_PII_ASSET.model)));
        SecurityAssetReadiness {
            l1: configured_level_readiness(self.shell_command_configured(&execution)),
            l2: configured_level_readiness(l2_configured),
            l3: configured_level_readiness(l3_configured),
        }
    }

    fn failed_asset_readiness(&self, failure: SecurityFailure) -> SecurityAssetReadiness {
        let configured = self.configured_asset_readiness();
        SecurityAssetReadiness {
            l1: failed_configured_level(configured.l1, failure.clone()),
            l2: failed_configured_level(configured.l2, failure.clone()),
            l3: failed_configured_level(configured.l3, failure),
        }
    }

    pub(super) fn model_base_dir(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        match &self.model_dir {
            Some(path) => Ok(path.clone()),
            None => Ok(patronus_ark_core::warmup::default_cache_root()
                .ok_or("Could not resolve cache directory")?),
        }
    }

    fn register_ntdb_l3_worker_model(
        &self,
        config: NtdbL2ModelConfig,
        category_dir: &Path,
        manifest: &PackageManifest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !config.has_l3 || self.max_level < SecurityLevel::L3 {
            return Ok(());
        }
        if self.scan_execution().l3_strategy() == L3Strategy::Multi {
            return Ok(());
        }
        let model = match config.category {
            SecurityCategory::Injection => ntdb_injection_l3_worker_model(
                &self.model_base_dir()?,
                self.scan_execution().wolf_selection(),
            )?,
            SecurityCategory::SensitiveDocument => {
                let asset = revision_pinned_l3_asset(config.category)?;
                LazyOnnxTextClassifier::from_dir_with_paths_at_sha(
                    category_dir,
                    manifest.task.labels.clone(),
                    config.public_model,
                    sensitive_l3_onnx_paths(),
                    "prompts/tokenizer.json",
                    256,
                    asset.revision,
                )?
            }
            SecurityCategory::ToolClass
            | SecurityCategory::ToolAction
            | SecurityCategory::ToolTags
            | SecurityCategory::Routing
            | SecurityCategory::UnsafeAction => {
                let asset = revision_pinned_l3_asset(config.category)?;
                LazyOnnxTextClassifier::from_dir_with_paths_at_sha(
                    category_dir,
                    manifest.task.labels.clone(),
                    config.public_model,
                    dedicated_l3_onnx_paths(),
                    "l3/tokenizer.json",
                    256,
                    asset.revision,
                )?
            }
            _ => return Ok(()),
        };
        let Some(mut model) = model else {
            return Ok(());
        };
        let execution = self.scan_execution();
        model.warmup_session(
            execution.backend(),
            execution.onnx_runtime_options(),
            execution.wolf_execution_options(),
        )?;
        self.l3_worker.register_model(config.public_model, model);
        Ok(())
    }
}

fn configured_level_readiness(configured: bool) -> SecurityLevelReadiness {
    if configured {
        SecurityLevelReadiness::Ready
    } else {
        SecurityLevelReadiness::NotConfigured
    }
}

fn failed_configured_level(
    configured: SecurityLevelReadiness,
    failure: SecurityFailure,
) -> SecurityLevelReadiness {
    match configured {
        SecurityLevelReadiness::NotConfigured => SecurityLevelReadiness::NotConfigured,
        SecurityLevelReadiness::Ready | SecurityLevelReadiness::NotReady { .. } => {
            SecurityLevelReadiness::NotReady {
                failures: vec![failure],
            }
        }
    }
}

fn asset_failure(message: String) -> SecurityFailure {
    let mut failure = warmup_failure(message);
    failure.stage = SecurityFailureStage::Asset;
    failure
}

fn warmup_failure(message: String) -> SecurityFailure {
    let lower = message.to_lowercase();
    let (stage, kind, retryable) = if lower.contains("integrity")
        || lower.contains("checksum")
        || lower.contains("hash mismatch")
    {
        (
            SecurityFailureStage::Asset,
            SecurityFailureKind::IntegrityFailure,
            false,
        )
    } else if lower.contains("missing")
        || lower.contains("not found")
        || lower.contains("no such file")
    {
        (
            SecurityFailureStage::Asset,
            SecurityFailureKind::MissingAsset,
            true,
        )
    } else {
        (
            SecurityFailureStage::Warmup,
            SecurityFailureKind::InitializationFailure,
            false,
        )
    };
    SecurityFailure {
        stage,
        level: None,
        detector_id: None,
        kind,
        retryable,
        message,
    }
}

fn ntdb_injection_l3_worker_model(
    base_dir: &Path,
    wolf: crate::WolfSelection,
) -> Result<Option<LazyOnnxTextClassifier>, Box<dyn std::error::Error>> {
    let labels = vec!["benign".to_string(), "attack".to_string()];
    let graphs = patronus_ark_core::wolf::graph_candidates(wolf.model, wolf.precision)?;
    Ok(LazyOnnxTextClassifier::from_dir_with_paths_at_sha(
        patronus_ark_core::warmup::wolf_bundle_dir(base_dir, wolf.model),
        labels,
        assets::WOLF_PIPELINE_MODEL,
        &graphs,
        "tokenizer.json",
        256,
        wolf.model.spec().revision,
    )?
    .map(|model| model.with_wolf_selection(wolf)))
}

/// Core's warmup options for one ARK preparation step.
fn core_warmup_options(download: bool) -> patronus_ark_core::warmup::WarmupOptions {
    patronus_ark_core::warmup::WarmupOptions {
        download: if download {
            patronus_ark_core::warmup::DownloadPolicy::Missing
        } else {
            patronus_ark_core::warmup::DownloadPolicy::Never
        },
        ..Default::default()
    }
}

fn dedicated_l3_onnx_paths() -> &'static [&'static str] {
    if assets::prefer_fp16_l3() {
        &[
            "l3/onnx/onnx_fp16/model_fp16.onnx",
            "l3/onnx/int8_int4_embeddings/model.onnx",
        ]
    } else {
        &[
            "l3/onnx/int8_int4_embeddings/model.onnx",
            "l3/onnx/onnx_fp16/model_fp16.onnx",
        ]
    }
}

fn sensitive_l3_onnx_paths() -> &'static [&'static str] {
    if assets::prefer_fp16_l3() {
        &[
            "prompts/onnx/onnx_fp16/model_fp16.onnx",
            "prompts/onnx/int8_int4_embeddings/model.onnx",
        ]
    } else {
        &[
            "prompts/onnx/int8_int4_embeddings/model.onnx",
            "prompts/onnx/onnx_fp16/model_fp16.onnx",
        ]
    }
}

fn revision_pinned_l3_asset(
    category: SecurityCategory,
) -> Result<assets::PipelineModelAssetSpec, Box<dyn std::error::Error>> {
    assets::dedicated_l3_asset(category).ok_or_else(|| {
        format!(
            "missing revision-pinned L3 asset for '{}'",
            category.as_str()
        )
        .into()
    })
}
