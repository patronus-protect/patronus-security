// SPDX-License-Identifier: AGPL-3.0-only
//! Asset synchronization and model-runtime initialization.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use crate::{
    assets,
    ml::{
        dynamic_pii::DynamicPiiRuntime,
        ntdb_executor::{manifest::PackageManifest, NtdbExecutor, NtdbPackageSpec},
        onnx::LazyOnnxTextClassifier,
    },
    SecurityAssetReadiness, SecurityCategory, SecurityFailure, SecurityFailureKind,
    SecurityFailureStage, SecurityLevel, SecurityLevelReadiness,
};

use super::ntdb_l2::{
    ntdb_l2_model_configs_for_category, ntdb_l2_package_dir, validate_ntdb_l2_package,
    NtdbL2ModelConfig,
};
use super::SecurityGateway;

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
        self.prepare_assets_inner(true)
            .map_err(|error| asset_failure(error.to_string()))?;
        Ok(self.configured_asset_readiness())
    }

    /// Inspect configured model assets without downloading or warming them.
    pub fn asset_readiness(&self) -> SecurityAssetReadiness {
        match self.prepare_assets_inner(false) {
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
        let base_dir = self.model_base_dir()?;
        let prepared = self.prepare_assets_inner(false)?;

        log::info!(
            "model_dir={}; max_level={}; downloads=false",
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

        let mut ntdb_specs = Vec::with_capacity(prepared.ntdb.len());
        for assets in prepared.ntdb {
            self.register_ntdb_l3_worker_model(
                assets.config,
                &assets.category_dir,
                &assets.manifest,
            )?;
            ntdb_specs.push(assets.spec);
        }

        if self.categories.contains(&SecurityCategory::DynamicPii)
            && self.max_level >= SecurityLevel::L3
            && self.scan_execution().allows_level(SecurityLevel::L3)
            && self
                .scan_execution()
                .allows_model(assets::DYNAMIC_PII_ASSET.model)
        {
            let bundle_dir = base_dir.join(assets::DYNAMIC_PII_ASSET.destination_path);
            let runtime = DynamicPiiRuntime::from_path(&bundle_dir)?;
            self.l3_worker
                .register_dynamic_pii(assets::DYNAMIC_PII_ASSET.model, runtime);
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
        }

        Ok(())
    }

    fn prepare_assets_inner(
        &self,
        allow_download: bool,
    ) -> Result<PreparedAssets, Box<dyn std::error::Error>> {
        let base_dir = self.model_base_dir()?;
        let execution = self.scan_execution();
        let mut prepared = PreparedAssets::default();

        for category in &self.categories {
            if *category == SecurityCategory::DynamicPii {
                if self.max_level < SecurityLevel::L3
                    || !execution.allows_level(SecurityLevel::L3)
                    || !execution.allows_model(assets::DYNAMIC_PII_ASSET.model)
                {
                    continue;
                }
                let bundle_dir = base_dir.join(assets::DYNAMIC_PII_ASSET.destination_path);
                if !assets::dynamic_pii_assets_present(&base_dir) {
                    if allow_download && self.should_download_assets_for(*category) {
                        assets::download_dynamic_pii_assets(&base_dir)?;
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
                continue;
            }

            let category_dir = match category {
                SecurityCategory::Injection => base_dir.join("injection"),
                SecurityCategory::SensitiveDocuments => base_dir.join("sensitive_documents"),
                SecurityCategory::ToolClassifier => base_dir.join("tool_classifier"),
                SecurityCategory::UserIntent | SecurityCategory::Dlp | SecurityCategory::Pii => {
                    continue
                }
                SecurityCategory::DynamicPii => unreachable!("handled above"),
            };
            let configs = ntdb_l2_model_configs_for_category(&execution, *category);
            if configs.is_empty() {
                continue;
            }

            for config in configs {
                let env_override = std::env::var_os(config.env_key).is_some();
                let package_dir = ntdb_l2_package_dir(config, &category_dir);
                if !env_override && !package_dir.join("manifest.json").exists() {
                    if allow_download && self.should_download_assets_for(*category) {
                        log::info!(
                            "{}/{} NTDB v2 L2 package missing; downloading package",
                            category.as_str(),
                            config.public_model
                        );
                        assets::download_ntdb_l2_package(
                            *category,
                            self.max_level,
                            config.public_model,
                            &category_dir,
                        )?;
                    } else {
                        return Err(format!(
                            "missing {} L2 package at {}; downloads disabled",
                            config.public_model,
                            package_dir.display()
                        )
                        .into());
                    }
                }

                let (spec, manifest) = validate_ntdb_l2_package(config, package_dir.clone())?;
                if allow_download && !env_override {
                    if let Err(error) =
                        assets::prepare_cached_ntdb_l2_compact_tokenizer(&manifest, &package_dir)
                    {
                        log::warn!(
                            "failed to prepare compact Granite tokenizer for cached {}/{} package: {error}; tokenizer.json remains available",
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

            if !assets::required_assets_present(*category, self.max_level, &category_dir) {
                if allow_download && self.should_download_assets_for(*category) {
                    assets::download_category_assets(*category, self.max_level, &category_dir)?;
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
        let l3_configured = execution.allows_level(SecurityLevel::L3)
            && (self.categories.iter().copied().any(|category| {
                ntdb_l2_model_configs_for_category(&execution, category)
                    .iter()
                    .any(|config| config.has_l3)
            }) || (self.categories.contains(&SecurityCategory::DynamicPii)
                && execution.allows_model(assets::DYNAMIC_PII_ASSET.model)));
        SecurityAssetReadiness {
            l2: configured_level_readiness(l2_configured),
            l3: configured_level_readiness(l3_configured),
        }
    }

    fn failed_asset_readiness(&self, failure: SecurityFailure) -> SecurityAssetReadiness {
        let configured = self.configured_asset_readiness();
        SecurityAssetReadiness {
            l2: failed_configured_level(configured.l2, failure.clone()),
            l3: failed_configured_level(configured.l3, failure),
        }
    }

    fn model_base_dir(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        match &self.model_dir {
            Some(path) => Ok(path.clone()),
            None => Ok(dirs::cache_dir()
                .ok_or("Could not resolve cache directory")?
                .join("patronus_security")),
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
            return Ok(());
        };
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
    category_dir: &Path,
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
