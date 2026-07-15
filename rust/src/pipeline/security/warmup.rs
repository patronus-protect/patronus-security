// SPDX-License-Identifier: AGPL-3.0-only
//! Asset verification, model downloads, and pipeline initialization.

use std::sync::Mutex;
use std::time::Instant;

use crate::{
    assets,
    ml::{
        dynamic_pii::DynamicPiiRuntime,
        ntdb_executor::{manifest::PackageManifest, NtdbExecutor},
        onnx::LazyOnnxTextClassifier,
    },
    SecurityCategory, SecurityFailure, SecurityFailureKind, SecurityFailureStage, SecurityLevel,
};

use super::ntdb_l2::{
    ntdb_l2_model_configs_for_category, ntdb_l2_package_dir, validate_ntdb_l2_package,
    NtdbL2ModelConfig,
};
use super::SecurityGateway;

impl SecurityGateway {
    pub fn warmup(&mut self) -> Result<(), SecurityFailure> {
        self.warmup_inner()
            .map_err(|error| warmup_failure(error.to_string()))
    }

    fn warmup_inner(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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
        let mut ntdb_specs = Vec::new();

        for cat in &self.categories {
            if *cat == SecurityCategory::DynamicPii {
                if self.max_level < SecurityLevel::L3
                    || !execution.allows_level(SecurityLevel::L3)
                    || !execution.allows_model(assets::DYNAMIC_PII_ASSET.model)
                {
                    log::info!("dynamic-pii is L3-only and is disabled by the current execution");
                    continue;
                }
                let bundle_dir = base_dir.join(assets::DYNAMIC_PII_ASSET.destination_path);
                if !assets::dynamic_pii_assets_present(&base_dir) {
                    if self.should_download_assets_for(*cat) {
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
                let runtime = DynamicPiiRuntime::from_path(&bundle_dir)?;
                self.l3_worker
                    .register_dynamic_pii(assets::DYNAMIC_PII_ASSET.model, runtime);
                log::info!(
                    "dynamic-pii L3 worker model registered from {}",
                    bundle_dir.display()
                );
                continue;
            }

            if *cat == SecurityCategory::Pii {
                log::info!("pii native-only; no model assets");
                continue;
            }

            let cat_dir = match cat {
                SecurityCategory::Injection => base_dir.join("injection"),
                SecurityCategory::SensitiveDocuments => base_dir.join("sensitive_documents"),
                SecurityCategory::ToolClassifier => base_dir.join("tool_classifier"),
                SecurityCategory::UserIntent => base_dir.join("user_intent"),
                SecurityCategory::Pii => unreachable!("handled above"),
                SecurityCategory::DynamicPii => unreachable!("handled above"),
                SecurityCategory::Dlp => {
                    log::info!("dlp native-only; no model assets");
                    continue;
                }
            };

            let ntdb_l2_configs = ntdb_l2_model_configs_for_category(&execution, *cat);

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
                if !env_override {
                    if let Err(err) =
                        assets::prepare_cached_ntdb_l2_compact_tokenizer(&manifest, &package_dir)
                    {
                        log::warn!(
                            "failed to prepare compact Granite tokenizer for cached {}/{} package: {err}; tokenizer.json remains available",
                            cat.as_str(),
                            config.public_model
                        );
                    }
                }
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
