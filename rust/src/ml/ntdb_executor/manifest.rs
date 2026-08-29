// SPDX-License-Identifier: GPL-3.0-only
use serde::Deserialize;
use std::collections::HashMap;

use super::{ntdb_error, NtdbResult};

const NTDB_L2_CONTENT_TOKENS_PER_CHUNK: usize = 254;

pub fn parse_package_manifest(json: &str) -> serde_json::Result<PackageManifest> {
    serde_json::from_str(
        &json
            .replace(": Infinity", ": null")
            .replace(": -Infinity", ": null")
            .replace(": NaN", ": null"),
    )
}

#[derive(Debug, Deserialize)]
pub struct PackageManifest {
    pub format: String,
    pub version: u32,
    pub runtime_contract: String,
    pub name: Option<String>,
    pub task: TaskManifest,
    pub chunk_size: usize,
    pub tokenizer_dir: String,
    pub minilm: MiniLmManifest,
    #[serde(default)]
    pub feature_contract: FeatureContract,
    pub runtime: RuntimeContract,
    #[serde(default)]
    pub heads: Vec<HeadManifest>,
    #[serde(default)]
    pub aggregators: Vec<AggregatorManifest>,
    #[serde(default)]
    pub joint_v3: Option<JointV3Manifest>,
}

impl PackageManifest {
    pub fn normalize_runtime_defaults(&mut self) {
        if self.version == 4 {
            return;
        }
        let target_size = if self.minilm.is_l3_tokenizer_compatible() {
            NTDB_L2_CONTENT_TOKENS_PER_CHUNK
        } else {
            256
        };
        self.chunk_size = target_size;
        self.minilm.content_tokens_per_chunk = target_size;
    }

    pub fn validate(&self) -> NtdbResult<()> {
        if self.format != "ntdb_model_package" || !matches!(self.version, 2 | 4) {
            return Err(ntdb_error(format!(
                "unsupported NTDB package format {} v{}",
                self.format, self.version
            )));
        }
        if self.version == 4 {
            return self.validate_joint_v3();
        }
        if self.heads.is_empty() {
            return Err(ntdb_error("NTDB package must contain at least one head"));
        }
        if self.aggregators.is_empty() {
            return Err(ntdb_error(
                "NTDB package must contain at least one aggregator",
            ));
        }
        if self.task.labels.is_empty() {
            return Err(ntdb_error("NTDB package task labels must not be empty"));
        }
        if self.chunk_size != self.minilm.content_tokens_per_chunk {
            return Err(ntdb_error(format!(
                "NTDB chunk_size mismatch: manifest {} vs minilm {}",
                self.chunk_size, self.minilm.content_tokens_per_chunk
            )));
        }
        if !self
            .runtime
            .shared_preprocessing
            .iter()
            .any(|stage| stage == "tokenization")
        {
            return Err(ntdb_error("NTDB package must declare shared tokenization"));
        }
        Ok(())
    }

    fn validate_joint_v3(&self) -> NtdbResult<()> {
        let joint = self
            .joint_v3
            .as_ref()
            .ok_or_else(|| ntdb_error("NTDB package v4 is missing joint_v3"))?;
        if self.runtime_contract != "raw_text_to_joint_v3_chunk_promoter_union_v1" {
            return Err(ntdb_error(format!(
                "unsupported NTDB package v4 runtime contract: {}",
                self.runtime_contract
            )));
        }
        if self.task.labels.is_empty() {
            return Err(ntdb_error("NTDB package task labels must not be empty"));
        }
        if self.chunk_size != self.minilm.content_tokens_per_chunk {
            return Err(ntdb_error(format!(
                "NTDB chunk_size mismatch: manifest {} vs encoder {}",
                self.chunk_size, self.minilm.content_tokens_per_chunk
            )));
        }
        if !self
            .runtime
            .shared_preprocessing
            .iter()
            .any(|stage| stage == "tokenization")
        {
            return Err(ntdb_error("NTDB package must declare shared tokenization"));
        }
        if joint.heads.is_empty()
            || joint.neural_stack.head_order.len() != joint.heads.len()
            || joint.neural_stack.head_order.len() != joint.neural_stack.head_class_counts.len()
        {
            return Err(ntdb_error(
                "NTDB package v4 neural head order does not match its heads",
            ));
        }
        if joint.neural_stack.promoter_feature_dim != joint.promoter.feature_dim {
            return Err(ntdb_error(
                "NTDB package v4 promoter feature dimensions are inconsistent",
            ));
        }
        if joint.document_decision.score != "best_non_default_class_score_minus_default_class_score"
            || joint.document_decision.comparison != ">= threshold means non-default risk class"
            || joint.document_decision.default_mode != "union_l2_l3"
        {
            return Err(ntdb_error(
                "NTDB package v4 document decision contract is unsupported",
            ));
        }
        for mode in ["l2_only", "l3_only", "union_l2_l3"] {
            if !joint.document_decision.modes.contains_key(mode) {
                return Err(ntdb_error(format!(
                    "NTDB package v4 is missing document mode {mode}"
                )));
            }
        }
        for head_id in &joint.neural_stack.head_order {
            if !joint.heads.iter().any(|head| &head.id == head_id) {
                return Err(ntdb_error(format!(
                    "NTDB package v4 neural stack references missing head {head_id}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct MiniLmManifest {
    pub embedding_matrix_file: String,
    pub vocab_size: usize,
    pub embedding_dim: usize,
    pub content_tokens_per_chunk: usize,
    pub source_model_path: Option<String>,
    pub model: Option<String>,
    pub tokenizer_family: Option<String>,
    #[serde(alias = "compat_l3_tokenizer")]
    pub compab_l3_tokenizer: Option<bool>,
}

impl MiniLmManifest {
    pub fn is_l3_tokenizer_compatible(&self) -> bool {
        if let Some(compat) = self.compab_l3_tokenizer {
            return compat;
        }
        self.tokenizer_family
            .as_deref()
            .is_some_and(|family| family.eq_ignore_ascii_case("mmbert"))
    }

    pub fn shared_embedder_identity(&self) -> Option<&str> {
        self.model
            .as_deref()
            .or(self.source_model_path.as_deref())
            .filter(|identity| !identity.trim().is_empty())
    }
}

#[derive(Debug, Deserialize)]
pub struct TaskManifest {
    #[serde(rename = "type")]
    pub kind: String,
    pub labels: Vec<String>,
    #[serde(default)]
    pub no_risk_class: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct FeatureContract {
    pub local_feature_order: Vec<String>,
    pub global_feature_order: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct JointV3Manifest {
    pub neural_stack: JointV3NeuralStackManifest,
    pub heads: Vec<JointV3HeadManifest>,
    pub promoter: JointV3PromoterManifest,
    pub document_decision: JointV3DocumentDecisionManifest,
}

#[derive(Debug, Deserialize)]
pub struct JointV3NeuralStackManifest {
    pub onnx: String,
    pub input_names: Vec<String>,
    pub head_order: Vec<String>,
    pub head_class_counts: Vec<usize>,
    pub promoter_feature_dim: usize,
}

#[derive(Debug, Deserialize)]
pub struct JointV3HeadManifest {
    pub id: String,
    pub frozen_lightgbm: String,
}

#[derive(Debug, Deserialize)]
pub struct JointV3PromoterManifest {
    pub scope: String,
    pub implementation: String,
    pub feature_dim: usize,
    pub models: HashMap<String, serde_json::Value>,
    pub operating_points: HashMap<String, JointV3PromoterOperatingPoint>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JointV3PromoterOperatingPoint {
    pub gate: String,
    #[serde(alias = "promoter_threshold")]
    pub promote_threshold: f32,
    pub aggregation: String,
    pub document_risk_margin_threshold: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JointV3DocumentDecisionManifest {
    pub score: String,
    pub comparison: String,
    pub default_mode: String,
    pub default_operating_point: String,
    pub modes: HashMap<String, JointV3DocumentModeManifest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JointV3DocumentModeManifest {
    pub aggregation: String,
    pub operating_points: HashMap<String, JointV3DocumentOperatingPointManifest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JointV3DocumentOperatingPointManifest {
    #[serde(alias = "document_risk_margin_threshold")]
    pub threshold: f32,
}

#[derive(Debug, Deserialize)]
pub struct JointV3GateManifest {
    pub lightgbm_model: Option<String>,
    pub metadata: String,
    pub n_features: usize,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeContract {
    #[serde(default)]
    pub shared_preprocessing: Vec<String>,
    #[serde(default)]
    pub parallel_stages: Vec<String>,
    #[serde(default)]
    pub ordering: String,
}

#[derive(Debug, Deserialize)]
pub struct HeadManifest {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub task: TaskManifest,
    pub classifiers: Vec<serde_json::Value>,
    pub feature_order: Vec<String>,
    pub static_dir: String,
    pub static_components: Vec<StaticComponentManifest>,
    pub projection_onnx: Option<String>,
    pub ntdb_head_onnx: String,
    pub model_type: String,
    pub reliability: ReliabilityManifest,
}

#[derive(Debug, Deserialize)]
pub struct StaticComponentManifest {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    pub labels: Option<Vec<String>>,
    pub input_names: Option<Vec<String>>,
    pub output_names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AggregatorManifest {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub task: TaskManifest,
    pub onnx: String,
    pub model_type: String,
    pub input_feature_order: Vec<String>,
    pub global_feature_order: Vec<String>,
    pub reliability: ReliabilityManifest,
    pub metric_sweep: Option<MetricSweepManifest>,
    pub promote_router: Option<PromoteRouterManifest>,
}

#[derive(Debug, Deserialize)]
pub struct PromoteRouterManifest {
    #[serde(rename = "type")]
    pub kind: String,
    pub onnx: String,
    pub model_type: String,
    pub input_feature_order: Vec<String>,
    pub global_feature_order: Vec<String>,
    pub reliability: ReliabilityManifest,
    pub metric_sweep: Option<MetricSweepManifest>,
}

#[derive(Debug, Deserialize)]
pub struct ReliabilityManifest {
    pub enabled: bool,
    pub hidden_dim: usize,
    pub execution: String,
}

#[derive(Debug, Deserialize)]
pub struct MetricSweepManifest {
    pub source: String,
    pub f1_window: Option<f32>,
    pub points: HashMap<String, OperatingPointManifest>,
    #[serde(default, skip_deserializing)]
    pub sweep: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct OperatingPointManifest {
    pub threshold: Option<f32>,
    pub metrics: serde_json::Value,
    pub attack_threshold: Option<f32>,
    pub promote_threshold: Option<f32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntdb_l2_manifests_use_canonical_256_token_chunks_at_runtime() {
        let mut manifest: PackageManifest = serde_json::from_str(
            r#"{
                "format": "ntdb_model_package",
                "version": 2,
                "runtime_contract": "raw_text_to_ntdb_outputs",
                "task": {"type": "binary", "labels": ["benign", "attack"]},
                "chunk_size": 384,
                "tokenizer_dir": "tokenizer",
                "minilm": {
                    "embedding_matrix_file": "embedding_matrix.f16",
                    "vocab_size": 180000,
                    "embedding_dim": 384,
                    "content_tokens_per_chunk": 384,
                    "source_model_path": "ntdb/artifacts/granite_embedding_97m_multilingual_r2",
                    "model": "ibm-granite/granite-embedding-97m-multilingual-r2",
                    "tokenizer_family": "ModernBERT"
                },
                "feature_contract": {
                    "local_feature_order": [],
                    "global_feature_order": []
                },
                "runtime": {
                    "shared_preprocessing": ["tokenization"],
                    "parallel_stages": [],
                    "ordering": "manifest_order"
                },
                "heads": [{
                    "id": "h",
                    "type": "binary",
                    "task": {"type": "binary", "labels": ["benign", "attack"]},
                    "classifiers": [],
                    "feature_order": [],
                    "static_dir": "heads/h",
                    "static_components": [],
                    "projection_onnx": null,
                    "ntdb_head_onnx": "heads/h/ntdb_head.onnx",
                    "model_type": "sequential_ntdb",
                    "reliability": {
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    }
                }],
                "aggregators": [{
                    "id": "a",
                    "type": "binary",
                    "task": {"type": "binary", "labels": ["benign", "attack"]},
                    "onnx": "aggregators/a.onnx",
                    "model_type": "sequential_ntdb",
                    "input_feature_order": [],
                    "global_feature_order": [],
                    "reliability": {
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    },
                    "metric_sweep": null,
                    "promote_router": null
                }]
            }"#,
        )
        .unwrap();

        manifest.normalize_runtime_defaults();

        assert_eq!(manifest.chunk_size, 256);
        assert_eq!(manifest.minilm.content_tokens_per_chunk, 256);
        manifest.validate().unwrap();
    }

    #[test]
    fn runtime_normalization_overrides_declared_chunk_size() {
        let mut manifest: PackageManifest = serde_json::from_str(
            r#"{
                "format": "ntdb_model_package",
                "version": 2,
                "runtime_contract": "raw_text_to_ntdb_outputs",
                "task": {"type": "binary", "labels": ["benign", "attack"]},
                "chunk_size": 2,
                "tokenizer_dir": "tokenizer",
                "minilm": {
                    "embedding_matrix_file": "embedding_matrix.f16",
                    "vocab_size": 1,
                    "embedding_dim": 1,
                    "content_tokens_per_chunk": 2,
                    "source_model_path": "test-embedder",
                    "model": null,
                    "tokenizer_family": null
                },
                "feature_contract": {
                    "local_feature_order": [],
                    "global_feature_order": []
                },
                "runtime": {
                    "shared_preprocessing": ["tokenization"],
                    "parallel_stages": [],
                    "ordering": "manifest_order"
                },
                "heads": [{
                    "id": "h",
                    "type": "binary",
                    "task": {"type": "binary", "labels": ["benign", "attack"]},
                    "classifiers": [],
                    "feature_order": [],
                    "static_dir": "heads/h",
                    "static_components": [],
                    "projection_onnx": null,
                    "ntdb_head_onnx": "heads/h/ntdb_head.onnx",
                    "model_type": "sequential_ntdb",
                    "reliability": {
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    }
                }],
                "aggregators": [{
                    "id": "a",
                    "type": "binary",
                    "task": {"type": "binary", "labels": ["benign", "attack"]},
                    "onnx": "aggregators/a.onnx",
                    "model_type": "sequential_ntdb",
                    "input_feature_order": [],
                    "global_feature_order": [],
                    "reliability": {
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    },
                    "metric_sweep": null,
                    "promote_router": null
                }]
            }"#,
        )
        .unwrap();

        manifest.normalize_runtime_defaults();

        assert_eq!(manifest.chunk_size, 256);
        assert_eq!(manifest.minilm.content_tokens_per_chunk, 256);
        manifest.validate().unwrap();
    }

    #[test]
    fn mmbert_manifest_normalizes_to_254_content_tokens_at_runtime() {
        let mut manifest: PackageManifest = serde_json::from_str(
            r#"{
                "format": "ntdb_model_package",
                "version": 2,
                "runtime_contract": "raw_text_to_ntdb_outputs",
                "task": {"type": "binary", "labels": ["benign", "attack"]},
                "chunk_size": 256,
                "tokenizer_dir": "tokenizer",
                "minilm": {
                    "embedding_matrix_file": "embedding_matrix.f16",
                    "vocab_size": 100,
                    "embedding_dim": 64,
                    "content_tokens_per_chunk": 256,
                    "source_model_path": "test-embedder",
                    "model": null,
                    "tokenizer_family": "mmbert"
                },
                "feature_contract": {
                    "local_feature_order": [],
                    "global_feature_order": []
                },
                "runtime": {
                    "shared_preprocessing": ["tokenization"],
                    "parallel_stages": [],
                    "ordering": "manifest_order"
                },
                "heads": [{
                    "id": "h",
                    "type": "binary",
                    "task": {"type": "binary", "labels": ["benign", "attack"]},
                    "classifiers": [],
                    "feature_order": [],
                    "static_dir": "heads/h",
                    "static_components": [],
                    "projection_onnx": null,
                    "ntdb_head_onnx": "heads/h/ntdb_head.onnx",
                    "model_type": "sequential_ntdb",
                    "reliability": {
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    }
                }],
                "aggregators": [{
                    "id": "a",
                    "type": "binary",
                    "task": {"type": "binary", "labels": ["benign", "attack"]},
                    "onnx": "aggregators/a.onnx",
                    "model_type": "sequential_ntdb",
                    "input_feature_order": [],
                    "global_feature_order": [],
                    "reliability": {
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    },
                    "metric_sweep": null,
                    "promote_router": null
                }]
            }"#,
        )
        .unwrap();

        manifest.normalize_runtime_defaults();

        assert_eq!(manifest.chunk_size, 254);
        assert_eq!(manifest.minilm.content_tokens_per_chunk, 254);
        manifest.validate().unwrap();
    }
}
