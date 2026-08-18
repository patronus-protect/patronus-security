// SPDX-License-Identifier: GPL-3.0-only
use serde::Deserialize;
use std::collections::HashMap;

use super::{ntdb_error, NtdbResult};

const NTDB_L2_CONTENT_TOKENS_PER_CHUNK: usize = 254;

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
    pub feature_contract: FeatureContract,
    pub runtime: RuntimeContract,
    pub heads: Vec<HeadManifest>,
    pub aggregators: Vec<AggregatorManifest>,
}

impl PackageManifest {
    pub fn normalize_runtime_defaults(&mut self) {
        let target_size = if self.minilm.is_l3_tokenizer_compatible() {
            NTDB_L2_CONTENT_TOKENS_PER_CHUNK
        } else {
            256
        };
        self.chunk_size = target_size;
        self.minilm.content_tokens_per_chunk = target_size;
    }

    pub fn validate(&self) -> NtdbResult<()> {
        if self.format != "ntdb_model_package" || self.version != 2 {
            return Err(ntdb_error(format!(
                "unsupported NTDB package format {} v{}",
                self.format, self.version
            )));
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
}

#[derive(Debug, Deserialize)]
pub struct FeatureContract {
    pub local_feature_order: Vec<String>,
    pub global_feature_order: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeContract {
    pub shared_preprocessing: Vec<String>,
    pub parallel_stages: Vec<String>,
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
