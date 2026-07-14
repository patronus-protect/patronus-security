// SPDX-License-Identifier: AGPL-3.0-only
use serde::Deserialize;
use std::collections::HashMap;

use super::{ntdb_error, NtdbResult};

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
    pub compab_l3_tokenizer: Option<bool>,
}

impl MiniLmManifest {
    pub fn shared_embedder_identity(&self) -> Option<&str> {
        self.source_model_path
            .as_deref()
            .or(self.model.as_deref())
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
