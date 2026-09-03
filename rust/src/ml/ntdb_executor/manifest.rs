// SPDX-License-Identifier: GPL-3.0-only
use serde::Deserialize;
use std::collections::HashMap;

use super::{ntdb_error, NtdbResult};

use crate::ml::tokenizer::CONTENT_TOKENS;

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
    pub runtime: RuntimeContract,
    #[serde(default)]
    pub joint_v3: Option<JointV3Manifest>,
}

impl PackageManifest {
    pub fn normalize_runtime_defaults(&mut self) {
        self.chunk_size = CONTENT_TOKENS;
        self.minilm.content_tokens_per_chunk = CONTENT_TOKENS;
    }

    pub fn validate(&self) -> NtdbResult<()> {
        if self.format != "ntdb_model_package" || self.version != 4 {
            return Err(ntdb_error(format!(
                "only NTDB package v4 is supported, got {} v{}",
                self.format, self.version
            )));
        }
        if !self.minilm.is_l3_tokenizer_compatible() {
            return Err(ntdb_error("NTDB v4 requires the compact mmBERT tokenizer"));
        }
        // Existing v4 exports describe 256 content tokens. Runtime preparation
        // consistently reserves the two model positions for BOS/EOS.
        if ![CONTENT_TOKENS, 256].contains(&self.chunk_size) {
            return Err(ntdb_error("unsupported NTDB v4 chunk size"));
        }
        self.validate_joint_v3()
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
}

impl MiniLmManifest {
    pub fn is_l3_tokenizer_compatible(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_exports_use_one_runtime_budget_and_v2_is_rejected() {
        let fixture = include_str!("../../../tests/fixtures/ntdb_v4.json");
        for exported in [254, 256] {
            let mut manifest = parse_package_manifest(fixture).unwrap();
            manifest.chunk_size = exported;
            manifest.minilm.content_tokens_per_chunk = exported;
            manifest.validate().unwrap();
            manifest.normalize_runtime_defaults();
            assert_eq!(manifest.chunk_size, CONTENT_TOKENS);
            assert_eq!(manifest.minilm.content_tokens_per_chunk, CONTENT_TOKENS);
            manifest.validate().unwrap();
        }
        let mut manifest = parse_package_manifest(fixture).unwrap();
        manifest.version = 2;
        assert!(manifest
            .validate()
            .unwrap_err()
            .to_string()
            .contains("only NTDB package v4"));
        manifest.version = 4;
        manifest.minilm.tokenizer_family = Some("ModernBERT".to_string());
        assert!(manifest.validate().is_err());
        manifest.minilm.tokenizer_family = Some("mmbert".to_string());
        manifest.chunk_size = 255;
        manifest.minilm.content_tokens_per_chunk = 255;
        assert!(manifest.validate().is_err());
        manifest.chunk_size = 254;
        manifest.minilm.content_tokens_per_chunk = 256;
        assert!(manifest.validate().is_err());
    }
}
