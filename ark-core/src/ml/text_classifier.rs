// SPDX-License-Identifier: MIT OR Apache-2.0
//! Synchronous mmBERT ONNX classification shared with Ark's lazy adapter.
//! Document-level Wolf scanning uses `crate::wolf::WolfRunner` instead.
use super::tokenizer::{RuntimeTokenizer, MODEL_TOKENS};
use crate::onnx::configured_session_builder;
use crate::{EvaluationResult, ExecutionBackend, OnnxRuntimeOptions};
use half::f16;
use ort::{session::Session, value::Tensor};
use std::path::{Path, PathBuf};
const DEFAULT_MAX_LEN: usize = MODEL_TOKENS;

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq)]
pub struct RawClassifierOutput {
    pub logits: Vec<f32>,
}

pub struct OnnxTextClassifier {
    tokenizer: RuntimeTokenizer,
    session: Session,
    input_names: Vec<String>,
    class_names: Vec<String>,
    max_len: usize,
    model_name: String,
    model_path: PathBuf,
    precision: String,
    execution_provider: String,
}

impl OnnxTextClassifier {
    pub fn from_dir<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        Self::from_dir_with_paths(
            dir,
            class_names,
            model_name,
            &["onnx/model_fp16.onnx", "onnx/model.onnx"],
            "tokenizer.json",
            DEFAULT_MAX_LEN,
            ExecutionBackend::Auto,
            OnnxRuntimeOptions::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_dir_with_paths<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
        onnx_candidates: &[&str],
        tokenizer_path: &str,
        max_len: usize,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        let tokenizer_file = dir.join(tokenizer_path);
        let compact_tokenizer_file = tokenizer_file.with_extension("mmbpe");
        if !tokenizer_file.exists() && !compact_tokenizer_file.exists() {
            return Ok(None);
        }

        let Some(model_path) = onnx_candidates
            .iter()
            .map(|candidate| dir.join(candidate))
            .find(|candidate| candidate.exists())
        else {
            return Ok(None);
        };

        if max_len != MODEL_TOKENS {
            return Err("classifier sequence length must be 256".into());
        }
        let tokenizer_dir = dir.join(tokenizer_path);
        let tokenizer =
            RuntimeTokenizer::load(tokenizer_dir.parent().ok_or("invalid tokenizer path")?)?;
        let (mut session_builder, execution_provider) =
            configured_session_builder(backend, Some(dir), options)?;
        let session = session_builder.commit_from_file(&model_path)?;
        let input_names = session_input_names(&session);

        Ok(Some(OnnxTextClassifier {
            tokenizer,
            session,
            input_names,
            class_names,
            max_len,
            model_name: model_name.into(),
            precision: precision_for_path(&model_path),
            model_path,
            execution_provider,
        }))
    }

    pub fn infer(&mut self, text: &str) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        let mut results = self.infer_batch(&[text.to_string()])?;
        results.pop().ok_or("ONNX batch returned no result".into())
    }

    pub fn infer_batch(
        &mut self,
        texts: &[String],
    ) -> Result<Vec<EvaluationResult>, Box<dyn std::error::Error>> {
        Ok(self
            .infer_batch_raw(texts)?
            .iter()
            .map(|output| result_from_logits(&output.logits, &self.class_names))
            .collect())
    }

    #[doc(hidden)]
    pub fn infer_token_ids_raw(
        &mut self,
        token_ids: &[u32],
    ) -> Result<RawClassifierOutput, Box<dyn std::error::Error>> {
        self.infer_token_ids_batch_raw(&[token_ids])?
            .pop()
            .ok_or_else(|| "ONNX batch returned no raw output".into())
    }

    #[doc(hidden)]
    pub fn infer_token_ids_batch_raw(
        &mut self,
        token_ids_batch: &[&[u32]],
    ) -> Result<Vec<RawClassifierOutput>, Box<dyn std::error::Error>> {
        if token_ids_batch.is_empty() {
            return Ok(Vec::new());
        }

        let batch_size = token_ids_batch.len();
        let kinds = self
            .input_names
            .iter()
            .map(|name| {
                let lower = name.to_lowercase();
                if lower.contains("attention") {
                    1
                } else if lower.contains("token_type") || lower.contains("segment") {
                    2
                } else {
                    0
                }
            })
            .collect::<Vec<_>>();
        let (ids, mask, types) =
            self.tokenizer
                .batch_inputs(token_ids_batch, kinds.contains(&1), kinds.contains(&2))?;
        let mut buffers = [ids, mask, types];

        let shape = vec![batch_size, self.max_len];
        let mut inputs = Vec::with_capacity(self.input_names.len().max(1));
        if self.input_names.is_empty() {
            inputs.push((
                "input_ids".to_string(),
                Tensor::from_array((shape.clone(), std::mem::take(&mut buffers[0])))?,
            ));
        } else {
            let mut remaining = [0usize; 3];
            for &kind in &kinds {
                remaining[kind] += 1;
            }
            for (name, kind) in self.input_names.iter().zip(kinds) {
                remaining[kind] -= 1;
                let values = if remaining[kind] == 0 {
                    std::mem::take(&mut buffers[kind])
                } else {
                    buffers[kind].clone()
                };
                inputs.push((name.clone(), Tensor::from_array((shape.clone(), values))?));
            }
        }

        let logits = {
            let outputs = self.session.run(inputs)?;
            first_logits_batch(&outputs, self.class_names.len(), batch_size)?
        };
        Ok(logits
            .into_iter()
            .map(|logits| RawClassifierOutput { logits })
            .collect())
    }

    fn infer_batch_raw(
        &mut self,
        texts: &[String],
    ) -> Result<Vec<RawClassifierOutput>, Box<dyn std::error::Error>> {
        let ids = texts
            .iter()
            .map(|text| self.tokenizer.single_chunk_ids(text))
            .collect::<Result<Vec<_>, _>>()?;
        let slices = ids.iter().map(Vec::as_slice).collect::<Vec<_>>();
        self.infer_token_ids_batch_raw(&slices)
    }

    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    pub fn precision(&self) -> &str {
        &self.precision
    }

    pub fn execution_provider(&self) -> &str {
        &self.execution_provider
    }
}

fn precision_for_path(path: &Path) -> String {
    let text = path.to_string_lossy().to_lowercase();
    if text.contains("fp16") {
        "fp16".to_string()
    } else {
        "full".to_string()
    }
}

#[cfg(ort_rc_10)]
fn session_input_names(session: &Session) -> Vec<String> {
    session
        .inputs
        .iter()
        .map(|input| input.name.clone())
        .collect()
}

#[cfg(not(ort_rc_10))]
fn session_input_names(session: &Session) -> Vec<String> {
    session
        .inputs()
        .iter()
        .map(|input| input.name().to_string())
        .collect()
}

fn first_logits_batch<'run>(
    outputs: &ort::session::SessionOutputs<'run>,
    expected_classes: usize,
    batch_size: usize,
) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
    let min_classes = expected_classes.max(2);
    let required = min_classes * batch_size;
    for (_name, value) in outputs.iter() {
        if let Ok((_shape, data)) = value.try_extract_tensor::<f32>() {
            if data.len() >= required {
                return Ok(rows_from_logits(
                    data.iter().copied(),
                    expected_classes,
                    batch_size,
                ));
            }
        }
        if let Ok((_shape, data)) = value.try_extract_tensor::<f16>() {
            if data.len() >= required {
                return Ok(rows_from_logits(
                    data.iter().map(|value| value.to_f32()),
                    expected_classes,
                    batch_size,
                ));
            }
        }
    }
    Err("ONNX model did not return f32/f16 logits".into())
}

fn rows_from_logits<I>(values: I, expected_classes: usize, batch_size: usize) -> Vec<Vec<f32>>
where
    I: IntoIterator<Item = f32>,
{
    let flat: Vec<f32> = values
        .into_iter()
        .take(batch_size * expected_classes)
        .collect();
    flat.chunks(expected_classes)
        .take(batch_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

fn result_from_logits(logits: &[f32], class_names: &[String]) -> EvaluationResult {
    let probabilities = softmax(logits);
    let (best_idx, confidence) = probabilities
        .iter()
        .copied()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .unwrap_or((0, 0.0));
    let class_name = class_names
        .get(best_idx)
        .cloned()
        .unwrap_or_else(|| best_idx.to_string());

    EvaluationResult {
        class_name,
        confidence: confidence as f64,
        level: "L3".to_string(),
    }
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|logit| (*logit - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum == 0.0 {
        return vec![0.0; logits.len()];
    }
    exps.into_iter().map(|value| value / sum).collect()
}

impl RawClassifierOutput {
    #[doc(hidden)]
    pub fn decode(&self, class_names: &[String]) -> EvaluationResult {
        result_from_logits(&self.logits, class_names)
    }
    #[doc(hidden)]
    pub fn probabilities(&self) -> Vec<f32> {
        softmax(&self.logits)
    }
}
