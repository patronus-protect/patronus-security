use crate::EvaluationResult;
use half::f16;
use ort::{session::Session, value::Tensor};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokenizers::Tokenizer;

const DEFAULT_MAX_LEN: usize = 128;
const DEFAULT_L3_TTL_SECS: u64 = 300;

pub struct LazyOnnxTextClassifier {
    dir: PathBuf,
    class_names: Vec<String>,
    model_name: String,
    onnx_candidates: Vec<String>,
    tokenizer_path: String,
    max_len: usize,
    ttl: Duration,
    loaded: Option<OnnxTextClassifier>,
    last_used: Option<Instant>,
}

impl LazyOnnxTextClassifier {
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
        )
    }

    pub fn from_dir_with_paths<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
        onnx_candidates: &[&str],
        tokenizer_path: &str,
        max_len: usize,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        let tokenizer_file = dir.join(tokenizer_path);
        if !tokenizer_file.exists() {
            return Ok(None);
        }

        let has_model = onnx_candidates
            .iter()
            .map(|candidate| dir.join(candidate))
            .any(|candidate| candidate.exists());
        if !has_model {
            return Ok(None);
        }

        Ok(Some(LazyOnnxTextClassifier {
            dir: dir.to_path_buf(),
            class_names,
            model_name: model_name.into(),
            onnx_candidates: onnx_candidates
                .iter()
                .map(|candidate| candidate.to_string())
                .collect(),
            tokenizer_path: tokenizer_path.to_string(),
            max_len,
            ttl: l3_ttl(),
            loaded: None,
            last_used: None,
        }))
    }

    pub fn infer(&mut self, text: &str) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded()?;
        let model = self.loaded.as_mut().ok_or("L3 ONNX model is not loaded")?;
        let result = model.infer(text)?;
        self.last_used = Some(Instant::now());
        Ok(result)
    }

    pub fn model_name(&self) -> &str {
        self.loaded
            .as_ref()
            .map(|model| model.model_name())
            .unwrap_or(&self.model_name)
    }

    pub fn model_path(&self) -> Option<&Path> {
        self.loaded.as_ref().map(|model| model.model_path())
    }

    pub fn precision(&self) -> Option<&str> {
        self.loaded.as_ref().map(|model| model.precision())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.is_some()
    }

    pub fn evict_expired(&mut self) {
        if self
            .last_used
            .is_some_and(|last_used| last_used.elapsed() > self.ttl)
        {
            self.loaded = None;
            self.last_used = None;
        }
    }

    fn ensure_loaded(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.loaded.is_some() {
            return Ok(());
        }

        let candidates: Vec<&str> = self
            .onnx_candidates
            .iter()
            .map(|candidate| candidate.as_str())
            .collect();
        let Some(model) = OnnxTextClassifier::from_dir_with_paths(
            &self.dir,
            self.class_names.clone(),
            self.model_name.clone(),
            &candidates,
            &self.tokenizer_path,
            self.max_len,
        )?
        else {
            return Err("L3 ONNX assets are no longer available".into());
        };
        self.loaded = Some(model);
        Ok(())
    }
}

pub struct OnnxTextClassifier {
    tokenizer: Tokenizer,
    session: Session,
    input_names: Vec<String>,
    class_names: Vec<String>,
    max_len: usize,
    model_name: String,
    model_path: PathBuf,
    precision: String,
}

fn l3_ttl() -> Duration {
    let secs = std::env::var("PATRONUS_L3_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_L3_TTL_SECS);
    Duration::from_secs(secs)
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
        )
    }

    pub fn from_dir_with_paths<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
        onnx_candidates: &[&str],
        tokenizer_path: &str,
        max_len: usize,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        let tokenizer_file = dir.join(tokenizer_path);
        if !tokenizer_file.exists() {
            return Ok(None);
        }

        let Some(model_path) = onnx_candidates
            .iter()
            .map(|candidate| dir.join(candidate))
            .find(|candidate| candidate.exists())
        else {
            return Ok(None);
        };

        let tokenizer = Tokenizer::from_file(&tokenizer_file)
            .map_err(|err| format!("failed to load tokenizer {:?}: {}", tokenizer_file, err))?;
        let session = Session::builder()?.commit_from_file(&model_path)?;
        let input_names = session
            .inputs()
            .iter()
            .map(|input| input.name().to_string())
            .collect();

        Ok(Some(OnnxTextClassifier {
            tokenizer,
            session,
            input_names,
            class_names,
            max_len,
            model_name: model_name.into(),
            precision: precision_for_path(&model_path),
            model_path,
        }))
    }

    pub fn infer(&mut self, text: &str) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|err| format!("failed to tokenize input: {}", err))?;

        let mut input_ids: Vec<i64> = encoding.get_ids().iter().map(|id| *id as i64).collect();
        let mut attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|mask| *mask as i64)
            .collect();
        truncate_and_pad(&mut input_ids, self.max_len, 0);
        truncate_and_pad(&mut attention_mask, self.max_len, 0);
        let token_type_ids = vec![0_i64; self.max_len];

        let shape = vec![1_usize, self.max_len];
        let mut inputs = Vec::with_capacity(self.input_names.len().max(1));
        if self.input_names.is_empty() {
            inputs.push((
                "input_ids".to_string(),
                Tensor::from_array((shape.clone(), input_ids.clone()))?,
            ));
        } else {
            for name in &self.input_names {
                let lower = name.to_lowercase();
                let values = if lower.contains("attention") {
                    attention_mask.clone()
                } else if lower.contains("token_type")
                    || lower.contains("token_type_ids")
                    || lower.contains("segment")
                {
                    token_type_ids.clone()
                } else {
                    input_ids.clone()
                };
                inputs.push((name.clone(), Tensor::from_array((shape.clone(), values))?));
            }
        }

        let outputs = self.session.run(inputs)?;
        let logits = first_logits(&outputs, self.class_names.len())?;
        let probabilities = softmax(&logits);
        let (best_idx, confidence) = probabilities
            .iter()
            .copied()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .ok_or("ONNX model returned empty logits")?;
        let class_name = self
            .class_names
            .get(best_idx)
            .cloned()
            .unwrap_or_else(|| best_idx.to_string());

        Ok(EvaluationResult {
            class_name,
            confidence: confidence as f64,
            level: "L3".to_string(),
        })
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
}

fn precision_for_path(path: &Path) -> String {
    let text = path.to_string_lossy().to_lowercase();
    if text.contains("fp16") {
        "fp16".to_string()
    } else {
        "full".to_string()
    }
}

fn truncate_and_pad(values: &mut Vec<i64>, max_len: usize, pad: i64) {
    values.truncate(max_len);
    if values.len() < max_len {
        values.resize(max_len, pad);
    }
}

fn first_logits<'run>(
    outputs: &ort::session::SessionOutputs<'run>,
    expected_classes: usize,
) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
    let min_classes = expected_classes.max(2);
    for (_name, value) in outputs.iter() {
        if let Ok((_shape, data)) = value.try_extract_tensor::<f32>() {
            if data.len() >= min_classes {
                return Ok(data.iter().take(expected_classes).copied().collect());
            }
        }
        if let Ok((_shape, data)) = value.try_extract_tensor::<f16>() {
            if data.len() >= min_classes {
                return Ok(data
                    .iter()
                    .take(expected_classes)
                    .map(|value| value.to_f32())
                    .collect());
            }
        }
    }
    Err("ONNX model did not return f32/f16 logits".into())
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
