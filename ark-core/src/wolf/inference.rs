use super::{inference, LogitOutput, WolfManifest, WolfRunner};
use crate::{ScanControl, ScanError, WolfExecutionOptions};
use ort::{
    session::{RunOptions, Session},
    value::Tensor,
};
use std::{path::Path, sync::Arc};

pub(super) fn validate_session(
    session: &Session,
    directory: &Path,
    options: WolfExecutionOptions,
    manifest: &WolfManifest,
) -> Result<Option<usize>, ScanError> {
    // The existing Small exports use ModernBERT's 8192 position table. Local
    // config.json may provide a stricter limit; no new asset is required.
    let limit = match std::fs::File::open(directory.join("config.json")) {
        Ok(file) => serde_json::from_reader::<_, serde_json::Value>(file).map_err(super::asset)?
            ["max_position_embeddings"]
            .as_u64()
            .unwrap_or(8192),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 8192,
        Err(e) => return Err(super::asset(e)),
    };
    if options.window_tokens as u64 > limit {
        return Err(ScanError::Config(format!(
            "Wolf window exceeds model position limit {limit}"
        )));
    }
    let mut fixed_width = None;
    #[cfg(not(ort_rc_10))]
    let inputs: Vec<_> = session
        .inputs()
        .iter()
        .map(|i| (i.name(), i.dtype()))
        .collect();
    #[cfg(ort_rc_10)]
    let inputs: Vec<_> = session
        .inputs
        .iter()
        .map(|i| (i.name.as_str(), &i.input_type))
        .collect();
    for (name, dtype) in inputs {
        if !matches!(name, "input_ids" | "attention_mask" | "token_type_ids") {
            return Err(inference(format!("unsupported Wolf input {name}")));
        }
        let shape = dtype
            .tensor_shape()
            .ok_or_else(|| inference("Wolf input must be a tensor"))?;
        if shape.len() != 2 || (shape[0] > 0 && (shape[0] != 1 || options.batch_size != 1)) {
            return Err(ScanError::Config("Wolf export does not support requested batch size (including partial final batches)".into()));
        }
        if shape[1] > 0 {
            let width = shape[1] as usize;
            if options.window_tokens > width
                || width as u64 > limit
                || fixed_width.is_some_and(|n| n != width)
            {
                return Err(ScanError::Config(
                    "Wolf window exceeds or conflicts with static export sequence dimensions"
                        .into(),
                ));
            }
            fixed_width = Some(width);
        }
    }
    #[cfg(not(ort_rc_10))]
    let outputs: Vec<_> = session
        .outputs()
        .iter()
        .map(|o| (o.name(), o.dtype()))
        .collect();
    #[cfg(ort_rc_10)]
    let outputs: Vec<_> = session
        .outputs
        .iter()
        .map(|o| (o.name.as_str(), &o.output_type))
        .collect();
    let (_, output) = outputs
        .into_iter()
        .find(|(name, _)| *name == manifest.output_name)
        .ok_or_else(|| inference("missing Wolf output"))?;
    let shape = output
        .tensor_shape()
        .ok_or_else(|| inference("Wolf output must be a tensor"))?;
    // Existing scalar rank-zero exports are valid for batch one only.
    if options.batch_size > 1 && (shape.is_empty() || shape[0] > 0) {
        return Err(ScanError::Config(
            "Wolf export output does not support variable batch sizes".into(),
        ));
    }
    // Preserve padding for existing opt-in fixed-sequence manifests even when
    // the graph accepts dynamic shapes.
    if !manifest.dynamic_sequence && fixed_width.is_none() {
        if options.window_tokens > manifest.sequence_tokens {
            return Err(ScanError::Config(
                "Wolf window exceeds fixed manifest sequence size".into(),
            ));
        }
        fixed_width = Some(manifest.sequence_tokens);
    }
    if let Some(width) = fixed_width {
        // Fixed padding can exceed the requested content window. Check the
        // actual tensor allocation as well as the public window configuration.
        WolfExecutionOptions {
            window_tokens: width,
            ..options
        }
        .validate()?;
    }
    Ok(fixed_width)
}

impl WolfRunner {
    pub(super) fn infer_batch(
        &mut self,
        batch: &[Vec<u32>],
        control: &ScanControl,
    ) -> Result<Vec<f64>, ScanError> {
        control.check()?;
        if batch.is_empty()
            || batch.len() > self.options.batch_size
            || batch
                .iter()
                .any(|t| t.len() > self.options.content_tokens())
        {
            return Err(inference("invalid Wolf window batch"));
        }
        let width = self
            .fixed_width
            .unwrap_or_else(|| batch.iter().map(|t| t.len() + 2).max().unwrap());
        let chunks: Vec<_> = batch.iter().map(Vec::as_slice).collect();
        let names = super::session_input_names(&self.session);
        let (mut ids, mut mask, mut types) = crate::ml::tokenizer::assemble_batch_inputs(
            &chunks,
            width,
            (
                self.tokenizer.bos(),
                self.tokenizer.eos(),
                self.manifest.pad_id,
            ),
            names.iter().any(|name| name == "attention_mask"),
            names.iter().any(|name| name == "token_type_ids"),
        )
        .map_err(inference)?;
        let mut inputs = Vec::new();
        for name in names {
            let values = match name.as_str() {
                "input_ids" => std::mem::take(&mut ids),
                "attention_mask" => std::mem::take(&mut mask),
                "token_type_ids" => std::mem::take(&mut types),
                _ => return Err(inference(format!("unsupported Wolf input {name}"))),
            };
            inputs.push((
                name,
                Tensor::from_array(([batch.len(), width], values)).map_err(inference)?,
            ));
        }
        let options = Arc::new(RunOptions::new().map_err(inference)?);
        let abort_options = Arc::clone(&options);
        let _abort = control.register_abort(move || {
            let _ = abort_options.terminate();
        })?;
        control.check()?;
        let output = self.session.run_with_options(inputs, &options);
        control.check()?;
        let outputs = output.map_err(inference)?;
        let value = outputs
            .get(&self.manifest.output_name)
            .ok_or_else(|| inference("missing Wolf output"))?;
        let (shape, values): (_, Vec<f64>) =
            if let Ok((shape, data)) = value.try_extract_tensor::<f32>() {
                (shape, data.iter().map(|&v| f64::from(v)).collect())
            } else if let Ok((shape, data)) = value.try_extract_tensor::<half::f16>() {
                (shape, data.iter().map(|v| f64::from(v.to_f32())).collect())
            } else {
                return Err(inference("Wolf output must be f32/f16 logits"));
            };
        let columns = match self.manifest.output {
            LogitOutput::Scalar => 1,
            LogitOutput::BinaryMargin => 2,
        };
        let shape_matches = (shape.first().copied() == Some(batch.len() as i64)
            && (shape.len() == 2 && shape[1] == columns as i64
                || columns == 1 && shape.len() == 1))
            || (shape.is_empty() && columns == 1 && batch.len() == 1);
        if values.len() != batch.len() * columns || !shape_matches {
            return Err(inference(
                "Wolf output shape does not match batch and output contract",
            ));
        }
        values
            .chunks_exact(columns)
            .map(|row| {
                let logit = if columns == 1 {
                    row[0]
                } else {
                    row[1] - row[0]
                };
                if row.iter().all(|v| v.is_finite()) && logit.is_finite() {
                    Ok(logit)
                } else {
                    Err(inference("non-finite Wolf logit"))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wolf::{WolfConfig, WolfPrecision};

    #[test]
    #[ignore = "requires ARK_WOLF_BUNDLE and ARK_WOLF_PRECISION=fp16 or int8_int4"]
    fn local_export_mixed_batch_rows_match_direct_ort() {
        let directory = std::path::PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").unwrap());
        let precision = match std::env::var("ARK_WOLF_PRECISION").unwrap().as_str() {
            "fp16" => WolfPrecision::Fp16,
            "int8_int4" => WolfPrecision::Int8Int4,
            _ => panic!("unknown precision"),
        };
        let mut config = WolfConfig::new(&directory, 0.8);
        config.precision = precision;
        config.backend = crate::ExecutionBackend::Cpu;
        let batch = vec![vec![400; 30], vec![1500; 9], vec![400; 23], vec![500; 1]];
        let (actual, model, bos, eos, pad) = {
            let mut runner = WolfRunner::new_with_options(
                &config,
                WolfExecutionOptions {
                    window_tokens: 32,
                    overlap_tokens: 0,
                    batch_size: 4,
                },
            )
            .unwrap();
            (
                runner.infer_batch(&batch, &ScanControl::default()).unwrap(),
                runner.model_path.clone(),
                runner.tokenizer.bos(),
                runner.tokenizer.eos(),
                runner.manifest.pad_id,
            )
        };
        // Independent tensor construction and direct ORT output decoding. No
        // Core inference/window helper participates in this reference path.
        let mut ids = vec![i64::from(pad); 4 * 32];
        let mut mask = vec![0_i64; 4 * 32];
        for (row, tokens) in batch.iter().enumerate() {
            ids[row * 32] = i64::from(bos);
            for (column, &id) in tokens.iter().enumerate() {
                ids[row * 32 + column + 1] = i64::from(id);
            }
            ids[row * 32 + tokens.len() + 1] = i64::from(eos);
            mask[row * 32..row * 32 + tokens.len() + 2].fill(1);
        }
        let (mut builder, _) = crate::onnx::configured_session_builder(
            config.backend,
            Some(&directory),
            config.runtime_options,
        )
        .unwrap();
        builder = builder.with_independent_thread_pool().unwrap();
        let mut session = builder.commit_from_file(model).unwrap();
        let output = session
            .run(vec![
                (
                    "input_ids",
                    Tensor::from_array(([4_usize, 32], ids)).unwrap(),
                ),
                (
                    "attention_mask",
                    Tensor::from_array(([4_usize, 32], mask)).unwrap(),
                ),
            ])
            .unwrap();
        let value = output.get("logits").unwrap();
        let values: Vec<f64> = if let Ok((shape, data)) = value.try_extract_tensor::<f32>() {
            assert_eq!(&shape[..], &[4, 2]);
            data.iter().map(|&v| f64::from(v)).collect()
        } else {
            let (shape, data) = value.try_extract_tensor::<half::f16>().unwrap();
            assert_eq!(&shape[..], &[4, 2]);
            data.iter().map(|v| f64::from(v.to_f32())).collect()
        };
        for (actual, row) in actual.iter().zip(values.as_chunks::<2>().0) {
            assert!((actual - (row[1] - row[0])).abs() < 1e-6);
        }
    }
}
