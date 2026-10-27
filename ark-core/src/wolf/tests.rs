use super::assets::existing_assets;
use super::*;
use ort::{session::RunOptions, value::Tensor};
use std::fs;

#[cfg(test)]
mod published_model_tests {
    use super::*;

    /// Full raw-logit, tokenizer and multi-window references belong in tests,
    /// rather than being rerun on every production Scanner construction.
    #[test]
    #[ignore = "requires ARK_WOLF_BUNDLE pointing to the pinned local FP16 bundle"]
    fn published_fp16_matches_short_window_training_references() {
        let bundle = std::env::var_os("ARK_WOLF_BUNDLE").expect("set ARK_WOLF_BUNDLE");
        let mut config = WolfConfig::new(PathBuf::from(bundle), 0.8);
        config.precision = WolfPrecision::Fp16;
        let mut runner = WolfRunner::new(&config).unwrap();
        let mut reference: WolfManifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/wolf_published_reference.json"
        ))
        .unwrap();
        // The reference revision identifies test data, not a runtime revision requirement.
        verified_file(
            &PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").unwrap()),
            &reference.model,
        )
        .unwrap();
        verified_file(
            &PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").unwrap()),
            &reference.tokenizer,
        )
        .unwrap();
        // These archived references used 256 content tokens. Only the short
        // dynamic-window logits are profile-independent; long-document values
        // must be regenerated independently for the 254-content profile.
        reference
            .parity_cases
            .retain(|case| case.token_ids.len() <= CONTENT_TOKENS);
        reference.document_cases.clear();
        reference.content_tokens = CONTENT_TOKENS;
        reference.sequence_tokens = SEQUENCE_TOKENS;
        reference.dynamic_sequence = true;
        runner.manifest = reference;
        runner.verify_reference_cases().unwrap();
    }
    /// Independent 254-content export/tokenization oracle. This is not the
    /// archived PyTorch 256-content document contract.
    #[test]
    #[ignore = "requires ARK_WOLF_BUNDLE with local FP16 export and tokenizer.json"]
    fn published_fp16_254_profile_matches_independent_hf_ort_oracle() {
        let bundle =
            PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").expect("set ARK_WOLF_BUNDLE"));
        let manifest = existing_assets(&bundle, WolfPrecision::Fp16, None).unwrap();
        let model = bundle.join(&manifest.model.path);
        let benign = "Ordinary meeting notes about project planning. ".repeat(50);
        let row: serde_json::Value = serde_json::from_str(
            include_str!("../../tests/fixtures/injection.jsonl")
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let embedded = format!("{} {} {}", benign, row["text"].as_str().unwrap(), benign);
        let texts = [benign, embedded];
        // The oracle owns its own HF tokenization and fixed-width tensors, and
        // explicitly drops its session before creating the Core runner.
        let references = {
            let mut tokenizer =
                tokenizers::Tokenizer::from_file(bundle.join("tokenizer.json")).unwrap();
            tokenizer.with_truncation(None).unwrap();
            tokenizer.with_padding(None);
            let bos = i64::from(tokenizer.token_to_id("<bos>").unwrap());
            let eos = i64::from(tokenizer.token_to_id("<eos>").unwrap());
            let pad = i64::from(tokenizer.token_to_id("<pad>").unwrap());
            let (mut builder, _) = crate::onnx::configured_session_builder(
                crate::ExecutionBackend::Cpu,
                Some(&bundle),
                crate::OnnxRuntimeOptions::default(),
            )
            .unwrap();
            builder = builder.with_independent_thread_pool().unwrap();
            let mut session = builder.commit_from_file(&model).unwrap();
            texts
                .iter()
                .map(|text| {
                    let tokens = tokenizer
                        .encode(text.as_str(), false)
                        .unwrap()
                        .get_ids()
                        .to_vec();
                    assert!(tokens.len() > 254);
                    let mut logits = Vec::new();
                    for chunk in tokens.chunks(254) {
                        let mut ids = vec![bos];
                        ids.extend(chunk.iter().map(|&token| i64::from(token)));
                        ids.push(eos);
                        let mut mask = vec![1_i64; ids.len()];
                        ids.resize(256, pad);
                        mask.resize(256, 0);
                        let inputs = vec![
                            (
                                "input_ids",
                                Tensor::from_array(([1_usize, 256], ids)).unwrap(),
                            ),
                            (
                                "attention_mask",
                                Tensor::from_array(([1_usize, 256], mask)).unwrap(),
                            ),
                        ];
                        let outputs = session.run(inputs).unwrap();
                        let value = outputs.get("logits").unwrap();
                        let values: Vec<f64> =
                            if let Ok((_, values)) = value.try_extract_tensor::<f32>() {
                                values.iter().map(|&value| f64::from(value)).collect()
                            } else {
                                value
                                    .try_extract_tensor::<half::f16>()
                                    .unwrap()
                                    .1
                                    .iter()
                                    .map(|value| f64::from(value.to_f32()))
                                    .collect()
                            };
                        assert_eq!(values.len(), 2);
                        logits.push(values[1] - values[0]);
                    }
                    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                    let pooled = max
                        + 0.1
                            * ((logits
                                .iter()
                                .map(|value| ((value - max) / 0.1).exp())
                                .sum::<f64>())
                            .ln()
                                - (logits.len() as f64).ln());
                    (tokens, logits.len() as u64, pooled)
                })
                .collect::<Vec<_>>()
        };
        let mut config = WolfConfig::new(&bundle, 0.8);
        config.precision = WolfPrecision::Fp16;
        config.backend = crate::ExecutionBackend::Cpu;
        let mut runner = WolfRunner::new(&config).unwrap();
        for (text, (tokens, windows, reference)) in texts.iter().zip(references) {
            let mut actual_tokens = Vec::new();
            runner
                .tokenizer
                .visit_tokens(text, |token| {
                    actual_tokens.push(token.id);
                    Ok(())
                })
                .unwrap();
            assert_eq!(actual_tokens, tokens);
            let actual = runner.scan(text).unwrap();
            assert_eq!(actual.windows, windows);
            assert!(
                (actual.document_logit - reference).abs() <= 0.02 + 0.005 * reference.abs(),
                "core={} independent={reference}",
                actual.document_logit
            );
            let probability = 1.0 / (1.0 + (-reference).exp());
            assert!((actual.attack_probability - probability).abs() <= 0.005);
        }
    }

    #[test]
    #[ignore = "requires ARK_WOLF_BUNDLE with local Wolf FP16 and tokenizer.json"]
    fn existing_fp16_and_json_tokenizer_run_without_migration() {
        let source =
            PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").expect("set ARK_WOLF_BUNDLE"));
        let dir = std::env::temp_dir().join(format!("ark-existing-wolf-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let relative_model = "onnx/onnx_fp16/model_fp16.onnx";
        fs::create_dir_all(dir.join("onnx/onnx_fp16")).unwrap();
        fs::hard_link(source.join(relative_model), dir.join(relative_model)).unwrap();
        fs::hard_link(source.join("tokenizer.json"), dir.join("tokenizer.json")).unwrap();
        fs::write(
            dir.join("config.json"),
            r#"{"id2label":{"0":"benign","1":"injection"},"pad_token_id":0}"#,
        )
        .unwrap();
        fs::write(
            dir.join(".patronus-revision"),
            "142fadc5474163d4c483cb761d5a6b02e3aa1741",
        )
        .unwrap();
        let mut runner = WolfRunner::new(&WolfConfig::new(&dir, 0.8)).unwrap();
        let result = runner
            .scan("Hello, please summarize the meeting agenda.")
            .unwrap();
        assert_eq!(result.revision, "142fadc5474163d4c483cb761d5a6b02e3aa1741");
        assert!(!result.matched);
        let expected: f64 = -19.3598575592041;
        assert!((result.document_logit - expected).abs() < 0.02 + 0.005 * expected.abs());
        assert!(
            runner
                .scan(&"Ordinary meeting notes. ".repeat(400))
                .unwrap()
                .windows
                > 1
        );
        assert!(!dir.join("wolf.manifest.json").exists());
        assert!(!dir.join("tokenizer.mmbpe").exists());
        assert!(!dir.join("tokenizer.mmbpe.meta.json").exists());
        assert_eq!(
            fs::read_to_string(dir.join(".patronus-revision")).unwrap(),
            "142fadc5474163d4c483cb761d5a6b02e3aa1741"
        );
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn progress_counts_windows_and_preserves_final_smooth_max() {
        let dir = std::env::temp_dir().join(format!("ark-wolf-progress-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        fs::write(
            dir.join("model_fp16.onnx"),
            include_bytes!("../../tests/fixtures/wolf_synthetic_fp16.onnx"),
        )
        .unwrap();
        fs::write(
            dir.join("tokenizer.mmbpe"),
            include_bytes!("../../tests/fixtures/tokenizer.mmbpe"),
        )
        .unwrap();
        fs::write(dir.join("config.json"), r#"{"num_labels":1}"#).unwrap();
        let mut runner = WolfRunner::new(&WolfConfig::new(&dir, 0.8)).unwrap();
        for (tokens, windows) in [(0, 1), (254, 1), (255, 2), (509, 3)] {
            let text = " a".repeat(tokens);
            let expected = runner.scan(&text).unwrap();
            let mut updates = Vec::new();
            let actual = runner
                .scan_with_progress(&text, &mut |update| updates.push(update))
                .unwrap();
            assert_eq!(updates.len(), windows + 1);
            assert!(updates[0].document_logit.is_none());
            for (index, update) in updates.iter().enumerate() {
                assert_eq!(update.windows, index as u64);
                assert_eq!(update.total_windows, windows as u64);
            }
            assert_eq!(actual.document_logit, expected.document_logit);
            assert_eq!(actual.attack_probability, expected.attack_probability);
            assert_eq!(
                updates.last().unwrap().document_logit,
                Some(actual.document_logit)
            );
        }
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    #[test]
    fn precision_contract_matches_legacy_preference_and_explicit_choices() {
        assert_eq!(
            precision_order(WolfPrecision::Auto, false),
            &[WolfPrecision::Int8Int4, WolfPrecision::Fp16]
        );
        assert_eq!(
            precision_order(WolfPrecision::Auto, true),
            &[WolfPrecision::Fp16, WolfPrecision::Int8Int4]
        );
        assert_eq!(
            precision_order(WolfPrecision::Fp16, false),
            &[WolfPrecision::Fp16]
        );
        assert_eq!(
            precision_order(WolfPrecision::Int8Int4, true),
            &[WolfPrecision::Int8Int4]
        );
        assert_eq!(
            serde_json::from_str::<WolfPrecision>("\"int8_int4\"").unwrap(),
            WolfPrecision::Int8Int4
        );
        assert!(serde_json::from_str::<WolfPrecision>("\"unknown\"").is_err());
    }

    #[test]
    fn existing_quantized_asset_selection_does_not_require_manifest_migration() {
        let dir = std::env::temp_dir().join(format!("ark-wolf-selection-{}", std::process::id()));
        fs::create_dir_all(dir.join("onnx/int8_int4_embeddings")).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        fs::write(
            dir.join("onnx/int8_int4_embeddings/model.onnx"),
            b"selection-only fixture",
        )
        .unwrap();
        fs::write(dir.join("tokenizer.mmbpe"), b"selection-only fixture").unwrap();
        let selected = existing_assets(&dir, WolfPrecision::Int8Int4, None).unwrap();
        assert_eq!(selected.model.path, "onnx/int8_int4_embeddings/model.onnx");
        assert_eq!(selected.precision, "int8_int4");
        assert_eq!(selected.content_tokens, 254);
        assert_eq!(selected.sequence_tokens, 256);
        assert!(existing_assets(&dir, WolfPrecision::Fp16, None).is_err());
        assert_eq!(
            existing_assets(&dir, WolfPrecision::Auto, None)
                .unwrap()
                .precision,
            "int8_int4"
        );
    }

    #[test]
    fn wolf_and_legacy_tokenizer_loaders_share_the_same_arc() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let legacy = crate::ml::tokenizer::RuntimeTokenizer::load(&dir).unwrap();
        let wolf = crate::ml::tokenizer_store::global_tokenizer_store()
            .load_mmbert(dir.join("tokenizer.mmbpe"))
            .unwrap();
        assert!(Arc::ptr_eq(&legacy.0, &wolf));
    }
}

#[cfg(test)]
mod termination_tests {
    use super::*;

    #[test]
    fn registered_deadline_interrupts_an_active_ort_run() {
        let (mut builder, _) = crate::onnx::configured_session_builder(
            crate::ExecutionBackend::Cpu,
            None,
            crate::OnnxRuntimeOptions::default(),
        )
        .unwrap();
        builder = builder.with_independent_thread_pool().unwrap();
        let mut session = builder
            .commit_from_memory(include_bytes!("../../tests/fixtures/wolf_cancellable.onnx"))
            .unwrap();
        let options = Arc::new(RunOptions::new().unwrap());
        let abort_options = Arc::clone(&options);
        let control = ScanControl::with_timeout(std::time::Duration::from_millis(30)).unwrap();
        let _registration = control
            .register_abort(move || {
                let _ = abort_options.terminate();
            })
            .unwrap();
        let input = Tensor::from_array(([1_usize, 3], vec![1_i64, 400, 2])).unwrap();
        let error = match session.run_with_options(vec![("input_ids", input)], &options) {
            Err(error) => error,
            Ok(_) => panic!("ORT must acknowledge the terminate signal, not finish its loop"),
        };
        assert!(
            error.to_string().to_lowercase().contains("terminate"),
            "{error}"
        );
        assert!(matches!(control.check(), Err(ScanError::DeadlineExceeded)));
        let fresh = RunOptions::new().unwrap();
        let empty = Tensor::from_array(([1_usize, 2], vec![1_i64, 2])).unwrap();
        assert!(session
            .run_with_options(vec![("input_ids", empty)], &fresh)
            .is_ok());
    }
}
