#![cfg(feature = "wolf")]
use patronus_ark_core::{
    ml::text_classifier::OnnxTextClassifier, ExecutionBackend, OnnxRuntimeOptions,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Bundle(PathBuf);
impl Bundle {
    fn new(model: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ark-classifier-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("model.onnx"), model).unwrap();
        fs::write(
            path.join("tokenizer.mmbpe"),
            include_bytes!("fixtures/tokenizer.mmbpe"),
        )
        .unwrap();
        Self(path)
    }
    fn classifier(
        &self,
        labels: Vec<String>,
    ) -> Result<Option<OnnxTextClassifier>, Box<dyn std::error::Error>> {
        OnnxTextClassifier::from_dir_with_paths(
            &self.0,
            labels,
            "fixture",
            &["model.onnx"],
            "tokenizer.json",
            256,
            ExecutionBackend::Cpu,
            OnnxRuntimeOptions::default(),
        )
    }
}
impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn eager_core_classifier_preserves_distinct_batch_rows() {
    let bundle = Bundle::new(include_bytes!("fixtures/wolf_batch_binary.onnx"));
    let labels = vec!["benign".into(), "attack".into()];
    let mut classifier = bundle.classifier(labels.clone()).unwrap().unwrap();
    let outputs = classifier
        .infer_token_ids_batch_raw(&[&[400], &[900, 400]])
        .unwrap();
    assert_eq!(outputs.len(), 2);
    for (output, expected) in outputs.iter().zip([0.0433_f32, 0.1343]) {
        assert_eq!(output.logits[0], 0.0);
        assert!((output.logits[1] - expected).abs() < 1e-6);
        assert_eq!(output.try_decode(&labels).unwrap().class_name, "attack");
    }
}

#[test]
fn invalid_class_configuration_returns_errors_instead_of_panics() {
    let bundle = Bundle::new(include_bytes!("fixtures/wolf_batch_binary.onnx"));
    assert!(bundle.classifier(vec![]).is_err());
    let mut wrong = bundle
        .classifier(vec!["first".into(), "second".into(), "third".into()])
        .unwrap()
        .unwrap();
    assert!(wrong
        .infer_token_ids_batch_raw(&[&[400], &[900, 400]])
        .is_err());
}

#[test]
fn scalar_wolf_output_is_not_treated_as_two_class_logits() {
    let bundle = Bundle::new(include_bytes!("fixtures/wolf_synthetic_fp16.onnx"));
    let mut classifier = bundle
        .classifier(vec!["benign".into(), "attack".into()])
        .unwrap()
        .unwrap();
    assert!(classifier.infer_token_ids_raw(&[400]).is_err());
}
