use std::path::PathBuf;

use patronus_security::{PatronusSecurity, SecurityCategory, SecurityLevel};

fn run_hf_e2e() -> bool {
    std::env::var("PATRONUS_RUN_HF_E2E").as_deref() == Ok("1")
}

fn model_dir() -> PathBuf {
    let dir = std::env::var("PATRONUS_HF_E2E_MODEL_DIR")
        .or_else(|_| std::env::var("PATRONUS_MODEL_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("patronus_security_standalone_bench_assets"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn assert_result_schema(results: &[patronus_security::SecurityScanResult], category: &str) {
    assert!(!results.is_empty(), "no scan results for {category}");
    for result in results {
        assert_eq!(result.category, category);
        assert!(!result.class_name.is_empty());
        assert!((0.0..=1.0).contains(&result.confidence));
        assert!(!result.level.is_empty());
        assert!(!result.model.is_empty());
        assert!(!result.layers.is_empty());

        let matched_layers: Vec<_> = result.layers.iter().filter(|layer| layer.matched).collect();
        assert_eq!(
            matched_layers.len(),
            1,
            "expected exactly one matched layer for {} / {}",
            result.category,
            result.model
        );

        let matched = matched_layers[0];
        assert_eq!(matched.level, result.level);
        assert_eq!(matched.class_name, result.class_name);
        assert_eq!(matched.confidence, result.confidence);

        for layer in &result.layers {
            assert!(!layer.level.is_empty());
            assert!(!layer.layer_type.is_empty());
            assert!(!layer.class_name.is_empty());
            assert!((0.0..=1.0).contains(&layer.confidence));
        }
    }
}

#[test]
fn hf_download_warmup_smoke_and_l3_onnx_loading() {
    if !run_hf_e2e() {
        eprintln!("skipping HF E2E; set PATRONUS_RUN_HF_E2E=1 to run");
        return;
    }

    let dir = model_dir();
    let categories = vec![
        SecurityCategory::Injection,
        SecurityCategory::ToolClassifier,
        SecurityCategory::SensitiveDocuments,
        SecurityCategory::Pii,
        SecurityCategory::Dlp,
    ];
    let mut scanner =
        PatronusSecurity::with_max_level(categories, SecurityLevel::L3, Some(dir.clone()), true);

    scanner.warmup().unwrap();

    assert!(scanner
        .injection_pipeline
        .as_ref()
        .is_some_and(|pipeline| pipeline.has_l3_model()));
    assert!(scanner
        .tool_classifier_prompts
        .as_ref()
        .is_some_and(|pipeline| pipeline.has_l3_model()));
    assert!(scanner
        .tool_classifier_executions
        .as_ref()
        .is_some_and(|pipeline| pipeline.has_l3_model()));
    assert!(scanner
        .tool_classifier_descriptions
        .as_ref()
        .is_some_and(|pipeline| pipeline.has_l3_model()));
    assert!(scanner
        .sensitive_documents_prompts
        .as_ref()
        .is_some_and(|pipeline| pipeline.has_l3_model()));

    assert!(scanner
        .injection_pipeline
        .as_ref()
        .is_some_and(|pipeline| !pipeline.is_l3_loaded()));
    assert!(scanner
        .tool_classifier_prompts
        .as_ref()
        .is_some_and(|pipeline| !pipeline.is_l3_loaded()));
    assert!(scanner
        .tool_classifier_executions
        .as_ref()
        .is_some_and(|pipeline| !pipeline.is_l3_loaded()));
    assert!(scanner
        .tool_classifier_descriptions
        .as_ref()
        .is_some_and(|pipeline| !pipeline.is_l3_loaded()));
    assert!(scanner
        .sensitive_documents_prompts
        .as_ref()
        .is_some_and(|pipeline| !pipeline.is_l3_loaded()));

    assert!(scanner
        .pii_model_pipeline
        .as_ref()
        .is_some_and(|pipeline| !pipeline.has_l3_model()));

    let smoke_text = "Please summarize this harmless onboarding note for ada@example.com.";
    for (category, name) in [
        (SecurityCategory::Injection, "injection"),
        (SecurityCategory::ToolClassifier, "tool_classifier"),
        (SecurityCategory::SensitiveDocuments, "sensitive_documents"),
        (SecurityCategory::Pii, "pii"),
        (SecurityCategory::Dlp, "dlp"),
    ] {
        let results = scanner.scan_category(category, smoke_text);
        assert_result_schema(&results, name);
    }

    let pii_results = scanner.scan_category(SecurityCategory::Pii, smoke_text);
    assert!(pii_results
        .iter()
        .flat_map(|result| result.layers.iter())
        .all(|layer| layer.level != "L3" && layer.layer_type != "onnx"));

    eprintln!("HF E2E model dir: {}", dir.display());
}
