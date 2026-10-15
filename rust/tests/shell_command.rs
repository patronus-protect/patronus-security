use std::path::{Path, PathBuf};

use patronus_ark::{
    assets::SHELL_COMMAND_ASSET,
    detectors::shell::shell_risk::{ShellRiskModel, ShellRiskPipeline},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityLevelReadiness,
};

const SCORE_TOLERANCE: f64 = 1e-5;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn parity_cases() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(fixture("shell_command_parity.json")).unwrap()).unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("patronus_shell_command_{name}_{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Write the synthetic model as a revision-pinned bundle in a model cache.
fn synthetic_bundle(model_dir: &Path, manifest_sha: Option<&str>) {
    let bundle = model_dir.join(SHELL_COMMAND_ASSET.destination_path);
    std::fs::create_dir_all(&bundle).unwrap();
    let model = std::fs::read(fixture("shell_command_synthetic_model.json")).unwrap();
    let sha = manifest_sha.map_or_else(|| sha256_hex(&model), str::to_string);
    std::fs::write(bundle.join("model.json"), &model).unwrap();
    std::fs::write(
        bundle.join("manifest.json"),
        serde_json::json!({"files": {"model.json": {"sha256": sha}}}).to_string(),
    )
    .unwrap();
    std::fs::write(bundle.join("LICENSE"), "Apache-2.0").unwrap();
    std::fs::write(
        bundle.join(".patronus-revision"),
        SHELL_COMMAND_ASSET.revision,
    )
    .unwrap();
}

fn assert_parity(model: &ShellRiskModel, key: &str) {
    let fixture = parity_cases();
    let mut max_error = 0.0_f64;
    for case in fixture["cases"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let expected = case[key].as_f64().unwrap();
        let actual = model.decision_score(text);
        let error = (actual - expected).abs();
        max_error = max_error.max(error);
        assert!(
            error < SCORE_TOLERANCE,
            "{key} mismatch for {text:?}: rust={actual} sklearn={expected}"
        );
    }
    eprintln!("{key}: max absolute score error {max_error:e}");
}

#[test]
fn synthetic_model_matches_scikit_learn() {
    let model = ShellRiskModel::from_json_slice(
        &std::fs::read(fixture("shell_command_synthetic_model.json")).unwrap(),
    )
    .unwrap();
    assert_parity(&model, "synthetic_score");
}

/// Runs against the published model when its bundle is cached locally, for
/// example after `PATRONUS_RUN_HF_E2E=1 cargo test --test hf_e2e`.
#[test]
fn published_model_matches_scikit_learn_when_cached() {
    let bundle = std::env::var("PATRONUS_SHELL_COMMAND_MODEL_DIR")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            dirs::cache_dir().map(|dir| {
                dir.join("patronus_ark")
                    .join(SHELL_COMMAND_ASSET.destination_path)
            })
        })
        .filter(|dir| dir.join("model.json").is_file());
    let Some(bundle) = bundle else {
        eprintln!("skipping published shell_command parity; set PATRONUS_SHELL_COMMAND_MODEL_DIR");
        return;
    };
    let expected_sha = parity_cases()["published_model"]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        sha256_hex(&std::fs::read(bundle.join("model.json")).unwrap()),
        expected_sha,
        "cached model.json is not the revision the parity fixture was generated from"
    );
    let model = ShellRiskModel::from_bundle_dir(&bundle).unwrap();
    assert_parity(&model, "published_score");

    // The published default policy flags the documented comment-padding bypass.
    let pipeline = ShellRiskPipeline::new(model);
    let padded = format!("rm -rf / # {}", "padding ".repeat(2048));
    let score = pipeline.score(&padded);
    assert!(score.full_score <= score.threshold, "{score:?}");
    assert!(score.flagged, "{score:?}");
    assert_eq!(score.variant, "comments_stripped");
}

#[test]
fn shell_command_category_parses_both_spellings() {
    for name in ["shell_command", "shell-command", "SHELL_COMMAND"] {
        assert_eq!(
            name.parse::<SecurityCategory>().unwrap(),
            SecurityCategory::ShellCommand
        );
    }
    assert_eq!(SecurityCategory::ShellCommand.as_str(), "shell_command");
}

#[test]
fn gateway_scans_commands_from_a_local_bundle() {
    let model_dir = temp_dir("gateway");
    synthetic_bundle(&model_dir, None);
    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::ShellCommand],
        SecurityLevel::L1,
        Some(model_dir.clone()),
        false,
    );
    assert!(matches!(
        gateway.runtime_readiness().l1,
        SecurityLevelReadiness::NotReady { .. }
    ));
    gateway.warmup().unwrap();
    assert_eq!(
        gateway.runtime_readiness().l1,
        SecurityLevelReadiness::Ready
    );

    let pipeline =
        ShellRiskPipeline::from_bundle_dir(&model_dir.join(SHELL_COMMAND_ASSET.destination_path))
            .unwrap();
    for case in parity_cases()["cases"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        if text.trim().is_empty() {
            continue;
        }
        let results = gateway.scan_categories(&[SecurityCategory::ShellCommand], text);
        assert_eq!(results.len(), 1, "{text:?}");
        let result = &results[0];
        assert_eq!(result.category, "shell_command");
        assert_eq!(result.model, SHELL_COMMAND_ASSET.model);
        assert_eq!(result.level, "L1");
        let score = pipeline.score(text);
        let expected = if score.flagged { "shell_risk" } else { "safe" };
        assert_eq!(result.class_name, expected, "{text:?}");
        let details = &result.layers[0].details;
        assert_eq!(details["decision_score"], score.decision_score);
        assert_eq!(details["threshold_policy"], "synthetic_default");
        assert_eq!(result.evidence_spans.is_empty(), !score.flagged, "{text:?}");
        for span in &result.evidence_spans {
            assert_eq!(&text[span.start_byte..span.end_byte], span.text);
        }
    }
    std::fs::remove_dir_all(model_dir).ok();
}

#[test]
fn warmup_rejects_a_model_that_does_not_match_its_manifest() {
    let model_dir = temp_dir("tampered");
    synthetic_bundle(&model_dir, Some(&"0".repeat(64)));
    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::ShellCommand],
        SecurityLevel::L1,
        Some(model_dir.clone()),
        false,
    );
    let error = gateway.warmup().unwrap_err();
    assert!(
        error.message.contains("does not match manifest"),
        "{error:?}"
    );
    std::fs::remove_dir_all(model_dir).ok();
}

#[test]
fn warmup_without_assets_and_downloads_disabled_fails() {
    let model_dir = temp_dir("missing");
    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::ShellCommand],
        SecurityLevel::L1,
        Some(model_dir.clone()),
        false,
    );
    let error = gateway.warmup().unwrap_err();
    assert!(
        error.message.contains("missing shell_command assets"),
        "{error:?}"
    );
    std::fs::remove_dir_all(model_dir).ok();
}
