// SPDX-License-Identifier: MIT OR Apache-2.0
use std::{path::PathBuf, process::Command};

pub fn texts() -> Vec<String> {
    let mut texts: Vec<String> = serde_json::from_str(include_str!(
        "../../tests/fixtures/tokenizer_adversarial.json"
    ))
    .expect("tokenizer adversarial fixture must be valid JSON");

    // Benchmark recipes are materialized by the repository's existing Python
    // generator; no generator implementation is copied into the Core crate.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let python = std::env::var_os("PATRONUS_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let output = Command::new(python)
        .arg(root.join("scripts/tokenizer_parity_texts.py"))
        .output()
        .expect("run the repository fixture materializer with PATRONUS_TEST_PYTHON");
    assert!(
        output.status.success(),
        "fixture materialization failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    texts.extend(
        serde_json::from_slice::<Vec<String>>(&output.stdout)
            .expect("materializer must return every benchmark text as JSON"),
    );
    texts
}

pub fn first_difference(left: &[u32], right: &[u32]) -> Option<usize> {
    left.iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .or_else(|| (left.len() != right.len()).then_some(left.len().min(right.len())))
}
