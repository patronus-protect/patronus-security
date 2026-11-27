// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tool-call model against the Python scores: `TOOL_MODEL_DIR=<release>`
//! with the reference `export.py` output (`manifest.json`, `model.json`,
//! `weights.bin`, `parity.jsonl`). Skipped without the variable: the weights
//! are a release artifact, not part of the repository.

use std::path::Path;

use patronus_ark_core::detectors::tool::{Json, ToolModel};

#[test]
fn model_matches_the_python_scores() {
    let Ok(dir) = std::env::var("TOOL_MODEL_DIR") else {
        return;
    };
    let model = ToolModel::load(Path::new(&dir), None).unwrap();
    let (mut n, mut max_d, mut decisions) = (0, 0f32, 0);
    for line in std::fs::read_to_string(Path::new(&dir).join("parity.jsonl"))
        .unwrap()
        .lines()
    {
        let r = Json::parse(line).unwrap();
        let py: Vec<f32> = match r.get("scores") {
            Some(Json::Array(a)) => a
                .iter()
                .map(|v| v.to_value().as_f64().unwrap() as f32)
                .collect(),
            _ => panic!("no scores"),
        };
        let z = model.raw_scores(r.get("item").unwrap());
        max_d = z
            .iter()
            .zip(&py)
            .map(|(a, b)| (a - b).abs())
            .fold(max_d, f32::max);
        decisions += usize::from(model.decide(&z).labels != model.decide(&py).labels);
        n += 1;
    }
    eprintln!("items {n}: max |p_rust - p_python| {max_d:.2e}, label sets differ {decisions}");
    assert!(n > 1000 && decisions == 0 && max_d < 1e-3);
}
