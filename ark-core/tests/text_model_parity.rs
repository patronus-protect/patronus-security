// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact parity of the text category models with the Python reference
//! (`scripts/l1_threat/category_model.py`): per row of
//! `testdata/model_parity.jsonl` the Rust score of the synthetic model is
//! bit-identical and the top features are the same.
use std::path::Path;

use patronus_ark_core::detectors::facts_common::model::TfidfLrModel;
use patronus_ark_core::detectors::text::{model, TextFacts, TEXT_MODEL};
use serde_json::Value;

fn testdata(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/detectors/text/testdata")
        .join(name);
    std::fs::read_to_string(path).expect("testdata")
}

#[test]
fn rust_scores_match_the_python_reference() {
    let model =
        TfidfLrModel::from_json_slice(testdata("synthetic_model.json").as_bytes(), TEXT_MODEL)
            .expect("synthetic model");
    let rows: Vec<Value> = testdata("model_parity.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parity row"))
        .collect();
    assert!(rows.len() >= 5);
    for row in &rows {
        let id = &row["id"];
        let text = row["text"].as_str().expect("text");
        let facts = TextFacts::from_json(&row["facts"]).expect("facts");
        let (score, top) = model::score(&model, text, &facts);
        let expected = row["score"].as_f64().expect("score");
        assert_eq!(
            score.to_bits(),
            expected.to_bits(),
            "{id}: {score} != {expected}"
        );
        let top: Vec<(&str, f64)> = top.iter().map(|f| (f.feature.as_str(), f.weight)).collect();
        let expected: Vec<(&str, f64)> = row["top"]
            .as_array()
            .expect("top")
            .iter()
            .map(|f| {
                let name = f["feature"].as_str().expect("feature");
                (name, f["weight"].as_f64().expect("weight"))
            })
            .collect();
        assert_eq!(top, expected, "{id}: top features");
    }
}
