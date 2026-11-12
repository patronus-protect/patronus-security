// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact parity of `patronus.text_facts/1` with the Python reference
//! (`scripts/l1_threat/text_facts.py`): per row of `testdata/parity.jsonl` the
//! Rust facts, their canonical JSON and the sorted `tf1` tokens.
use std::ops::Range;
use std::path::Path;

use patronus_ark_core::detectors::text::{extract, visit_tf1, DataRef, Finding, TextFacts};
use serde_json::Value;

fn rows() -> Vec<Value> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/detectors/text/testdata/parity.jsonl");
    std::fs::read_to_string(path)
        .expect("parity goldens")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parity row"))
        .collect()
}

fn span(value: &Value) -> Range<usize> {
    let at = |i: usize| value[i].as_u64().expect("offset") as usize;
    at(0)..at(1)
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().expect(key)
}

#[test]
fn rust_facts_match_the_python_reference() {
    let rows = rows();
    assert!(rows.len() >= 5);
    for row in &rows {
        let id = &row["id"];
        let text = str_of(row, "text");
        let findings: Vec<Finding> = row["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .map(|f| Finding {
                category: str_of(f, "category"),
                family: str_of(f, "family"),
                pattern: str_of(f, "pattern"),
                points: f["points"].as_i64().expect("points"),
                span: span(&f["span"]),
            })
            .collect();
        let data: Vec<DataRef> = row["data"]
            .as_array()
            .expect("data")
            .iter()
            .map(|d| DataRef {
                source: str_of(d, "source"),
                label: str_of(d, "label"),
                span: span(&d["span"]),
            })
            .collect();
        let facts = extract(text, &findings, &data);
        let canonical = str_of(row, "canonical");
        assert_eq!(facts.canonical_json(), canonical, "{id}: canonical");
        let kept = TextFacts::from_json(&row["facts"]).expect("facts document");
        assert_eq!(kept, facts, "{id}: facts");
        let mut tokens = Vec::new();
        visit_tf1(text, &facts, &mut |t| tokens.push(t.to_string()));
        tokens.sort();
        let expected: Vec<&str> = row["tf1"]
            .as_array()
            .expect("tf1")
            .iter()
            .map(|t| t.as_str().expect("token"))
            .collect();
        assert_eq!(tokens, expected, "{id}: tf1");
    }
}
