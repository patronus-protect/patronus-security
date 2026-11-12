// SPDX-License-Identifier: MIT OR Apache-2.0
//! `patronus.text_facts/1` on the text-facts goldens (`generate_l1_goldens.py`,
//! suite `text_facts_l1`): language, carrier, addressee and sinks exactly, the
//! counter contexts at least.
use std::path::Path;

use patronus_ark_core::detectors::text::facts::extract;
use serde_json::Value;

fn goldens() -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/text_facts_l1.jsonl");
    std::fs::read_to_string(path)
        .expect("text facts goldens")
        .lines()
        .map(|line| serde_json::from_str(line).expect("golden row"))
        .collect()
}

fn names(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .expect("fact list")
        .iter()
        .map(|name| name.as_str().expect("fact name"))
        .collect()
}

#[test]
fn facts_match_the_goldens() {
    let rows = goldens();
    let mut failures = Vec::new();
    for row in &rows {
        let facts = extract(row["text"].as_str().expect("text"), &[], &[]);
        let expected = &row["expected_facts"];
        let mut sinks: Vec<&str> = facts.sinks.iter().map(|sink| sink.kind).collect();
        sinks.dedup();
        let counter_ok = names(&expected["counter"])
            .iter()
            .all(|id| facts.counter.contains(id));
        if facts.language != expected["language"]
            || facts.carrier != names(&expected["carrier"])
            || facts.addressee != names(&expected["addressee"])
            || sinks != names(&expected["sinks"])
            || !counter_ok
        {
            failures.push(format!(
                "{}: got language={} carrier={:?} addressee={:?} sinks={sinks:?} counter={:?}, expected {expected}",
                row["id"], facts.language, facts.carrier, facts.addressee, facts.counter
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn goldens_cover_both_languages_and_case_types() {
    let rows = goldens();
    for language in ["de", "en"] {
        for case_type in ["positive", "hard_negative"] {
            let count = rows
                .iter()
                .filter(|row| row["language"] == language && row["case_type"] == case_type)
                .count();
            assert!(count >= 5, "{language} {case_type}: {count}");
        }
    }
}
