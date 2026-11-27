// SPDX-License-Identifier: MIT OR Apache-2.0
//! `patronus.tool_facts/1` and the tool policies against the Python reference
//! (`tool_facts_reference.py synthetic`): hand-written sessions with given
//! model labels, expected facts and fired policies (core plus the example
//! user policy `examples/tool_policies/new_recipient.cedar`).
//!
//! `TOOL_FACTS_PARITY=<file>` runs the same check on a larger file of the same
//! format (`tool_facts_reference.py external`, public sessions, not committed).

use patronus_ark_core::detectors::tool::facts::canonical;
use patronus_ark_core::detectors::tool::{
    Json, ModelLabels, ToolAssessor, ToolCall, ToolFacts, ToolPolicies, ToolPolicyConfig,
};
use serde_json::Value;

const GOLDENS: &str = include_str!("../src/detectors/tool/testdata/goldens.jsonl");
const EXAMPLE_POLICY: &str = include_str!("../examples/tool_policies/new_recipient.cedar");

fn assessor() -> ToolAssessor {
    let config = ToolPolicyConfig {
        user_policies: vec![EXAMPLE_POLICY.to_string()],
    };
    ToolAssessor::new(None, ToolPolicies::with_config(&config).unwrap())
}

/// Mismatches of one session file: (session, call index, what differs).
fn check(text: &str, max_report: usize) -> (usize, Vec<String>) {
    let assessor = assessor();
    let (mut calls, mut bad) = (0, Vec::new());
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let session = Json::parse(line).unwrap();
        let v: Value = serde_json::from_str(line).unwrap();
        let name = v["name"].as_str().unwrap_or("").to_string();
        let known: Vec<String> = v["known_targets"].as_array().map_or(Vec::new(), |a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        });
        let Some(Json::Array(items)) = session.get("calls") else {
            panic!("{name}: no calls")
        };
        let mut prior: Vec<ToolFacts> = Vec::new();
        for (i, (item, expected)) in items
            .iter()
            .zip(v["expected"].as_array().unwrap())
            .enumerate()
        {
            calls += 1;
            let call = ToolCall::from_json(item.get("call").unwrap()).unwrap();
            let labels: ModelLabels =
                serde_json::from_value(item.get("model").unwrap().to_value()).unwrap();
            let a = assessor
                .assess_with_labels(&call, &labels, &prior, &known)
                .unwrap();
            let got = a.facts.to_json();
            let want = canonical(&expected["facts"]);
            let mut ids: Vec<String> = a.hits.iter().map(|h| h.id.clone()).collect();
            ids.sort();
            let want_ids: Vec<String> =
                serde_json::from_value(expected["policies"].clone()).unwrap();
            if got != want || ids != want_ids {
                if bad.len() < max_report {
                    let keys: Vec<&String> = want
                        .as_object()
                        .unwrap()
                        .keys()
                        .filter(|k| got.get(k.as_str()) != want.get(k.as_str()))
                        .collect();
                    bad.push(format!(
                        "{name}#{i} {}: fields {keys:?}; policies {ids:?} vs {want_ids:?}{}",
                        call.tool,
                        keys.first().map_or(String::new(), |k| format!(
                            "; {k}: {} vs {}",
                            got[k.as_str()],
                            want[k.as_str()]
                        ))
                    ));
                } else {
                    bad.push(String::new());
                }
            }
            prior.push(a.facts);
        }
    }
    (calls, bad)
}

#[test]
fn synthetic_sessions_match_the_reference() {
    let (calls, bad) = check(GOLDENS, 20);
    assert!(calls > 30);
    assert!(
        bad.is_empty(),
        "{} of {calls} calls differ:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn parity_file_matches_the_reference() {
    let Ok(path) = std::env::var("TOOL_FACTS_PARITY") else {
        return;
    };
    let (calls, bad) = check(&std::fs::read_to_string(path).unwrap(), 15);
    eprintln!("parity: {} of {calls} calls differ", bad.len());
    assert!(
        bad.is_empty(),
        "{} of {calls} calls differ:\n{}",
        bad.len(),
        bad.iter()
            .filter(|b| !b.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
