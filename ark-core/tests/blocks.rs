// SPDX-License-Identifier: MIT OR Apache-2.0
//! Released blocks (`patronus.block/1`) against their own `block.py`: the same
//! `block.safetensors`, run natively here and by the reference in one file.
//! `PATRONUS_BLOCKS_DIR=<dir>` with `tool-call-v11/block.safetensors`,
//! `tool-call-v11.cross.jsonl`, `cat-shell/block.safetensors` and
//! `cat-shell.cross.jsonl` (`cross_reference.py`); skipped without it, the
//! blocks are release artifacts.

use std::path::{Path, PathBuf};

use patronus_ark_core::detectors::facts_common::block::BlockFile;
use patronus_ark_core::detectors::shell::ShellRiskPipeline;
use patronus_ark_core::detectors::tool::facts::canonical;
use patronus_ark_core::detectors::tool::{
    Json, ToolAssessor, ToolCall, ToolFacts, ToolPolicyConfig,
};
use serde_json::Value;

fn dir() -> Option<PathBuf> {
    std::env::var("PATRONUS_BLOCKS_DIR").ok().map(PathBuf::from)
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn tool_block_matches_its_block_py() {
    let Some(dir) = dir() else { return };
    let block = BlockFile::open(&dir.join("tool-call-v11/block.safetensors"), None).unwrap();
    let assessor = ToolAssessor::from_block(&block, &ToolPolicyConfig::default()).unwrap();
    let (mut calls, mut bad) = (0, Vec::new());
    for line in lines(&dir.join("tool-call-v11.cross.jsonl")) {
        let session = Json::parse(&line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        let Some(Json::Array(items)) = session.get("calls") else {
            panic!("no calls")
        };
        let mut prior: Vec<ToolFacts> = Vec::new();
        for (i, (item, want)) in items
            .iter()
            .zip(v["outputs"].as_array().unwrap())
            .enumerate()
        {
            calls += 1;
            let a = assessor
                .assess(&ToolCall::from_json(item).unwrap(), &prior, &[])
                .unwrap();
            let ids: Vec<&str> = a.hits.iter().map(|h| h.id.as_str()).collect();
            let want_ids: Vec<&str> = want["policies"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["id"].as_str().unwrap())
                .collect();
            let facts = a.facts.to_json();
            if a.decision.as_str() != want["decision"]
                || ids != want_ids
                || facts != canonical(&want["facts"])
            {
                if bad.len() < 10 {
                    let fields: Vec<&String> = facts
                        .as_object()
                        .unwrap()
                        .keys()
                        .filter(|k| {
                            facts.get(k.as_str()) != canonical(&want["facts"]).get(k.as_str())
                        })
                        .collect();
                    bad.push(format!(
                        "{}#{i}: {:?} vs {}, {ids:?} vs {want_ids:?}, facts {fields:?}",
                        v["name"], a.decision, want["decision"]
                    ));
                } else {
                    bad.push(String::new());
                }
            }
            prior.push(a.facts);
        }
    }
    eprintln!("tool block: {} of {calls} calls differ", bad.len());
    assert!(calls > 1000 && bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn cat_block_matches_its_block_py() {
    let Some(dir) = dir() else { return };
    let pipeline =
        ShellRiskPipeline::from_bundle_dir(&dir.join("cat-shell/block.safetensors")).unwrap();
    let (mut n, mut bad) = (0, Vec::new());
    for line in lines(&dir.join("cat-shell.cross.jsonl")) {
        let v: Value = serde_json::from_str(&line).unwrap();
        let command = v["command"].as_str().unwrap();
        let got = pipeline
            .verdict(command, None, &[], |_| true)
            .unwrap()
            .to_json(true);
        let want = &v["verdict"];
        n += 1;
        let same = [
            "decision",
            "score",
            "cuts",
            "policies",
            "allowlisted",
            "facts",
        ]
        .iter()
        .all(|k| got[*k] == want[*k])
            && ["id", "score", "decision"]
                .iter()
                .all(|k| got["model"][*k] == want["model"][*k])
            && same_top_features(
                &got["model"]["top_features"],
                &want["model"]["top_features"],
            );
        if !same {
            if bad.len() < 10 {
                let keys: Vec<&str> = ["decision", "score", "model", "policies", "facts"]
                    .into_iter()
                    .filter(|k| got[*k] != want[*k])
                    .collect();
                let sub: Vec<String> = got["model"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .filter(|(k, x)| want["model"].get(k.as_str()) != Some(x))
                    .map(|(k, x)| format!("{k}: {x} vs {}", want["model"][k.as_str()]))
                    .collect();
                bad.push(format!("{n}: {keys:?} {sub:?}"));
            } else {
                bad.push(String::new());
            }
        }
    }
    eprintln!("cat block: {} of {n} commands differ", bad.len());
    assert!(n > 1000 && bad.is_empty(), "{}", bad.join("\n"));
}

/// Top features up to ties: the same weights in order, and the same features
/// above the smallest weight (features of equal weight sort differently in
/// numpy and here, and the cut at five may take a different one of a tie).
fn same_top_features(a: &Value, b: &Value) -> bool {
    let (a, b) = (a.as_array().unwrap(), b.as_array().unwrap());
    let weights = |x: &[Value]| {
        x.iter()
            .map(|f| f["weight"].as_f64().unwrap())
            .collect::<Vec<_>>()
    };
    if weights(a) != weights(b) {
        return false;
    }
    let min = weights(a).into_iter().fold(f64::INFINITY, f64::min);
    fn above(x: &[Value], min: f64) -> Vec<&str> {
        let mut v: Vec<&str> = x
            .iter()
            .filter(|f| f["weight"].as_f64().unwrap() > min)
            .map(|f| f["feature"].as_str().unwrap())
            .collect();
        v.sort_unstable();
        v
    }
    above(a, min) == above(b, min)
}
