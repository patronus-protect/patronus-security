// SPDX-License-Identifier: MIT OR Apache-2.0
//! Assess tool calls from JSONL: one call per line,
//! `{"session"?: "<id>", "tool": "...", "arguments": {...} | "<json>", "harness"?, "description"?,
//!   "known_targets"?: [...]}`, out one assessment per line:
//! `{"decision": "allow|ask|block", "policies": [...], "facts": {...}, "p": {...}}`.
//! Calls with the same `session` see each other's facts (the last five).
//!
//! cargo run --release --example tool_facts -- <model_dir> [policy_dir ...] < calls.jsonl

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;

use patronus_ark_core::detectors::tool::{Json, ToolAssessor, ToolCall, ToolFacts, SESSION_WINDOW};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let model_dir = args
        .first()
        .ok_or("usage: tool_facts <model_dir> [policy_dir ...] < calls.jsonl")?;
    let policy_dirs: Vec<&Path> = args[1..].iter().map(Path::new).collect();
    let assessor = ToolAssessor::load(Path::new(model_dir), None, &policy_dirs)?;
    eprintln!("{} policies loaded", assessor.policies().len());
    let mut sessions: HashMap<String, Vec<ToolFacts>> = HashMap::new();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let v = Json::parse(&line)?;
        let call = ToolCall::from_json(&v)?;
        let known: Vec<String> = match v.get("known_targets") {
            Some(Json::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            _ => Vec::new(),
        };
        let key = v.get("session").map(Json::py_str).unwrap_or_default();
        let prior = sessions.entry(key).or_default();
        let a = assessor.assess(&call, prior, &known)?;
        writeln!(out, "{}", a.to_json()).map_err(|e| e.to_string())?;
        prior.push(a.facts);
        if prior.len() > SESSION_WINDOW {
            prior.remove(0);
        }
    }
    Ok(())
}
