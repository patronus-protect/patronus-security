// SPDX-License-Identifier: GPL-3.0-only
//! JSONL scanner bridge for reproducible offline L1 calibration.
use patronus_ark::{ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel};
use std::io::{self, BufRead};
fn main() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Injection, SecurityCategory::Threat],
        SecurityLevel::L1,
        None,
        false,
    );
    gateway.set_execution_gates(ScanGateMatrix::all_enabled());
    for line in io::stdin().lock().lines() {
        let input: serde_json::Value =
            serde_json::from_str(&line.expect("stdin")).expect("JSON input");
        let category = match input["category"].as_str().expect("category") {
            "injection" => SecurityCategory::Injection,
            "threat" => SecurityCategory::Threat,
            _ => panic!("unsupported calibration category"),
        };
        let results = gateway.scan_category(category, input["text"].as_str().expect("text"));
        let output: Vec<_> = results.into_iter().map(|r| serde_json::json!({
            "model": r.model, "class_name": r.class_name,
            "layers": r.layers.into_iter().map(|l| serde_json::json!({"details": l.details})).collect::<Vec<_>>()
        })).collect();
        println!("{}", serde_json::to_string(&output).unwrap());
    }
}
