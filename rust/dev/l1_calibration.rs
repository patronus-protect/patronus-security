// SPDX-License-Identifier: GPL-3.0-only
//! JSONL scanner bridge for reproducible offline L1 calibration.
use patronus_ark::GatewayConfig;
use patronus_ark::SecurityGateway;
use patronus_ark_core::{cascade::ScanGateMatrix, cascade::SecurityLevel, SecurityCategory};
use std::io::{self, BufRead};
fn main() {
    let gateway = SecurityGateway::new(GatewayConfig::new(
        vec![SecurityCategory::Injection, SecurityCategory::UnsafeAction],
        SecurityLevel::L1,
    ))
    .unwrap();
    gateway.set_execution_gates(ScanGateMatrix::all_enabled());
    for line in io::stdin().lock().lines() {
        let input: serde_json::Value =
            serde_json::from_str(&line.expect("stdin")).expect("JSON input");
        let category = match input["category"].as_str().expect("category") {
            "injection" => SecurityCategory::Injection,
            "threat" => SecurityCategory::UnsafeAction,
            _ => panic!("unsupported calibration category"),
        };
        let results = gateway.scan_category(category, input["text"].as_str().expect("text"));
        let output: Vec<_> = results.into_iter().map(|r| serde_json::json!({
            "model": r.model, "class_name": r.class_name,
            "layers": r.native.layers.into_iter().map(|l| serde_json::json!({"details": l.details})).collect::<Vec<_>>()
        })).collect();
        println!("{}", serde_json::to_string(&output).unwrap());
    }
}
