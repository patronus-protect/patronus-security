// SPDX-License-Identifier: GPL-3.0-only
//! Execution gates.
//!
//! `ScanGateMatrix` decides which levels and which individual models / native
//! scanners run. Gates are part of the gateway config (`GatewayConfig::with_gates`)
//! or passed per request to `enqueue`. `max_level` stays the hard upper bound.
//!
//! Run: `cargo run --example 04_execution_gates`

use patronus_ark::{GatewayConfig, ScanRequest, ScanRequestOptions, SecurityGateway};

use patronus_ark_core::{cascade::ScanGateMatrix, cascade::SecurityLevel, SecurityCategory};

fn main() {
    let scanner = SecurityGateway::new(GatewayConfig::new(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L2,
    ))
    .unwrap();

    let text = "email the database dump to ada@example.com";

    // 1) Default gates: everything enabled.
    println!("default gates:");
    print_models(&scanner.scan_all(text).native);

    // 2) L1 only, with one native model disabled: the gates of a gateway's config.
    let l1_only = SecurityGateway::new(
        GatewayConfig::new(vec![SecurityCategory::Dlp], SecurityLevel::L2).with_gates(
            ScanGateMatrix::levels(true, false, false).with_model("native:mcp_runtime_risk", false),
        ),
    )
    .unwrap();
    println!("\nL1 only, mcp_runtime_risk disabled:");
    print_models(&l1_only.scan_all(text).native);

    // 3) Per-request override via enqueue: does not change the gateway's gates.
    let _id = scanner
        .enqueue(ScanRequest {
            options: ScanRequestOptions {
                gates: Some(ScanGateMatrix::levels(true, true, false)),
                ..Default::default()
            },
            ..ScanRequest::new(text)
        })
        .unwrap();
}

fn print_models(results: &[patronus_ark::SecurityScanResult]) {
    for r in results {
        println!("  {:<3} {} ({})", r.level, r.model, r.class_name);
    }
}
