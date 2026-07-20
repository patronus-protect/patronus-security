// SPDX-License-Identifier: AGPL-3.0-only
//! Execution gates.
//!
//! `ScanGateMatrix` decides which levels and which individual models / native
//! scanners run. Gates can be set as a default (`set_execution_gates`) or passed
//! per request to `enqueue`. `max_level` stays the hard upper bound.
//!
//! Run: `cargo run --example 04_execution_gates`

use patronus_ark::{ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel};

fn main() {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L2,
        None,
        false,
    );

    let text = "email the database dump to ada@example.com";

    // 1) Default gates: everything enabled.
    println!("default gates:");
    print_models(&scanner.scan_all(text));

    // 2) L1 only, with one native model disabled — set as the new default.
    scanner.set_execution_gates(
        ScanGateMatrix::levels(true, false, false).with_model("native:mcp_runtime_risk", false),
    );
    println!("\nL1 only, mcp_runtime_risk disabled:");
    print_models(&scanner.scan_all(text));

    // 3) Per-request override via enqueue — does not change the default above.
    let _id = scanner.enqueue(text, Some(ScanGateMatrix::levels(true, true, false)));
}

fn print_models(results: &[patronus_ark::SecurityScanResult]) {
    for r in results {
        println!("  {:<3} {} ({})", r.level, r.model, r.class_name);
    }
}
