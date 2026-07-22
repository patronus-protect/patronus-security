// SPDX-License-Identifier: GPL-3.0-only
use std::time::Duration;

use patronus_ark::{
    ConditionalPipelineGate, DynamicPiiConfig, GateExpression, MetadataCondition,
    QueuedSecurityEvent, ResultCondition, ScanGateMatrix, SecurityCategory, SecurityGateway,
    SecurityLevel,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gateway = SecurityGateway::with_max_level(
        vec![
            SecurityCategory::Injection,
            SecurityCategory::Routing,
            SecurityCategory::DynamicPii,
        ],
        SecurityLevel::L3,
        None,
        false,
    );
    gateway.set_dynamic_pii_config(DynamicPiiConfig {
        labels: vec!["person".to_string(), "organization".to_string()],
        queue_timeout_ms: 3_000,
        timeout_ms: 5_000,
        timeout_per_chunk_ms: 500,
        max_timeout_ms: 60_000,
        ..DynamicPiiConfig::default()
    })?;

    let mut gates = ScanGateMatrix::all_enabled();
    gates.set_conditional(vec![ConditionalPipelineGate {
        level: SecurityLevel::L3,
        pipeline: Some("dynamic-pii".to_string()),
        when: GateExpression::Not(Box::new(GateExpression::Any(vec![
            GateExpression::Metadata(MetadataCondition {
                path: "content.format".to_string(),
                equals: Some(serde_json::json!("source_code")),
                in_values: None,
                exists: None,
            }),
            GateExpression::Result(ResultCondition {
                pipeline: "routing".to_string(),
                classes: vec!["code_development_request".to_string()],
                min_confidence: Some(0.9),
            }),
        ]))),
    }])?;

    let request_id = gateway.enqueue_with_metadata(
        "fn main() { println!(\"hello\"); }",
        serde_json::json!({
            "tool": {"name": "read_file", "action": "read"},
            "content": {"format": "source_code", "mime_type": "text/x-rust"}
        }),
        Some(gates),
    );

    while let Some(event) = gateway.consume_next_event(Some(Duration::from_secs(2))) {
        match event {
            QueuedSecurityEvent::Result(queued) => println!(
                "{} {} {} {}",
                queued.request_id,
                queued.result.level,
                queued.result.category,
                queued.result.class_name
            ),
            QueuedSecurityEvent::Finished {
                request_id,
                completion,
            } => {
                println!("{request_id} finished: {completion:?}");
                break;
            }
        }
    }
    assert!(!gateway.has_request(&request_id));
    Ok(())
}
