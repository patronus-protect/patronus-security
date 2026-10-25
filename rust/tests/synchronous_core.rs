use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};
use patronus_ark_core::{Category, ScanError, Scanner, ScannerConfig};

#[test]
fn core_preserves_gateway_native_decisions_and_source_evidence() {
    let mut core = Scanner::new(ScannerConfig::default()).unwrap();
    let gateway = SecurityGateway::with_max_level(
        vec![
            SecurityCategory::Pii,
            SecurityCategory::Dlp,
            SecurityCategory::Injection,
        ],
        SecurityLevel::L1,
        None,
        false,
    );
    for fixture in [
        include_str!("../../python/patronus_ark/benchmark_data/injection.jsonl"),
        include_str!("../../python/patronus_ark/benchmark_data/pii_l1.jsonl"),
        include_str!("../../python/patronus_ark/benchmark_data/dlp_l1.jsonl"),
    ] {
        for line in fixture.lines().filter(|line| !line.trim().is_empty()) {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            let Some(text) = row["text"].as_str() else {
                continue;
            };
            let direct = core.scan(text).unwrap();
            let queued = gateway.scan_all(text);
            assert_eq!(direct.native.len(), queued.len());
            for (a, b) in direct.native.iter().zip(&queued) {
                assert_eq!(
                    (&a.category, &a.model, &a.class_name, a.confidence),
                    (&b.category, &b.model, &b.class_name, b.confidence),
                    "text={text:?}"
                );
                assert_eq!(
                    serde_json::to_value(&a.evidence_spans).unwrap(),
                    serde_json::to_value(&b.evidence_spans).unwrap(),
                    "model={} text={text:?}",
                    a.model
                );
                assert_eq!(a.decision, b.decision, "text={text:?}");
            }
        }
    }
}
#[test]
fn synchronous_limits_are_errors_not_clean_results() {
    let mut core = Scanner::new(ScannerConfig {
        categories: vec![Category::Pii],
        max_input_bytes: 8,
        ..Default::default()
    })
    .unwrap();
    assert!(matches!(
        core.scan("longer than eight bytes"),
        Err(ScanError::InputLimit { .. })
    ));
    let mut core = Scanner::new(ScannerConfig {
        categories: vec![Category::Pii],
        max_findings: 1,
        ..Default::default()
    })
    .unwrap();
    assert!(matches!(
        core.scan("alice@example.org bob@example.net"),
        Err(ScanError::FindingLimit { .. })
    ));
}
