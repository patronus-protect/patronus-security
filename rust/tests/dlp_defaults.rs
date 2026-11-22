use patronus_ark::GatewayConfig;
use patronus_ark::SecurityGateway;
use patronus_ark_core::{
    cascade::ScanGateMatrix, cascade::SecurityLevel, detectors::dlp::dlp::DLP_PATTERNS,
    SecurityCategory,
};

#[test]
fn default_and_partial_matrices_share_the_credential_and_marking_inventory() {
    for gates in [
        ScanGateMatrix::default(),
        ScanGateMatrix::levels(true, false, false),
    ] {
        for pattern in DLP_PATTERNS {
            let credential = matches!(
                pattern.entity_group,
                "API_KEY"
                    | "CLOUD_KEY"
                    | "CREDENTIAL"
                    | "CRYPTO_KEY"
                    | "PASSWORD_HASH"
                    | "PAYMENT_KEY"
                    | "PRIVATE_KEY"
                    | "SECRET_TOKEN"
            );
            // M23: classification markings are the one document class on by default.
            let marking = pattern.entity_group == "dlp.document.classification_marking";
            assert_eq!(
                gates.allows_rule(pattern.name),
                credential || marking,
                "{}",
                pattern.name
            );
            assert!(ScanGateMatrix::all_enabled().allows_rule(pattern.name));
        }
        assert!(gates.allows_rule("pii_email"));
        assert!(gates.allows_rule("ark.injection.escalation.multi_turn"));
        for id in [
            "dlp_mcp_policy",
            "dlp_mcp_runtime_risk",
            "dlp_destructive_operation",
        ] {
            assert!(!gates.allows_rule(id));
            assert!(gates.clone().with_rule(id, true).allows_rule(id));
        }
    }
}

#[test]
fn gateway_default_excludes_sql_and_explicit_rule_enables_it() {
    let gateway = |gates: ScanGateMatrix| {
        SecurityGateway::new(
            GatewayConfig::new(vec![SecurityCategory::Dlp], SecurityLevel::L1).with_gates(gates),
        )
        .unwrap()
    };
    let scanner = gateway(ScanGateMatrix::default());
    let text = "password = CorrectHorseBatteryStaple\nSELECT * FROM customer;";
    let results = scanner.scan_all(text).native;
    assert!(results
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "CREDENTIAL"));
    assert!(!results
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "dlp.content.sql"));
    assert!(!results.iter().any(|r| r.model == "native:mcp_policy"));

    let scanner = gateway(ScanGateMatrix::default().with_rule("dlp_sql_statement", true));
    assert!(scanner
        .scan_all(text)
        .native
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "dlp.content.sql"));
    let scanner = gateway(ScanGateMatrix::default());
    assert!(!scanner
        .scan_all(text)
        .native
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "dlp.content.sql"));
}
