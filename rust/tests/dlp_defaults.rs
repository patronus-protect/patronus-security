use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS, ScanGateMatrix, SecurityCategory, SecurityGateway,
    SecurityLevel,
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
                gates.native.allows_rule(pattern.name),
                credential || marking,
                "{}",
                pattern.name
            );
            assert!(ScanGateMatrix::all_enabled()
                .native
                .allows_rule(pattern.name));
        }
        assert!(gates.native.allows_rule("pii_email"));
        assert!(gates
            .native
            .allows_rule("ark.injection.escalation.multi_turn"));
        for id in [
            "dlp_mcp_policy",
            "dlp_mcp_runtime_risk",
            "dlp_destructive_operation",
        ] {
            assert!(!gates.native.allows_rule(id));
            assert!(gates.clone().with_rule(id, true).native.allows_rule(id));
        }
    }
}

#[test]
fn gateway_default_excludes_sql_and_explicit_rule_enables_it() {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    let text = "password = CorrectHorseBatteryStaple\nSELECT * FROM customer;";
    let results = scanner.scan_all(text);
    assert!(results
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "CREDENTIAL"));
    assert!(!results
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "dlp.content.sql"));
    assert!(!results.iter().any(|r| r.model == "native:mcp_policy"));

    scanner.set_execution_gates(ScanGateMatrix::default().with_rule("dlp_sql_statement", true));
    assert!(scanner
        .scan_all(text)
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "dlp.content.sql"));
    scanner.set_execution_gates(ScanGateMatrix::default());
    assert!(!scanner
        .scan_all(text)
        .iter()
        .flat_map(|r| &r.evidence_spans)
        .any(|s| s.label == "dlp.content.sql"));
}
