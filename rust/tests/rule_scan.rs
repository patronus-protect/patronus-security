// SPDX-License-Identifier: GPL-3.0-only
//! The rule layer's public scan: exact evidence spans without the pipeline,
//! available with and without the `ml` feature.
use patronus_ark::detectors::dlp::dlp::DlpPipeline;
use patronus_ark::detectors::pii::pii::PiiPipeline;

#[test]
fn pii_scan_returns_exact_spans() {
    let text = "Bitte an qa-test@example.com, IBAN DE89370400440532013000.";
    let scan = PiiPipeline::new().scan(text);
    let labels: Vec<(&str, &str)> = scan
        .evidence_spans
        .iter()
        .map(|span| (span.label.as_str(), &text[span.start_byte..span.end_byte]))
        .collect();
    assert!(labels.contains(&("EMAIL", "qa-test@example.com")), "{labels:?}");
    assert!(labels.contains(&("IBAN", "DE89370400440532013000")), "{labels:?}");
    assert_eq!(scan.result.class_name, "EMAIL");
}

#[test]
fn dlp_scan_keeps_to_the_default_secret_rules() {
    let text = "config: password=Sommer2026!x";
    let scan = DlpPipeline::new().scan(text);
    assert!(
        scan.evidence_spans.iter().any(|span| span.label == "CREDENTIAL"),
        "{:?}",
        scan.evidence_spans
    );
    let clean = DlpPipeline::new().scan("SELECT name FROM users WHERE id = 7");
    assert!(clean.evidence_spans.is_empty(), "content rules stay off: {:?}", clean.evidence_spans);
}
