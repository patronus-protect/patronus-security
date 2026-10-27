use crate::SecurityCategory;
pub use patronus_ark_core::post_prediction::*;
/// K08: DLP vs. PII double labels. When DLP and PII scan the same text, a
/// DLP secret span owns its range: PII spans overlapping it (a URL password
/// read as the local part of an e-mail address, token digits read as a card
/// number) are dropped from the PII results. Only evidence changes; the PII
/// decision stays as scanned. `results[i]` holds the results of `inputs[i]`.
pub(crate) fn resolve_dlp_pii_overlaps(
    inputs: &[crate::ExternalL1Input],
    results: &mut [Vec<crate::SecurityScanResult>],
) {
    let is_pii = |category| {
        matches!(
            category,
            SecurityCategory::Pii | SecurityCategory::DynamicPii
        )
    };
    if !inputs
        .iter()
        .any(|input| input.category == SecurityCategory::Dlp)
        || !inputs.iter().any(|input| is_pii(input.category))
    {
        return;
    }
    for (dlp, dlp_input) in inputs.iter().enumerate() {
        if dlp_input.category != SecurityCategory::Dlp {
            continue;
        }
        let secrets = dlp_secret_ranges(
            results[dlp]
                .iter()
                .flat_map(|result| &result.evidence_spans),
        );
        if secrets.is_empty() {
            continue;
        }
        for (pii, pii_input) in inputs.iter().enumerate() {
            if !is_pii(pii_input.category) || *pii_input.text != *dlp_input.text {
                continue;
            }
            for result in &mut results[pii] {
                retain_pii_outside_secret_ranges(&mut result.evidence_spans, &secrets);
            }
        }
    }
}

#[cfg(test)]
mod overlap_grouping_tests {
    use super::resolve_dlp_pii_overlaps;
    use crate::{EvidenceSpan, ExternalL1Input, SecurityCategory, SecurityScanResult};

    fn span(text: &str, label: &str, start: usize, end: usize) -> EvidenceSpan {
        EvidenceSpan {
            label: label.into(),
            text: text[start..end].into(),
            score: 0.73,
            start_byte: start,
            end_byte: end,
            start_char: text[..start].chars().count(),
            end_char: text[..end].chars().count(),
        }
    }

    fn result(category: &str, spans: Vec<EvidenceSpan>) -> SecurityScanResult {
        patronus_ark_core::NativeResult {
            category: category.into(),
            model: "fixture".into(),
            class_name: "found".into(),
            confidence: 0.82,
            level: "L1".into(),
            duration_ms: 1.25,
            layers: Vec::new(),
            evidence_spans: spans,
            label_scores: Vec::new(),
            decision: None,
        }
        .into()
    }

    #[test]
    fn equal_text_groups_pii_and_dynamic_pii_without_affecting_other_inputs_or_decisions() {
        let text = "😀abcdefgh";
        let other = "😀zyxwvuts";
        let inputs = [
            ExternalL1Input::new(SecurityCategory::Dlp, text),
            ExternalL1Input::new(SecurityCategory::Pii, text.to_owned()),
            ExternalL1Input::new(SecurityCategory::DynamicPii, text.to_owned()),
            ExternalL1Input::new(SecurityCategory::Pii, other),
        ];
        let pii_spans = |text| {
            vec![
                span(text, "person", 0, 4),
                span(text, "person", 4, 6),
                span(text, "person", 8, 10),
            ]
        };
        let mut results = vec![
            vec![result("dlp", vec![span(text, "CREDENTIAL", 4, 8)])],
            vec![result("pii", pii_spans(text))],
            vec![result("dynamic-pii", pii_spans(text))],
            vec![result("pii", pii_spans(other))],
        ];
        let mut expected = results.clone();
        expected[1][0].evidence_spans.remove(1);
        expected[2][0].evidence_spans.remove(1);
        resolve_dlp_pii_overlaps(&inputs, &mut results);
        for (actual, expected) in results
            .into_iter()
            .flatten()
            .zip(expected.into_iter().flatten())
        {
            let actual: patronus_ark_core::NativeResult = actual.into();
            let expected: patronus_ark_core::NativeResult = expected.into();
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        filter_evidence, is_real_secret_assignment, LocalPathPersonHook, PostPredictionHook,
        PrivateNetworkDiagnosticHook,
    };
    use crate::{EvidenceSpan, SecurityCategory};

    fn person(text: &str, start: usize) -> EvidenceSpan {
        EvidenceSpan {
            label: "person".into(),
            text: text.into(),
            score: 0.9,
            start_byte: start,
            end_byte: start + text.len(),
            start_char: start,
            end_char: start + text.len(),
        }
    }

    #[test]
    fn filters_person_only_inside_local_paths() {
        let path = "/Users/alice/project/main.rs";
        let span = person("alice", 7);
        assert!(!LocalPathPersonHook.retain(SecurityCategory::DynamicPii, path, &span));
        assert!(LocalPathPersonHook.retain(
            SecurityCategory::DynamicPii,
            "Alice works here",
            &person("Alice", 0)
        ));
        assert!(LocalPathPersonHook.retain(
            SecurityCategory::DynamicPii,
            path,
            &EvidenceSpan {
                label: "location".into(),
                ..span.clone()
            }
        ));
        assert!(filter_evidence(SecurityCategory::Pii, path, vec![span]).is_empty());
    }

    #[test]
    fn local_path_filter_preserves_unicode_whitespace_boundaries() {
        let text = "Alex\u{202f}Vithurjan works here";
        let start = "Alex\u{202f}".len();

        assert!(LocalPathPersonHook.retain(
            SecurityCategory::DynamicPii,
            text,
            &person("Vithurjan", start),
        ));
    }

    #[test]
    fn filters_private_ip_evidence_only_from_network_diagnostics() {
        let private = EvidenceSpan {
            label: "IP_ADDRESS".into(),
            text: "192.168.178.96".into(),
            score: 1.0,
            start_byte: 41,
            end_byte: 55,
            start_char: 41,
            end_char: 55,
        };
        let diagnostic = "NetworkState diagnostics: local endpoint 192.168.178.96";

        assert!(!PrivateNetworkDiagnosticHook.retain(SecurityCategory::Pii, diagnostic, &private));
        assert!(PrivateNetworkDiagnosticHook.retain(
            SecurityCategory::Pii,
            "Connect to 192.168.178.96 now.",
            &EvidenceSpan {
                start_byte: 11,
                end_byte: 25,
                start_char: 11,
                end_char: 25,
                ..private.clone()
            }
        ));
        assert!(PrivateNetworkDiagnosticHook.retain(
            SecurityCategory::Pii,
            "Network diagnostics: public endpoint 8.8.8.8",
            &EvidenceSpan {
                text: "8.8.8.8".into(),
                start_byte: 37,
                end_byte: 44,
                start_char: 37,
                end_char: 44,
                ..private.clone()
            }
        ));
        assert!(filter_evidence(SecurityCategory::Pii, diagnostic, vec![private]).is_empty());
    }

    #[test]
    fn base64_padding_is_no_assignment() {
        // F-GEN2: `KEY: <base64>=` in a Kubernetes Secret keeps its span.
        assert!(is_real_secret_assignment(
            "c2stYW50LWFkbWluMDEtRTMzaGpnNmY2OG9ERTdF="
        ));
        assert!(is_real_secret_assignment("dXNlcjpLeDdwUTJ2TDlyVDQ=="));
        assert!(!is_real_secret_assignment("password=changeme"));
        assert!(!is_real_secret_assignment("token="));
        assert!(is_real_secret_assignment("password=Kx7pQ2vL9rT4mW"));
    }
}
