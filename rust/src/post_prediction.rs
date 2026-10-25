use crate::{EvidenceSpan, SecurityCategory};
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
        let mut secrets = results[dlp]
            .iter()
            .flat_map(|result| &result.evidence_spans)
            .filter(|span| crate::detectors::dlp::dlp::SECRET_GROUPS.contains(&span.label.as_str()))
            .map(|span| (span.start_byte, span.end_byte))
            .collect::<Vec<_>>();
        if secrets.is_empty() {
            continue;
        }
        secrets.sort_unstable();
        let overlaps_secret = |span: &EvidenceSpan| {
            let after = secrets.partition_point(|&(start, _)| start < span.end_byte);
            secrets[..after]
                .iter()
                .any(|&(_, end)| end > span.start_byte)
        };
        for (pii, pii_input) in inputs.iter().enumerate() {
            if !is_pii(pii_input.category) || *pii_input.text != *dlp_input.text {
                continue;
            }
            for result in &mut results[pii] {
                result.evidence_spans.retain(|span| !overlaps_secret(span));
            }
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
