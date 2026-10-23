// SPDX-License-Identifier: GPL-3.0-only
use std::net::{IpAddr, Ipv4Addr};

use crate::{EvidenceSpan, SecurityCategory};

/// Post-prediction evidence filter. Predictions remain available for diagnostics;
/// the hook only decides which spans are actionable evidence.
pub trait PostPredictionHook: Send + Sync {
    fn retain(&self, category: SecurityCategory, text: &str, span: &EvidenceSpan) -> bool;
}

/// Suppresses GLiNER/native \`person\` spans that are merely usernames in local
/// POSIX/macOS paths. Other labels and person spans in prose are unchanged.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalPathPersonHook;

#[derive(Debug, Default, Clone, Copy)]
pub struct CredentialTemplateHook;

/// Keeps private/local IP predictions for diagnostics while preventing their
/// evidence spans from triggering redaction in network diagnostic output.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrivateNetworkDiagnosticHook;

impl PostPredictionHook for CredentialTemplateHook {
    fn retain(&self, category: SecurityCategory, _text: &str, span: &EvidenceSpan) -> bool {
        if category != SecurityCategory::Dlp
            || !matches!(
                span.label.to_ascii_uppercase().as_str(),
                "CREDENTIAL" | "SECRET_TOKEN"
            )
        {
            return true;
        }
        is_real_secret_assignment(&span.text)
    }
}

impl PostPredictionHook for LocalPathPersonHook {
    fn retain(&self, category: SecurityCategory, text: &str, span: &EvidenceSpan) -> bool {
        if !matches!(
            category,
            SecurityCategory::Pii | SecurityCategory::DynamicPii
        ) || !span.label.eq_ignore_ascii_case("person")
        {
            return true;
        }
        !is_local_path_span(text, span)
    }
}

impl PostPredictionHook for PrivateNetworkDiagnosticHook {
    fn retain(&self, category: SecurityCategory, text: &str, span: &EvidenceSpan) -> bool {
        if category != SecurityCategory::Pii || !span.label.eq_ignore_ascii_case("IP_ADDRESS") {
            return true;
        }
        !(is_private_or_local_ip(&span.text) && looks_like_network_diagnostic(text))
    }
}

fn is_private_or_local_ip(value: &str) -> bool {
    // An IP span may carry a zone ID or CIDR prefix length, and an IPv4-mapped
    // address is one span (B-IP).
    let v4 = |address: Ipv4Addr| {
        address.is_private() || address.is_link_local() || address.is_loopback()
    };
    match crate::detectors::pii::validators::ip_address_part(value).parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => v4(address),
        Ok(IpAddr::V6(address)) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_loopback()
                || address.to_ipv4_mapped().is_some_and(v4)
        }
        Err(_) => false,
    }
}

fn looks_like_network_diagnostic(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "networkstate",
        "network state",
        "network diagnostic",
        "local endpoint",
        "private endpoint",
        "network interface",
        "interface address",
        "lan address",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn is_local_path_span(text: &str, span: &EvidenceSpan) -> bool {
    let before = &text[..span.start_byte.min(text.len())];
    let after = &text[span.end_byte.min(text.len())..];
    let path_start = before
        .rfind(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '(' | '[' | '{'))
        .map_or(0, |index| {
            index + text[index..].chars().next().map_or(0, char::len_utf8)
        });
    let prefix = &text[path_start..span.start_byte.min(text.len())];
    let suffix_end = after
        .find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ')' | ']' | '}'))
        .unwrap_or(after.len());
    let suffix = &after[..suffix_end];
    let path = format!("{prefix}{}{suffix}", span.text);
    (path.starts_with("/Users/")
        || path.starts_with("/private/tmp/")
        || path.starts_with("/tmp/")
        || path.starts_with("~/"))
        && path.contains('/')
}

pub(crate) fn filter_evidence(
    category: SecurityCategory,
    text: &str,
    spans: Vec<EvidenceSpan>,
) -> Vec<EvidenceSpan> {
    let hook = LocalPathPersonHook;
    spans
        .into_iter()
        .filter(|span| hook.retain(category, text, span))
        .filter(|span| CredentialTemplateHook.retain(category, text, span))
        .filter(|span| PrivateNetworkDiagnosticHook.retain(category, text, span))
        .collect()
}

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

pub(crate) fn is_real_secret_assignment(value: &str) -> bool {
    let Some((_, raw)) = value.split_once('=') else {
        return true;
    };
    let value = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    if matches!(
        value.as_str(),
        "" | "changeme" | "your-token-here" | "replace-me" | "your_api_key_here"
    ) {
        return false;
    }
    value.len() >= 12 && shannon_entropy(value.as_bytes()) >= 2.5
}

fn shannon_entropy(value: &[u8]) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut frequencies = [0usize; 256];
    for byte in value {
        frequencies[*byte as usize] += 1;
    }
    let length = value.len() as f64;
    frequencies
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::{
        filter_evidence, LocalPathPersonHook, PostPredictionHook, PrivateNetworkDiagnosticHook,
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
}
