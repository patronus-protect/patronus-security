// SPDX-License-Identifier: MIT OR Apache-2.0
use std::net::{IpAddr, Ipv4Addr};

use crate::{EvidenceSpan, SecurityCategory};

/// Extract DLP secret byte ranges, sorted by start/end, without cloning evidence.
/// The host selects the DLP results belonging to the same source text.
pub fn dlp_secret_ranges<'a>(
    spans: impl IntoIterator<Item = &'a EvidenceSpan>,
) -> Vec<(usize, usize)> {
    let mut ranges = spans
        .into_iter()
        .filter(|span| crate::detectors::dlp::dlp::SECRET_GROUPS.contains(&span.label.as_str()))
        .map(|span| (span.start_byte, span.end_byte))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    ranges
}

/// Retain PII evidence outside secret ranges returned by [`dlp_secret_ranges`].
/// Ranges must be sorted by start/end. Touching end-exclusive byte ranges do not
/// overlap. This operation changes only evidence, never a classifier decision.
pub fn retain_pii_outside_secret_ranges(spans: &mut Vec<EvidenceSpan>, secrets: &[(usize, usize)]) {
    debug_assert!(secrets.is_sorted());
    spans.retain(|span| {
        let after = secrets.partition_point(|&(start, _)| start < span.end_byte);
        !secrets[..after]
            .iter()
            .any(|&(_, end)| end > span.start_byte)
    });
}

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

pub fn filter_evidence(
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

pub fn is_real_secret_assignment(value: &str) -> bool {
    // F-GEN2: base64 padding (`KEY: <base64>=` in a Kubernetes Secret) is no
    // assignment.
    let unpadded = value
        .strip_suffix("==")
        .or_else(|| value.strip_suffix('='))
        .unwrap_or(value);
    if unpadded.len() >= 16
        && unpadded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_'))
    {
        return true;
    }
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
mod overlap_tests {
    use super::*;

    fn span(label: &str, start: usize, end: usize) -> EvidenceSpan {
        EvidenceSpan {
            label: label.into(),
            text: String::new(),
            score: 0.73,
            start_byte: start,
            end_byte: end,
            start_char: 0,
            end_char: 0,
        }
    }

    #[test]
    fn only_secret_labels_produce_sorted_ranges() {
        let dlp = [
            span("SECRET_TOKEN", 20, 30),
            span("SENSITIVE_DOCUMENT", 0, 40),
            span("CREDENTIAL", 4, 12),
        ];
        assert_eq!(dlp_secret_ranges(&dlp), [(4, 12), (20, 30)]);
    }

    #[test]
    fn strict_byte_overlap_removes_nested_and_partial_spans_but_not_touching_spans() {
        let secrets = dlp_secret_ranges(&[span("CREDENTIAL", 4, 12), span("API_KEY", 8, 16)]);
        let mut pii = vec![
            span("EMAIL", 0, 4),
            span("EMAIL", 3, 5),
            span("EMAIL", 5, 7),
            span("EMAIL", 12, 17),
            span("EMAIL", 16, 20),
            span("EMAIL", 0, 20),
        ];
        retain_pii_outside_secret_ranges(&mut pii, &secrets);
        assert_eq!(
            pii.iter()
                .map(|s| (s.start_byte, s.end_byte))
                .collect::<Vec<_>>(),
            [(0, 4), (16, 20)]
        );
        assert!(pii.iter().all(|s| s.score == 0.73));
        retain_pii_outside_secret_ranges(&mut pii, &[]);
        assert_eq!(pii.len(), 2);
    }
}
