// SPDX-License-Identifier: GPL-3.0-only
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

fn is_local_path_span(text: &str, span: &EvidenceSpan) -> bool {
    let before = &text[..span.start_byte.min(text.len())];
    let after = &text[span.end_byte.min(text.len())..];
    let path_start = before
        .rfind(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '(' | '[' | '{'))
        .map_or(0, |index| index + 1);
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
        .collect()
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
    use super::{filter_evidence, LocalPathPersonHook, PostPredictionHook};
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
}
