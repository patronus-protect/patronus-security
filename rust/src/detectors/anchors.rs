//! Bounded previews of native L1 context; these are not security findings.
use std::collections::HashMap;

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use super::evidence::char_offsets;

pub(crate) struct AnchorPattern {
    pub category: &'static str,
    pub strength: &'static str,
    pub anchor_kind: &'static str,
    pub pattern: &'static str,
}

const MAX_JSON_BYTES: usize = 4096;
const MAX_ANCHORS: usize = 12;
const MAX_TEXT_BYTES: usize = 96;

#[derive(Serialize)]
struct Anchor<'a> {
    kind: &'static str,
    anchor_kind: &'static str,
    category: &'static str,
    strength: &'static str,
    text: &'a str,
    start_byte: usize,
    end_byte: usize,
    start_char: usize,
    end_char: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_truncated: Option<bool>,
}

pub(crate) fn details(
    text: &str,
    regexes: &[Regex],
    patterns: &[AnchorPattern],
) -> HashMap<String, Value> {
    let mut anchors = Vec::new();
    let mut truncated = false;
    'patterns: for (regex, pattern) in regexes.iter().zip(patterns) {
        for matched in regex.find_iter(text) {
            if anchors.len() == MAX_ANCHORS {
                truncated = true;
                break 'patterns;
            }
            let mut preview_end = matched.len().min(MAX_TEXT_BYTES);
            while !matched.as_str().is_char_boundary(preview_end) {
                preview_end -= 1;
            }
            anchors.push(Anchor {
                kind: "anchor",
                anchor_kind: pattern.anchor_kind,
                category: pattern.category,
                strength: pattern.strength,
                text: &matched.as_str()[..preview_end],
                start_byte: matched.start(),
                end_byte: matched.end(),
                start_char: 0,
                end_char: 0,
                text_truncated: (preview_end < matched.len()).then_some(true),
            });
        }
    }
    if anchors.is_empty() {
        return HashMap::new();
    }
    anchors.sort_by_key(|anchor| (anchor.start_byte, anchor.end_byte));
    let ranges = anchors
        .iter()
        .map(|a| (a.start_byte, a.end_byte))
        .collect::<Vec<_>>();
    for (anchor, (start, end)) in anchors.iter_mut().zip(char_offsets(text, &ranges)) {
        anchor.start_char = start;
        anchor.end_char = end;
    }
    // Reserve the object/array delimiters and the truncation flag. Text is
    // bounded before serialization, including in the temporary JSON values.
    let mut remaining = MAX_JSON_BYTES - 128;
    let mut values = Vec::new();
    for anchor in anchors {
        let size = serde_json::to_vec(&anchor)
            .expect("anchor must serialize")
            .len()
            + 1;
        if size > remaining {
            truncated = true;
            break;
        }
        remaining -= size;
        values.push(serde_json::to_value(anchor).expect("anchor must serialize"));
    }
    let mut details = HashMap::from([("l1_anchors".into(), Value::Array(values))]);
    if truncated {
        details.insert("l1_anchors_truncated".into(), Value::Bool(true));
    }
    details
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_context_is_bounded_without_scanning_every_match() {
        let patterns = [AnchorPattern {
            category: "test",
            strength: "weak",
            anchor_kind: "lexical",
            pattern: "token",
        }];
        let regexes = [Regex::new("token").unwrap()];
        let details = details(&"token ".repeat(64_000), &regexes, &patterns);
        assert_eq!(details["l1_anchors_truncated"], true);
        assert_eq!(details["l1_anchors"].as_array().unwrap().len(), MAX_ANCHORS);
        assert!(serde_json::to_vec(&details).unwrap().len() <= MAX_JSON_BYTES);
    }

    #[test]
    fn large_escaped_unicode_matches_keep_full_offsets_and_bounded_previews() {
        let patterns = [AnchorPattern {
            category: "test",
            strength: "strong",
            anchor_kind: "structural",
            pattern: r"(?s)BEGIN.*END",
        }];
        let regexes = [Regex::new(patterns[0].pattern).unwrap()];
        let text = format!("Grüße BEGIN{}END", "\u{0001}🛡".repeat(10_000));
        let details = details(&text, &regexes, &patterns);
        let anchor = &details["l1_anchors"][0];
        assert_eq!(anchor["text_truncated"], true);
        assert_eq!(anchor["start_char"], 6);
        assert_eq!(anchor["end_char"], text.chars().count());
        assert_eq!(anchor["end_byte"], text.len());
        assert!(anchor["text"].as_str().unwrap().len() <= MAX_TEXT_BYTES);
        assert!(serde_json::to_vec(&details).unwrap().len() <= MAX_JSON_BYTES);
    }
}
