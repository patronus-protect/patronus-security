// SPDX-License-Identifier: GPL-3.0-only
//! Shared, source-bound evidence produced by native L1 matchers.
use std::ops::Range;

use serde::Serialize;

use super::NativeDetection;
use crate::{EvaluationResult, EvidenceSpan};

/// Resolve all requested UTF-8 boundaries in one forward traversal, including
/// overlapping spans. Memory scales with the number of spans, not text bytes.
pub(crate) fn char_offsets(text: &str, ranges: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut boundaries = ranges
        .iter()
        .enumerate()
        .flat_map(|(index, &(start, end))| [(start, index, false), (end, index, true)])
        .collect::<Vec<_>>();
    boundaries.sort_unstable();
    let mut offsets = vec![(0, 0); ranges.len()];
    let (mut byte_cursor, mut char_cursor) = (0, 0);
    for (byte, index, is_end) in boundaries {
        char_cursor += text[byte_cursor..byte].chars().count();
        byte_cursor = byte;
        if is_end {
            offsets[index].1 = char_cursor;
        } else {
            offsets[index].0 = char_cursor;
        }
    }
    offsets
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct L1Component {
    pub component_id: String,
    pub explanation: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub span_precision: &'static str,
}

impl L1Component {
    pub fn new(id: impl Into<String>, range: Range<usize>) -> Self {
        let id = id.into();
        Self {
            explanation: id.clone(),
            component_id: id,
            start_byte: range.start,
            end_byte: range.end,
            span_precision: "exact",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct L1Match {
    pub components: Vec<L1Component>,
    source: Range<usize>,
}

impl L1Match {
    pub fn new(components: Vec<L1Component>) -> Self {
        assert!(!components.is_empty(), "L1 matches require source evidence");
        let source = components.iter().map(|c| c.start_byte).min().unwrap()
            ..components.iter().map(|c| c.end_byte).max().unwrap();
        Self { components, source }
    }

    pub fn range(&self) -> Range<usize> {
        self.source.clone()
    }

    pub fn at(source: Range<usize>, components: Vec<L1Component>) -> Self {
        let mut matched = Self::new(components);
        matched.source = source;
        matched
    }

    /// Regex validators consume the value; surrounding captures retain the anchors.
    pub fn from_captures(
        regex: &regex::Regex,
        captures: &regex::Captures<'_>,
        value_group: Option<usize>,
    ) -> Self {
        let whole = captures.get(0).unwrap();
        let mut components = Vec::new();
        if let Some(value) = value_group.and_then(|g| captures.get(g)) {
            if whole.start() < value.start() {
                components.push(L1Component::new(
                    "anchor_prefix",
                    whole.start()..value.start(),
                ));
            }
            components.push(L1Component::new("value", value.range()));
            if value.end() < whole.end() {
                components.push(L1Component::new("anchor_suffix", value.end()..whole.end()));
            }
        } else {
            components.push(L1Component::new("value", whole.range()));
            for (index, name) in regex.capture_names().enumerate().skip(1) {
                if let Some(found) = captures.get(index).filter(|m| !m.is_empty()) {
                    components.push(L1Component::new(
                        name.map(str::to_owned)
                            .unwrap_or_else(|| format!("anchor_{index}")),
                        found.range(),
                    ));
                }
            }
        }
        Self::at(whole.range(), components)
    }
}

/// Case-folded matching view with offsets mapped back to the original UTF-8 text.
/// Unlike `to_lowercase()` plus byte offsets, this handles expanding characters.
pub(crate) struct MatchText {
    pub text: String,
    starts: Vec<usize>,
    ends: Vec<usize>,
}

impl MatchText {
    pub fn lower(original: &str) -> Self {
        // ASCII lowercasing preserves every byte offset; avoid two mapping arrays.
        if original.is_ascii() {
            return Self {
                text: original.to_ascii_lowercase(),
                starts: Vec::new(),
                ends: Vec::new(),
            };
        }
        Self::mapped(original, Some, true)
    }

    pub fn mapped(original: &str, map: impl Fn(char) -> Option<char>, lowercase: bool) -> Self {
        let mut text = String::new();
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        for (start, c) in original.char_indices() {
            let Some(mapped) = map(c) else {
                continue;
            };
            let mut push = |value: char| {
                text.push(value);
                starts.extend(std::iter::repeat_n(start, value.len_utf8()));
                ends.extend(std::iter::repeat_n(start + c.len_utf8(), value.len_utf8()));
            };
            if lowercase {
                for lower in mapped.to_lowercase() {
                    push(lower);
                }
            } else {
                push(mapped);
            }
        }
        Self { text, starts, ends }
    }

    pub fn component(&self, id: impl Into<String>, range: Range<usize>) -> L1Component {
        assert!(range.start < range.end);
        if self.starts.is_empty() {
            return L1Component::new(id, range);
        }
        L1Component::new(id, self.starts[range.start]..self.ends[range.end - 1])
    }
}

pub(crate) fn detection_from_matches(
    text: &str,
    rule_id: &str,
    class_name: &str,
    matches: Vec<L1Match>,
) -> NativeDetection {
    let mut evidence_spans = Vec::new();
    let mut matched_rules = Vec::new();
    for matched in matches {
        let range = matched.range();
        evidence_spans.push(EvidenceSpan {
            label: class_name.into(),
            text: text[range.clone()].into(),
            score: 1.0,
            start_byte: range.start,
            end_byte: range.end,
            start_char: text[..range.start].chars().count(),
            end_char: text[..range.end].chars().count(),
        });
        matched_rules.push(serde_json::json!({
            "rule_id": rule_id, "start_byte": range.start, "end_byte": range.end,
            "components": matched.components,
        }));
    }
    NativeDetection {
        result: EvaluationResult {
            class_name: if evidence_spans.is_empty() {
                "safe"
            } else {
                class_name
            }
            .into(),
            confidence: 1.0,
            level: "L1".into(),
        },
        evidence_spans,
        details: if matched_rules.is_empty() {
            std::collections::HashMap::new()
        } else {
            std::collections::HashMap::from([(
                "matched_rules".into(),
                serde_json::json!(matched_rules),
            )])
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expanding_lowercase_and_multibyte_prefix_keep_original_offsets() {
        let text = "İ – Grüße PASSWORD";
        let view = MatchText::lower(text);
        let start = view.text.find("password").unwrap();
        let component = view.component("anchor", start..start + 8);
        assert_eq!(&text[component.start_byte..component.end_byte], "PASSWORD");
        let expanding = view.component("expanding", 0..3);
        assert_eq!(&text[expanding.start_byte..expanding.end_byte], "İ");
    }
}
