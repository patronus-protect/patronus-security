// SPDX-License-Identifier: GPL-3.0-only
pub mod dlp;
pub mod injection;
pub mod mcp;
pub mod pii;

use regex::Regex;
use std::collections::HashMap;

use crate::{EvaluationResult, EvidenceSpan};

pub(crate) type NativeMatchValidator = fn(&str) -> bool;

pub(crate) struct NativeDetection {
    pub result: EvaluationResult,
    pub evidence_spans: Vec<EvidenceSpan>,
    pub details: HashMap<String, serde_json::Value>,
}

/// Shared detection contract for native regex scanners that return exact evidence.
pub(crate) trait NativeRegexDetector {
    fn regexes(&self) -> &[Regex];
    fn entity_groups(&self) -> &[&'static str];
    fn rule_ids(&self) -> &[&'static str] {
        self.entity_groups()
    }
    fn validators(&self) -> &[Option<NativeMatchValidator>];
    fn capture_groups(&self) -> Option<&[Option<usize>]> {
        None
    }
    fn preserve_cross_label_overlaps(&self) -> bool {
        false
    }
    fn details(&self, _text: &str) -> HashMap<String, serde_json::Value> {
        HashMap::new()
    }

    fn detect(&self, text: &str) -> NativeDetection {
        self.detect_with_rule_filter(text, |_| true)
    }

    fn detect_with_rule_filter<F>(&self, text: &str, allows_rule: F) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        let details = self.details(text);
        let mut class_name = None;
        let mut evidence_spans = Vec::new();
        for (index, regex) in self.regexes().iter().enumerate() {
            if !allows_rule(self.rule_ids()[index]) {
                continue;
            }
            let mut push_match = |matched: regex::Match<'_>| {
                if self.validators()[index].is_some_and(|validator| !validator(matched.as_str())) {
                    return;
                }
                class_name.get_or_insert(self.entity_groups()[index]);
                evidence_spans.push(EvidenceSpan {
                    label: self.entity_groups()[index].to_string(),
                    text: matched.as_str().to_string(),
                    score: 1.0,
                    start_byte: matched.start(),
                    end_byte: matched.end(),
                    start_char: 0,
                    end_char: 0,
                });
            };
            if let Some(group) = self
                .capture_groups()
                .and_then(|groups| groups.get(index))
                .copied()
                .flatten()
            {
                for captures in regex.captures_iter(text) {
                    if let Some(matched) = captures.get(group) {
                        push_match(matched);
                    }
                }
            } else {
                for matched in regex.find_iter(text) {
                    push_match(matched);
                }
            }
        }

        let Some(class_name) = class_name else {
            return NativeDetection {
                result: safe_result(),
                evidence_spans: Vec::new(),
                details,
            };
        };
        let preserve_cross_label_overlaps = self.preserve_cross_label_overlaps();
        let mut non_overlapping_spans = Vec::with_capacity(evidence_spans.len());
        for span in evidence_spans {
            let overlaps_existing = non_overlapping_spans.iter().any(|existing: &EvidenceSpan| {
                span.start_byte < existing.end_byte
                    && existing.start_byte < span.end_byte
                    && (!preserve_cross_label_overlaps || span.label == existing.label)
            });
            if !overlaps_existing {
                non_overlapping_spans.push(span);
            }
        }
        non_overlapping_spans.sort_by_key(|span| (span.start_byte, span.end_byte));
        if preserve_cross_label_overlaps {
            populate_overlapping_char_offsets(text, &mut non_overlapping_spans);
        } else {
            populate_char_offsets(text, &mut non_overlapping_spans);
        }
        NativeDetection {
            result: EvaluationResult {
                class_name: class_name.to_string(),
                confidence: 1.0,
                level: "L1".to_string(),
            },
            evidence_spans: non_overlapping_spans,
            details,
        }
    }
}

fn populate_char_offsets(text: &str, spans: &mut [EvidenceSpan]) {
    let mut byte_cursor = 0;
    let mut char_cursor = 0;
    for span in spans {
        char_cursor += text[byte_cursor..span.start_byte].chars().count();
        span.start_char = char_cursor;
        char_cursor += text[span.start_byte..span.end_byte].chars().count();
        span.end_char = char_cursor;
        byte_cursor = span.end_byte;
    }
}

fn populate_overlapping_char_offsets(text: &str, spans: &mut [EvidenceSpan]) {
    for span in spans {
        span.start_char = text[..span.start_byte].chars().count();
        span.end_char = text[..span.end_byte].chars().count();
    }
}

fn safe_result() -> EvaluationResult {
    EvaluationResult {
        class_name: "safe".to_string(),
        confidence: 1.0,
        level: "L1".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDetector {
        regexes: Vec<Regex>,
        capture_groups: Option<Vec<Option<usize>>>,
        rule_ids: Vec<&'static str>,
    }

    impl TestDetector {
        fn new(pattern: &str, capture_group: Option<usize>) -> Self {
            Self {
                regexes: vec![Regex::new(pattern).unwrap()],
                capture_groups: capture_group.map(|group| vec![Some(group)]),
                rule_ids: vec!["test.rule"],
            }
        }
    }

    impl NativeRegexDetector for TestDetector {
        fn regexes(&self) -> &[Regex] {
            &self.regexes
        }

        fn entity_groups(&self) -> &[&'static str] {
            &["TEST_ID"]
        }

        fn rule_ids(&self) -> &[&'static str] {
            &self.rule_ids
        }

        fn validators(&self) -> &[Option<NativeMatchValidator>] {
            &[None]
        }

        fn capture_groups(&self) -> Option<&[Option<usize>]> {
            self.capture_groups.as_deref()
        }
    }

    #[test]
    fn default_detector_emits_the_complete_match() {
        let detector = TestDetector::new(r"Kundennummer:\s*[[:alnum:]-]+", None);
        let detection = detector.detect("Vor Kundennummer: ABC-42 nach");

        assert_eq!(detection.evidence_spans.len(), 1);
        assert_eq!(detection.evidence_spans[0].text, "Kundennummer: ABC-42");
    }

    #[test]
    fn capture_detector_emits_only_value_with_utf8_offsets() {
        let detector = TestDetector::new(r"Kundennummer:\s*(\S+)", Some(1));
        let text = "Grüße – Kundennummer: ÄBC-42 danach";
        let detection = detector.detect(text);
        let value = text.find("ÄBC-42").unwrap();
        let span = &detection.evidence_spans[0];

        assert_eq!(span.text, "ÄBC-42");
        assert_eq!(
            (span.start_byte, span.end_byte),
            (value, value + "ÄBC-42".len())
        );
        assert_eq!(span.start_char, text[..value].chars().count());
        assert_eq!(
            span.end_char,
            text[..value + "ÄBC-42".len()].chars().count()
        );
    }

    #[test]
    fn opted_in_detector_preserves_overlaps_between_different_labels() {
        struct OverlapDetector {
            regexes: Vec<Regex>,
        }

        impl NativeRegexDetector for OverlapDetector {
            fn regexes(&self) -> &[Regex] {
                &self.regexes
            }

            fn entity_groups(&self) -> &[&'static str] {
                &["SOURCE_CODE", "CREDENTIAL"]
            }

            fn validators(&self) -> &[Option<NativeMatchValidator>] {
                &[None, None]
            }

            fn preserve_cross_label_overlaps(&self) -> bool {
                true
            }
        }

        let patterns = [r"(?s)```.*?```", r"sk-test-[A-Za-z0-9]+"];
        let detector = OverlapDetector {
            regexes: patterns
                .iter()
                .map(|pattern| Regex::new(pattern).unwrap())
                .collect(),
        };
        let detection = detector.detect("```python\ntoken = \"sk-test-abc123\"\n```");

        assert_eq!(detection.evidence_spans.len(), 2);
        assert_eq!(detection.evidence_spans[0].label, "SOURCE_CODE");
        assert_eq!(detection.evidence_spans[1].label, "CREDENTIAL");
    }

    #[test]
    fn rule_filter_skips_only_the_disabled_pattern() {
        let detector = TestDetector::new(r"Kundennummer:\s*(\S+)", Some(1));

        let detection = detector
            .detect_with_rule_filter("Kundennummer: ABC-42", |rule_id| rule_id != "test.rule");

        assert_eq!(detection.result.class_name, "safe");
        assert!(detection.evidence_spans.is_empty());
    }
}
