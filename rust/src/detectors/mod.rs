// SPDX-License-Identifier: AGPL-3.0-only
pub mod dlp;
pub mod injection;
pub mod mcp;
pub mod pii;

use regex::{Regex, RegexSet};

use crate::{EvaluationResult, EvidenceSpan};

pub(crate) type NativeMatchValidator = fn(&str) -> bool;

pub(crate) struct NativeDetection {
    pub result: EvaluationResult,
    pub evidence_spans: Vec<EvidenceSpan>,
}

/// Shared detection contract for native regex scanners that return exact evidence.
pub(crate) trait NativeRegexDetector {
    fn regex_set(&self) -> &RegexSet;
    fn regexes(&self) -> &[Regex];
    fn entity_groups(&self) -> &[&'static str];
    fn validators(&self) -> &[Option<NativeMatchValidator>];

    fn detect(&self, text: &str) -> NativeDetection {
        let candidate_indices = self.regex_set().matches(text);
        if !candidate_indices.matched_any() {
            return NativeDetection {
                result: safe_result(),
                evidence_spans: Vec::new(),
            };
        }

        let mut class_name = None;
        let mut evidence_spans = Vec::new();
        for index in candidate_indices.iter() {
            for matched in self.regexes()[index].find_iter(text) {
                if self.validators()[index].is_some_and(|validator| !validator(matched.as_str())) {
                    continue;
                }
                class_name.get_or_insert(self.entity_groups()[index]);
                evidence_spans.push(EvidenceSpan {
                    label: self.entity_groups()[index].to_string(),
                    text: matched.as_str().to_string(),
                    score: 1.0,
                    start_byte: matched.start(),
                    end_byte: matched.end(),
                    start_char: text[..matched.start()].chars().count(),
                    end_char: text[..matched.end()].chars().count(),
                });
            }
        }

        let Some(class_name) = class_name else {
            return NativeDetection {
                result: safe_result(),
                evidence_spans: Vec::new(),
            };
        };
        let mut non_overlapping_spans = Vec::with_capacity(evidence_spans.len());
        for span in evidence_spans {
            let overlaps_existing = non_overlapping_spans.iter().any(|existing: &EvidenceSpan| {
                span.start_byte < existing.end_byte && existing.start_byte < span.end_byte
            });
            if !overlaps_existing {
                non_overlapping_spans.push(span);
            }
        }
        non_overlapping_spans.sort_by_key(|span| (span.start_byte, span.end_byte));
        NativeDetection {
            result: EvaluationResult {
                class_name: class_name.to_string(),
                confidence: 1.0,
                level: "L1".to_string(),
            },
            evidence_spans: non_overlapping_spans,
        }
    }
}

fn safe_result() -> EvaluationResult {
    EvaluationResult {
        class_name: "safe".to_string(),
        confidence: 1.0,
        level: "L1".to_string(),
    }
}
