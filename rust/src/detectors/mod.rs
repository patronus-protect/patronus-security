// SPDX-License-Identifier: GPL-3.0-only
pub(crate) mod anchor_gate;
mod anchors;
pub mod dlp;
pub(crate) mod evidence;
pub mod injection;
pub mod lexical_anchors;
pub mod mcp;
pub(crate) mod obfuscation;
pub mod pii;
pub mod shell;
pub(crate) mod structure;
pub mod threat;
pub mod validators;

use regex::Regex;
use std::{collections::HashMap, ops::Range};

use crate::{EvaluationResult, EvidenceSpan};

pub(crate) type NativeMatchValidator = fn(&str) -> bool;

/// A value that the document structure binds to a rule (K04).
pub(crate) struct StructuredValue {
    /// Byte range of the key that names the value.
    pub key: Range<usize>,
    pub value: Range<usize>,
    /// `json`, `kv`, `xml`, `csv` or `table`.
    pub carrier: &'static str,
}

/// Score of an accepted match in a scored mode, with the context that explains it.
pub(crate) struct MatchScore {
    pub score: f64,
    /// Added to the `matched_rules` entry as `context`.
    pub context: Option<serde_json::Value>,
}

pub(crate) struct NativeDetection {
    pub result: EvaluationResult,
    pub evidence_spans: Vec<EvidenceSpan>,
    pub details: HashMap<String, serde_json::Value>,
}

/// Shared detection contract for native regex scanners that return exact evidence.
pub(crate) trait NativeRegexDetector {
    fn regexes(&self) -> &[Regex];
    fn anchor_gates(&self) -> &[anchor_gate::AnchorGate] {
        &[]
    }
    fn prefilters(&self) -> Option<&[Option<Regex>]> {
        None
    }
    /// One prefilter pass over `text` for all rules (K07): which rules may
    /// match, and where rules searched near their keywords look.
    fn rule_scan(&self, _text: &str) -> Option<dlp::prefilter::RuleScan> {
        None
    }
    /// The matches of rule `index`, identical to `regex.captures_iter(text)`.
    fn rule_captures<'t>(
        &self,
        _index: usize,
        regex: &Regex,
        text: &'t str,
        _scan: Option<&dlp::prefilter::RuleScan>,
    ) -> Vec<regex::Captures<'t>> {
        regex.captures_iter(text).collect()
    }
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
    fn finalize_spans(&self, _text: &str, _spans: &mut Vec<EvidenceSpan>) {}

    /// Rule metadata added to the `matched_rules` entry of a match of rule
    /// `index` with value `value`.
    fn match_details(
        &self,
        _index: usize,
        _value: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    /// Reject contextually ambiguous matches before emitting evidence or rule details.
    fn allows_match(
        &self,
        _index: usize,
        _prepared: &crate::threat::NativeText<'_>,
        _captures: &regex::Captures<'_>,
    ) -> bool {
        true
    }

    /// Value regexes per rule, `(?P<value>…)\z`, for the values that the document
    /// structure binds to the rule (K04). `None` for a rule without structural values.
    fn structured_regexes(&self) -> Option<&[Option<Regex>]> {
        None
    }

    /// The structural fields bound to rule `index`. A
    /// value counts only if the rule's value regex matches it in full; the validator
    /// and [`Self::allows_match`] decide as for a regex match.
    fn structured_values(
        &self,
        _index: usize,
        _prepared: &crate::threat::NativeText<'_>,
    ) -> Vec<StructuredValue> {
        Vec::new()
    }

    fn detect(&self, text: &str) -> NativeDetection {
        self.detect_with_rule_filter(text, |_| true)
    }

    fn detect_with_rule_filter<F>(&self, text: &str, allows_rule: F) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        self.detect_with_options(text, allows_rule, false)
    }

    fn detect_with_options<F>(&self, text: &str, allows_rule: F, explain: bool) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        self.detect_prepared_with_options(
            &crate::threat::NativeText::new(text),
            allows_rule,
            explain,
        )
    }

    /// Score of an accepted match in a scored mode. Unscored detection keeps `1.0`.
    fn match_score(
        &self,
        _index: usize,
        _prepared: &crate::threat::NativeText<'_>,
        _captures: &regex::Captures<'_>,
    ) -> MatchScore {
        MatchScore {
            score: 1.0,
            context: None,
        }
    }

    fn detect_prepared_with_options<F>(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: F,
        explain: bool,
    ) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        self.detect_prepared_scored(prepared, allows_rule, explain, None)
    }

    /// `min_score: None` is the unscored contract: every finding scores `1.0`.
    /// With `Some(threshold)`, findings carry `match_score`, matches below the
    /// threshold are dropped, and `matched_rules` entries record the score and
    /// its context.
    fn detect_prepared_scored<F>(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: F,
        explain: bool,
        min_score: Option<f64>,
    ) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        let text = prepared.text();
        let mut details = if explain {
            self.details(text)
        } else {
            HashMap::new()
        };
        let mut matched_rules = Vec::new();
        let mut class_name = None;
        let mut evidence_spans = Vec::new();
        let scan = self.rule_scan(text);
        for (index, regex) in self.regexes().iter().enumerate() {
            if !allows_rule(self.rule_ids()[index]) {
                continue;
            }
            let gated = scan.as_ref().is_some_and(|scan| !scan.is_active(index))
                || self.anchor_gates().get(index).is_some_and(|gate| {
                    !gate.is_unconditional() && !gate.allows(prepared.anchors())
                })
                || self
                    .prefilters()
                    .and_then(|filters| filters[index].as_ref())
                    .is_some_and(|filter| !filter.is_match(text));
            // Structural values carry their key outside the regex, so the anchor
            // gate and prefilter of the regex do not apply to them.
            let structured = self
                .structured_regexes()
                .and_then(|regexes| regexes[index].as_ref());
            if gated && structured.is_none() {
                continue;
            }
            let value_group = self
                .capture_groups()
                .and_then(|groups| groups.get(index))
                .copied()
                .flatten();
            let regex_matches: Vec<_> = if gated {
                Vec::new()
            } else {
                self.rule_captures(index, regex, text, scan.as_ref())
            };
            let regex_values: Vec<_> = regex_matches
                .iter()
                .filter_map(|captures| captures.get(value_group.unwrap_or(0)))
                .map(|matched| matched.range())
                .collect();
            // A key names its whole value, so structural values come first and keep
            // their span against a shorter regex match of the same rule. A value the
            // regex finds as well keeps the regex evidence (its field name).
            let structural_matches = structured.into_iter().flat_map(|value_regex| {
                self.structured_values(index, prepared)
                    .into_iter()
                    .filter(|structured| !regex_values.contains(&structured.value))
                    .filter_map(move |structured| {
                        let value = structured.value.clone();
                        let captures = value_regex.captures_at(&text[..value.end], value.start)?;
                        (captures.get(0)?.start() == value.start)
                            .then_some((captures, Some(structured)))
                    })
            });
            let candidates = structural_matches
                .collect::<Vec<_>>()
                .into_iter()
                .chain(regex_matches.into_iter().map(|captures| (captures, None)));
            for (captures, structured) in candidates {
                let Some(matched) = captures.get(value_group.unwrap_or(0)) else {
                    continue;
                };
                if matched.is_empty()
                    || self.validators()[index]
                        .is_some_and(|validator| !validator(matched.as_str()))
                    || !self.allows_match(index, prepared, &captures)
                {
                    continue;
                }
                let (score, context) = match min_score {
                    None => (1.0, None),
                    Some(threshold) => {
                        let scored = self.match_score(index, prepared, &captures);
                        if scored.score < threshold {
                            continue;
                        }
                        (scored.score, scored.context)
                    }
                };
                let evidence = match &structured {
                    None => evidence::L1Match::from_captures(regex, &captures, value_group),
                    Some(structured) => evidence::L1Match::at(
                        matched.range(),
                        vec![
                            evidence::L1Component::new("structure_key", structured.key.clone()),
                            evidence::L1Component::new("value", matched.range()),
                        ],
                    ),
                };
                let mut rule = serde_json::json!({
                    "rule_id": self.rule_ids()[index],
                    "start_byte": matched.start(), "end_byte": matched.end(),
                    "components": evidence.components,
                });
                if let Some(structured) = &structured {
                    rule["structure"] = structured.carrier.into();
                }
                if min_score.is_some() {
                    rule["score"] = serde_json::json!(score);
                }
                if let Some(context) = context {
                    rule["context"] = context;
                }
                if let Some(rule) = rule.as_object_mut() {
                    rule.extend(self.match_details(index, matched.as_str()));
                }
                matched_rules.push(rule);
                class_name.get_or_insert(self.entity_groups()[index]);
                evidence_spans.push(EvidenceSpan {
                    label: self.entity_groups()[index].to_string(),
                    text: matched.as_str().to_string(),
                    score,
                    start_byte: matched.start(),
                    end_byte: matched.end(),
                    start_char: 0,
                    end_char: 0,
                });
            }
        }

        if !matched_rules.is_empty() {
            details.insert("matched_rules".into(), serde_json::json!(matched_rules));
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
        let mut intervals = HashMap::<String, std::collections::BTreeMap<usize, usize>>::new();
        for span in evidence_spans {
            let group = if preserve_cross_label_overlaps {
                span.label.clone()
            } else {
                String::new()
            };
            let intervals = intervals.entry(group).or_default();
            let overlaps_existing = intervals
                .range(..span.end_byte)
                .next_back()
                .is_some_and(|(_, &end)| end > span.start_byte);
            if !overlaps_existing {
                intervals.insert(span.start_byte, span.end_byte);
                non_overlapping_spans.push(span);
            }
        }
        self.finalize_spans(text, &mut non_overlapping_spans);
        non_overlapping_spans.sort_by_key(|span| (span.start_byte, span.end_byte));
        if non_overlapping_spans.is_empty() {
            return NativeDetection {
                result: safe_result(),
                evidence_spans: Vec::new(),
                details,
            };
        }
        let final_class_name = if non_overlapping_spans
            .iter()
            .any(|span| span.label == class_name)
        {
            class_name.to_string()
        } else {
            non_overlapping_spans[0].label.clone()
        };
        populate_char_offsets(text, &mut non_overlapping_spans);
        // Unscored findings all score 1.0, so this stays 1.0 without a mode.
        let confidence = non_overlapping_spans
            .iter()
            .map(|span| span.score)
            .fold(0.0, f64::max);
        NativeDetection {
            result: EvaluationResult {
                class_name: final_class_name,
                confidence,
                level: "L1".to_string(),
            },
            evidence_spans: non_overlapping_spans,
            details,
        }
    }
}

pub(crate) fn populate_char_offsets(text: &str, spans: &mut [EvidenceSpan]) {
    let ranges = spans
        .iter()
        .map(|span| (span.start_byte, span.end_byte))
        .collect::<Vec<_>>();
    for (span, (start, end)) in spans.iter_mut().zip(evidence::char_offsets(text, &ranges)) {
        span.start_char = start;
        span.end_char = end;
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
