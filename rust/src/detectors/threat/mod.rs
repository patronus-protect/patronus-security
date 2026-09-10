// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, source-bound Threat L1 rules. A match describes risky behavior,
//! not a calibrated probability that the author is malicious.
use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::json;

use super::{
    evidence::{char_offsets, L1Match},
    NativeDetection,
};
use crate::{EvaluationResult, EvidenceSpan};

mod scorer;

const RULES: &str = include_str!("rules.json");
const MAX_FINDINGS: usize = 256;
const WINDOW_BYTES: usize = 8192;
const OVERLAP_BYTES: usize = 4096;

#[derive(Deserialize)]
struct Catalog {
    schema_version: u32,
    reference_revision: String,
    rules: Vec<Rule>,
}
#[derive(Deserialize)]
struct Rule {
    id: String,
    class_name: String,
    upstream_groups: Vec<String>,
    pattern: String,
}
struct CompiledRule {
    rule: Rule,
    regex: Regex,
    anchor_gate: super::anchor_gate::AnchorGate,
}

fn catalog() -> &'static (String, Vec<CompiledRule>) {
    static COMPILED: OnceLock<(String, Vec<CompiledRule>)> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let catalog: Catalog = serde_json::from_str(RULES).expect("valid Threat L1 catalog");
        assert_eq!(catalog.schema_version, 1);
        let mut ids = HashSet::new();
        let rules = catalog
            .rules
            .into_iter()
            .map(|rule| {
                assert!(ids.insert(rule.id.clone()), "duplicate Threat rule");
                let regex = RegexBuilder::new(&rule.pattern)
                    .case_insensitive(true)
                    .build()
                    .expect("valid bounded Threat regex");
                assert!(
                    regex.capture_names().flatten().count() >= 2,
                    "Threat rules require components"
                );
                let anchor_gate = super::anchor_gate::AnchorGate::regex(&rule.pattern, true);
                CompiledRule {
                    rule,
                    regex,
                    anchor_gate,
                }
            })
            .collect();
        (catalog.reference_revision, rules)
    })
}

pub struct ThreatPipeline;
impl Default for ThreatPipeline {
    fn default() -> Self {
        Self::new()
    }
}
impl ThreatPipeline {
    pub fn new() -> Self {
        let _ = catalog();
        Self
    }

    pub(crate) fn detect(&self, text: &str, allows_rule: impl Fn(&str) -> bool) -> NativeDetection {
        self.detect_prepared(&crate::threat::NativeText::new(text), allows_rule)
    }

    pub(crate) fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: impl Fn(&str) -> bool,
    ) -> NativeDetection {
        let text = prepared.text();
        let (revision, rules) = catalog();
        let enabled: Vec<_> = rules
            .iter()
            .filter(|r| {
                allows_rule(&r.rule.id)
                    && (r.anchor_gate.is_unconditional()
                        || r.anchor_gate.allows(prepared.anchors()))
            })
            .collect();
        let mut spans = Vec::new();
        let mut matched_rules = Vec::new();
        let mut seen = HashSet::new();
        let mut window_start = 0;
        let mut capped = false;
        'windows: while window_start < text.len() && !enabled.is_empty() {
            let mut window_end = (window_start + WINDOW_BYTES).min(text.len());
            while !text.is_char_boundary(window_end) {
                window_end -= 1;
            }
            let window = &text[window_start..window_end];
            for compiled in &enabled {
                for captures in compiled.regex.captures_iter(window) {
                    let m = captures.get(0).unwrap();
                    // A window edge is not a source word/URL boundary. The
                    // overlapping next/previous window covers complete matches.
                    if (window_end < text.len() && m.end() == window.len())
                        || (window_start > 0 && m.start() == 0)
                    {
                        continue;
                    }
                    let start = window_start + m.start();
                    let end = window_start + m.end();
                    if is_negated(text, start, end) {
                        continue;
                    }
                    if compiled.rule.id == "ark.threat.ssrf_metadata"
                        && !metadata_url(captures.name("url").unwrap().as_str())
                    {
                        continue;
                    }
                    if compiled.rule.id == "ark.threat.privileged_container"
                        && text[end..].starts_with('=')
                    {
                        continue;
                    }
                    if let (Some(action), Some(target)) = (
                        captures
                            .name("access")
                            .or_else(|| captures.name("transfer"))
                            .or_else(|| captures.name("action")),
                        captures
                            .name("target")
                            .or_else(|| captures.name("secret"))
                            .or_else(|| captures.name("guard")),
                    ) {
                        if action.end() <= target.start()
                            && negated_object(&window[action.end()..target.start()])
                        {
                            continue;
                        }
                    }
                    if !seen.insert((compiled.rule.id.as_str(), start, end)) {
                        continue;
                    }
                    if spans.len() == MAX_FINDINGS {
                        capped = true;
                        break 'windows;
                    }
                    let mut evidence = L1Match::from_captures(&compiled.regex, &captures, None);
                    for component in &mut evidence.components {
                        component.start_byte += window_start;
                        component.end_byte += window_start;
                    }
                    matched_rules.push(json!({
                        "rule_id": compiled.rule.id, "class_name": compiled.rule.class_name,
                        "start_byte": start, "end_byte": end,
                        "components": evidence.components, "span_precision": "exact",
                        "source": "ark-native", "source_revision": env!("CARGO_PKG_VERSION"),
                        "references": {"source": "NVIDIA/SkillSpector", "revision": revision,
                            "groups": compiled.rule.upstream_groups},
                    }));
                    spans.push(EvidenceSpan {
                        label: compiled.rule.class_name.clone(),
                        text: text[start..end].into(),
                        score: 1.0,
                        start_byte: start,
                        end_byte: end,
                        start_char: 0,
                        end_char: 0,
                    });
                }
            }
            if window_end == text.len() {
                break;
            }
            window_start = window_end - OVERLAP_BYTES;
            while !text.is_char_boundary(window_start) {
                window_start += 1;
            }
        }
        let (score, accepted) = scorer::score(&matched_rules);
        if !accepted {
            spans.clear();
        } else {
            for span in &mut spans {
                span.score = score;
            }
        }
        spans.sort_by_key(|s| (s.start_byte, s.end_byte, s.label.clone()));
        let ranges: Vec<_> = spans.iter().map(|s| (s.start_byte, s.end_byte)).collect();
        for (span, (start, end)) in spans.iter_mut().zip(char_offsets(text, &ranges)) {
            span.start_char = start;
            span.end_char = end;
        }
        // Use the existing unified Threat taxonomy. Prefer the most specific risk
        // when one operation has both access and transfer evidence.
        let class_name = [
            "exfiltration_attempt",
            "harmful_behavior",
            "secrets_access",
            "tool_abuse",
        ]
        .into_iter()
        .find(|class| spans.iter().any(|s| s.label == *class))
        .unwrap_or("benign");
        let details = HashMap::from([
            ("matched_rules".into(), json!(matched_rules)),
            ("score".into(), json!(score)),
            ("accepted".into(), json!(accepted)),
            (
                "acceptance_threshold".into(),
                json!(scorer::config().acceptance_threshold),
            ),
            (
                "score_version".into(),
                json!(scorer::config().score_version),
            ),
            ("registry_id".into(), json!("ark-threat-l1-0.1.7")),
            ("match_limit_reached".into(), json!(capped)),
            (
                "confidence_semantics".into(),
                json!("logistic_decision_score_not_malicious_intent_probability"),
            ),
        ]);
        NativeDetection {
            result: EvaluationResult {
                class_name: class_name.into(),
                confidence: if accepted { score } else { 1.0 - score },
                level: "L1".into(),
            },
            evidence_spans: spans,
            details,
        }
    }
}

fn metadata_url(input: &str) -> bool {
    let Ok(url) = url::Url::parse(input) else {
        return false;
    };
    matches!(
        url.host_str(),
        Some(
            "169.254.169.254"
                | "100.100.100.200"
                | "metadata.google.internal"
                | "[fd00:ec2::254]"
                | "[::ffff:a9fe:a9fe]"
        )
    )
}

/// Only local grammatical negation, never a document-wide allowlist. Quoting
/// an executable command does not by itself make the command harmless.
fn is_negated(text: &str, start: usize, end: usize) -> bool {
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    static SUFFIX: OnceLock<Regex> = OnceLock::new();
    let prefix = PREFIX.get_or_init(|| Regex::new(r"(?i)(?:\bdo not|\bdon't|\bnever|\bavoid|\bmust not|\bshould not|\bnicht|\bniemals|\bnie|\bvermeide)(?:[ \t]+[\p{L}-]+){0,5}[ \t]+$").unwrap());
    let suffix = SUFFIX
        .get_or_init(|| Regex::new(r"(?i)^[ \t]+(?:bitte[ \t]+)?(?:nicht|niemals|nie)\b").unwrap());
    let mut before = start.saturating_sub(160);
    while !text.is_char_boundary(before) {
        before += 1;
    }
    prefix.is_match(&text[before..start]) || suffix.is_match(&text[end..])
}

fn negated_object(text: &str) -> bool {
    static NEGATION: OnceLock<Regex> = OnceLock::new();
    NEGATION
        .get_or_init(|| Regex::new(r"(?i)\b(?:no|not|never|keine?[nmr]?|nicht|niemals)\b").unwrap())
        .is_match(text)
}
