// SPDX-License-Identifier: GPL-3.0-only
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::candidate::candidates_from_signals;
use crate::detectors::NativeDetection;
use crate::{EvaluationResult, EvidenceSpan};

const ARK_NATIVE_REGISTRY_JSON: &str = include_str!("rules/ark_native_71ff48e.json");
const SIGNAL_WINDOW_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub(crate) struct InjectionSignal {
    pub rule_id: String,
    pub upstream_id: Option<String>,
    pub family: String,
    pub severity: String,
    pub description: String,
    pub source: String,
    pub source_revision: String,
    pub source_license: Option<String>,
    pub source_file: Option<String>,
    pub provenance_weight: Option<f64>,
    pub evidence_tier: Option<String>,
    pub candidate_only: bool,
    pub adaptation: Option<String>,
    pub references: Vec<InjectionReference>,
    pub start_byte: usize,
    pub end_byte: usize,
    pub span_precision: &'static str,
    pub feature_kind: &'static str,
    pub components: Vec<InjectionSignalComponent>,
}

#[derive(Debug, Clone)]
pub(crate) struct InjectionSignalComponent {
    pub component_id: &'static str,
    pub explanation: &'static str,
    pub start_byte: usize,
    pub end_byte: usize,
    pub span_precision: &'static str,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct InjectionReference {
    pub source: String,
    pub source_revision: String,
    pub upstream_id: String,
}

#[derive(Debug, Deserialize)]
struct NativeRegistry {
    schema_version: u32,
    registry_id: String,
    source: String,
    source_revision: String,
    rules: Vec<NativeRuleDefinition>,
}

#[derive(Debug, Deserialize)]
struct NativeRuleDefinition {
    model: String,
    id: String,
    family: String,
    severity: String,
    description: String,
    source_file: String,
}

pub(crate) fn native_signals<F>(model: &str, text: &str, evaluate: F) -> Vec<InjectionSignal>
where
    F: Fn(&str) -> EvaluationResult,
{
    let registry = native_registry();
    let definition = registry
        .rules
        .iter()
        .find(|definition| definition.model == model)
        .unwrap_or_else(|| panic!("missing injection registry entry for {model}"));
    localized_matches(text, evaluate)
        .into_iter()
        .map(|(start_byte, end_byte, span_precision)| InjectionSignal {
            rule_id: definition.id.clone(),
            upstream_id: None,
            family: definition.family.clone(),
            severity: definition.severity.clone(),
            description: definition.description.clone(),
            source: registry.source.clone(),
            source_revision: registry.source_revision.clone(),
            source_license: None,
            source_file: Some(definition.source_file.clone()),
            provenance_weight: None,
            evidence_tier: None,
            candidate_only: false,
            adaptation: None,
            references: Vec::new(),
            start_byte,
            end_byte,
            span_precision,
            feature_kind: "rule_match",
            components: Vec::new(),
        })
        .collect()
}

pub(crate) fn detection_from_signals(
    result: EvaluationResult,
    text: &str,
    signals: Vec<InjectionSignal>,
    registry_id: Option<&str>,
) -> NativeDetection {
    let candidates = candidates_from_signals(text, &signals);
    let evidence_spans = signals
        .iter()
        .map(|signal| EvidenceSpan {
            label: signal.rule_id.clone(),
            text: text[signal.start_byte..signal.end_byte].to_string(),
            score: 1.0,
            start_byte: signal.start_byte,
            end_byte: signal.end_byte,
            start_char: text[..signal.start_byte].chars().count(),
            end_char: text[..signal.end_byte].chars().count(),
        })
        .collect();
    let mut details = HashMap::new();
    if let Some(registry_id) = registry_id {
        details.insert("registry_id".to_string(), json!(registry_id));
    }
    if !signals.is_empty() {
        details.insert(
            "matched_rules".to_string(),
            Value::Array(signals.iter().map(signal_json).collect()),
        );
        details.insert(
            "l1_candidates".to_string(),
            serde_json::to_value(candidates).expect("L1 candidates must serialize"),
        );
    }
    NativeDetection {
        result,
        evidence_spans,
        details,
    }
}

pub(crate) fn native_registry_id() -> &'static str {
    &native_registry().registry_id
}

fn native_registry() -> &'static NativeRegistry {
    static REGISTRY: OnceLock<NativeRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry: NativeRegistry = serde_json::from_str(ARK_NATIVE_REGISTRY_JSON)
            .expect("embedded native injection registry must parse");
        assert_eq!(registry.schema_version, 1, "unsupported registry schema");
        let mut models = HashSet::new();
        let mut ids = HashSet::new();
        for rule in &registry.rules {
            assert!(
                models.insert(&rule.model),
                "duplicate model: {}",
                rule.model
            );
            assert!(ids.insert(&rule.id), "duplicate rule ID: {}", rule.id);
        }
        registry
    })
}

fn signal_json(signal: &InjectionSignal) -> Value {
    let mut value = json!({
        "rule_id": signal.rule_id,
        "upstream_id": signal.upstream_id,
        "family": signal.family,
        "severity": signal.severity,
        "description": signal.description,
        "source": signal.source,
        "source_revision": signal.source_revision,
        "source_license": signal.source_license,
        "source_file": signal.source_file,
        "provenance_weight": signal.provenance_weight,
        "adaptation": signal.adaptation,
        "references": signal.references,
        "start_byte": signal.start_byte,
        "end_byte": signal.end_byte,
        "span_precision": signal.span_precision,
    });
    if let Some(evidence_tier) = &signal.evidence_tier {
        value["evidence_tier"] = json!(evidence_tier);
    }
    if signal.candidate_only {
        value["candidate_only"] = json!(true);
    }
    value
}

fn localized_matches<F>(text: &str, evaluate: F) -> Vec<(usize, usize, &'static str)>
where
    F: Fn(&str) -> EvaluationResult,
{
    let mut matches = candidate_clauses(text)
        .into_iter()
        .filter(|(start, end)| evaluate(&text[*start..*end]).class_name != "safe")
        .map(|(start, end)| (start, end, "clause"))
        .collect::<Vec<_>>();
    if matches.is_empty() {
        matches = candidate_windows(text, SIGNAL_WINDOW_BYTES)
            .into_iter()
            .filter(|(start, end)| evaluate(&text[*start..*end]).class_name != "safe")
            .map(|(start, end)| (start, end, "window"))
            .collect();
    }
    if matches.is_empty() && evaluate(text).class_name != "safe" {
        matches.push((0, text.len(), "document"));
    }
    matches.dedup_by_key(|(start, end, _)| (*start, *end));
    matches
}

pub(crate) fn candidate_clauses(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (index, character) in text.char_indices() {
        if matches!(character, '.' | '!' | '?' | ';' | '\n') {
            push_trimmed_span(text, start, index + character.len_utf8(), &mut spans);
            start = index + character.len_utf8();
        }
    }
    push_trimmed_span(text, start, text.len(), &mut spans);
    spans
}

fn candidate_windows(text: &str, window_bytes: usize) -> Vec<(usize, usize)> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut windows = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + window_bytes).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        push_trimmed_span(text, start, end, &mut windows);
        if end == text.len() {
            break;
        }
        start = end.saturating_sub(window_bytes / 3);
        while !text.is_char_boundary(start) {
            start += 1;
        }
    }
    windows
}

fn push_trimmed_span(text: &str, start: usize, end: usize, spans: &mut Vec<(usize, usize)>) {
    let candidate = &text[start..end];
    let leading = candidate.len() - candidate.trim_start().len();
    let trailing = candidate.len() - candidate.trim_end().len();
    let trimmed_start = start + leading;
    let trimmed_end = end.saturating_sub(trailing);
    if trimmed_start < trimmed_end {
        spans.push((trimmed_start, trimmed_end));
    }
}
