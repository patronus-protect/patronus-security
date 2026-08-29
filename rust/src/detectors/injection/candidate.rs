// SPDX-License-Identifier: GPL-3.0-only
use serde::Serialize;

use super::signal::{InjectionReference, InjectionSignal};

#[derive(Debug, Serialize)]
pub(crate) struct L1Candidate {
    pub candidate_id: String,
    pub category: &'static str,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
    pub rule_ids: Vec<String>,
    pub families: Vec<String>,
    pub max_severity: String,
    pub features: Vec<L1Feature>,
}

#[derive(Debug, Serialize)]
pub(crate) struct L1Feature {
    pub feature_id: String,
    pub kind: &'static str,
    pub value: f64,
    pub explanation: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
    pub span_precision: &'static str,
    pub provenance: L1FeatureProvenance,
}

#[derive(Debug, Serialize)]
pub(crate) struct L1FeatureProvenance {
    pub rule_id: String,
    pub upstream_id: Option<String>,
    pub source: String,
    pub source_revision: String,
    pub source_license: Option<String>,
    pub source_file: Option<String>,
    pub adaptation: Option<String>,
    pub references: Vec<InjectionReference>,
}

pub(crate) fn candidates_from_signals(text: &str, signals: &[InjectionSignal]) -> Vec<L1Candidate> {
    if signals.is_empty() {
        return Vec::new();
    }

    let mut ordered = signals.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|signal| (signal.start_byte, signal.end_byte, signal.rule_id.as_str()));

    let mut candidates = Vec::new();
    let mut group = vec![ordered[0]];
    let mut group_end = ordered[0].end_byte;
    for signal in ordered.into_iter().skip(1) {
        if signal.start_byte <= group_end {
            group_end = group_end.max(signal.end_byte);
            group.push(signal);
        } else {
            candidates.push(candidate_from_group(text, &group));
            group = vec![signal];
            group_end = signal.end_byte;
        }
    }
    candidates.push(candidate_from_group(text, &group));
    candidates
}

fn candidate_from_group(text: &str, signals: &[&InjectionSignal]) -> L1Candidate {
    let start_byte = signals
        .iter()
        .map(|signal| signal.start_byte)
        .min()
        .expect("candidate group must not be empty");
    let end_byte = signals
        .iter()
        .map(|signal| signal.end_byte)
        .max()
        .expect("candidate group must not be empty");
    let mut rule_ids = Vec::new();
    let mut families = Vec::new();
    for signal in signals {
        push_unique(&mut rule_ids, &signal.rule_id);
        push_unique(&mut families, &signal.family);
    }
    let max_severity = signals
        .iter()
        .max_by_key(|signal| severity_rank(&signal.severity))
        .map(|signal| signal.severity.clone())
        .expect("candidate group must not be empty");
    let features = signals
        .iter()
        .flat_map(|signal| features_from_signal(text, signal))
        .collect();

    L1Candidate {
        candidate_id: format!("injection:l1:{start_byte}:{end_byte}"),
        category: "injection",
        start_byte,
        end_byte,
        start_char: text[..start_byte].chars().count(),
        end_char: text[..end_byte].chars().count(),
        rule_ids,
        families,
        max_severity,
        features,
    }
}

fn features_from_signal(text: &str, signal: &InjectionSignal) -> Vec<L1Feature> {
    if !signal.components.is_empty() {
        return signal
            .components
            .iter()
            .map(|component| L1Feature {
                feature_id: format!(
                    "structural:{}:{}:{}:{}",
                    signal.rule_id,
                    component.component_id,
                    component.start_byte,
                    component.end_byte
                ),
                kind: "structural",
                value: 1.0,
                explanation: component.explanation.to_string(),
                start_byte: component.start_byte,
                end_byte: component.end_byte,
                start_char: text[..component.start_byte].chars().count(),
                end_char: text[..component.end_byte].chars().count(),
                span_precision: component.span_precision,
                provenance: provenance_from_signal(signal),
            })
            .collect();
    }

    vec![L1Feature {
        feature_id: format!(
            "rule:{}:{}:{}",
            signal.rule_id, signal.start_byte, signal.end_byte
        ),
        kind: signal.feature_kind,
        value: 1.0,
        explanation: signal.description.clone(),
        start_byte: signal.start_byte,
        end_byte: signal.end_byte,
        start_char: text[..signal.start_byte].chars().count(),
        end_char: text[..signal.end_byte].chars().count(),
        span_precision: signal.span_precision,
        provenance: provenance_from_signal(signal),
    }]
}

fn provenance_from_signal(signal: &InjectionSignal) -> L1FeatureProvenance {
    L1FeatureProvenance {
        rule_id: signal.rule_id.clone(),
        upstream_id: signal.upstream_id.clone(),
        source: signal.source.clone(),
        source_revision: signal.source_revision.clone(),
        source_license: signal.source_license.clone(),
        source_file: signal.source_file.clone(),
        adaptation: signal.adaptation.clone(),
        references: signal.references.clone(),
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(
        rule_id: &str,
        family: &str,
        severity: &str,
        start: usize,
        end: usize,
    ) -> InjectionSignal {
        InjectionSignal {
            rule_id: rule_id.to_string(),
            upstream_id: None,
            family: family.to_string(),
            severity: severity.to_string(),
            description: format!("{rule_id} explanation"),
            source: "test".to_string(),
            source_revision: "revision".to_string(),
            source_license: None,
            source_file: None,
            provenance_weight: None,
            adaptation: None,
            references: Vec::new(),
            start_byte: start,
            end_byte: end,
            span_precision: "exact",
            feature_kind: "rule_match",
            components: Vec::new(),
        }
    }

    #[test]
    fn overlapping_signals_form_one_candidate_with_all_features() {
        let text = "0123456789abcdefghij";
        let signals = vec![
            signal("rule-b", "boundary", "high", 8, 16),
            signal("rule-a", "override", "critical", 4, 12),
        ];

        let candidates = candidates_from_signals(text, &signals);

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.candidate_id, "injection:l1:4:16");
        assert_eq!(candidate.rule_ids, ["rule-a", "rule-b"]);
        assert_eq!(candidate.families, ["override", "boundary"]);
        assert_eq!(candidate.max_severity, "critical");
        assert_eq!(candidate.features.len(), 2);
    }

    #[test]
    fn separated_signals_remain_separate_candidates() {
        let text = "0123456789abcdefghij";
        let signals = vec![
            signal("rule-a", "override", "high", 1, 4),
            signal("rule-b", "boundary", "high", 10, 14),
        ];

        let candidates = candidates_from_signals(text, &signals);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].candidate_id, "injection:l1:1:4");
        assert_eq!(candidates[1].candidate_id, "injection:l1:10:14");
    }
}
