// SPDX-License-Identifier: GPL-3.0-only
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::signal::{InjectionReference, InjectionSignal};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct L1Candidate {
    pub candidate_id: String,
    pub category: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
    pub rule_ids: Vec<String>,
    pub rule_severities: BTreeMap<String, String>,
    pub families: Vec<String>,
    pub max_severity: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub candidate_only: bool,
    pub features: Vec<L1Feature>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct L1Feature {
    pub feature_id: String,
    pub kind: String,
    pub value: f64,
    pub explanation: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
    pub span_precision: String,
    pub provenance: L1FeatureProvenance,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct L1FeatureProvenance {
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    pub upstream_id: Option<String>,
    pub source: String,
    pub source_revision: String,
    pub source_license: Option<String>,
    pub source_file: Option<String>,
    pub adaptation: Option<String>,
    pub references: Vec<InjectionReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_tier: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub candidate_only: bool,
}

pub(crate) fn candidates_from_signals(text: &str, signals: &[InjectionSignal]) -> Vec<L1Candidate> {
    if signals.is_empty() {
        return Vec::new();
    }

    let mut eligible = signals
        .iter()
        .filter(|signal| !signal.candidate_only)
        .collect::<Vec<_>>();
    let mut candidate_only = signals
        .iter()
        .filter(|signal| signal.candidate_only)
        .collect::<Vec<_>>();
    let compare = |left: &&InjectionSignal, right: &&InjectionSignal| {
        (left.start_byte, left.end_byte, left.rule_id.as_str()).cmp(&(
            right.start_byte,
            right.end_byte,
            right.rule_id.as_str(),
        ))
    };
    eligible.sort_by(compare);
    candidate_only.sort_by(compare);

    let mut groups: Vec<Vec<&InjectionSignal>> = Vec::new();
    for signal in eligible {
        if let Some(group) = groups.last_mut() {
            let acceptance_end = group
                .iter()
                .filter(|member| !member.candidate_only)
                .map(|member| member.end_byte)
                .max()
                .expect("eligible group must contain acceptance evidence");
            if signal.start_byte <= acceptance_end {
                group.push(signal);
                continue;
            }
        }
        groups.push(vec![signal]);
    }

    let mut unattached = Vec::new();
    for signal in candidate_only {
        if let Some(group) = groups.iter_mut().find(|group| {
            acceptance_bounds_for_signals(group)
                .is_some_and(|(start, end)| signal.start_byte <= end && start <= signal.end_byte)
        }) {
            group.push(signal);
        } else {
            unattached.push(signal);
        }
    }

    for signal in unattached {
        if let Some(group) = groups.last_mut().filter(|group| {
            group.iter().all(|member| member.candidate_only)
                && signal.start_byte
                    <= group
                        .iter()
                        .map(|member| member.end_byte)
                        .max()
                        .expect("candidate-only group must not be empty")
        }) {
            group.push(signal);
        } else {
            groups.push(vec![signal]);
        }
    }
    let mut candidates = groups
        .iter()
        .map(|group| candidate_from_group(text, group))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| (candidate.start_byte, candidate.end_byte));
    candidates
}

fn acceptance_bounds_for_signals(signals: &[&InjectionSignal]) -> Option<(usize, usize)> {
    let mut eligible = signals.iter().filter(|signal| !signal.candidate_only);
    let first = eligible.next()?;
    Some(eligible.fold(
        (first.start_byte, first.end_byte),
        |(start, end), signal| (start.min(signal.start_byte), end.max(signal.end_byte)),
    ))
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
    let mut rule_severities = BTreeMap::new();
    let mut families = Vec::new();
    for signal in signals {
        push_unique(&mut rule_ids, &signal.rule_id);
        rule_severities.insert(signal.rule_id.clone(), signal.severity.clone());
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
    let candidate_only = signals.iter().all(|signal| signal.candidate_only);

    L1Candidate {
        candidate_id: format!("injection:l1:{start_byte}:{end_byte}"),
        category: "injection".to_string(),
        start_byte,
        end_byte,
        start_char: text[..start_byte].chars().count(),
        end_char: text[..end_byte].chars().count(),
        rule_ids,
        rule_severities,
        families,
        max_severity,
        candidate_only,
        features,
    }
}

fn features_from_signal(text: &str, signal: &InjectionSignal) -> Vec<L1Feature> {
    if !signal.components.is_empty() {
        let mut features = signal
            .components
            .iter()
            .map(|component| L1Feature {
                feature_id: format!(
                    "{}:{}:{}:{}:{}",
                    if signal.feature_kind == "structural" {
                        "structural"
                    } else {
                        "rule_component"
                    },
                    signal.rule_id,
                    component.component_id,
                    component.start_byte,
                    component.end_byte
                ),
                kind: if signal.feature_kind == "structural" {
                    "structural"
                } else {
                    "anchor"
                }
                .to_string(),
                value: 1.0,
                explanation: component.explanation.to_string(),
                start_byte: component.start_byte,
                end_byte: component.end_byte,
                start_char: text[..component.start_byte].chars().count(),
                end_char: text[..component.end_byte].chars().count(),
                span_precision: component.span_precision.to_string(),
                provenance: provenance_from_signal(signal),
            })
            .collect::<Vec<_>>();
        if signal.feature_kind == "rule_match" {
            features.insert(0, rule_feature(text, signal));
        }
        return features;
    }
    vec![rule_feature(text, signal)]
}

fn rule_feature(text: &str, signal: &InjectionSignal) -> L1Feature {
    L1Feature {
        feature_id: format!(
            "rule:{}:{}:{}",
            signal.rule_id, signal.start_byte, signal.end_byte
        ),
        kind: signal.feature_kind.to_string(),
        value: 1.0,
        explanation: signal.description.clone(),
        start_byte: signal.start_byte,
        end_byte: signal.end_byte,
        start_char: text[..signal.start_byte].chars().count(),
        end_char: text[..signal.end_byte].chars().count(),
        span_precision: signal.span_precision.to_string(),
        provenance: provenance_from_signal(signal),
    }
}

fn provenance_from_signal(signal: &InjectionSignal) -> L1FeatureProvenance {
    L1FeatureProvenance {
        rule_id: signal.rule_id.clone(),
        family: Some(signal.family.clone()),
        upstream_id: signal.upstream_id.clone(),
        source: signal.source.clone(),
        source_revision: signal.source_revision.clone(),
        source_license: signal.source_license.clone(),
        source_file: signal.source_file.clone(),
        adaptation: signal.adaptation.clone(),
        references: signal.references.clone(),
        evidence_tier: signal.evidence_tier.clone(),
        candidate_only: signal.candidate_only,
    }
}

fn is_false(value: &bool) -> bool {
    !*value
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
            evidence_tier: None,
            candidate_only: false,
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

    #[test]
    fn audited_evidence_tier_is_visible_only_when_explicitly_set() {
        let text = "0123456789";
        let plain = candidate_from_group(text, &[&signal("plain", "override", "high", 0, 4)]);
        let plain_json = serde_json::to_value(&plain).unwrap();
        assert!(plain_json["features"][0]["provenance"]
            .get("evidence_tier")
            .is_none());

        let mut audited_signal = signal("audited", "override", "high", 0, 4);
        audited_signal.evidence_tier = Some("audited_high_precision".to_string());
        let audited = candidate_from_group(text, &[&audited_signal]);
        let audited_json = serde_json::to_value(&audited).unwrap();
        assert_eq!(
            audited_json["features"][0]["provenance"]["evidence_tier"],
            "audited_high_precision"
        );
    }

    #[test]
    fn candidate_only_is_visible_only_when_true_and_family_is_preserved() {
        let text = "0123456789";
        let plain = candidate_from_group(text, &[&signal("plain", "override", "high", 0, 4)]);
        let plain_provenance = &serde_json::to_value(&plain).unwrap()["features"][0]["provenance"];
        assert!(plain_provenance.get("candidate_only").is_none());
        assert_eq!(plain_provenance["family"], "override");

        let mut candidate_signal = signal("candidate", "lexicon", "high", 0, 4);
        candidate_signal.candidate_only = true;
        let candidate = candidate_from_group(text, &[&candidate_signal]);
        assert!(candidate.candidate_only);
        assert_eq!(
            serde_json::to_value(&candidate).unwrap()["candidate_only"],
            true
        );
        assert_eq!(
            serde_json::to_value(candidate).unwrap()["features"][0]["provenance"]["candidate_only"],
            true
        );
    }

    #[test]
    fn candidate_only_signal_does_not_bridge_separate_acceptance_candidates() {
        let text = "0123456789abcdefghij";
        let left = signal("left", "override", "high", 0, 4);
        let right = signal("right", "leak", "high", 10, 14);
        let mut bridge = signal("bridge", "lexicon", "critical", 3, 11);
        bridge.candidate_only = true;

        let candidates = candidates_from_signals(text, &[left, bridge, right]);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].start_byte, 0);
        assert_eq!(candidates[0].end_byte, 11);
        assert_eq!(candidates[1].start_byte, 10);
        assert_eq!(candidates[1].end_byte, 14);
        assert!(!candidates[0].candidate_only);
        assert_eq!(
            candidates[0]
                .features
                .iter()
                .filter(|feature| !feature.provenance.candidate_only)
                .count(),
            1
        );
    }
}
