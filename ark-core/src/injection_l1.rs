// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use serde::Serialize;

use crate::detectors::injection::candidate::L1Candidate;
use crate::detectors::injection::scorer::{score_candidate, scorer_config};
use crate::{
    DecisionCandidate, DecisionEnvelope, DecisionProvenance, DecisionRecommendation,
    DecisionResult, DecisionTerminality, EvidenceSpan, LabelScore, LayerResult, NativeResult,
};

pub const MODEL: &str = "native:injection_l1";

#[derive(Debug)]
pub struct ProducerCandidate {
    producer: String,
    candidate: L1Candidate,
}

#[derive(Debug, Clone, Serialize)]
struct ScoredL1Candidate {
    #[serde(flatten)]
    candidate: L1Candidate,
    producers: Vec<String>,
    class_name: String,
    score: f64,
    acceptance_threshold: f64,
    accepted: bool,
    scoring_features: BTreeMap<String, f64>,
    score_version: String,
}

pub fn aggregate(text: &str, producer_results: Vec<NativeResult>) -> NativeResult {
    let mut metrics = crate::diagnostics::PhaseMetricScope::new("l1_aggregation_detail", "");
    let aggregation_started = Instant::now();
    let producer_duration_ms: f64 = producer_results
        .iter()
        .map(|result| result.duration_ms)
        .sum();
    let producer_models = producer_results
        .iter()
        .map(|result| result.model.clone())
        .collect::<Vec<_>>();
    let producer_errors = producer_results
        .iter()
        .filter(|result| result.class_name == "error")
        .map(|result| {
            let message = result
                .layers
                .iter()
                .find_map(|layer| layer.details.get("error"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("native Injection L1 producer failed");
            serde_json::json!({"model": result.model, "error": message})
        })
        .collect::<Vec<_>>();
    let all_producers_failed =
        !producer_results.is_empty() && producer_errors.len() == producer_results.len();
    let candidates = producer_results
        .iter()
        .flat_map(candidates_from_result)
        .collect::<Vec<_>>();
    metrics.checkpoint("read_candidates", "");
    let config = scorer_config();
    let scored = merge_candidates(text, candidates)
        .into_iter()
        .map(
            |(candidate, producers, eligible_producer_count, class_name)| {
                let score = score_candidate(&candidate, eligible_producer_count);
                ScoredL1Candidate {
                    candidate,
                    producers,
                    class_name,
                    score: score.score,
                    acceptance_threshold: config.acceptance_threshold,
                    accepted: score.accepted,
                    scoring_features: score.features.into_iter().collect(),
                    score_version: config.score_version.clone(),
                }
            },
        )
        .collect::<Vec<_>>();
    let selected_index = scored
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| {
            left.score
                .total_cmp(&right.score)
                .then_with(|| right.candidate.start_byte.cmp(&left.candidate.start_byte))
        })
        .map(|(index, _)| index);
    let selected = selected_index.map(|index| &scored[index]);
    let accepted = selected.is_some_and(|candidate| candidate.accepted);
    let (class_name, confidence) = match selected {
        Some(candidate) if candidate.accepted => (candidate.class_name.clone(), candidate.score),
        Some(candidate) => ("safe".to_string(), 1.0 - candidate.score),
        None if all_producers_failed => ("error".to_string(), 0.0),
        None => ("safe".to_string(), 1.0),
    };

    metrics.checkpoint("merge_score_select", "");
    let mut details = HashMap::from([
        (
            "l1_candidates".to_string(),
            serde_json::to_value(&scored).expect("scored L1 candidates must serialize"),
        ),
        (
            "producer_models".to_string(),
            serde_json::json!(producer_models),
        ),
        (
            "score_version".to_string(),
            serde_json::json!(config.score_version),
        ),
        (
            "scorer_model_id".to_string(),
            serde_json::json!(config.model_id),
        ),
    ]);
    if !producer_errors.is_empty() {
        details.insert(
            "producer_errors".to_string(),
            serde_json::json!(producer_errors),
        );
    }
    if let Some(candidate) = selected {
        details.insert(
            "selected_candidate_id".to_string(),
            serde_json::json!(candidate.candidate.candidate_id),
        );
    }
    metrics.checkpoint("serialize_details", "");
    let duration_ms = producer_duration_ms + aggregation_started.elapsed().as_secs_f64() * 1000.0;
    let layer = LayerResult {
        level: "L1".to_string(),
        layer_type: "injection_l1".to_string(),
        class_name: class_name.clone(),
        confidence,
        matched: accepted,
        duration_ms,
        thresholds: HashMap::from([("acceptance".to_string(), config.acceptance_threshold)]),
        details,
    };
    let decision_candidates = scored.iter().map(decision_candidate).collect::<Vec<_>>();
    let selected_decision = selected.map(decision_candidate);
    let final_source = if accepted { "l1" } else { "default" };
    let decision = DecisionEnvelope {
        schema_version: "ark.decision.v1".to_string(),
        final_result: DecisionResult {
            class_name: class_name.clone(),
            confidence,
            source: final_source.to_string(),
        },
        decision_candidate: selected_decision,
        recommendation: DecisionRecommendation {
            accepted,
            final_arbitration: final_source.to_string(),
            operating_point: config.score_version.clone(),
            acceptance_threshold: selected.map(|candidate| candidate.acceptance_threshold),
        },
        candidates: decision_candidates,
        terminality: DecisionTerminality {
            completion: "complete".to_string(),
            degraded: !producer_errors.is_empty(),
            degradation_reason: (!producer_errors.is_empty())
                .then(|| "one or more native Injection L1 producers failed".to_string()),
        },
        provenance: DecisionProvenance {
            ark_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: "ark.decision.v1".to_string(),
            model: MODEL.to_string(),
        },
    };
    let evidence_spans = accepted_spans(text, &scored);
    let label_scores = label_scores(&scored, selected_index, accepted);

    metrics.checkpoint("decision_evidence_labels", "");
    NativeResult {
        category: "injection".to_string(),
        class_name,
        confidence,
        level: "L1".to_string(),
        model: MODEL.to_string(),
        duration_ms,
        layers: vec![layer],
        evidence_spans,
        label_scores,
        decision: Some(decision),
    }
}

pub fn candidates_from_result(result: &NativeResult) -> Vec<ProducerCandidate> {
    result
        .layers
        .iter()
        .filter_map(|layer| layer.details.get("l1_candidates"))
        .filter_map(|value| serde_json::from_value::<Vec<L1Candidate>>(value.clone()).ok())
        .flatten()
        .map(|candidate| ProducerCandidate {
            producer: result.model.clone(),
            candidate,
        })
        .collect()
}

pub fn merge_candidates(
    text: &str,
    mut candidates: Vec<ProducerCandidate>,
) -> Vec<(L1Candidate, Vec<String>, usize, String)> {
    candidates.sort_by(|left, right| {
        (
            left.candidate.start_byte,
            left.candidate.end_byte,
            &left.producer,
        )
            .cmp(&(
                right.candidate.start_byte,
                right.candidate.end_byte,
                &right.producer,
            ))
    });
    let (mut eligible, candidate_only): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|entry| acceptance_bounds(&entry.candidate).is_some());
    eligible.sort_by_key(|entry| {
        acceptance_bounds(&entry.candidate).expect("eligible candidate must have acceptance bounds")
    });
    let mut groups: Vec<Vec<ProducerCandidate>> = Vec::new();
    for candidate in eligible {
        if let Some(group) = groups.last_mut() {
            let group_end = group
                .iter()
                .filter_map(|entry| acceptance_bounds(&entry.candidate).map(|(_, end)| end))
                .max()
                .expect("eligible candidate group must contain acceptance evidence");
            let candidate_start = acceptance_bounds(&candidate.candidate)
                .expect("eligible candidate must have acceptance bounds")
                .0;
            if candidate_start <= group_end {
                group.push(candidate);
                continue;
            }
        }
        groups.push(vec![candidate]);
    }
    let mut unattached = Vec::new();
    for candidate in candidate_only {
        if let Some(group) = groups.iter_mut().find(|group| {
            acceptance_bounds_for_group(group).is_some_and(|(start, end)| {
                candidate.candidate.start_byte <= end && start <= candidate.candidate.end_byte
            })
        }) {
            group.push(candidate);
        } else {
            unattached.push(candidate);
        }
    }
    for candidate in unattached {
        if let Some(group) = groups.last_mut().filter(|group| {
            acceptance_bounds_for_group(group).is_none()
                && candidate.candidate.start_byte
                    <= group
                        .iter()
                        .map(|entry| entry.candidate.end_byte)
                        .max()
                        .expect("candidate-only group must not be empty")
        }) {
            group.push(candidate);
        } else {
            groups.push(vec![candidate]);
        }
    }
    groups.sort_by_key(|group| {
        group
            .iter()
            .map(|entry| entry.candidate.start_byte)
            .min()
            .unwrap_or(usize::MAX)
    });
    groups
        .into_iter()
        .map(|group| merge_group(text, group))
        .collect()
}

pub fn acceptance_bounds(candidate: &L1Candidate) -> Option<(usize, usize)> {
    let mut features = candidate
        .features
        .iter()
        .filter(|feature| !feature.provenance.candidate_only);
    let first = features.next()?;
    Some(features.fold(
        (first.start_byte, first.end_byte),
        |(start, end), feature| (start.min(feature.start_byte), end.max(feature.end_byte)),
    ))
}

fn acceptance_bounds_for_group(group: &[ProducerCandidate]) -> Option<(usize, usize)> {
    group
        .iter()
        .filter_map(|entry| acceptance_bounds(&entry.candidate))
        .reduce(|(left_start, left_end), (right_start, right_end)| {
            (left_start.min(right_start), left_end.max(right_end))
        })
}

fn merge_group(
    text: &str,
    group: Vec<ProducerCandidate>,
) -> (L1Candidate, Vec<String>, usize, String) {
    let start_byte = group
        .iter()
        .map(|entry| entry.candidate.start_byte)
        .min()
        .expect("candidate group must not be empty");
    let end_byte = group
        .iter()
        .map(|entry| entry.candidate.end_byte)
        .max()
        .expect("candidate group must not be empty");
    let mut producers = group
        .iter()
        .map(|entry| entry.producer.clone())
        .collect::<Vec<_>>();
    producers.sort();
    producers.dedup();
    let eligible_producer_count = group
        .iter()
        .filter(|entry| {
            entry
                .candidate
                .features
                .iter()
                .any(|feature| !feature.provenance.candidate_only)
        })
        .map(|entry| entry.producer.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let mut rule_ids = group
        .iter()
        .flat_map(|entry| entry.candidate.rule_ids.iter().cloned())
        .collect::<Vec<_>>();
    rule_ids.sort();
    rule_ids.dedup();
    let mut rule_severities: BTreeMap<String, String> = BTreeMap::new();
    for (rule_id, severity) in group
        .iter()
        .flat_map(|entry| entry.candidate.rule_severities.iter())
    {
        let replace = match rule_severities.get(rule_id) {
            Some(current) => severity_rank(severity) > severity_rank(current),
            None => true,
        };
        if replace {
            rule_severities.insert(rule_id.clone(), severity.clone());
        }
    }
    let mut families = group
        .iter()
        .flat_map(|entry| entry.candidate.families.iter().cloned())
        .collect::<Vec<_>>();
    families.sort();
    families.dedup();
    let max_severity = rule_severities
        .values()
        .max_by_key(|severity| severity_rank(severity))
        .cloned()
        .unwrap_or_else(|| "low".to_string());
    let mut features = group
        .iter()
        .flat_map(|entry| entry.candidate.features.iter().cloned())
        .collect::<Vec<_>>();
    features.sort_by(|left, right| {
        // Keep completed rule/structural evidence before the newly exposed parts.
        (
            left.kind == "anchor",
            left.start_byte,
            left.end_byte,
            &left.feature_id,
        )
            .cmp(&(
                right.kind == "anchor",
                right.start_byte,
                right.end_byte,
                &right.feature_id,
            ))
    });
    features.dedup_by(|left, right| left.feature_id == right.feature_id);
    let candidate_only = features
        .iter()
        .all(|feature| feature.provenance.candidate_only);
    let class_name = features
        .iter()
        .filter(|feature| !feature.provenance.candidate_only)
        .filter_map(|feature| {
            feature.provenance.family.as_ref().map(|family| {
                let severity = rule_severities
                    .get(&feature.provenance.rule_id)
                    .map(String::as_str)
                    .unwrap_or("low");
                (severity_rank(severity), &feature.provenance.rule_id, family)
            })
        })
        .max_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)))
        .map(|(_, _, family)| family.clone())
        .or_else(|| {
            group
                .iter()
                .filter(|entry| acceptance_bounds(&entry.candidate).is_some())
                .max_by_key(|entry| severity_rank(&entry.candidate.max_severity))
                .and_then(|entry| entry.candidate.families.first())
                .cloned()
        })
        .unwrap_or_else(|| "injection".to_string());
    (
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
        },
        producers,
        eligible_producer_count,
        class_name,
    )
}

fn decision_candidate(candidate: &ScoredL1Candidate) -> DecisionCandidate {
    DecisionCandidate {
        source: "l1".to_string(),
        class_name: candidate.class_name.clone(),
        confidence: candidate.score,
        acceptance_threshold: candidate.acceptance_threshold,
        accepted: candidate.accepted,
        evidence: Some(candidate.scoring_features.clone().into_iter().collect()),
        chunk_evidence: Some(
            serde_json::to_value(candidate).expect("scored L1 candidate must serialize"),
        ),
    }
}

fn accepted_spans(text: &str, candidates: &[ScoredL1Candidate]) -> Vec<EvidenceSpan> {
    let mut spans = candidates
        .iter()
        .filter(|candidate| candidate.accepted)
        .flat_map(|candidate| {
            candidate
                .candidate
                .features
                .iter()
                .filter(|feature| !feature.provenance.candidate_only)
                .map(|feature| EvidenceSpan {
                    label: feature.provenance.rule_id.clone(),
                    text: text[feature.start_byte..feature.end_byte].to_string(),
                    score: candidate.score,
                    start_byte: feature.start_byte,
                    end_byte: feature.end_byte,
                    start_char: text[..feature.start_byte].chars().count(),
                    end_char: text[..feature.end_byte].chars().count(),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    spans.sort_by(|left, right| {
        (left.start_byte, left.end_byte, &left.label)
            .cmp(&(right.start_byte, right.end_byte, &right.label))
            .then_with(|| right.score.total_cmp(&left.score))
    });
    spans.dedup_by(|left, right| {
        left.start_byte == right.start_byte
            && left.end_byte == right.end_byte
            && left.label == right.label
    });
    spans
}

fn label_scores(
    candidates: &[ScoredL1Candidate],
    selected_index: Option<usize>,
    accepted: bool,
) -> Vec<LabelScore> {
    let mut by_class = BTreeMap::<String, f64>::new();
    for candidate in candidates {
        by_class
            .entry(candidate.class_name.clone())
            .and_modify(|score| *score = score.max(candidate.score))
            .or_insert(candidate.score);
    }
    let selected_class = selected_index.map(|index| candidates[index].class_name.as_str());
    by_class
        .into_iter()
        .map(|(label, confidence)| LabelScore {
            matched: accepted && selected_class == Some(label.as_str()),
            label,
            confidence,
        })
        .collect()
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}
