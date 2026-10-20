// SPDX-License-Identifier: GPL-3.0-only
//! Cross-label overlap resolution in the scored modes (K07).
//!
//! Number labels compete for the same digits: the BBAN of a grouped IBAN or the
//! digits of a `+49` number can pass Luhn, an account field can hold an IBAN or
//! a card-shaped number. In `balanced` and `recall` one value yields one label.
//! Of two overlapping findings with different competing labels the first
//! criterion that differs decides: an IBAN (country code and MOD-97 prove the
//! kind of value), the longer value (a checksum-valid part of a longer value is
//! a coincidence), context that supports its own label (a field name, a
//! structural key or a nearby support term), a checksum, the higher score, the
//! earlier rule. A finding inside a printed IBAN form (`DE64 7172 …`) yields
//! even when no IBAN is reported because its check digits fail. The loser leaves
//! the evidence; its `matched_rules` entries stay and name `overlap`. `strict`
//! keeps both labels (decision T07).
use std::{cmp::Ordering, ops::Range, sync::LazyLock};

use regex::Regex;

use super::pii::PII_PATTERNS;
use super::score::ValidatorStrength;
use crate::detectors::NativeDetection;

/// Labels whose values rules of another label in this set can also match.
pub const COMPETING_LABELS: [&str; 5] = [
    "IBAN",
    "CREDITCARD",
    "FINANCIAL_ACCOUNT_NUMBER",
    "STEUERID",
    "PHONE",
];

/// A printed IBAN: country code, check digits and groups of four separated by
/// single spaces, with a shorter last group.
static IBAN_FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z]{2}[0-9]{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?\b").unwrap()
});

/// A competing finding with what its deciding rule proves.
struct Finding {
    /// Index into `evidence_spans`.
    span: usize,
    label: String,
    range: Range<usize>,
    /// Score in integer points.
    points: i64,
    /// Its context supports its label: a field name, a structural key or a
    /// nearby support term (K03, K04).
    supported: bool,
    checksum: bool,
    /// Registry index of the deciding rule.
    rule: usize,
}

impl Finding {
    fn overlaps(&self, other: &Self) -> bool {
        self.range.start < other.range.end && other.range.start < self.range.end
    }
}

/// Whether `a` beats `b`, and the criterion that decides.
fn decide(a: &Finding, b: &Finding) -> (Ordering, &'static str) {
    [
        ("iban", (a.label == "IBAN").cmp(&(b.label == "IBAN"))),
        ("longer_value", a.range.len().cmp(&b.range.len())),
        ("context", a.supported.cmp(&b.supported)),
        ("checksum", a.checksum.cmp(&b.checksum)),
        ("score", a.points.cmp(&b.points)),
        ("rule_order", b.rule.cmp(&a.rule)),
    ]
    .into_iter()
    .find(|(_, ordering)| ordering.is_ne())
    .map_or((Ordering::Equal, "rule_order"), |(reason, ordering)| {
        (ordering, reason)
    })
}

/// Removes the findings that yield to an overlapping finding of another
/// competing label or lie inside a printed IBAN form, and records why on their
/// `matched_rules` entries.
pub(crate) fn resolve(text: &str, detection: &mut NativeDetection) {
    let rules = detection
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    // The rule that kept a span is the earliest one in the registry that reported
    // it: (registry index, matched_rules entry).
    let rule_of = |label: &str, range: &Range<usize>| {
        rules
            .iter()
            .filter(|rule| {
                rule["start_byte"].as_u64() == Some(range.start as u64)
                    && rule["end_byte"].as_u64() == Some(range.end as u64)
            })
            .filter_map(|rule| {
                PII_PATTERNS
                    .iter()
                    .position(|pattern| rule["rule_id"] == pattern.name)
                    .map(|index| (index, rule))
            })
            .filter(|&(index, _)| PII_PATTERNS[index].entity_group == label)
            .min_by_key(|&(index, _)| index)
    };
    let mut findings: Vec<Finding> = detection
        .evidence_spans
        .iter()
        .enumerate()
        .filter(|(_, span)| COMPETING_LABELS.contains(&span.label.as_str()))
        .map(|(index, span)| {
            let range = span.start_byte..span.end_byte;
            let rule = rule_of(&span.label, &range);
            let pattern = rule.map(|(rule, _)| &PII_PATTERNS[rule]);
            Finding {
                span: index,
                label: span.label.clone(),
                range,
                points: (span.score * 100.0).round() as i64,
                supported: rule.is_some_and(|(_, entry)| {
                    entry["context"]["bonus"]
                        .as_u64()
                        .is_some_and(|bonus| bonus > 0)
                }),
                checksum: pattern
                    .is_some_and(|pattern| pattern.strength == ValidatorStrength::Checksum),
                rule: rule.map_or(usize::MAX, |(rule, _)| rule),
            }
        })
        .collect();
    if findings.iter().all(|finding| finding.label == "IBAN") {
        return;
    }

    // (loser, winner label, reason)
    let mut losers = Vec::new();
    findings.sort_by(|a, b| decide(b, a).0);
    let mut kept: Vec<Finding> = Vec::with_capacity(findings.len());
    for finding in findings {
        match kept
            .iter()
            .find(|winner| winner.label != finding.label && winner.overlaps(&finding))
        {
            Some(winner) => {
                let reason = decide(winner, &finding).1;
                losers.push((finding, Some(winner.label.clone()), reason));
            }
            None => kept.push(finding),
        }
    }
    let forms: Vec<_> = IBAN_FORM.find_iter(text).map(|form| form.range()).collect();
    for finding in kept {
        let inside_form = finding.label != "IBAN"
            && forms
                .iter()
                .any(|form| form.start < finding.range.start && finding.range.end <= form.end);
        if inside_form {
            losers.push((finding, None, "iban_form"));
        }
    }
    if losers.is_empty() {
        return;
    }

    if let Some(rules) = detection
        .details
        .get_mut("matched_rules")
        .and_then(|rules| rules.as_array_mut())
    {
        for (loser, winner, reason) in &losers {
            for rule in rules.iter_mut().filter(|rule| {
                rule["start_byte"].as_u64() == Some(loser.range.start as u64)
                    && rule["end_byte"].as_u64() == Some(loser.range.end as u64)
                    && PII_PATTERNS.iter().any(|pattern| {
                        rule["rule_id"] == pattern.name && pattern.entity_group == loser.label
                    })
            }) {
                let mut overlap = serde_json::json!({ "reason": reason });
                if let Some(winner) = winner {
                    overlap["yields_to"] = winner.as_str().into();
                }
                rule["overlap"] = overlap;
            }
        }
    }
    let removed: Vec<usize> = losers.iter().map(|(loser, ..)| loser.span).collect();
    let mut index = 0;
    detection.evidence_spans.retain(|_| {
        index += 1;
        !removed.contains(&(index - 1))
    });

    let spans = &detection.evidence_spans;
    let result = &mut detection.result;
    let Some(first) = spans.first() else {
        *result = crate::detectors::safe_result();
        return;
    };
    if !spans.iter().any(|span| span.label == result.class_name) {
        result.class_name = first.label.clone();
    }
    result.confidence = spans.iter().map(|span| span.score).fold(0.0, f64::max);
}
