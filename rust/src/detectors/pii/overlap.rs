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
//! the evidence; its `matched_rules` entries stay and name `overlap`. Document
//! numbers (`DOCUMENT_LABELS`, F08) compete with an overlapping finding of any
//! other label: their context-free check digit (7-3-1 mod 10) fits one in ten
//! letter-led codes, so a field name such as `Kundennummer` decides. `strict`
//! keeps both labels (decision T07) and only marks the card-shaped part of a
//! valid IBAN and an account finding on an IBAN value as secondary evidence.
use std::{cmp::Ordering, ops::Range, sync::LazyLock};

use regex::Regex;

use super::pii::PII_PATTERNS;
use super::score::ValidatorStrength;
use crate::detectors::NativeDetection;

/// Labels whose values rules of another label in this set can also match.
/// Among the VAT IDs the Italian, the French, the Croatian and the Latvian carry
/// eleven digits that can be a Steuer-ID (`IT 00743110157`, `FR 40 303 265 045`,
/// `HR 57419348408`, `LV 71890053205`), and the twelve digits of a Lithuanian one
/// can be a card number (`LT 621223427710`); the others are shorter or end in letters.
pub const COMPETING_LABELS: [&str; 10] = [
    "IBAN",
    "CREDITCARD",
    "FINANCIAL_ACCOUNT_NUMBER",
    "STEUERID",
    "PHONE",
    "VAT_ID_IT",
    "VAT_ID_FR",
    "VAT_ID_HR",
    "VAT_ID_LT",
    "VAT_ID_LV",
];

/// Labels whose findings compete with an overlapping finding of any other label
/// (F08): a bare passport or identity card check digit proves little.
pub const DOCUMENT_LABELS: [&str; 2] = ["PASSPORT_NUMBER", "IDENTITY_CARD_NUMBER"];

/// Whether findings of `a` and `b` compete for overlapping characters.
fn compete(a: &str, b: &str) -> bool {
    a != b
        && ((COMPETING_LABELS.contains(&a) && COMPETING_LABELS.contains(&b))
            || DOCUMENT_LABELS.contains(&a)
            || DOCUMENT_LABELS.contains(&b))
}

/// Labels whose findings inside a reported IBAN are secondary evidence of it in
/// `strict` (decision T07).
pub const SECONDARY_IN_IBAN: [&str; 2] = ["CREDITCARD", "FINANCIAL_ACCOUNT_NUMBER"];

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
    /// Rank of the context of its label (K03, K04): 2 for a field name, a
    /// structural key or a nearby support term, plus 1 unless it is a document
    /// number (F08) without a field name or key. A document number with only a
    /// nearby term ranks below every other supported label, one without
    /// context below every other label.
    context: u8,
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
        ("context", a.context.cmp(&b.context)),
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
/// `matched_rules` entries. A document number competes with every label.
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
    let spans = &detection.evidence_spans;
    let mut findings: Vec<Finding> = spans
        .iter()
        .enumerate()
        .filter(|(_, span)| {
            COMPETING_LABELS.contains(&span.label.as_str())
                || spans.iter().any(|other| {
                    compete(&span.label, &other.label)
                        && span.start_byte < other.end_byte
                        && other.start_byte < span.end_byte
                })
        })
        .map(|(index, span)| {
            let range = span.start_byte..span.end_byte;
            let rule = rule_of(&span.label, &range);
            let pattern = rule.map(|(rule, _)| &PII_PATTERNS[rule]);
            Finding {
                span: index,
                label: span.label.clone(),
                range,
                points: (span.score * 100.0).round() as i64,
                context: {
                    let context = rule.map(|(_, entry)| &entry["context"]);
                    let supported = context
                        .and_then(|context| context["bonus"].as_u64())
                        .is_some_and(|bonus| bonus > 0);
                    let field = context.is_some_and(|context| {
                        context["anchor"] == "field" || context["side"] == "key"
                    });
                    let document = DOCUMENT_LABELS.contains(&span.label.as_str());
                    2 * u8::from(supported) + u8::from(!document || field)
                },
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
            .find(|winner| compete(&winner.label, &finding.label) && winner.overlaps(&finding))
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
            && COMPETING_LABELS.contains(&finding.label.as_str())
            && forms
                .iter()
                .any(|form| form.start <= finding.range.start && finding.range.end <= form.end);
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

/// Lists the card and account findings inside a reported IBAN under
/// `secondary_evidence` (`strict`, decision T07): `iban_value` for the IBAN's own
/// span, `iban_part` for a part of it. Findings, class and confidence stay as they
/// are; evaluations score primary findings only.
pub(crate) fn mark_secondary(detection: &mut NativeDetection) {
    let spans = &detection.evidence_spans;
    let secondary: Vec<_> = spans
        .iter()
        .filter(|span| SECONDARY_IN_IBAN.contains(&span.label.as_str()))
        .filter_map(|span| {
            let iban = spans.iter().find(|iban| {
                iban.label == "IBAN"
                    && iban.start_byte <= span.start_byte
                    && span.end_byte <= iban.end_byte
            })?;
            let reason = if (iban.start_byte, iban.end_byte) == (span.start_byte, span.end_byte) {
                "iban_value"
            } else {
                "iban_part"
            };
            Some(serde_json::json!({
                "label": span.label, "start_byte": span.start_byte, "end_byte": span.end_byte,
                "reason": reason, "primary_label": "IBAN",
            }))
        })
        .collect();
    if !secondary.is_empty() {
        detection
            .details
            .insert("secondary_evidence".into(), secondary.into());
    }
}
