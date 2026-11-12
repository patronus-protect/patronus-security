// SPDX-License-Identifier: MIT OR Apache-2.0
//! The context terms of a text (addressee, support, counter) and the
//! modifiers of a finding's span.

use std::ops::Range;

use super::super::super::context_lexica::{ContextScan, Kind};
use super::super::super::text_views::TextViews;

/// The text-wide context facts, each list sorted and without duplicates.
pub(super) struct TextContext {
    pub addressee: Vec<&'static str>,
    pub support: Vec<&'static str>,
    pub counter: Vec<&'static str>,
}

impl TextContext {
    pub(super) fn of(scan: &ContextScan) -> Self {
        let (mut addressee, mut support, mut counter) = (Vec::new(), Vec::new(), Vec::new());
        for hit in scan.hits() {
            match (hit.kind, hit.lexicon) {
                (_, "addressee") => addressee.push("model"),
                (_, "authority") => addressee.push("authority"),
                // Sink terms are reported as sinks.
                (_, "sink") => {}
                (Kind::Support, id) => support.push(id),
                (Kind::Counter, id) => counter.push(id),
            }
        }
        for list in [&mut addressee, &mut support, &mut counter] {
            list.sort_unstable();
            list.dedup();
        }
        Self {
            addressee,
            support,
            counter,
        }
    }
}

/// Modifiers of a finding at `span`, sorted: `decoded` (a decoded view
/// overlaps it), `defensive` (defensive or meta context in its clause),
/// `negated`, `obfuscated` (the obfuscation view changed it), `quoted` (quote
/// marks, a `>` line or a reporting verb) and `test_code`.
pub(super) fn modifiers(
    text: &str,
    scan: &ContextScan,
    views: &TextViews,
    span: Range<usize>,
) -> Vec<&'static str> {
    let clause = scan.at(text, span.clone());
    let decoded = views
        .decoded
        .iter()
        .any(|view| view.source.start < span.end && span.start < view.source.end);
    let obfuscated = views
        .deobfuscated
        .as_ref()
        .is_some_and(|view| !view.kinds(span).is_empty());
    [
        ("decoded", decoded),
        ("defensive", clause.has("defensive") || clause.has("meta")),
        ("negated", clause.negated()),
        ("obfuscated", obfuscated),
        ("quoted", clause.quoted || clause.has("quotation")),
        ("test_code", clause.has("test_code")),
    ]
    .into_iter()
    .filter_map(|(name, set)| set.then_some(name))
    .collect()
}
