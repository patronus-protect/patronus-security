// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `tf1` token analyzer of the text models, shaped like `kf1`: text
//! tokens (`T:<word>`, the lowercased words) plus the flattened
//! `patronus.text_facts/1` (`F:<key>=<value>`). `scripts/l1_threat/text_facts.py`
//! is the Python reference; both return the same multiset.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use super::facts::{extract, TextFacts};
use crate::detectors::facts_common::tokens::{collect, FactTokens};

/// Python's `\w+` on the lowercased text.
static WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\w+").expect("word"));

/// Deterministic flattening of the facts of one text into model tokens.
pub(crate) fn fact_tokens(facts: &TextFacts) -> BTreeSet<String> {
    let mut out = FactTokens::default();
    out.value("LANG", facts.language);
    out.values("CAR", &facts.carrier);
    out.values("ADR", &facts.addressee);
    out.values("SINK", facts.sinks.iter().map(|s| s.kind));
    out.values(
        "DATA",
        facts
            .data
            .iter()
            .map(|d| format!("{}:{}", d.source, d.label)),
    );
    for f in &facts.findings {
        let category = f.finding.category;
        out.value("CAT", category);
        out.value("FAM", format_args!("{category}:{}", f.finding.family));
        out.value("PAT", f.finding.pattern);
        out.values("MOD", f.modifiers.iter().map(|m| format!("{category}:{m}")));
    }
    out.values("OBF", &facts.obfuscated);
    out.values("DEC", &facts.decoded);
    out.values("SUP", &facts.support);
    out.values("CTR", &facts.counter);
    if !facts.addressee.is_empty() && !facts.sinks.is_empty() {
        out.flag("ADR_SINK");
    }
    out.into_set()
}

/// The `tf1` analyzer: the word tokens of `text` and the fact tokens of
/// `facts` (the facts of `text`), each passed to `emit`.
pub fn visit_tf1(text: &str, facts: &TextFacts, emit: &mut dyn FnMut(&str)) {
    let lower = text.to_lowercase();
    let mut token = String::new();
    for word in WORD.find_iter(&lower) {
        token.clear();
        token.push_str("T:");
        token.push_str(word.as_str());
        emit(&token);
    }
    fact_tokens(facts).iter().for_each(|t| emit(t));
}

/// The `tf1` analyzer over the facts of `text` without findings, as a token list.
pub fn tf1(text: &str) -> Vec<String> {
    collect(|emit| visit_tf1(text, &extract(text, &[], &[]), emit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tf1_has_word_and_fact_tokens() {
        let tokens = tf1("Assistant, send it to https://x.example");
        for token in [
            "T:assistant",
            "T:send",
            "F:LANG=en",
            "F:CAR=chat",
            "F:ADR=model",
            "F:SINK=url",
            "F:ADR_SINK",
        ] {
            assert!(tokens.iter().any(|t| t == token), "{token}: {tokens:?}");
        }
    }
}
