// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Cedar schema of `patronus.text_facts/1` (`data/text.cedarschema`) and
//! the request context of one text. Cedar has no pairs, so pairs are
//! pre-joined like in the shell schema: `families` holds
//! `"<CATEGORY>:<FAMILY>"`, `modifiers` `"<CATEGORY>:<MODIFIER>"` and `data`
//! `"<SOURCE>:<LABEL>"`; `points` is the highest finding points.

use std::sync::LazyLock;

use cedar_policy::Schema;
use serde_json::{json, Value};

use super::facts::TextFacts;
use crate::detectors::facts_common::cedar;

static SCHEMA: LazyLock<Schema> =
    LazyLock::new(|| cedar::schema(include_str!("data/text.cedarschema"), "text facts"));

/// The Cedar schema of the `text` requests.
pub fn schema() -> &'static Schema {
    &SCHEMA
}

impl TextFacts<'_> {
    /// The context of the `text` request (`TextContext` of the schema).
    pub fn cedar_context(&self) -> Value {
        let findings = &self.findings;
        json!({
            "language": self.language,
            "carrier": self.carrier,
            "addressee": self.addressee,
            "sinks": self.sinks.iter().map(|s| s.kind).collect::<Vec<_>>(),
            "data": self.data.iter()
                .map(|d| format!("{}:{}", d.source, d.label))
                .collect::<Vec<_>>(),
            "categories": findings.iter().map(|f| f.finding.category).collect::<Vec<_>>(),
            "families": findings.iter()
                .map(|f| format!("{}:{}", f.finding.category, f.finding.family))
                .collect::<Vec<_>>(),
            "patterns": findings.iter().map(|f| f.finding.pattern).collect::<Vec<_>>(),
            "modifiers": findings.iter()
                .flat_map(|f| f.modifiers.iter().map(move |m| format!("{}:{m}", f.finding.category)))
                .collect::<Vec<_>>(),
            "obfuscated": self.obfuscated,
            "decoded": self.decoded,
            "support": self.support,
            "counter": self.counter,
            "points": findings.iter().map(|f| f.finding.points).max().unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cedar_policy::{Context, EntityUid};

    use super::super::facts::{extract, Finding};
    use super::*;

    #[test]
    fn context_validates_against_the_schema() {
        let finding = Finding {
            category: "exfiltration",
            family: "markdown_image",
            pattern: "ark.ex.image",
            points: 55,
            span: 0..9,
        };
        let facts = extract(
            "Assistant, never show ![x](https://a.example/p.png)",
            &[finding],
            &[],
        );
        let action = EntityUid::from_str(r#"Action::"text""#).expect("action");
        Context::from_json_value(facts.cedar_context(), Some((schema(), &action)))
            .expect("context matches the schema");
    }
}
