// SPDX-License-Identifier: MIT OR Apache-2.0
//! Facts as model tokens. The analyzers (`kf1` for commands, `tf1` for texts)
//! emit text tokens plus the flattened facts; the TF-IDF block consumes the
//! multiset, so the order does not matter.

use std::collections::BTreeSet;
use std::fmt::Display;

/// The fact tokens of one document: `F:<key>=<value>` and `F:<flag>`, each
/// once, sorted.
#[derive(Debug, Default)]
pub struct FactTokens(BTreeSet<String>);

impl FactTokens {
    /// `F:<key>=<value>`.
    pub fn value(&mut self, key: &str, value: impl Display) {
        self.0.insert(format!("F:{key}={value}"));
    }

    /// `F:<key>=<value>` for every value.
    pub fn values<V: Display>(&mut self, key: &str, values: impl IntoIterator<Item = V>) {
        values.into_iter().for_each(|value| self.value(key, value));
    }

    /// `F:<flag>`.
    pub fn flag(&mut self, flag: &str) {
        self.0.insert(format!("F:{flag}"));
    }

    pub fn into_set(self) -> BTreeSet<String> {
        self.0
    }
}

/// The tokens an analyzer passes to `emit`, as a list.
pub fn collect(visit: impl FnOnce(&mut dyn FnMut(&str))) -> Vec<String> {
    let mut out = Vec::new();
    visit(&mut |token| out.push(token.to_string()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fact_tokens_are_sorted_and_unique() {
        let mut tokens = FactTokens::default();
        tokens.values("C", ["b", "a", "b"]);
        tokens.value("N", 3);
        tokens.flag("SENS");
        let set: Vec<String> = tokens.into_set().into_iter().collect();
        assert_eq!(set, ["F:C=a", "F:C=b", "F:N=3", "F:SENS"]);
    }

    #[test]
    fn collect_keeps_every_emitted_token() {
        let tokens = collect(|emit| ["a", "b", "a"].into_iter().for_each(emit));
        assert_eq!(tokens, ["a", "b", "a"]);
    }
}
