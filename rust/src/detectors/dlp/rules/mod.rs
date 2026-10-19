// SPDX-License-Identifier: GPL-3.0-only
//! DLP rules by family. `DLP_RULES` concatenates the families in registry
//! order. The order is behaviour: rules run in this order, the first matching
//! rule sets the result class and `matched_rules` follows it
//! (`rust/tests/dlp_rule_registry.rs`).
mod content;
mod credentials;
mod crypto;
mod hashes;
mod identifiers;
mod providers;

use super::dlp::DlpPattern;

const PARTS: &[&[DlpPattern]] = &[
    providers::RULES,
    crypto::RULES,
    credentials::RULES,
    hashes::RULES,
    credentials::URL_USERINFO_RULES,
    identifiers::RULES,
    content::RULES,
];

pub(super) static DLP_RULES: [DlpPattern; rule_count(PARTS)] = concat(PARTS);

const fn rule_count(parts: &[&[DlpPattern]]) -> usize {
    let mut count = 0;
    let mut part = 0;
    while part < parts.len() {
        count += parts[part].len();
        part += 1;
    }
    count
}

const fn concat<const N: usize>(parts: &[&[DlpPattern]]) -> [DlpPattern; N] {
    const EMPTY: DlpPattern = DlpPattern {
        name: "",
        pattern: "",
        entity_group: "",
        validator: None,
        span_group: None,
    };
    let mut rules = [EMPTY; N];
    let mut index = 0;
    let mut part = 0;
    while part < parts.len() {
        let mut rule = 0;
        while rule < parts[part].len() {
            rules[index] = parts[part][rule];
            index += 1;
            rule += 1;
        }
        part += 1;
    }
    assert!(index == N);
    rules
}
