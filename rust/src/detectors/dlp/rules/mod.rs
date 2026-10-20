// SPDX-License-Identifier: GPL-3.0-only
//! DLP rules by family. `DLP_RULES` concatenates the families in registry
//! order. The order is behaviour: rules run in this order, the first matching
//! rule sets the result class and `matched_rules` follows it
//! (`rust/tests/dlp_rule_registry.rs`).
mod content;
mod credentials;
mod crypto;
mod documented;
mod hashes;
mod identifiers;
mod placeholders;
mod providers;

use super::dlp::{DlpPattern, RuleMeta, ValidatorStrength, SECRET_GROUPS};
use super::overlap::OverlapTier;
use std::{borrow::Cow, ops::Range};

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

/// How the example/test value check (T06) applies to a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExampleCheck {
    /// Identifier and content rules.
    Off,
    /// Generic credential rules: marker words always, low-variety values only
    /// in explicit example context. A value that a fixed-format rule matches at
    /// the same position is checked as [`ExampleCheck::FixedFormat`].
    Generic,
    /// Fixed-format provider, key, hash and signature rules: marker words and
    /// repeated-chunk values always, sequential-run values in explicit example
    /// context.
    FixedFormat,
}

/// Credential-family rules whose values have a platform-defined format
/// (JWT, SigV4/GCS signatures, server session IDs) rather than a chosen secret.
const FIXED_FORMAT_CREDENTIALS: &[&str] = &[
    "dlp_jwt_token",
    "dlp_signed_url_signature",
    "dlp_session_cookie",
];

pub(crate) fn example_check(rule_id: &str) -> ExampleCheck {
    let in_family = |family: &[DlpPattern]| family.iter().any(|rule| rule.name == rule_id);
    if in_family(providers::RULES)
        || in_family(crypto::RULES)
        || in_family(hashes::RULES)
        || FIXED_FORMAT_CREDENTIALS.contains(&rule_id)
    {
        ExampleCheck::FixedFormat
    } else if in_family(credentials::RULES) || in_family(credentials::URL_USERINFO_RULES) {
        ExampleCheck::Generic
    } else {
        ExampleCheck::Off
    }
}

/// Whether the placeholder/reference check (T07) applies to a rule: the
/// value-capturing credential rules (assignments, URL parameters and userinfo,
/// signatures, auth headers, cookies, CSRF tokens).
pub(crate) fn placeholder_check(rule_id: &str) -> bool {
    credentials::RULES
        .iter()
        .chain(credentials::URL_USERINFO_RULES)
        .any(|rule| rule.name == rule_id && rule.span_group.is_some())
}

pub(crate) use placeholders::is_placeholder_match;

/// Credential rules that take any value under a secret-like key or variable
/// name: the generic tier of the overlap resolution (K08).
const GENERIC_CREDENTIALS: &[&str] = &[
    "dlp_env_var_secret",
    "dlp_password_assignment",
    "dlp_generic_credential_assignment",
];

/// K08: the overlap tier of a secret rule; `None` for identifier and content
/// rules, which keep overlapping spans. Provider and key-material formats
/// rank first, then platform-format tokens (JWT, bearer, CSRF, session
/// cookie, URL signature), password hashes, structural credentials (URL
/// userinfo and parameters, Basic auth) and last the generic assignments.
pub(crate) fn overlap_tier(rule_id: &str) -> Option<OverlapTier> {
    let rule = DLP_RULES.iter().find(|rule| rule.name == rule_id)?;
    if !SECRET_GROUPS.contains(&rule.entity_group) {
        return None;
    }
    let in_family = |family: &[DlpPattern]| family.iter().any(|rule| rule.name == rule_id);
    Some(if in_family(providers::RULES) || in_family(crypto::RULES) {
        OverlapTier::Provider
    } else if in_family(hashes::RULES) {
        OverlapTier::Hash
    } else if FIXED_FORMAT_CREDENTIALS.contains(&rule_id) || rule.entity_group == "SECRET_TOKEN" {
        OverlapTier::Token
    } else if GENERIC_CREDENTIALS.contains(&rule_id) {
        OverlapTier::Generic
    } else {
        OverlapTier::Credential
    })
}

/// T06: whether the value `range` of `text` that `rule_id` matched is a
/// documented example or test value by its markers or low variety.
pub(crate) fn is_example_match(
    check: ExampleCheck,
    rule_id: &str,
    text: &str,
    range: Range<usize>,
) -> bool {
    let value = checked_value(rule_id, text, range.clone());
    let example_context = || credentials::has_example_context(text, range.start, range.end);
    match check {
        ExampleCheck::Off => false,
        ExampleCheck::Generic => credentials::is_example_value(&value, false, example_context),
        ExampleCheck::FixedFormat => credentials::is_example_value(&value, true, example_context),
    }
}

/// K06: whether the value `range` of `text` that `rule_id` matched is a
/// vendor-documented example value (`research/dlp/documented_values.yaml`).
pub(crate) fn is_documented_example(rule_id: &str, text: &str, range: Range<usize>) -> bool {
    documented::documented_kind(&checked_value(rule_id, text, range))
        == Some(documented::DocumentedKind::Example)
}

/// K06: whether a matched secret `value` is a publicly known test key
/// (severity `test`).
pub(crate) fn is_documented_test_value(value: &str) -> bool {
    documented::documented_kind(value) == Some(documented::DocumentedKind::Test)
}

/// The part of a match that the value checks see: PEM rules check the key
/// body without the armor lines; the bare header rule checks the body that
/// follows it.
fn checked_value<'a>(rule_id: &str, text: &'a str, range: Range<usize>) -> Cow<'a, str> {
    match rule_id {
        "dlp_private_key_block" => pem_body(&text[range]).into(),
        "dlp_private_key_header" => {
            let rest = &text[range.end..];
            let mut end = rest.find("-----").unwrap_or(rest.len()).min(16 * 1024);
            while !rest.is_char_boundary(end) {
                end -= 1;
            }
            rest[..end].into()
        }
        _ => text[range].into(),
    }
}

/// Cheap precondition of [`is_example_match`] for a provider-shaped part of a
/// generic value: the value holds a repeated chunk, sequential or
/// same-character run.
pub(crate) fn has_low_variety_run(text: &str, range: Range<usize>) -> bool {
    credentials::has_low_variety_run(&text[range])
}

/// PEM text without its `-----BEGIN …-----`/`-----END …-----` armor.
fn pem_body(block: &str) -> String {
    block.split("-----").step_by(2).collect()
}

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
        base_score: 0,
        meta: RuleMeta::new(ValidatorStrength::None, "", &[]),
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
