// SPDX-License-Identifier: GPL-3.0-only
//! Local context for DLP values (K04).
//!
//! The context of a finding follows the PII context engine (PII K03): a value
//! the rule binds to a field name of its own (assignments, headers, URL
//! parameters and userinfo, keyed provider secrets) has field context. A
//! secret the rule matches without a field name (provider tokens, key
//! material, JWTs) takes the nearest DE/EN term on its line: a credential term
//! of `anchor_lexicons/dlp.json` supports it, a nearer digest/hash/ID term
//! (`dlp.digest_reference`: checksum, tx hash, commit SHA, UUID …) counters
//! it. Content classes and business identifiers without a field name score
//! without context. This module only maps lexicon IDs; the windows, word
//! boundaries and line limits are those of [`crate::detectors::pii::context`].
use std::sync::LazyLock;

use super::dlp::{DlpPattern, SECRET_GROUPS};
use crate::detectors::pii::context::{Evidence, ProximityLexicon};

/// Support lexicon IDs of `dlp.json` for secrets without a field name.
pub static SUPPORT_LEXICON: &[&str] = &[
    "dlp.password",
    "dlp.credentials",
    "dlp.api_key",
    "dlp.access_key",
    "dlp.access_token",
    "dlp.refresh_token",
    "dlp.secret_token",
    "dlp.client_secret",
    "dlp.service_account_key",
    "dlp.encryption_key",
    "dlp.signing_key",
    "dlp.private_key",
    "dlp.secret",
    "dlp.secret_environment_labels",
    "dlp.database_connection",
    "dlp.authorization_header",
    "dlp.credential_files",
];

/// Counter-context lexicon IDs of `dlp.json`: values that are no secret.
pub static COUNTER_LEXICON: &[&str] = &["dlp.digest_reference"];

static LEXICON: LazyLock<ProximityLexicon> =
    LazyLock::new(|| ProximityLexicon::new(SUPPORT_LEXICON, COUNTER_LEXICON));

/// Where the context of a rule's findings comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSource {
    /// The rule captures the value behind a field name of its own.
    Field,
    /// A secret without a field name: two-sided proximity on its line.
    Proximity,
    /// Content classes and identifiers without a field name.
    None,
}

impl ContextSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Field => "field",
            Self::Proximity => "proximity",
            Self::None => "none",
        }
    }
}

/// Context source of `pattern`: value-capturing rules bind a field name,
/// other secret rules use proximity; content classes have no context.
pub fn source(pattern: &DlpPattern) -> ContextSource {
    let content = pattern.entity_group.starts_with("dlp.content.")
        || pattern.entity_group.starts_with("dlp.internal.");
    if content {
        ContextSource::None
    } else if pattern.span_group.is_some() {
        ContextSource::Field
    } else if SECRET_GROUPS.contains(&pattern.entity_group) {
        ContextSource::Proximity
    } else {
        ContextSource::None
    }
}

/// Context of a finding of `pattern` whose value is at `value` (byte range).
pub fn evidence(pattern: &DlpPattern, text: &str, value: (usize, usize)) -> Evidence {
    match source(pattern) {
        ContextSource::Field => Evidence::field(),
        ContextSource::Proximity => LEXICON.evidence(text, value),
        ContextSource::None => Evidence::none(),
    }
}
