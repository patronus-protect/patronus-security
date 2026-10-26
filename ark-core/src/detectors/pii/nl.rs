// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dutch identifiers (B-EU1): the burgerservicenummer (BSN).
//!
//! Nine digits with the 11-proof: nine bare digits pass it one time in eleven, so
//! the BSN is reported in every mode only with a term of its label near the value
//! or as its key. In `balanced` and `recall` the form printed on Dutch identity
//! documents, `1234.56.782`, is also reported bare (K05).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// BSN, nine digits, 3-3-3 or `1234.56.782`, with a BSN term near the value or as
/// its key.
pub(super) const BSN: PiiPattern = PiiPattern {
    name: "pii_bsn_nl",
    pattern: r"(?-u:\b)(?:[0-9]{9}|[0-9]{3} [0-9]{3} [0-9]{3}|[0-9]{4}\.[0-9]{2}\.[0-9]{3})(?-u:\b)",
    entity_group: "NL_BSN",
    validator: Some(validators::nl_bsn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare BSN printed `1234.56.782`, in `balanced` and `recall` only.
pub(super) const BSN_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_bsn_nl_context_free",
    pattern: r"(?-u:\b)[0-9]{4}\.[0-9]{2}\.[0-9]{3}(?-u:\b)",
    entity_group: "NL_BSN",
    validator: Some(validators::nl_bsn),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
