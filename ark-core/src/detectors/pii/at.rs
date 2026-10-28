// SPDX-License-Identifier: MIT OR Apache-2.0
//! Austrian identifiers (B-EU2): the social security number (Versicherungsnummer).
//!
//! Ten digits `LLLC DDMMYY`: three serial digits from 100 on, a check digit mod 11
//! and, usually, the birth date. Ten bare digits pass the check one time in eleven
//! and are a phone, order or account number too often, so they need a term of the
//! label in every mode. In `balanced` and `recall` the printed form with a space
//! after the check digit and a calendar date behind it (`1237 010180`) is also
//! reported bare (K05).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Social security number, `NNNN DDMMYY` or ten digits, with a social security
/// term near the value or as its key.
pub(super) const SOCIAL_SECURITY_NUMBER: PiiPattern = PiiPattern {
    name: "pii_social_security_number_at",
    pattern: r"(?-u:\b)[1-9][0-9]{3} ?[0-9]{6}(?-u:\b)",
    entity_group: "AT_SOCIAL_SECURITY_NUMBER",
    validator: Some(validators::at_social_security_number),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare social security number printed `NNNN DDMMYY` with a calendar day and
/// month, in `balanced` and `recall` only.
pub(super) const SOCIAL_SECURITY_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_social_security_number_at_context_free",
    pattern: r"(?-u:\b)[1-9][0-9]{3} (?:0[1-9]|[12][0-9]|3[01])(?:0[1-9]|1[0-2])[0-9]{2}(?-u:\b)",
    entity_group: "AT_SOCIAL_SECURITY_NUMBER",
    validator: Some(validators::at_social_security_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
