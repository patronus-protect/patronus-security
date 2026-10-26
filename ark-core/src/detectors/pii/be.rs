// SPDX-License-Identifier: MIT OR Apache-2.0
//! Belgian identifiers (B-EU1): the national number (rijksregisternummer, numéro
//! de registre national).
//!
//! Eleven digits, a birth date, a serial number and a check mod 97. Eleven bare
//! digits are also a Steuer-ID or a phone number, so the value is reported in every
//! mode only with a term of its label near it or as its key. In `balanced` and
//! `recall` the printed form of the Belgian identity card, `85.07.30-033.28`, is
//! also reported bare (K05).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// National number, eleven digits, `85.07.30-033.28` or `850730-033.28` /
/// `850730 033 28`, with a national number term near the value or as its key.
pub(super) const NATIONAL_NUMBER: PiiPattern = PiiPattern {
    name: "pii_national_number_be",
    pattern: r"(?-u:\b)(?:[0-9]{11}|[0-9]{2}\.[0-9]{2}\.[0-9]{2}-[0-9]{3}\.[0-9]{2}|[0-9]{6}[- ][0-9]{3}[- .][0-9]{2})(?-u:\b)",
    entity_group: "BE_NATIONAL_NUMBER",
    validator: Some(validators::be_national_number),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare national number printed `85.07.30-033.28`, in `balanced` and `recall`
/// only.
pub(super) const NATIONAL_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_national_number_be_context_free",
    pattern: r"(?-u:\b)[0-9]{2}\.[0-9]{2}\.[0-9]{2}-[0-9]{3}\.[0-9]{2}(?-u:\b)",
    entity_group: "BE_NATIONAL_NUMBER",
    validator: Some(validators::be_national_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
