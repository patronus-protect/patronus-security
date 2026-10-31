// SPDX-License-Identifier: MIT OR Apache-2.0
//! Indian identifiers (B-IN): the Aadhaar number, the GSTIN, the PAN and the
//! voter ID (EPIC).
//!
//! The Aadhaar number is twelve digits, first digit 2–9, plain or grouped 4-4-4
//! with spaces, hyphens or colons, the last a Verhoeff check digit. The GSTIN is
//! fifteen characters: a state code, the PAN of the holder, an entity number,
//! `Z` and a mod-36 check character. The PAN (five letters with the holder type
//! as the fourth, four digits, a letter) and the EPIC (three letters, seven
//! digits, not all zero) carry no check, so they are format and context only.
//! With a term of the label near it or as its key a value is reported in every
//! mode; in `balanced` and `recall` the grouped Aadhaar number and the GSTIN are
//! also reported bare (K05), where the check carries the finding.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Aadhaar number, plain or grouped, with an Aadhaar term near the value or as
/// its key.
pub(super) const AADHAAR: PiiPattern = PiiPattern {
    name: "pii_aadhaar_in",
    pattern: r"(?-u:\b)[2-9][0-9]{3}(?:[0-9]{8}| [0-9]{4} [0-9]{4}|-[0-9]{4}-[0-9]{4}|:[0-9]{4}:[0-9]{4})(?-u:\b)",
    entity_group: "IN_AADHAAR",
    validator: Some(validators::in_aadhaar),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare grouped Aadhaar number, in `balanced` and `recall` only.
pub(super) const AADHAAR_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_aadhaar_in_context_free",
    pattern: r"(?-u:\b)[2-9][0-9]{3}(?: [0-9]{4} [0-9]{4}|-[0-9]{4}-[0-9]{4}|:[0-9]{4}:[0-9]{4})(?-u:\b)",
    entity_group: "IN_AADHAAR",
    validator: Some(validators::in_aadhaar),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// The GSTIN form: state code, PAN, entity number, `Z`, check character.
macro_rules! gstin {
    () => {
        r"(?-u:\b)[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z](?-u:\b)"
    };
}

/// GSTIN with a GSTIN term near the value or as its key.
pub(super) const GSTIN: PiiPattern = PiiPattern {
    name: "pii_gstin_in",
    pattern: gstin!(),
    entity_group: "IN_GSTIN",
    validator: Some(validators::in_gstin),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare GSTIN, in `balanced` and `recall` only.
pub(super) const GSTIN_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_gstin_in_context_free",
    pattern: gstin!(),
    entity_group: "IN_GSTIN",
    validator: Some(validators::in_gstin),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// PAN with a PAN term near the value or as its key.
pub(super) const PAN: PiiPattern = PiiPattern {
    name: "pii_pan_in",
    pattern: r"(?-u:\b)[A-Z]{5}[0-9]{4}[A-Z](?-u:\b)",
    entity_group: "IN_PAN",
    validator: Some(validators::in_pan),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// Voter ID (EPIC) with a voter ID term near the value or as its key.
pub(super) const VOTER_ID: PiiPattern = PiiPattern {
    name: "pii_voter_id_in",
    pattern: r"(?-u:\b)[A-Z]{3}[0-9]{7}(?-u:\b)",
    entity_group: "IN_VOTER",
    validator: Some(validators::in_voter_id),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
