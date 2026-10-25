// SPDX-License-Identifier: GPL-3.0-only
//! Australian identifiers (B-APAC): Business Number, Company Number, Tax File
//! Number, Medicare card number.
//!
//! All four carry a check digit, but a weak one for their length: nine digits pass
//! the ACN mod-10 check one time in ten and the TFN mod-11 sum one time in eleven,
//! ten digits the Medicare check one time in ten. Each value is therefore reported
//! in every mode only with a term of its label near it or as its key. In `balanced`
//! and `recall` the printed groupings that add to the check digit are also reported
//! bare (K05): the ABN in 2-3-3-3 groups (mod 89) and the Medicare number in 4-5-1
//! groups. A bare run of nine to eleven digits is an order, invoice or phone number
//! too often.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Australian Business Number, 2-3-3-3 (`51 824 753 556`) or eleven digits, with an
/// ABN term near the value or as its key.
pub(super) const ABN: PiiPattern = PiiPattern {
    name: "pii_abn_au",
    pattern: r"(?-u:\b)[1-9][0-9](?: [0-9]{3} [0-9]{3} [0-9]{3}|[0-9]{9})(?-u:\b)",
    entity_group: "AU_ABN",
    validator: Some(validators::au_abn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare ABN in its printed 2-3-3-3 groups, in `balanced` and `recall` only. The
/// grouping is the Steuer-ID's too; a term of either label decides (K07).
pub(super) const ABN_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_abn_au_context_free",
    pattern: r"(?-u:\b)[1-9][0-9] [0-9]{3} [0-9]{3} [0-9]{3}(?-u:\b)",
    entity_group: "AU_ABN",
    validator: Some(validators::au_abn),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// Australian Company Number, 3-3-3 (`006 249 976`) or nine digits, with an ACN
/// term near the value or as its key.
pub(super) const ACN: PiiPattern = PiiPattern {
    name: "pii_acn_au",
    pattern: r"(?-u:\b)(?:[0-9]{3} [0-9]{3} [0-9]{3}|[0-9]{9})(?-u:\b)",
    entity_group: "AU_ACN",
    validator: Some(validators::au_acn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// Tax File Number, 3-3-3 (`876 543 210`) or nine digits, with a TFN term near the
/// value or as its key.
pub(super) const TFN: PiiPattern = PiiPattern {
    name: "pii_tfn_au",
    pattern: r"(?-u:\b)(?:[0-9]{3} [0-9]{3} [0-9]{3}|[0-9]{9})(?-u:\b)",
    entity_group: "AU_TFN",
    validator: Some(validators::au_tfn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// Medicare card number, 4-5-1 (`2123 45670 1`) or ten digits, with a Medicare
/// term near the value or as its key.
pub(super) const MEDICARE: PiiPattern = PiiPattern {
    name: "pii_medicare_au",
    pattern: r"(?-u:\b)[2-6](?:[0-9]{3} [0-9]{5} [0-9]|[0-9]{9})(?-u:\b)",
    entity_group: "AU_MEDICARE",
    validator: Some(validators::au_medicare),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare Medicare number in its printed 4-5-1 groups, in `balanced` and `recall`
/// only.
pub(super) const MEDICARE_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_medicare_au_context_free",
    pattern: r"(?-u:\b)[2-6][0-9]{3} [0-9]{5} [0-9](?-u:\b)",
    entity_group: "AU_MEDICARE",
    validator: Some(validators::au_medicare),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
