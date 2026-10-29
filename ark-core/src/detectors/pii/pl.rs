// SPDX-License-Identifier: MIT OR Apache-2.0
//! Polish identifiers (A13): the PESEL of a person and the REGON of a business.
//!
//! The PESEL is eleven digits `YYMMDDZZZXC`: the birth date with the century in
//! the month and a check digit weighted 1 3 7 9 mod 10. The REGON is nine digits
//! with a check digit mod 11, or fourteen for a local unit whose first nine are
//! the REGON of the business. Bare runs of nine, eleven or fourteen digits prove
//! too little, so both need a term of their label near the value or as its key,
//! in every mode. The NIP is the body of the Polish VAT ID
//! (`vat::VAT_ID_PL_PROXIMITY`, B16).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// PESEL with a PESEL term near the value or as its key.
pub(super) const PESEL: PiiPattern = PiiPattern {
    name: "pii_pesel_pl",
    pattern: r"(?-u:\b)[0-9]{11}(?-u:\b)",
    entity_group: "PL_PESEL",
    validator: Some(validators::pl_pesel),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// REGON, nine or fourteen digits, with a REGON term near the value or as its key.
pub(super) const REGON: PiiPattern = PiiPattern {
    name: "pii_regon_pl",
    pattern: r"(?-u:\b)(?:[0-9]{9}|[0-9]{14})(?-u:\b)",
    entity_group: "PL_REGON",
    validator: Some(validators::pl_regon),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
