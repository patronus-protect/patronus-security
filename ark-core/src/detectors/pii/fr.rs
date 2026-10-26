// SPDX-License-Identifier: MIT OR Apache-2.0
//! French identifiers (B-EU1): NIR (numéro de sécurité sociale), SIREN and SIRET.
//!
//! The NIR carries a two-digit key mod 97 on top of its sex, birth month and
//! département fields; with a term of its label near the value or as its key it is
//! reported in every mode, and in `balanced` and `recall` also bare (K05), printed
//! 1-2-2-2-3-3-2 or as fifteen characters with sex `1` or `2`. SIREN and SIRET end
//! in a Luhn digit: nine bare digits pass it one time in ten, so the SIREN needs a
//! term in every mode, like the Australian Company Number. A SIRET in its printed
//! 3-3-3-5 groups is also reported bare in the scored modes; fourteen bare digits
//! need the term.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// NIR, 1-2-2-2-3-3-2 (`2 95 10 99 126 111 93`) or fifteen characters with the
/// key apart or not, with a NIR term near the value or as its key.
pub(super) const NIR: PiiPattern = PiiPattern {
    name: "pii_nir_fr",
    pattern: r"(?-u:\b)[1-478](?: [0-9]{2} [0-9]{2} (?:[0-9]{2}|2[AB]) [0-9]{3} [0-9]{3} |[0-9]{4}(?:[0-9]{2}|2[AB])[0-9]{6} ?)[0-9]{2}(?-u:\b)",
    entity_group: "FR_NIR",
    validator: Some(validators::fr_nir),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare NIR of sex `1` or `2`, printed 1-2-2-2-3-3-2 or as fifteen characters,
/// in `balanced` and `recall` only.
pub(super) const NIR_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_nir_fr_context_free",
    pattern: r"(?-u:\b)[12](?: [0-9]{2} [0-9]{2} (?:[0-9]{2}|2[AB]) [0-9]{3} [0-9]{3} |[0-9]{4}(?:[0-9]{2}|2[AB])[0-9]{6})[0-9]{2}(?-u:\b)",
    entity_group: "FR_NIR",
    validator: Some(validators::fr_nir),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// SIREN, 3-3-3 (`732 829 320`) or nine digits, with a SIREN term near the value
/// or as its key.
pub(super) const SIREN: PiiPattern = PiiPattern {
    name: "pii_siren_fr",
    pattern: r"(?-u:\b)(?:[0-9]{3} [0-9]{3} [0-9]{3}|[0-9]{9})(?-u:\b)",
    entity_group: "FR_SIREN",
    validator: Some(validators::fr_siren),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// SIRET, 3-3-3-5 (`732 829 320 00074`) or fourteen digits, with a SIRET term near
/// the value or as its key.
pub(super) const SIRET: PiiPattern = PiiPattern {
    name: "pii_siret_fr",
    pattern: r"(?-u:\b)(?:[0-9]{3} [0-9]{3} [0-9]{3} [0-9]{5}|[0-9]{14})(?-u:\b)",
    entity_group: "FR_SIRET",
    validator: Some(validators::fr_siret),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare SIRET in its printed 3-3-3-5 groups, in `balanced` and `recall` only.
pub(super) const SIRET_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_siret_fr_context_free",
    pattern: r"(?-u:\b)[0-9]{3} [0-9]{3} [0-9]{3} [0-9]{5}(?-u:\b)",
    entity_group: "FR_SIRET",
    validator: Some(validators::fr_siret),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
