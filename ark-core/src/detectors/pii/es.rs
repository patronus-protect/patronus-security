// SPDX-License-Identifier: MIT OR Apache-2.0
//! Spanish personal identifiers (B-ESIT): the DNI/NIF of Spanish citizens and the
//! NIE (número de identidad de extranjero) of foreigners.
//!
//! Both end in the control letter of the number mod 23 (`validators::es_nif`,
//! `validators::es_nie`), which is also the body of a Spanish VAT ID after `ES`
//! (B01). With a term of the label near it or as its key a value is reported in
//! every mode, in any case and with a hyphen before the letter; in `balanced` and
//! `recall` an uppercase value is also reported bare (K05). The CIF of companies
//! is the Spanish VAT ID without `ES` (`vat::VAT_ID_ES_PROXIMITY`).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// DNI/NIF, eight digits (seven of an older DNI) and the control letter, with an
/// NIF term near the value or as its key.
pub(super) const NIF: PiiPattern = PiiPattern {
    name: "pii_nif_es",
    pattern: r"(?-u:\b)[0-9]{7,8}-?[A-Za-z](?-u:\b)",
    entity_group: "ES_NIF",
    validator: Some(validators::es_nif),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare uppercase DNI/NIF of eight digits, in `balanced` and `recall` only.
pub(super) const NIF_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_nif_es_context_free",
    pattern: r"(?-u:\b)[0-9]{8}-?[A-Z](?-u:\b)",
    entity_group: "ES_NIF",
    validator: Some(validators::es_nif),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// NIE, `X`/`Y`/`Z`, seven digits and the control letter, with an NIE term near
/// the value or as its key.
pub(super) const NIE: PiiPattern = PiiPattern {
    name: "pii_nie_es",
    pattern: r"(?-u:\b)[XYZxyz]-?[0-9]{7}-?[A-Za-z](?-u:\b)",
    entity_group: "ES_NIE",
    validator: Some(validators::es_nie),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare uppercase NIE, in `balanced` and `recall` only.
pub(super) const NIE_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_nie_es_context_free",
    pattern: r"(?-u:\b)[XYZ]-?[0-9]{7}-?[A-Z](?-u:\b)",
    entity_group: "ES_NIE",
    validator: Some(validators::es_nie),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
