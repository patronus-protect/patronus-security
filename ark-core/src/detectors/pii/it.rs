// SPDX-License-Identifier: MIT OR Apache-2.0
//! Italian personal identifiers (B-ESIT): the codice fiscale of a person.
//!
//! Sixteen characters: three letters of the surname, three of the name, the
//! birth year, a month letter, the day (plus 40 for women), the place code and a
//! check letter mod 26 (`validators::it_fiscal_code`); duplicates replace digits
//! by letters (omocodia). With a term of the label near it or as its key a code
//! is reported in every mode, in any case; in `balanced` and `recall` an
//! uppercase code is also reported bare (K05). The Partita IVA is the Italian VAT
//! ID (`vat::VAT_ID_IT_PROXIMITY`, B01).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Codice fiscale with a fiscal code term near the value or as its key.
pub(super) const FISCAL_CODE: PiiPattern = PiiPattern {
    name: "pii_fiscal_code_it",
    pattern: r"(?i)(?-u:\b)[A-Z]{6}[0-9LMNP-V]{2}[ABCDEHLMPRST][0-9LMNP-V]{2}[A-Z][0-9LMNP-V]{3}[A-Z](?-u:\b)",
    entity_group: "IT_FISCAL_CODE",
    validator: Some(validators::it_fiscal_code),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare uppercase codice fiscale, in `balanced` and `recall` only.
pub(super) const FISCAL_CODE_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_fiscal_code_it_context_free",
    pattern: r"(?-u:\b)[A-Z]{6}[0-9LMNP-V]{2}[ABCDEHLMPRST][0-9LMNP-V]{2}[A-Z][0-9LMNP-V]{3}[A-Z](?-u:\b)",
    entity_group: "IT_FISCAL_CODE",
    validator: Some(validators::it_fiscal_code),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
