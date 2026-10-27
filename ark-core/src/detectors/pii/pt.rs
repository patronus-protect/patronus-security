// SPDX-License-Identifier: MIT OR Apache-2.0
//! Portuguese identifiers (B-EU2): the NIF (número de identificação fiscal).
//!
//! Nine digits with the mod-11 check digit of the Portuguese VAT ID, which is the
//! NIF behind `PT` (B16); the bare NIF has its own label. Nine digits pass the
//! check one time in eleven and are also a SIREN, a BSN, a SIN or an order number,
//! so the NIF is reported in every mode only with a term of its label near it or
//! as its key; there is no context-free form.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// NIF, nine digits or 3-3-3 by spaces or hyphens, with a NIF term near the value
/// or as its key.
pub(super) const NIF: PiiPattern = PiiPattern {
    name: "pii_nif_pt",
    pattern: r"(?-u:\b)[1-9][0-9]{2}(?: [0-9]{3} [0-9]{3}|-[0-9]{3}-[0-9]{3}|[0-9]{6})(?-u:\b)",
    entity_group: "PT_NIF",
    validator: Some(validators::pt_nif),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
