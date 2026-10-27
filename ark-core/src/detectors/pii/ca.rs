// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canadian identifiers (B-LUHN): the Social Insurance Number (SIN).
//!
//! Nine digits with a Luhn check digit; the first names the region of
//! registration (1–7) or a temporary resident (9). Nine digits pass Luhn one time
//! in ten, so a bare run or 3-3-3 groups by spaces (also the print form of a SIREN,
//! a BSN or the body of a VAT ID, `DE 130 692 544`) need a term of the label in
//! every mode. In `balanced` and `recall` the hyphenated groups (`130-692-544`) are
//! also reported bare (K05).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// SIN, 3-3-3 by spaces or hyphens or nine digits, with a SIN term near the value
/// or as its key.
pub(super) const SIN: PiiPattern = PiiPattern {
    name: "pii_sin_ca",
    pattern: r"(?-u:\b)[1-79][0-9]{2}(?: [0-9]{3} [0-9]{3}|-[0-9]{3}-[0-9]{3}|[0-9]{6})(?-u:\b)",
    entity_group: "CA_SIN",
    validator: Some(validators::ca_sin),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare SIN in hyphenated 3-3-3 groups, in `balanced` and `recall` only.
pub(super) const SIN_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_sin_ca_context_free",
    pattern: r"(?-u:\b)[1-79][0-9]{2}-[0-9]{3}-[0-9]{3}(?-u:\b)",
    entity_group: "CA_SIN",
    validator: Some(validators::ca_sin),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
