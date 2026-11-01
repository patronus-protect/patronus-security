// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vehicle, securities, legal entity and pharmaceutical identifiers (B-FIN).
//!
//! The VIN (ISO 3779) of North American vehicles carries a check digit in its ninth
//! place (`pii_vin`); European VINs carry none and pass `pii_vin_format`. The
//! ISIN (ISO 6166, Luhn over the expanded letters), the LEI (ISO 17442, MOD 97-10)
//! and the German PZN (weighted mod 11) each have a check digit. Every check
//! passes one random value in ten or eleven, and these forms are those of order,
//! serial and article numbers, so all five rules report a value only with a term
//! of its label near it or as its key, in every mode.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// VIN with its North American check digit and a VIN term near the value or as
/// its key.
pub(super) const VIN: PiiPattern = PiiPattern {
    name: "pii_vin",
    pattern: r"(?-u:\b)[A-HJ-NPR-Z0-9]{13}[0-9]{4}(?-u:\b)",
    entity_group: "VIN",
    validator: Some(validators::vin_check_digit),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// VIN in the ISO 3779 form without a check digit (European manufacturers) and a
/// VIN term near the value or as its key.
pub(super) const VIN_FORMAT: PiiPattern = PiiPattern {
    name: "pii_vin_format",
    pattern: r"(?-u:\b)[A-HJ-NPR-Z0-9]{13}[0-9]{4}(?-u:\b)",
    entity_group: "VIN",
    validator: Some(validators::vin),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// ISIN with an ISIN or securities term near the value or as its key.
pub(super) const ISIN: PiiPattern = PiiPattern {
    name: "pii_isin",
    pattern: r"(?-u:\b)[A-Z]{2}[A-Z0-9]{9}[0-9](?-u:\b)",
    entity_group: "ISIN",
    validator: Some(validators::isin),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// LEI with an LEI term near the value or as its key.
pub(super) const LEI: PiiPattern = PiiPattern {
    name: "pii_lei",
    pattern: r"(?-u:\b)[A-Z0-9]{18}[0-9]{2}(?-u:\b)",
    entity_group: "LEI",
    validator: Some(validators::lei),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// Pharmazentralnummer, eight digits or the seven of before 2013, with a PZN term
/// near the value or as its key.
pub(super) const PZN: PiiPattern = PiiPattern {
    name: "pii_pzn_de",
    pattern: r"(?-u:\b)[0-9]{7,8}(?-u:\b)",
    entity_group: "DE_PZN",
    validator: Some(validators::de_pzn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
