// SPDX-License-Identifier: MIT OR Apache-2.0
//! South African identifiers (B-LUHN): the identity number.
//!
//! Thirteen digits `YYMMDD SSSS C A Z`: birth date, sequence number, citizenship
//! (0–2), an 8 or 9 and a Luhn check digit. The date, the two fixed fields and the
//! check digit leave about one thirteen-digit run in five thousand, so in
//! `balanced` and `recall` the value is also reported bare (K05), plain or grouped
//! 6-4-3; with a term of its label near it or as its key it is reported in every
//! mode.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// The identity number, thirteen digits or 6-4-3 (`800101 5009 087`), with the
/// citizenship digit and the 8 or 9 in place.
macro_rules! za_id_number {
    () => {
        r"(?-u:\b)(?:[0-9]{10}|[0-9]{6} [0-9]{4} )[0-2][89][0-9](?-u:\b)"
    };
}

/// South African identity number with an identity number term near the value or
/// as its key.
pub(super) const ID_NUMBER: PiiPattern = PiiPattern {
    name: "pii_id_number_za",
    pattern: za_id_number!(),
    entity_group: "ZA_ID_NUMBER",
    validator: Some(validators::za_id_number),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare South African identity number, in `balanced` and `recall` only.
pub(super) const ID_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_id_number_za_context_free",
    pattern: za_id_number!(),
    entity_group: "ZA_ID_NUMBER",
    validator: Some(validators::za_id_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
