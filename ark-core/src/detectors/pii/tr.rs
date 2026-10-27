// SPDX-License-Identifier: MIT OR Apache-2.0
//! Turkish identifiers (B-LUHN): the T.C. Kimlik No (TCKN).
//!
//! Eleven digits without a leading zero and two check digits. The number has no
//! print groups, and eleven bare digits are also a Steuer-ID, a phone number or a
//! fødselsnummer, so it is reported in every mode only with a term of its label
//! near it or as its key; there is no context-free form. In the scored modes it
//! competes with the other eleven-digit labels (K07), where the term decides.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// T.C. Kimlik No, eleven digits, with a T.C. Kimlik term near the value or as its
/// key.
pub(super) const NATIONAL_ID: PiiPattern = PiiPattern {
    name: "pii_national_id_tr",
    pattern: r"(?-u:\b)[1-9][0-9]{10}(?-u:\b)",
    entity_group: "TR_NATIONAL_ID",
    validator: Some(validators::tr_national_id),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
