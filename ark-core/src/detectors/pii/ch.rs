// SPDX-License-Identifier: MIT OR Apache-2.0
//! Swiss identifiers (B-EU2): the AHV number (AHVN13, numéro AVS, numero AVS).
//!
//! Thirteen digits, the country code 756 and an EAN-13 check digit, printed
//! `756.1234.5678.97`. With a term of the label near it or as its key the value is
//! reported in every mode, also plain or in groups by spaces; in `balanced` and
//! `recall` the dotted form is also reported bare (K05), where the prefix, the
//! dots and the check digit carry the finding.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// AHV number, `756.NNNN.NNNN.NN`, by spaces or thirteen digits, with an AHV term
/// near the value or as its key.
pub(super) const AHV_NUMBER: PiiPattern = PiiPattern {
    name: "pii_ahv_number_ch",
    pattern: r"(?-u:\b)756(?:[0-9]{10}|\.[0-9]{4}\.[0-9]{4}\.[0-9]{2}| [0-9]{4} [0-9]{4} [0-9]{2})(?-u:\b)",
    entity_group: "CH_AHV_NUMBER",
    validator: Some(validators::ch_ahv_number),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare AHV number printed `756.NNNN.NNNN.NN`, in `balanced` and `recall` only.
pub(super) const AHV_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_ahv_number_ch_context_free",
    pattern: r"(?-u:\b)756\.[0-9]{4}\.[0-9]{4}\.[0-9]{2}(?-u:\b)",
    entity_group: "CH_AHV_NUMBER",
    validator: Some(validators::ch_ahv_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
