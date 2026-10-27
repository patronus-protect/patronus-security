// SPDX-License-Identifier: MIT OR Apache-2.0
//! Irish identifiers (B-EU2): the PPS number (Personal Public Service Number).
//!
//! Seven digits, a check letter mod 23 (the one of the Irish VAT number) and an
//! optional second letter. Seven digits and a letter are a common reference or
//! order code and pass the check letter one time in 23, so the PPSN is reported in
//! every mode only with a term of its label near it or as its key; there is no
//! context-free form.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// PPSN, `1234567T` or `1234567FA`, with a PPSN term near the value or as its key.
pub(super) const PPSN: PiiPattern = PiiPattern {
    name: "pii_ppsn_ie",
    pattern: r"(?-u:\b)[0-9]{7}[A-W][ABTWX]?(?-u:\b)",
    entity_group: "IE_PPSN",
    validator: Some(validators::ie_ppsn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
