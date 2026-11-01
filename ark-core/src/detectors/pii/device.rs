// SPDX-License-Identifier: MIT OR Apache-2.0
//! Mobile device and SIM identifiers (B-DEVID): the IMEI, the MEID, the ICCID
//! and the IMSI.
//!
//! The IMEI is fifteen digits, plain or grouped 2-6-6-1, the last a Luhn check
//! digit. The MEID is fourteen upper-case hex digits led by a regional code
//! `A0`–`FF` and a check digit computed by Luhn in base 16. The ICCID is 19 or
//! 20 digits led by the telecom prefix `89`, plain or in blocks of four, the
//! last a Luhn check digit. The IMSI (fifteen digits led by a mobile country
//! code `2xx`–`7xx`) carries no check digit. One bare fifteen-digit number in
//! ten passes Luhn, so every rule reports its value in every mode only with a
//! term of its label near the value or as its key.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// IMEI, plain or 2-6-6-1, with an IMEI term near the value or as its key.
pub(super) const IMEI: PiiPattern = PiiPattern {
    name: "pii_imei",
    pattern: r"(?-u:\b)[0-9]{2}(?:[0-9]{13}|-[0-9]{6}-[0-9]{6}-[0-9]| [0-9]{6} [0-9]{6} [0-9])(?-u:\b)",
    entity_group: "IMEI",
    validator: Some(validators::imei),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// MEID with its hex check digit and a MEID term near the value or as its key.
pub(super) const MEID: PiiPattern = PiiPattern {
    name: "pii_meid",
    pattern: r"(?-u:\b)[A-F][0-9A-F]{14}(?-u:\b)",
    entity_group: "MEID",
    validator: Some(validators::meid),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// ICCID, plain or in blocks of four, with a SIM term near the value or as its
/// key.
pub(super) const ICCID: PiiPattern = PiiPattern {
    name: "pii_iccid",
    pattern: r"(?-u:\b)89(?:[0-9]{17,18}|[0-9]{2}(?: [0-9]{4}){3} [0-9]{3,4})(?-u:\b)",
    entity_group: "ICCID",
    validator: Some(validators::iccid),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// IMSI with an IMSI term near the value or as its key.
pub(super) const IMSI: PiiPattern = PiiPattern {
    name: "pii_imsi",
    pattern: r"(?-u:\b)[2-7][0-9]{14}(?-u:\b)",
    entity_group: "IMSI",
    validator: Some(validators::imsi),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
