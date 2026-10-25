// SPDX-License-Identifier: GPL-3.0-only
//! Singapore identifiers (B-APAC): NRIC/FIN and Unique Entity Number.
//!
//! Both end in a check letter mod 11. With a term of its label near the value or as
//! its key, a value is reported in every mode, the NRIC/FIN in either case. In
//! `balanced` and `recall` an uppercase NRIC/FIN (series letter, seven digits,
//! check letter) and a UEN of format B (registration year) or C (`T`/`S`/`R`,
//! entity type) are also reported bare (K05). A UEN of format A, eight digits and
//! a letter, has the form of a Spanish DNI and needs the term in every mode.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// NRIC/FIN (`S0642712Z`, `G0228472W`, `M1235467X`) in either case, with an NRIC or
/// FIN term near the value or as its key.
pub(super) const NRIC_FIN: PiiPattern = PiiPattern {
    name: "pii_nric_fin_sg",
    pattern: r"(?i-u)\b[STFGM][0-9]{7}[A-Z]\b",
    entity_group: "SG_NRIC_FIN",
    validator: Some(validators::sg_nric_fin),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare uppercase NRIC/FIN, in `balanced` and `recall` only.
pub(super) const NRIC_FIN_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_nric_fin_sg_context_free",
    pattern: r"(?-u)\b[STFGM][0-9]{7}[A-Z]\b",
    entity_group: "SG_NRIC_FIN",
    validator: Some(validators::sg_nric_fin),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// UEN of format A (`53125226D`), B (`201434292D`) or C (`S57TU0392K`), with a
/// UEN term near the value or as its key.
pub(super) const UEN: PiiPattern = PiiPattern {
    name: "pii_uen_sg",
    pattern: r"(?-u)\b(?:[0-9]{8,9}|[TSR][0-9]{2}[A-Z]{2}[0-9]{4})[A-Z]\b",
    entity_group: "SG_UEN",
    validator: Some(validators::sg_uen),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare UEN of format B or C, in `balanced` and `recall` only.
pub(super) const UEN_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_uen_sg_context_free",
    pattern: r"(?-u)\b(?:(?:18|19|20)[0-9]{7}|[TSR][0-9]{2}[A-Z]{2}[0-9]{4})[A-Z]\b",
    entity_group: "SG_UEN",
    validator: Some(validators::sg_uen),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
