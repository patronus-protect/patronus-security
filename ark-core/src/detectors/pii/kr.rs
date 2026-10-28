// SPDX-License-Identifier: MIT OR Apache-2.0
//! Korean identifiers (B-KR): the resident registration number (주민등록번호, RRN),
//! the foreigner registration number (외국인등록번호, FRN) and the business
//! registration number (사업자등록번호, BRN).
//!
//! RRN and FRN are thirteen digits `YYMMDD-GHHSSSC`: birth date, a sex and century
//! digit (1–4 residents, 5–8 foreigners), a region code up to 95 and a check digit
//! mod 11. The BRN is ten digits `NNN-NN-NNNNN` with a weighted check digit mod 10.
//! With a term of the label near it or as its key a value is reported in every
//! mode, also without the hyphen; in `balanced` and `recall` the hyphenated forms
//! are also reported bare (K05), where the date, the region code and the check
//! digit (RRN, FRN) or the 3-2-5 print form and the check digit (BRN) carry the
//! finding.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// A registration number with the sex and century digits of `$sex`, hyphenated
/// or as thirteen digits.
macro_rules! registration_number {
    ($sex:literal) => {
        concat!(
            r"(?-u:\b)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])-?",
            $sex,
            r"[0-9]{6}(?-u:\b)"
        )
    };
}

/// The hyphenated registration number with the sex and century digits of `$sex`.
macro_rules! hyphenated_registration_number {
    ($sex:literal) => {
        concat!(
            r"(?-u:\b)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])-",
            $sex,
            r"[0-9]{6}(?-u:\b)"
        )
    };
}

/// Resident registration number with an RRN term near the value or as its key.
pub(super) const RESIDENT_REGISTRATION_NUMBER: PiiPattern = PiiPattern {
    name: "pii_rrn_kr",
    pattern: registration_number!("[1-4]"),
    entity_group: "KR_RRN",
    validator: Some(validators::kr_rrn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare hyphenated resident registration number, in `balanced` and `recall` only.
pub(super) const RESIDENT_REGISTRATION_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_rrn_kr_context_free",
    pattern: hyphenated_registration_number!("[1-4]"),
    entity_group: "KR_RRN",
    validator: Some(validators::kr_rrn),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// Foreigner registration number with an FRN term near the value or as its key.
pub(super) const FOREIGNER_REGISTRATION_NUMBER: PiiPattern = PiiPattern {
    name: "pii_frn_kr",
    pattern: registration_number!("[5-8]"),
    entity_group: "KR_FRN",
    validator: Some(validators::kr_frn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare hyphenated foreigner registration number, in `balanced` and `recall` only.
pub(super) const FOREIGNER_REGISTRATION_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_frn_kr_context_free",
    pattern: hyphenated_registration_number!("[5-8]"),
    entity_group: "KR_FRN",
    validator: Some(validators::kr_frn),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// Business registration number, `NNN-NN-NNNNN` or ten digits, with a BRN term
/// near the value or as its key.
pub(super) const BUSINESS_REGISTRATION_NUMBER: PiiPattern = PiiPattern {
    name: "pii_brn_kr",
    pattern: r"(?-u:\b)(?:[0-9]{3}-[0-9]{2}-[0-9]{5}|[0-9]{10})(?-u:\b)",
    entity_group: "KR_BRN",
    validator: Some(validators::kr_brn),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare business registration number printed `NNN-NN-NNNNN`, in `balanced` and
/// `recall` only.
pub(super) const BUSINESS_REGISTRATION_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_brn_kr_context_free",
    pattern: r"(?-u:\b)[0-9]{3}-[0-9]{2}-[0-9]{5}(?-u:\b)",
    entity_group: "KR_BRN",
    validator: Some(validators::kr_brn),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
