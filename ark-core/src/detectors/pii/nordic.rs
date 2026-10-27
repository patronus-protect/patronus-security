// SPDX-License-Identifier: MIT OR Apache-2.0
//! Nordic personal identity numbers (B-NORD): Swedish personnummer, Danish CPR
//! number, Norwegian fødselsnummer, Finnish personal identity code (henkilötunnus);
//! the Swedish organisationsnummer (B-LUHN).
//!
//! All four start with the birth date and end in a check digit or character: Luhn
//! (SE), a weighted sum mod 11 (DK), two digits mod 11 (NO), the nine digits mod 31
//! (FI). With a term of its label near the value or as its key, a value is reported
//! in every mode. In `balanced` and `recall` the printed forms are also reported
//! bare (K05): the personnummer and the CPR number with their `-` (`811228-9874`,
//! `080572-3300`), the fødselsnummer in 6-5 groups (`150244 27975`) and the
//! henkilötunnus with its century sign (`131052-308T`). A bare run of ten to twelve
//! digits is an order, account or phone number too often and needs the term.
//! The SE, DK and FI forms share `DDDDDD-DDDD`; a value that passes two of the
//! checks competes in the scored modes (K07), where a term of a label decides.
//!
//! The Swedish organisationsnummer (B-LUHN) shares the form too, but its third
//! digit is 2 or more where the personal numbers carry a birth month; it ends in a
//! Luhn digit and follows the same two rules.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Swedish personnummer, `YYMMDD-NNNC`, with `+` from the 100th birthday, or the
/// ten or twelve digits (`198112289874`), with a personnummer term near the value
/// or as its key.
pub(super) const PERSONNUMMER: PiiPattern = PiiPattern {
    name: "pii_personnummer_se",
    pattern: r"(?-u:\b)(?:19|20)?[0-9]{6}[-+]?[0-9]{4}(?-u:\b)",
    entity_group: "SE_PERSONNUMMER",
    validator: Some(validators::se_personnummer),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare personnummer in its printed form `YYMMDD-NNNC` (or `+`), in `balanced`
/// and `recall` only. Twelve digits with a dash also print a date stamp and a time
/// (`20241026-1529`) and need the term.
pub(super) const PERSONNUMMER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_personnummer_se_context_free",
    pattern: r"(?-u:\b)[0-9]{6}[-+][0-9]{4}(?-u:\b)",
    entity_group: "SE_PERSONNUMMER",
    validator: Some(validators::se_personnummer),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// Danish CPR number, `DDMMYY-SSSS` or ten digits, with a CPR term near the value
/// or as its key.
pub(super) const CPR: PiiPattern = PiiPattern {
    name: "pii_cpr_dk",
    pattern: r"(?-u:\b)[0-9]{6}-?[0-9]{4}(?-u:\b)",
    entity_group: "DK_CPR",
    validator: Some(validators::dk_cpr),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare CPR number in its printed form `DDMMYY-SSSS`, in `balanced` and
/// `recall` only.
pub(super) const CPR_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_cpr_dk_context_free",
    pattern: r"(?-u:\b)[0-9]{6}-[0-9]{4}(?-u:\b)",
    entity_group: "DK_CPR",
    validator: Some(validators::dk_cpr),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// Norwegian fødselsnummer or D-number, eleven digits or `DDMMYY NNNKK`, with a
/// fødselsnummer term near the value or as its key.
pub(super) const FODSELSNUMMER: PiiPattern = PiiPattern {
    name: "pii_fodselsnummer_no",
    pattern: r"(?-u:\b)[0-9]{6} ?[0-9]{5}(?-u:\b)",
    entity_group: "NO_FODSELSNUMMER",
    validator: Some(validators::no_fodselsnummer),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare fødselsnummer in its printed 6-5 groups (`150244 27975`), in `balanced`
/// and `recall` only. Eleven bare digits are also a Steuer-ID or a phone number.
pub(super) const FODSELSNUMMER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_fodselsnummer_no_context_free",
    pattern: r"(?-u:\b)[0-9]{6} [0-9]{5}(?-u:\b)",
    entity_group: "NO_FODSELSNUMMER",
    validator: Some(validators::no_fodselsnummer),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// The henkilötunnus: `DDMMYY`, century sign, individual number, check character,
/// in either letter case.
macro_rules! hetu {
    () => {
        r"(?i-u)\b[0-9]{6}[-YXWVUA-F][0-9]{3}[0-9A-Y]\b"
    };
}

/// Finnish personal identity code (`131052-308T`, `010594Y9032`), with a HETU term
/// near the value or as its key.
pub(super) const HETU: PiiPattern = PiiPattern {
    name: "pii_hetu_fi",
    pattern: hetu!(),
    entity_group: "FI_PERSONAL_IDENTITY_CODE",
    validator: Some(validators::fi_hetu),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare henkilötunnus, in `balanced` and `recall` only: the century sign inside
/// the value and the mod-31 check character carry the form.
pub(super) const HETU_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_hetu_fi_context_free",
    pattern: hetu!(),
    entity_group: "FI_PERSONAL_IDENTITY_CODE",
    validator: Some(validators::fi_hetu),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// Swedish organisationsnummer (B-LUHN), `NNNNNN-NNNN` or ten digits with a third
/// digit of 2 or more, with an organisationsnummer term near the value or as its
/// key.
pub(super) const ORGANISATIONSNUMMER: PiiPattern = PiiPattern {
    name: "pii_organisationsnummer_se",
    pattern: r"(?-u:\b)[0-9]{2}[2-9][0-9]{3}-?[0-9]{4}(?-u:\b)",
    entity_group: "SE_ORGANISATIONSNUMMER",
    validator: Some(validators::se_organisationsnummer),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A bare organisationsnummer in its printed form `NNNNNN-NNNN`, in `balanced` and
/// `recall` only. Its third digit keeps it apart from the personnummer, the CPR
/// number and the henkilötunnus, whose month stands there; ten bare digits are a
/// phone, order or account number too often and need the term.
pub(super) const ORGANISATIONSNUMMER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_organisationsnummer_se_context_free",
    pattern: r"(?-u:\b)[0-9]{2}[2-9][0-9]{3}-[0-9]{4}(?-u:\b)",
    entity_group: "SE_ORGANISATIONSNUMMER",
    validator: Some(validators::se_organisationsnummer),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
