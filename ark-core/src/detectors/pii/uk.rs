// SPDX-License-Identifier: MIT OR Apache-2.0
//! United Kingdom identifiers: National Insurance number, NHS number, passport, BBAN.
//!
//! The NINO rule binds a value to its field name, alone or in pairs
//! (`AB 12 34 56 C`), in any case; a bare NINO in one case is reported in `balanced`
//! and `recall` only (B-UK). Its validator checks the letters HMRC issues, no check
//! digit. The NHS number has a mod-11 check digit, but ten digits in phone groups
//! pass it one time in eleven: it needs an NHS term near the value or as its key in
//! every mode, like the UK passport number, whose form has no check digit at all. The UK
//! driving licence lives with the other licences in `driver_license`.
//!
//! The GB BBAN (T29: bank code, sort code, account, `ZFJR88590163492773`) has no check
//! digit either: it is an account number only with a BBAN or account term near the
//! value or as its key, in every mode, and never bare.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// The NINO forms: one block (`AB123456C`, `AB 123456 C`) or pairs (`AB 12 34 56 C`).
macro_rules! nino_value {
    () => {
        r"[A-Z]{2}(?: ?[0-9]{6} ?| [0-9]{2} [0-9]{2} [0-9]{2} )[A-D]"
    };
}

pub(super) const NINO: PiiPattern = PiiPattern {
    name: "pii_ni_uk",
    pattern: concat!(
        r"(?i)\b(?:nino|national[ \t]+insurance[ \t]+(?:number|no)|ni[-_ \t]?(?:number|no|nummer|nr)|britische[ \t]+sozialversicherungsnummer)\b\.?[ \t]*(?:(?:is|ist|lautet)[ \t]*)?[:#=\-]?[ \t]*(?P<value>",
        nino_value!(),
        r")\b"
    ),
    entity_group: "NATIONALID",
    validator: Some(validators::uk_nino),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// A bare NINO in one letter case (`AB123456C`, `hh 01 02 03 d`), as presidio-analyzer
/// reports it without context. The issued prefixes and suffixes stand in for a check
/// digit: the value just reaches the `balanced` threshold, a nearer counter-context
/// term drops it, and `strict` never runs the rule.
pub(super) const NINO_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_ni_uk_context_free",
    pattern: concat!(r"(?i-u)\b", nino_value!(), r"\b"),
    entity_group: "NATIONALID",
    validator: Some(validators::uk_nino_context_free),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// Ten digits with the NHS check digit, grouped 3-3-4 by spaces or hyphens or bare,
/// with an NHS term near the value or as its key.
pub(super) const NHS_NUMBER: PiiPattern = PiiPattern {
    name: "pii_nhs_number_uk",
    pattern: r"(?-u:\b)(?:[0-9]{3} [0-9]{3} [0-9]{4}|[0-9]{3}-[0-9]{3}-[0-9]{4}|[0-9]{10})(?-u:\b)",
    entity_group: "NHS_NUMBER",
    validator: Some(validators::uk_nhs_number),
    strength: ValidatorStrength::Checksum,
    base_score: 25,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A UK passport number, nine digits (`925665416`), with a passport term near the
/// value or as its key.
pub(super) const PASSPORT_NUMBER: PiiPattern = PiiPattern {
    name: "pii_passport_number_uk",
    pattern: r"(?-u:\b)[0-9]{9}(?-u:\b)",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::nine_digits),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A GB BBAN, four letters of the bank code, the six-digit sort code and the
/// eight-digit account (`ZFJR88590163492773`), with a BBAN or account term near the
/// value or as its key.
pub(super) const BBAN: PiiPattern = PiiPattern {
    name: "pii_bban_gb",
    pattern: r"(?-u:\b)[A-Z]{4}[0-9]{14}(?-u:\b)",
    entity_group: "FINANCIAL_ACCOUNT_NUMBER",
    validator: Some(validators::uk_bban),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
