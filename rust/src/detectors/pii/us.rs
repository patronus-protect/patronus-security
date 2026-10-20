// SPDX-License-Identifier: GPL-3.0-only
//! United States identifiers: NANP phone numbers, Social Security Number.
use super::{pii::PiiPattern, validators};

// ── Telefon ──────────────────────────────────────────────────────────────────
pub(super) const PHONE: PiiPattern = PiiPattern {
    name: "pii_phone_us",
    pattern: r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b",
    entity_group: "PHONE",
    validator: Some(validators::unanchored_phone),
    captured_value: false,
};

// ── Sozialversicherung ───────────────────────────────────────────────────────
pub(super) const SSN: PiiPattern = PiiPattern {
    name: "pii_ssn_us",
    pattern: r"(?i)\b(?:ssn|social[ \t]+security[ \t]+number|(?:us[- \t]+)?sozialversicherungsnummer)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{3}[ -]\d{2}[ -]\d{4})\b",
    entity_group: "SSN",
    validator: Some(validators::us_ssn),
    captured_value: true,
};
