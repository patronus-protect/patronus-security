// SPDX-License-Identifier: GPL-3.0-only
//! United States identifiers: NANP phone numbers, Social Security Number.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── Telefon ──────────────────────────────────────────────────────────────────
pub(super) const PHONE: PiiPattern = PiiPattern {
    name: "pii_phone_us",
    pattern: r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b",
    entity_group: "PHONE",
    validator: Some(validators::unanchored_phone),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

// ── Sozialversicherung ───────────────────────────────────────────────────────
pub(super) const SSN: PiiPattern = PiiPattern {
    name: "pii_ssn_us",
    pattern: r"(?i)\b(?:ssn|social[ \t]+security[ \t]+number|(?:us[- \t]+)?sozialversicherungsnummer|num(?:é|e)ro[ \t]+de[ \t]+s(?:é|e)curit(?:é|e)[ \t]+sociale|n(?:ú|u)mero[ \t]+de[ \t]+(?:(?:la[ \t]+)?seguridad|seguro)[ \t]+social|numero[ \t]+di[ \t]+(?:sicurezza|previdenza)[ \t]+sociale|sociaal[-_ \t]?zekerheidsnummer|socialezekerheidsnummer)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{3}[ -]\d{2}[ -]\d{4})\b",
    entity_group: "SSN",
    validator: Some(validators::us_ssn),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};
