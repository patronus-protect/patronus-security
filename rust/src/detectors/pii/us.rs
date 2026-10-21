// SPDX-License-Identifier: GPL-3.0-only
//! United States identifiers: NANP phone numbers, Social Security Number.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── Telefon ──────────────────────────────────────────────────────────────────
pub(super) const PHONE: PiiPattern = PiiPattern {
    name: "pii_phone_us",
    // A balanced `(NXX)` starts the span (T04); `\b` never holds before `(` after a
    // space, so the second branch alone yields `415) 555-2671`. The area code is set
    // off by `)` or a separator (T17): `712390-9678` (6-4) and zero-padded IDs like
    // `0000012345` have no NANP grouping. A trunk `1`/`+1` or a `00` international
    // prefix belongs to the span (T18: `1-800-123-4567`, `1 (800) 123-4567`,
    // `001 415 555 2671`); it is optional, so it only widens a number found without it.
    // No separator is a line break.
    pattern: r"(?:(?:\+1|\b(?:00[1-9]\d{0,2}|1))[\s\-\.&&[^\n-\r\x85\x{2028}\x{2029}]])?(?:\(\d{3}\)[\s\-\.&&[^\n-\r\x85\x{2028}\x{2029}]]?|\b\(?\d{3}(?:\)[\s\-\.&&[^\n-\r\x85\x{2028}\x{2029}]]?|[\s\-\.&&[^\n-\r\x85\x{2028}\x{2029}]]))\d{3}[\s\-\.&&[^\n-\r\x85\x{2028}\x{2029}]]?\d{4}\b",
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
