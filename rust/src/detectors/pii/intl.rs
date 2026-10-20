// SPDX-License-Identifier: GPL-3.0-only
//! International payment identifiers: IBAN, payment card number, CVV, card expiry, SWIFT/BIC.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── IBAN ─────────────────────────────────────────────────────────────────
// Keep IBAN as the primary classification when a numeric substring also
// passes the card validator. Evidence retains both labels.
pub(super) const IBAN_DE: PiiPattern = PiiPattern {
    name: "pii_iban_de",
    pattern: r"\bDE\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{2}\b",
    entity_group: "IBAN",
    validator: Some(validators::mod97),
    strength: ValidatorStrength::Checksum,
    base_score: 55,
    captured_value: false,
    requires_context: false,
};

pub(super) const IBAN_GENERIC: PiiPattern = PiiPattern {
    name: "pii_iban_generic",
    pattern: r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    entity_group: "IBAN",
    validator: Some(validators::mod97),
    strength: ValidatorStrength::Checksum,
    base_score: 45,
    captured_value: false,
    requires_context: false,
};

// ── Kreditkarte ──────────────────────────────────────────────────────────
pub(super) const CREDIT_CARD: PiiPattern = PiiPattern {
    name: "pii_credit_card",
    pattern: r"\b(?:\d[ \-]?){11,18}\d\b",
    entity_group: "CREDITCARD",
    validator: Some(validators::luhn),
    strength: ValidatorStrength::Checksum,
    base_score: 40,
    captured_value: false,
    requires_context: false,
};

pub(super) const CREDIT_CARD_CVV: PiiPattern = PiiPattern {
    name: "pii_credit_card_cvv",
    pattern: r"(?i)\b(?:cvv2?|cvc2?|card[ \t]+verification[ \t]+(?:value|code)|kartenpr(?:ü|ue)fnummer|kartenpr(?:ü|ue)fziffer|sicherheitscode)[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{3,4})\b",
    entity_group: "CREDITCARD_CVV",
    validator: Some(validators::cvv),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: true,
    requires_context: false,
};

pub(super) const CREDIT_CARD_EXPIRY: PiiPattern = PiiPattern {
    name: "pii_credit_card_expiry",
    pattern: r"(?i)\b(?:expiry|expiration|expires|ablaufdatum|g(?:ü|ue)ltig[ \t]+bis)[ \t]*(?:date[ \t]*)?(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{1,2}[/-]\d{2}(?:\d{2})?)\b",
    entity_group: "CREDITCARD_EXPIRY",
    validator: Some(validators::card_expiry),
    strength: ValidatorStrength::Format,
    base_score: 25,
    captured_value: true,
    requires_context: false,
};

// ── SWIFT / BIC ─────────────────────────────────────────────────────────
pub(super) const SWIFT_BIC_CONTEXT: PiiPattern = PiiPattern {
    name: "pii_swift_bic_context",
    // "Swift supports ..." describes a programming language, not a bank field.
    pattern: r"(?i)\b(?:(?:swift|bic)(?:[ \t]+code)?[ \t]*[:#=][ \t]*|(?:swift[ \t]+code|bic(?:[ \t]+code)?)[ \t]+is[ \t]+)(?P<value>[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
    entity_group: "SWIFT_CODE",
    validator: Some(validators::bic),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: true,
    requires_context: false,
};
