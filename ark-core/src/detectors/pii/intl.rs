// SPDX-License-Identifier: MIT OR Apache-2.0
//! International payment identifiers: IBAN, payment card number, CVV, card expiry, SWIFT/BIC;
//! passport and identity card numbers by field name or a document term near the value
//! (B-PASS): a format rule after an explicit passport field name, the US letter form,
//! Austrian and Swiss, Italian and Spanish documents, two letters and seven digits.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── IBAN ─────────────────────────────────────────────────────────────────
// Keep IBAN as the primary classification when a numeric substring also
// passes the card validator. Evidence retains both labels; strict lists the
// card as secondary evidence of the IBAN (T07), the scored modes drop it (K07).
pub(super) const IBAN_DE: PiiPattern = PiiPattern {
    name: "pii_iban_de",
    pattern: r"\b(?:DE|de)\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{2}\b",
    entity_group: "IBAN",
    validator: Some(validators::iban),
    strength: ValidatorStrength::Checksum,
    base_score: 55,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

// Every registry country, compact or in blocks of four (letters included), in
// upper or in lower case (B-IBAN). The validator holds the registry length per
// country; a grouped match that runs into the next word or block is cut to that
// length first (`PiiPipeline::rule_captures`).
pub(super) const IBAN_GENERIC: PiiPattern = PiiPattern {
    name: "pii_iban_generic",
    pattern: r"\b(?:[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?|[a-z]{2}[0-9]{2}(?: ?[a-z0-9]{4}){2,7}(?: ?[a-z0-9]{1,3})?)\b",
    entity_group: "IBAN",
    validator: Some(validators::iban),
    strength: ValidatorStrength::Checksum,
    base_score: 45,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

// ── Kreditkarte ──────────────────────────────────────────────────────────
// Luhn plus IIN prefix and length per brand (B-PAN), in every mode; the position
// check (no `+` before it, no token segment) sits in `allows_match`.
pub(super) const CREDIT_CARD: PiiPattern = PiiPattern {
    name: "pii_credit_card",
    pattern: r"\b(?:\d[ \-]?){11,18}\d\b",
    entity_group: "CREDITCARD",
    validator: Some(validators::payment_card),
    strength: ValidatorStrength::Checksum,
    base_score: 40,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

pub(super) const CREDIT_CARD_CVV: PiiPattern = PiiPattern {
    name: "pii_credit_card_cvv",
    pattern: r"(?i)\b(?:cvv2?|cvc2?|card[ \t]+verification[ \t]+(?:value|code)|kartenpr(?:ü|ue)fnummer|kartenpr(?:ü|ue)fziffer|sicherheitscode|code[ \t]+de[ \t]+s(?:é|e)curit(?:é|e)[ \t]+de[ \t]+(?:la[ \t]+)?carte(?:[ \t]+(?:de[ \t]+cr(?:é|e)dit|bancaire))?|cryptogramme(?:[ \t]+visuel)?|c(?:ó|o)digo[ \t]+de[ \t]+seguridad[ \t]+de[ \t]+(?:la[ \t]+)?tarjeta(?:[ \t]+de[ \t]+(?:cr(?:é|e)dito|d(?:é|e)bito))?|codice[ \t]+di[ \t]+sicurezza[ \t]+della[ \t]+carta(?:[ \t]+di[ \t]+(?:credito|debito))?|(?:creditcard|kaart)[- \t]?(?:veiligheids|beveiligings|verificatie)code)[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{3,4})\b",
    entity_group: "CREDITCARD_CVV",
    validator: Some(validators::cvv),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: true,
    requires_context: false,
    scored_only: false,
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
    scored_only: false,
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
    scored_only: false,
};

// ── Reisepass ───────────────────────────────────────────────────────────
/// A passport number of two letters and seven digits (`PA1234567` Ireland,
/// `TK1234567` Japan), with a passport term near the value or as its key. The UK
/// numbers its passports with nine digits (`uk::PASSPORT_NUMBER`).
pub(super) const PASSPORT_NUMBER_TWO_LETTERS: PiiPattern = PiiPattern {
    name: "pii_passport_number_two_letters",
    pattern: r"(?-u:\b)[A-Z]{2}[0-9]{7}(?-u:\b)",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::passport_number_two_letters),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A passport number after an explicit passport field name in English, German,
/// Spanish, French, Italian or Dutch (T24, B-PASS): `Passport No. X45929398`,
/// `Reisepass: P4366918`, `Mi pasaporte es AAA123456`, `passaporto n. M0572847`.
/// Format only, in every mode; [`validators::passport_number_field`] keeps the
/// value a document number.
pub(super) const PASSPORT_NUMBER_FIELD: PiiPattern = PiiPattern {
    name: "pii_passport_number_field",
    pattern: r#"(?i)\b(?:passport(?:[-_ \t]?(?:number|num|no|nr|id))?\.?|reisepass(?:[-_ \t]?(?:nummer|nr))?\.?|pass(?:[-_ \t]?(?:nummer|nr))\.?|n(?:ú|u)mero[ \t]+de[ \t]+pasaporte|pasaporte(?:[ \t]+(?:n(?:ú|u)mero|n(?:º|°|o)\.?))?|num(?:é|e)ro[ \t]+de[ \t]+passeport|passeport(?:[ \t]+(?:num(?:é|e)ro|n(?:°|o)\.?))?|numero[ \t]+(?:di|del)[ \t]+passaporto|passaporto(?:[ \t]+(?:numero|n(?:°|\.)?))?|paspoort(?:[-_ \t]?(?:nummer|nr))?\.?|reisdocumentnummer)["']?[ \t]*(?:(?:is|ist|lautet|es|est|è)[ \t]+)?[:#=]?[ \t]*["'(]?(?P<value>(?-i:[A-Z0-9]{6,9}))\b"#,
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::passport_number_field),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// A US passport number in the letter form, one letter and eight digits
/// (`A12803456`), with a passport term near the value or as its key (A05,
/// B-PASS). Nine digits are `uk::PASSPORT_NUMBER`.
pub(super) const PASSPORT_NUMBER_US: PiiPattern = PiiPattern {
    name: "pii_passport_number_us",
    pattern: r"(?-u:\b)[A-Z][0-9]{8}(?-u:\b)",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::us_passport_number),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// An Austrian or Swiss passport number, one letter and seven digits
/// (`P4366918`), with a passport term near the value or as its key (B08, B-PASS).
pub(super) const PASSPORT_NUMBER_AT_CH: PiiPattern = PiiPattern {
    name: "pii_passport_number_at_ch",
    pattern: r"(?-u:\b)[A-Z][0-9]{7}(?-u:\b)",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::letter_seven_digits),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// An Austrian Personalausweis or Swiss Identitätskarte number, one letter and
/// seven digits (`X0217453`), with an identity card term near the value or as its
/// key (B08, B-PASS).
pub(super) const IDENTITY_CARD_NUMBER_AT_CH: PiiPattern = PiiPattern {
    name: "pii_identity_card_number_at_ch",
    pattern: r"(?-u:\b)[A-Z][0-9]{7}(?-u:\b)",
    entity_group: "IDENTITY_CARD_NUMBER",
    validator: Some(validators::letter_seven_digits),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// An Italian carta d'identità number, the CIE (`CA48213EF`), with an identity card term near the value or as its key (T10,
/// B-PASS). The Italian passport has two letters and seven digits
/// ([`PASSPORT_NUMBER_TWO_LETTERS`]).
pub(super) const IDENTITY_CARD_NUMBER_IT: PiiPattern = PiiPattern {
    name: "pii_identity_card_number_it",
    pattern: r"(?-u:\b)[A-Z]{2}[0-9]{5}[A-Z]{2}(?-u:\b)",
    entity_group: "IDENTITY_CARD_NUMBER",
    validator: Some(validators::it_identity_card_number),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

/// A Spanish pasaporte number, three letters and six digits (`PAA482913`), with a
/// passport term near the value or as its key (T10, B-PASS).
pub(super) const PASSPORT_NUMBER_ES: PiiPattern = PiiPattern {
    name: "pii_passport_number_es",
    pattern: r"(?-u:\b)[A-Z]{3}[0-9]{6}(?-u:\b)",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::es_passport_number),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
