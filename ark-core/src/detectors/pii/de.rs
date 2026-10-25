// SPDX-License-Identifier: MIT OR Apache-2.0
//! German national identifiers: phone numbers, Steuer-ID, Steuernummer, social and health
//! insurance numbers, LANR, passport, identity card, vehicle registration. The driving
//! licence lives in `driver_license` with the other licence formats.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── Telefon ──────────────────────────────────────────────────────────────────
pub(super) const PHONE: PiiPattern = PiiPattern {
    name: "pii_phone_de",
    // No separator is a line break (T18).
    pattern: r"(?:\+49|0049)[\s&&[^\n-\r\x85\x{2028}\x{2029}]]?[1-9][\d\s\-\/&&[^\n-\r\x85\x{2028}\x{2029}]]{5,12}\d",
    entity_group: "PHONE",
    validator: Some(validators::unanchored_phone),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

pub(super) const PHONE_NATIONAL_CONTEXT: PiiPattern = PiiPattern {
    name: "pii_phone_de_national_context",
    pattern: r"(?i)\b(?:phone(?:[ \t]+number)?|telephone|mobile(?:[ \t]+number)?|telefon(?:[-_ ]?(?:nummer|nr))?|tel(?:efon)?[-_ ]?nr\.?|tel\.?|festnetz(?:[-_ ]?(?:nummer|nr))?|mobil(?:telefon|funk)?(?:[-_ ]?(?:nummer|nr))?|handy(?:[-_ ]?(?:nummer|nr))?|fax(?:[-_ ]?(?:nummer|nr))?)[ \t]*[:#=\-]?[ \t]*(?P<value>0(?:[ \t()./\-]*\d){6,14})\b",
    entity_group: "PHONE",
    validator: Some(validators::phone),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

// A national number without a field name right before it: "ist unter 0176 90817263
// erreichbar", "Rückruf bitte unter (030) 1234567", "0151 2345678 (Handy)". The
// context engine requires a phone term of the lexicon on either side.
pub(super) const PHONE_NATIONAL_PROXIMITY: PiiPattern = PiiPattern {
    name: "pii_phone_de_national_proximity",
    pattern: r"(?:\(0[1-9][0-9]{1,4}\)|(?-u:\b)0[1-9][0-9]{1,4})(?:[ \t]?[/\-][ \t]?|[ \t])?[0-9](?:[ \t\-]?[0-9]){3,9}(?-u:\b)",
    entity_group: "PHONE",
    validator: Some(validators::phone),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};

// ── Deutsche Steuer-IDs ──────────────────────────────────────────────────
pub(super) const STEUER_ID: PiiPattern = PiiPattern {
    name: "pii_steuer_id_de",
    pattern: r"(?i)\b(?:steuer[-_ ]?id|steueridentifikationsnummer|idnr\b\.?|(?:german[ \t]+)?tax[ \t]+(?:identification[ \t]+number|id))\s*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[1-9](?:[ \t]?\d){10})\b",
    entity_group: "STEUERID",
    validator: Some(validators::steuer_id),
    strength: ValidatorStrength::Checksum,
    base_score: 40,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// A bare Steuer-ID, 11 digits or grouped 2-3-3-3, in `balanced` and `recall` only
/// (K05). Strict keeps the field name of [`STEUER_ID`]; here the issued digit
/// distribution and the check digit carry the finding.
pub(super) const STEUER_ID_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_steuer_id_de_context_free",
    pattern: r"\b[1-9](?:[0-9]{10}|[0-9] [0-9]{3} [0-9]{3} [0-9]{3})\b",
    entity_group: "STEUERID",
    validator: Some(validators::steuer_id_issued),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

pub(super) const STEUERNUMMER: PiiPattern = PiiPattern {
    name: "pii_steuernummer_de",
    pattern: r"(?i)\b(?:steuernummer|steuer[-_ \t]*nr|(?:german[ \t]+)?tax[ \t]+number)\b\.?[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d(?:[0-9 /-]{8,20}\d))\b",
    entity_group: "TAX_NUMBER_DE",
    validator: Some(validators::de_tax_number),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

// ── Deutsche Ausweise / Sozialversicherung ───────────────────────────────
pub(super) const RENTENVERSICHERUNG: PiiPattern = PiiPattern {
    name: "pii_rentenversicherung_de",
    pattern: r"(?i)\b(?:sozialversicherungsnummer|rentenversicherungsnummer|sv[-_ \t]*nr|(?:german[ \t]+)?(?:pension[ \t]+insurance|social[ \t]+security)[ \t]+number)\b\.?\s*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{2}[ \t]?\d{6}[ \t]?[A-Z][ \t]?\d{3})\b",
    entity_group: "SOCIALID",
    validator: Some(validators::de_social_security_number),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

pub(super) const HEALTH_INSURANCE_NUMBER: PiiPattern = PiiPattern {
    name: "pii_health_insurance_number_de",
    pattern: r"(?i)\b(?:versichertennummer|krankenversicherungsnummer|kvnr|health[ \t]+insurance[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z]\d{9})\b",
    entity_group: "HEALTH_INSURANCE_NUMBER",
    validator: Some(validators::de_health_insurance_number),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

pub(super) const PHYSICIAN_NUMBER_LANR: PiiPattern = PiiPattern {
    name: "pii_physician_number_lanr_de",
    pattern: r"(?i)\b(?:lanr|lebenslange[ \t]+arztnummer|(?:lifelong[ \t]+)?physician[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{9})\b",
    entity_group: "PHYSICIAN_NUMBER_LANR",
    validator: Some(validators::lanr),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

pub(super) const PASSPORT_NUMBER: PiiPattern = PiiPattern {
    name: "pii_passport_number_de",
    pattern: r"(?i)\b(?:reisepass(?:nummer)?|passnummer|passport[ \t]+number|num(?:é|e)ro[ \t]+de[ \t]+passeport|passeport[ \t]+num(?:é|e)ro|n(?:ú|u)mero[ \t]+de[ \t]+pasaporte|pasaporte[ \t]+n(?:ú|u)mero|numero[ \t]+(?:di|del)[ \t]+passaporto|passaporto[ \t]+numero|paspoort(?:nummer|[-_ \t]?nr)|reisdocumentnummer)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[0-9CFGHJKLMNPRTVWXYZ]{9})\b",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::de_document_number),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

pub(super) const IDENTITY_CARD_NUMBER: PiiPattern = PiiPattern {
    name: "pii_identity_card_number_de",
    pattern: r"(?i)\b(?:personalausweis(?:nummer)?|ausweisnummer|identity[ \t]+card[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[0-9CFGHJKLMNPRTVWXYZ]{9})\b",
    entity_group: "IDENTITY_CARD_NUMBER",
    validator: Some(validators::de_document_number),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// A bare passport number with its ICAO 9303 check digit, in `balanced` and
/// `recall` only (F08, K05): series C, F, G, H, J or K, eight characters plus the
/// check digit (`F12345671`) or the MRZ form, nine plus the check digit
/// (`C01X00T478`). Strict keeps the field name and format check of
/// [`PASSPORT_NUMBER`]: a printed nine-character serial has no check digit.
pub(super) const PASSPORT_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_passport_number_de_context_free",
    pattern: r"(?i)\b[CFGHJK][0-9CFGHJKLMNPRTVWXYZ]{7,8}[0-9]\b",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::de_passport_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// The old numeric passport serial, nine digits plus the check digit
/// (`3000123454`). Ten digits with a mod-10 digit prove too little alone: the
/// context engine requires a passport term on either side or as the key.
pub(super) const PASSPORT_NUMBER_LEGACY: PiiPattern = PiiPattern {
    name: "pii_passport_number_de_legacy",
    pattern: r"\b[0-9]{10}\b",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::de_passport_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: true,
};

/// A bare identity card number with its ICAO 9303 check digit, in `balanced`
/// and `recall` only (F08, K05): series L, M, N, P, R, T, V, W, X or Y, eight
/// characters plus the check digit (`L01X00T44`) or the MRZ form
/// (`T220001293`, also inside `IDD<<T220001293<<…`).
pub(super) const IDENTITY_CARD_NUMBER_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_identity_card_number_de_context_free",
    pattern: r"(?i)\b[LMNPRTVWXY][0-9CFGHJKLMNPRTVWXYZ]{7,8}[0-9]\b",
    entity_group: "IDENTITY_CARD_NUMBER",
    validator: Some(validators::de_identity_card_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// The numeric serial of identity cards issued before November 2010
/// (`1220001297`: authority code, serial, check digit), with an identity card
/// term on either side or as the key.
pub(super) const IDENTITY_CARD_NUMBER_LEGACY: PiiPattern = PiiPattern {
    name: "pii_identity_card_number_de_legacy",
    pattern: r"\b[0-9]{10}\b",
    entity_group: "IDENTITY_CARD_NUMBER",
    validator: Some(validators::de_identity_card_number),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: true,
};

pub(super) const KFZ_KENNZEICHEN: PiiPattern = PiiPattern {
    name: "pii_kfz_kennzeichen_de",
    pattern: r"(?i)\b(?:kfz[-_ ]?(?:kennzeichen)?|kennzeichen|nummernschild|vehicle[ \t]+registration)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-ZÄÖÜ]{1,3}[- ][A-Z]{1,2}[ ]?\d{1,4}(?:[EH])?)\b",
    entity_group: "LICENSEPLATE",
    validator: None,
    strength: ValidatorStrength::None,
    base_score: 40,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};
