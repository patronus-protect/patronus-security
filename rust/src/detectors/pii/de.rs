// SPDX-License-Identifier: GPL-3.0-only
//! German national identifiers: phone numbers, Steuer-ID, Steuernummer, social and health
//! insurance numbers, LANR, passport, identity card, driving licence, vehicle registration.
use super::{pii::PiiPattern, validators};

// ── Telefon ──────────────────────────────────────────────────────────────────
pub(super) const PHONE: PiiPattern = PiiPattern {
    name: "pii_phone_de",
    pattern: r"(?:\+49|0049)\s?[1-9][\d\s\-\/]{5,12}\d",
    entity_group: "PHONE",
    validator: Some(validators::unanchored_phone),
    captured_value: false,
};

pub(super) const PHONE_NATIONAL_CONTEXT: PiiPattern = PiiPattern {
    name: "pii_phone_de_national_context",
    pattern: r"(?i)\b(?:phone(?:[ \t]+number)?|telephone|mobile(?:[ \t]+number)?|telefon(?:[-_ ]?(?:nummer|nr))?|tel(?:efon)?[-_ ]?nr\.?|tel\.?|festnetz(?:[-_ ]?(?:nummer|nr))?|mobil(?:telefon|funk)?(?:[-_ ]?(?:nummer|nr))?|handy(?:[-_ ]?(?:nummer|nr))?|fax(?:[-_ ]?(?:nummer|nr))?)[ \t]*[:#=\-]?[ \t]*(?P<value>0(?:[ \t()./\-]*\d){6,14})\b",
    entity_group: "PHONE",
    validator: Some(validators::phone),
    captured_value: true,
};

// ── Deutsche Steuer-IDs ──────────────────────────────────────────────────
pub(super) const STEUER_ID: PiiPattern = PiiPattern {
    name: "pii_steuer_id_de",
    pattern: r"(?i)\b(?:steuer[-_ ]?id|steueridentifikationsnummer|idnr\b\.?|(?:german[ \t]+)?tax[ \t]+(?:identification[ \t]+number|id))\s*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[1-9](?:[ \t]?\d){10})\b",
    entity_group: "STEUERID",
    validator: Some(validators::steuer_id),
    captured_value: true,
};

pub(super) const STEUERNUMMER: PiiPattern = PiiPattern {
    name: "pii_steuernummer_de",
    pattern: r"(?i)\b(?:steuernummer|steuer[-_ \t]*nr|(?:german[ \t]+)?tax[ \t]+number)\b\.?[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d(?:[0-9 /-]{8,20}\d))\b",
    entity_group: "TAX_NUMBER_DE",
    validator: Some(validators::de_tax_number),
    captured_value: true,
};

// ── Deutsche Ausweise / Sozialversicherung ───────────────────────────────
pub(super) const RENTENVERSICHERUNG: PiiPattern = PiiPattern {
    name: "pii_rentenversicherung_de",
    pattern: r"(?i)\b(?:sozialversicherungsnummer|rentenversicherungsnummer|sv[-_ \t]*nr|(?:german[ \t]+)?(?:pension[ \t]+insurance|social[ \t]+security)[ \t]+number)\b\.?\s*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{2}[ \t]?\d{6}[ \t]?[A-Z][ \t]?\d{3})\b",
    entity_group: "SOCIALID",
    validator: Some(validators::de_social_security_number),
    captured_value: true,
};

pub(super) const HEALTH_INSURANCE_NUMBER: PiiPattern = PiiPattern {
    name: "pii_health_insurance_number_de",
    pattern: r"(?i)\b(?:versichertennummer|krankenversicherungsnummer|kvnr|health[ \t]+insurance[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z]\d{9})\b",
    entity_group: "HEALTH_INSURANCE_NUMBER",
    validator: Some(validators::de_health_insurance_number),
    captured_value: true,
};

pub(super) const PHYSICIAN_NUMBER_LANR: PiiPattern = PiiPattern {
    name: "pii_physician_number_lanr_de",
    pattern: r"(?i)\b(?:lanr|lebenslange[ \t]+arztnummer|(?:lifelong[ \t]+)?physician[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{9})\b",
    entity_group: "PHYSICIAN_NUMBER_LANR",
    validator: Some(validators::lanr),
    captured_value: true,
};

pub(super) const PASSPORT_NUMBER: PiiPattern = PiiPattern {
    name: "pii_passport_number_de",
    pattern: r"(?i)\b(?:reisepass(?:nummer)?|passnummer|passport[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[0-9CFGHJKLMNPRTVWXYZ]{9})\b",
    entity_group: "PASSPORT_NUMBER",
    validator: Some(validators::de_document_number),
    captured_value: true,
};

pub(super) const IDENTITY_CARD_NUMBER: PiiPattern = PiiPattern {
    name: "pii_identity_card_number_de",
    pattern: r"(?i)\b(?:personalausweis(?:nummer)?|ausweisnummer|identity[ \t]+card[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[0-9CFGHJKLMNPRTVWXYZ]{9})\b",
    entity_group: "IDENTITY_CARD_NUMBER",
    validator: Some(validators::de_document_number),
    captured_value: true,
};

pub(super) const DRIVER_LICENSE_NUMBER: PiiPattern = PiiPattern {
    name: "pii_driver_license_number_de",
    pattern: r"(?i)\b(?:f(?:ü|ue)hrerschein(?:nummer)?|fahrerlaubnis(?:nummer)?|driver'?s?[ \t]+licen[cs]e[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9]{11})\b",
    entity_group: "DRIVER_LICENSE_NUMBER",
    validator: Some(validators::de_driver_license_number),
    captured_value: true,
};

pub(super) const KFZ_KENNZEICHEN: PiiPattern = PiiPattern {
    name: "pii_kfz_kennzeichen_de",
    pattern: r"(?i)\b(?:kfz[-_ ]?(?:kennzeichen)?|kennzeichen|nummernschild|vehicle[ \t]+registration)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-ZÄÖÜ]{1,3}[- ][A-Z]{1,2}[ ]?\d{1,4}(?:[EH])?)\b",
    entity_group: "LICENSEPLATE",
    validator: None,
    captured_value: true,
};
