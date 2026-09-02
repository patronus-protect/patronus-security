// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    detectors::{NativeMatchValidator, NativeRegexDetector},
    EvaluationResult,
};

use super::validators;
use regex::Regex;

/// A single PII heuristic pattern.
pub struct PiiPattern {
    /// Stable public rule id used by `ScanGateMatrix::rules`.
    pub name: &'static str,
    /// Regex pattern string.
    pub pattern: &'static str,
    /// Entity group label used in `NerResult` and `PlaceholderEncoder`.
    pub entity_group: &'static str,
    /// Optional validator called after a regex match to reduce false positives.
    pub validator: Option<fn(&str) -> bool>,
    /// For anchor-bound patterns, emit only the named `value` capture.
    pub captured_value: bool,
}

pub static PII_PATTERNS: &[PiiPattern] = &[
    // ── Email ────────────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_email",
        pattern: r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        entity_group: "EMAIL",
        validator: None,
        captured_value: false,
    },
    // ── IP-Adressen ─────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_ipv4",
        pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_ipv6_full",
        pattern: r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_ipv6_compressed",
        pattern: r"\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_ipv6_loopback",
        pattern: r"::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
        captured_value: false,
    },
    // ── Telefon ──────────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_phone_international",
        pattern: r"\+[1-9](?:[\s./()\-]*\d){6,14}\b",
        entity_group: "PHONE",
        validator: Some(validators::phone),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_phone_de",
        pattern: r"(?:\+49|0049)\s?[1-9][\d\s\-\/]{5,12}\d",
        entity_group: "PHONE",
        validator: Some(validators::phone),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_phone_de_national_context",
        pattern: r"(?i)\b(?:telefon(?:[-_ ]?(?:nummer|nr))?|tel(?:efon)?[-_ ]?nr\.?|tel\.?|festnetz(?:[-_ ]?(?:nummer|nr))?|mobil(?:telefon|funk)?(?:[-_ ]?(?:nummer|nr))?|handy(?:[-_ ]?(?:nummer|nr))?|fax(?:[-_ ]?(?:nummer|nr))?)[ \t]*[:#=\-]?[ \t]*(?P<value>0(?:[ \t()./\-]*\d){6,14})\b",
        entity_group: "PHONE",
        validator: Some(validators::phone),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_phone_us",
        pattern: r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b",
        entity_group: "PHONE",
        validator: Some(validators::phone),
        captured_value: false,
    },
    // ── MAC-Adresse ─────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_mac_address",
        pattern: r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b",
        entity_group: "MAC_ADDRESS",
        validator: Some(validators::mac_address),
        captured_value: false,
    },
    // ── IBAN ─────────────────────────────────────────────────────────────────
    // Keep validated IBANs ahead of the broader numeric card candidate so the
    // shared overlap resolver retains the more specific identifier.
    PiiPattern {
        name: "pii_iban_de",
        pattern: r"\bDE\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{2}\b",
        entity_group: "IBAN",
        validator: Some(validators::mod97),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_iban_generic",
        pattern: r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        entity_group: "IBAN",
        validator: Some(validators::mod97),
        captured_value: false,
    },
    // ── Kreditkarte ──────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_credit_card",
        pattern: r"\b(?:\d[ \-]?){11,18}\d\b",
        entity_group: "CREDITCARD",
        validator: Some(validators::luhn),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_credit_card_cvv",
        pattern: r"(?i)\b(?:cvv2?|cvc2?|card[ \t]+verification[ \t]+(?:value|code))[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{3,4})\b",
        entity_group: "CREDITCARD_CVV",
        validator: Some(validators::cvv),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_credit_card_expiry",
        pattern: r"(?i)\b(?:expiry|expiration|expires|ablaufdatum|g(?:ü|ue)ltig[ \t]+bis)[ \t]*(?:date[ \t]*)?(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{1,2}[/-]\d{2}(?:\d{2})?)\b",
        entity_group: "CREDITCARD_EXPIRY",
        validator: Some(validators::card_expiry),
        captured_value: true,
    },
    // ── SWIFT / BIC ─────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_swift_bic_context",
        pattern: r"(?i)\b(?:swift|bic)(?:[ \t]+code)?(?:[ \t]+is)?[ \t]*[:#=\-]?[ \t]*(?P<value>[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        entity_group: "SWIFT_CODE",
        validator: Some(validators::bic),
        captured_value: true,
    },
    // ── Anchor-gebundene Personenkennungen ─────────────────────────────────
    PiiPattern {
        name: "pii_employee_id",
        pattern: r"(?i)\b(?:personalnummer|pers(?:onal)?[ \t]*nr\.?|mitarbeiter(?:nummer|[-_ ]?id)|employee(?:[ \t_-]+)(?:id|number)|personnel[ \t]+(?:id|number)|staff[ \t]+(?:id|code|number)|kennung)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
        entity_group: "EMPLOYEE_ID",
        validator: Some(validators::bounded_employee_identifier),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_employee_id_ocr_field",
        pattern: r"(?m)(?:^|[\n|])[ \t]*ID[ \t]*[:#=\-]?[ \t]*(?P<value>[A-Z]{1,8}[ \t]{1,3}\d{2,20})\b",
        entity_group: "EMPLOYEE_ID",
        validator: Some(validators::bounded_employee_identifier),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_employee_id_prefixed",
        pattern: r"(?i)\bEMP[-_/][A-Z0-9]+[-_/][A-Z0-9](?:[A-Z0-9._/-]{1,24}[A-Z0-9])?\b",
        entity_group: "EMPLOYEE_ID",
        validator: Some(validators::bounded_employee_identifier),
        captured_value: false,
    },
    PiiPattern {
        name: "pii_customer_id",
        pattern: r"(?i)\b(?:kundennummer|kunden[-_ ]?id|debitor(?:ennummer)?|customer[ \t]+(?:id|number))\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
        entity_group: "CUSTOMER_ID",
        validator: Some(validators::bounded_identifier),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_patient_id",
        pattern: r"(?i)\b(?:patientennummer|patienten[-_ ]?id|patient[ \t]+(?:id|number)|mrn|medical[ \t]+record[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
        entity_group: "PATIENT_ID",
        validator: Some(validators::bounded_identifier),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_student_id",
        pattern: r"(?i)\b(?:matrikelnummer|sch(?:ü|ue)ler(?:nummer|[-_ ]?id)|student(?:en)?[-_ ]?(?:id|nummer)|student[ \t]+number)\b[ \t]*(?:(?:lautet|ist|is)[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
        entity_group: "STUDENT_ID",
        validator: Some(validators::bounded_identifier),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_applicant_id",
        pattern: r"(?i)\b(?:bewerber(?:nummer|[-_ ]?id)|applicant[ \t]+(?:id|number)|candidate[ \t]+id)\b[ \t]*(?:(?:lautet|ist|is)[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
        entity_group: "APPLICANT_ID",
        validator: Some(validators::bounded_identifier),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_username",
        pattern: r"(?i)\b(?:benutzername|benutzer|login|username|user[ \t]+name|account[ \t]+name)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._@-]{0,62}[A-Z0-9])?)\b",
        entity_group: "USERNAME",
        validator: Some(validators::username),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_date_of_birth",
        pattern: r"(?i)\b(?:geburtsdatum|geboren[ \t]+am|date[ \t]+of[ \t]+birth|dob)\b[ \t]*(?:(?:is|as|ist|lautet)[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b",
        entity_group: "DOB",
        validator: Some(validators::calendar_date),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_date_of_birth_written_day_first",
        pattern: r"(?i)\b(?:geburtsdatum|geboren[ \t]+am|date[ \t]+of[ \t]+birth|dob)\b[ \t]*(?:(?:is|as|ist|lautet)[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{1,2}\.?[ \t]+(?:januar|februar|m(?:ä|ae)rz|april|mai|juni|juli|august|september|oktober|november|dezember|january|february|march|may|june|july|october|december)[ \t]+\d{4})\b",
        entity_group: "DOB",
        validator: Some(validators::written_calendar_date),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_date_of_birth_written_month_first",
        pattern: r"(?i)\b(?:date[ \t]+of[ \t]+birth|dob)\b[ \t]*(?:(?:is|as)[ \t]*)?[:#=\-]?[ \t]*(?P<value>(?:january|february|march|april|may|june|july|august|september|october|november|december)[ \t]+\d{1,2}(?:st|nd|rd|th)?[,]?[ \t]+\d{4})\b",
        entity_group: "DOB",
        validator: Some(validators::written_calendar_date),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_financial_account_number",
        pattern: r"(?i)\b(?:kontonummer|konto[-_ ]?nr|depotnummer|depot[-_ ]?nr|account[ \t]+number|bank[ \t]+account)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
        entity_group: "FINANCIAL_ACCOUNT_NUMBER",
        validator: Some(validators::bounded_identifier),
        captured_value: true,
    },
    // ── Deutsche Steuer-IDs ──────────────────────────────────────────────────
    PiiPattern {
        name: "pii_steuer_id_de",
        pattern: r"(?i)\b(?:steuer[-_ ]?id|steueridentifikationsnummer|idnr\b\.?)\s*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[1-9](?:[ \t]?\d){10})\b",
        entity_group: "STEUERID",
        validator: Some(validators::steuer_id),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_steuernummer_de",
        pattern: r"(?i)\b(?:steuernummer|steuer[-_ \t]*nr)\b\.?[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d(?:[0-9 /-]{8,20}\d))\b",
        entity_group: "TAX_NUMBER_DE",
        validator: Some(validators::de_tax_number),
        captured_value: true,
    },
    // ── Deutsche Ausweise / Sozialversicherung ───────────────────────────────
    PiiPattern {
        name: "pii_rentenversicherung_de",
        pattern: r"(?i)\b(?:sozialversicherungsnummer|rentenversicherungsnummer|sv[-_ \t]*nr)\b\.?\s*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{2}[ \t]?\d{6}[ \t]?[A-Z][ \t]?\d{3})\b",
        entity_group: "SOCIALID",
        validator: Some(validators::de_social_security_number),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_health_insurance_number_de",
        pattern: r"(?i)\b(?:versichertennummer|krankenversicherungsnummer|kvnr|health[ \t]+insurance[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z]\d{9})\b",
        entity_group: "HEALTH_INSURANCE_NUMBER",
        validator: Some(validators::de_health_insurance_number),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_physician_number_lanr_de",
        pattern: r"(?i)\b(?:lanr|lebenslange[ \t]+arztnummer)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{9})\b",
        entity_group: "PHYSICIAN_NUMBER_LANR",
        validator: Some(validators::lanr),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_passport_number_de",
        pattern: r"(?i)\b(?:reisepass(?:nummer)?|passnummer|passport[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[0-9CFGHJKLMNPRTVWXYZ]{9})\b",
        entity_group: "PASSPORT_NUMBER",
        validator: Some(validators::de_document_number),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_identity_card_number_de",
        pattern: r"(?i)\b(?:personalausweis(?:nummer)?|ausweisnummer|identity[ \t]+card[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[0-9CFGHJKLMNPRTVWXYZ]{9})\b",
        entity_group: "IDENTITY_CARD_NUMBER",
        validator: Some(validators::de_document_number),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_driver_license_number_de",
        pattern: r"(?i)\b(?:f(?:ü|ue)hrerschein(?:nummer)?|fahrerlaubnis(?:nummer)?|driver'?s?[ \t]+licen[cs]e[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9]{11})\b",
        entity_group: "DRIVER_LICENSE_NUMBER",
        validator: Some(validators::de_driver_license_number),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_kfz_kennzeichen_de",
        pattern: r"(?i)\b(?:kfz[-_ ]?(?:kennzeichen)?|kennzeichen|nummernschild|vehicle[ \t]+registration)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-ZÄÖÜ]{1,3}[- ][A-Z]{1,2}[ ]?\d{1,4}(?:[EH])?)\b",
        entity_group: "LICENSEPLATE",
        validator: None,
        captured_value: true,
    },
    // ── US / UK ──────────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_ssn_us",
        pattern: r"(?i)\b(?:ssn|social[ \t]+security[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{3}[ -]\d{2}[ -]\d{4})\b",
        entity_group: "SSN",
        validator: Some(validators::us_ssn),
        captured_value: true,
    },
    PiiPattern {
        name: "pii_ni_uk",
        pattern: r"(?i)\b(?:nino|national[ \t]+insurance[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z]{2}[ ]?\d{6}[ ]?[A-D])\b",
        entity_group: "NATIONALID",
        validator: Some(validators::uk_nino),
        captured_value: true,
    },
];

/// Context facts that are useful for Dynamic PII but are not findings by
/// themselves. A field name such as `Diagnose` says what a nearby value may be;
/// it does not prove that the text already contains a sensitive value.
struct PiiAnchorPattern {
    category: &'static str,
    strength: &'static str,
    pattern: &'static str,
}

static PII_ANCHOR_PATTERNS: &[PiiAnchorPattern] = &[
    PiiAnchorPattern {
        category: "person_identity",
        strength: "weak",
        pattern: r"(?i)\b(?:vollständige[rs]?[ \t]+name|komplette[rs]?[ \t]+name|vor[-_ \t]?name|ruf[-_ \t]?name|zweite[rs]?[ \t]+vorname|nach[-_ \t]?name|familien[-_ \t]?name|geburts[-_ \t]?name|mädchen[-_ \t]?name|patienten[-_ \t]?name|kunden[-_ \t]?name|mitarbeiter[-_ \t]?name|name|first[-_ \t]+name|given[-_ \t]+name|middle[-_ \t]+name|last[-_ \t]+name|family[-_ \t]+name|full[-_ \t]+name|legal[-_ \t]+name|preferred[-_ \t]+name|maiden[-_ \t]+name|birth[-_ \t]+name|surname|patient[-_ \t]+name|customer[-_ \t]+name|employee[-_ \t]+name)\b",
    },
    PiiAnchorPattern {
        category: "person_role",
        strength: "weak",
        pattern: r"(?i)\b(?:ansprechpartner(?:in)?|kontaktperson|notfallkontakt|kontoinhaber(?:in)?|versicherte[rs]?|mitglied|patient(?:in)?|bewerber(?:in)?|kandidat(?:in)?|beschäftigte[rs]?|arbeitnehmer(?:in)?|mitarbeiter(?:in)?|kunde|kundin|contact[-_ \t]+person|emergency[-_ \t]+contact|account[-_ \t]+holder|policy[-_ \t]+holder|insured[-_ \t]+person|insured|member|patient|applicant|candidate|employee|worker|customer|client)\b",
    },
    PiiAnchorPattern {
        category: "contact",
        strength: "medium",
        pattern: r"(?i)\b(?:e[-_ ]?mail(?:[-_ ]?adresse)?|mail[-_ ]?adresse|telefon(?:[-_ ]?(?:nummer|nr))?|tel(?:efon)?[-_ ]?nr|festnetz(?:[-_ ]?nummer)?|mobil(?:telefon|funk)?(?:[-_ ]?(?:nummer|nr))?|handy(?:[-_ ]?(?:nummer|nr))?|fax(?:[-_ ]?(?:nummer|nr))?|durchwahl|kontakt[-_ ]?nummer|email[-_ \t]+address|email[-_ \t]+id|phone[-_ \t]+number|telephone[-_ \t]+number|contact[-_ \t]+number|mobile[-_ \t]+(?:number|phone)|cell(?:ular)?[-_ \t]+(?:number|phone)|cellphone|home[-_ \t]+phone|work[-_ \t]+phone|fax[-_ \t]+number|extension|emergency[-_ \t]+contact)\b",
    },
    PiiAnchorPattern {
        category: "address",
        strength: "weak",
        pattern: r"(?i)\b(?:anschrift|wohn[-_ ]?(?:anschrift|adresse)|melde[-_ ]?(?:anschrift|adresse)|post[-_ ]?(?:anschrift|adresse)|korrespondenz[-_ ]?adresse|zustell[-_ ]?adresse|rechnungs[-_ ]?adresse|liefer[-_ ]?adresse|geschäfts[-_ ]?adresse|heimat[-_ ]?adresse|adresse|straße|strasse|str\.|haus[-_ ]?(?:nummer|nr)|post[-_ ]?leitzahl|plz|postfach|wohnort|address|street[-_ \t]+address|street|house[-_ \t]+number|postal[-_ \t]+code|postcode|zip(?:[-_ \t]+code)?|home[-_ \t]+address|residential[-_ \t]+address|permanent[-_ \t]+address|current[-_ \t]+address|physical[-_ \t]+address|mailing[-_ \t]+address|correspondence[-_ \t]+address|billing[-_ \t]+address|shipping[-_ \t]+address|delivery[-_ \t]+address|business[-_ \t]+address|p\.?[ \t]*o\.?[-_ \t]+box|city|town)\b",
    },
    PiiAnchorPattern {
        category: "date_of_birth",
        strength: "strong",
        pattern: r"(?i)\b(?:geburts[-_ ]?datum|geb(?:urts)?[.-]*[ \t]*dat(?:um)?|geburtstag|geboren(?:[-_ \t]+am)?|date[-_ \t]+of[-_ \t]+birth|birth[-_ \t]*date|birthday|born(?:[-_ \t]+on)?|d\.?[ \t]*o\.?[ \t]*b\.?)\b",
    },
    PiiAnchorPattern {
        category: "person_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:personal[-_ ]?(?:nummer|nr)|mitarbeiter[-_ ]?(?:nummer|nr|id)|personal[-_ ]?id|beschäftigten[-_ ]?(?:nummer|id)|kund(?:en)?[-_ ]?(?:nummer|nr|id)|debitor(?:en)?[-_ ]?(?:nummer|nr|id)?|patienten[-_ ]?(?:nummer|nr|id)|krankenhaus[-_ ]?(?:nummer|id)|mrn|medical[-_ \t]+record[-_ \t]+(?:number|no)|health[-_ \t]+record[-_ \t]+(?:number|id)|matrikel[-_ ]?(?:nummer|nr)|immatrikulations[-_ ]?nummer|sch(?:ü|ue)ler[-_ ]?(?:nummer|nr|id)|student(?:en)?[-_ ]?(?:id|nummer|nr)|bewerber[-_ ]?(?:nummer|nr|id)|kandidaten[-_ ]?(?:nummer|id)|employee[-_ \t]+(?:id|number|no)|personnel[-_ \t]+(?:id|number|no)|staff[-_ \t]+(?:id|number|no)|customer[-_ \t]+(?:id|number|no)|client[-_ \t]+(?:id|number|no)|debtor[-_ \t]+(?:id|number|no)|patient[-_ \t]+(?:id|number|no)|student[-_ \t]+(?:id|number|no)|pupil[-_ \t]+(?:id|number|no)|applicant[-_ \t]+(?:id|number|no)|application[-_ \t]+(?:id|number|no)|candidate[-_ \t]+(?:id|number|no))\b",
    },
    PiiAnchorPattern {
        category: "account_identifier",
        strength: "medium",
        pattern: r"(?i)\b(?:benutzer[-_ ]?name|benutzer[-_ ]?kennung|benutzer[-_ ]?konto|login[-_ ]?(?:name|kennung)|konto[-_ ]?name|username|user[-_ \t]+name|user[-_ \t]+id|login[-_ \t]+name|login[-_ \t]+id|account[-_ \t]+name|account[-_ \t]+id)\b",
    },
    PiiAnchorPattern {
        category: "payment_card",
        strength: "strong",
        pattern: r"(?i)\b(?:cvv2?|cvc2?|karten[-_ ]?prüf[-_ ]?(?:nummer|ziffer)|prüf[-_ ]?ziffer|sicherheits[-_ ]?code|karten[-_ ]?ablauf[-_ ]?(?:datum|date)|ablauf[-_ ]?datum|gültig[-_ ]+bis|card[-_ \t]+verification[-_ \t]+(?:value|code)|card[-_ \t]+security[-_ \t]+code|security[-_ \t]+code|expiry(?:[-_ \t]+date)?|expiration(?:[-_ \t]+date)?|expires)\b",
    },
    PiiAnchorPattern {
        category: "financial_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:bic|swift(?:[-_ ]?code)?|bankleitzahl|blz|konto[-_ ]?(?:nummer|nr)|bankkonto[-_ ]?(?:nummer|nr)?|depot[-_ ]?(?:nummer|nr)|account[-_ \t]+number|bank[-_ \t]+account(?:[-_ \t]+number)?|brokerage[-_ \t]+account(?:[-_ \t]+number)?|routing[-_ \t]+number)\b",
    },
    PiiAnchorPattern {
        category: "government_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:steuer[-_ ]?(?:id|identifikations[-_ ]?nummer|nummer|nr)|id[-_ ]?nr|st[-_ ]?nr|sozialversicherungs[-_ ]?(?:nummer|nr)|sv[-_ ]?nr|rentenversicherungs[-_ ]?(?:nummer|nr)|rv[-_ ]?nr|krankenversicherungs[-_ ]?(?:nummer|nr)|versicherten[-_ ]?(?:nummer|nr)|kv[-_ ]?nr|kvnr|lanr|lebenslange[-_ \t]+arzt[-_ ]?(?:nummer|nr)|arzt[-_ ]?(?:nummer|nr)|reisepass[-_ ]?(?:nummer|nr)|pass[-_ ]?(?:nummer|nr)|personalausweis[-_ ]?(?:nummer|nr)|ausweis[-_ ]?(?:nummer|nr)|führerschein[-_ ]?(?:nummer|nr)|fahrerlaubnis[-_ ]?(?:nummer|nr)|ssn|social[-_ \t]+security[-_ \t]+(?:number|no)|nino|national[-_ \t]+insurance[-_ \t]+(?:number|no)|passport[-_ \t]+(?:number|no)|identity[-_ \t]+card[-_ \t]+(?:number|no)|id[-_ \t]+card[-_ \t]+(?:number|no)|driver'?s?[-_ \t]+licen[cs]e[-_ \t]+(?:number|no))\b",
    },
    PiiAnchorPattern {
        category: "vehicle_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:kfz[-_ ]?(?:kennzeichen|nummer)?|kraftfahrzeug[-_ ]?kennzeichen|kennzeichen|nummern[-_ ]?schild|amtliches[-_ ]?kennzeichen|vehicle[-_ \t]+registration(?:[-_ \t]+(?:number|no))?|registration[-_ \t]+(?:number|no)|license[-_ \t]+plate|licence[-_ \t]+plate|number[-_ \t]+plate)\b",
    },
    PiiAnchorPattern {
        category: "medical",
        strength: "medium",
        pattern: r"(?i)\b(?:patienten[-_ ]?akte|kranken[-_ ]?akte|gesundheits[-_ ]?akte|elektronische[ \t]+patientenakte|epa|arzt[-_ ]?brief|entlassungs[-_ ]?(?:brief|bericht)|behandlungs[-_ ]?(?:bericht|plan)|behandlung|therapie|verschreibung|verordnung|rezept|symptom(?:e)?|allergie(?:n)?|diagnose(?:n)?|anamnes[ei]|medikation|medikament(?:e)?|befund(?:e)?|labor[-_ ]?(?:wert|ergebnis|befund)(?:e|se)?|icd(?:[-_ ]?10)?|krankheit|erkrankung|gesundheits[-_ ]?zustand|patient[-_ \t]+record|medical[-_ \t]+record|health[-_ \t]+record|electronic[-_ \t]+health[-_ \t]+record|ehr|electronic[-_ \t]+medical[-_ \t]+record|emr|clinical[-_ \t]+note|discharge[-_ \t]+summary|medical[-_ \t]+history|health[-_ \t]+condition|diagnos(?:is|es)|treatment[-_ \t]+plan|treatment|therapy|prescription|symptoms?|allerg(?:y|ies)|lab(?:oratory)?[-_ \t]+(?:result|report|value)s?|medication(?:s)?)\b",
    },
    PiiAnchorPattern {
        category: "special_category",
        strength: "medium",
        pattern: r"(?i)\b(?:religion|religions[-_ ]?zugehörigkeit|glaubens[-_ ]?richtung|konfession|weltanschauung|politische[-_ ]+(?:meinung|einstellung)|parteizugehörigkeit|partei[-_ ]?mitgliedschaft|gewerkschafts[-_ ]?(?:zugehörigkeit|mitgliedschaft)|behinderung|schwerbehinderung|sexuelle[-_ ]+(?:orientierung|identität)|geschlechts[-_ ]?identität|ethnische[-_ ]+(?:herkunft|zugehörigkeit)|rassische[-_ ]?herkunft|genetische[-_ ]+daten|biometrische[-_ ]+daten|religious[-_ \t]+beliefs?|religious[-_ \t]+affiliation|philosophical[-_ \t]+beliefs?|political[-_ \t]+opinions?|political[-_ \t]+affiliation|party[-_ \t]+membership|trade[-_ \t]+union(?:[-_ \t]+membership)?|disability[-_ \t]+status|sexual[-_ \t]+orientation|gender[-_ \t]+identity|ethnic[-_ \t]+origin|racial[-_ \t]+origin|genetic[-_ \t]+data|biometric[-_ \t]+data)\b",
    },
    PiiAnchorPattern {
        category: "employment_compensation",
        strength: "weak",
        pattern: r"(?i)\b(?:gehalt|grund[-_ ]?gehalt|brutto[-_ ]?gehalt|netto[-_ ]?gehalt|jahres[-_ ]?gehalt|monats[-_ ]?gehalt|vergütung|gesamt[-_ ]?vergütung|entgelt|bezüge|besoldung|lohn|stunden[-_ ]?lohn|provision|prämie|bonus|ziel[-_ ]?bonus|lohn[-_ ]?abrechnung|gehalts[-_ ]?abrechnung|entgelt[-_ ]?abrechnung|personal[-_ ]?akte|salary|base[-_ \t]+salary|gross[-_ \t]+salary|net[-_ \t]+salary|annual[-_ \t]+salary|monthly[-_ \t]+salary|compensation|total[-_ \t]+compensation|remuneration|wages?|hourly[-_ \t]+rate|commission|bonus|target[-_ \t]+bonus|payroll|pay[-_ \t]*slip|salary[-_ \t]+statement|pay[-_ \t]+grade|stock[-_ \t]+options?|restricted[-_ \t]+stock[-_ \t]+units?|rsu|personnel[-_ \t]+file|employee[-_ \t]+file)\b",
    },
];

pub struct PiiPipeline {
    regexes: Vec<Regex>,
    rule_ids: Vec<&'static str>,
    entity_groups: Vec<&'static str>,
    validators: Vec<Option<NativeMatchValidator>>,
    capture_groups: Vec<Option<usize>>,
    anchor_regexes: Vec<Regex>,
}

impl Default for PiiPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiPipeline {
    pub fn new() -> Self {
        let mut regexes = Vec::new();
        let mut entity_groups = Vec::new();
        let mut rule_ids = Vec::new();
        let mut validators = Vec::new();
        let mut capture_groups = Vec::new();

        for p in PII_PATTERNS {
            regexes.push(Regex::new(p.pattern).unwrap());
            entity_groups.push(p.entity_group);
            rule_ids.push(p.name);
            validators.push(p.validator);
            capture_groups.push(p.captured_value.then_some(1));
        }

        let anchor_regexes = PII_ANCHOR_PATTERNS
            .iter()
            .map(|anchor| Regex::new(anchor.pattern).unwrap())
            .collect();
        PiiPipeline {
            regexes,
            rule_ids,
            entity_groups,
            validators,
            capture_groups,
            anchor_regexes,
        }
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}

impl NativeRegexDetector for PiiPipeline {
    fn regexes(&self) -> &[Regex] {
        &self.regexes
    }

    fn entity_groups(&self) -> &[&'static str] {
        &self.entity_groups
    }

    fn rule_ids(&self) -> &[&'static str] {
        &self.rule_ids
    }

    fn validators(&self) -> &[Option<fn(&str) -> bool>] {
        &self.validators
    }

    fn capture_groups(&self) -> Option<&[Option<usize>]> {
        Some(&self.capture_groups)
    }

    fn details(&self, text: &str) -> std::collections::HashMap<String, serde_json::Value> {
        let mut anchors = self
            .anchor_regexes
            .iter()
            .zip(PII_ANCHOR_PATTERNS)
            .flat_map(|(regex, definition)| {
                regex.find_iter(text).map(move |matched| {
                    serde_json::json!({
                        "kind": "anchor",
                        "anchor_kind": "lexical",
                        "category": definition.category,
                        "strength": definition.strength,
                        "text": matched.as_str(),
                        "start_byte": matched.start(),
                        "end_byte": matched.end(),
                        "start_char": text[..matched.start()].chars().count(),
                        "end_char": text[..matched.end()].chars().count(),
                    })
                })
            })
            .collect::<Vec<_>>();
        anchors.sort_by_key(|anchor| {
            (
                anchor["start_byte"].as_u64().unwrap_or_default(),
                anchor["end_byte"].as_u64().unwrap_or_default(),
            )
        });

        if anchors.is_empty() {
            std::collections::HashMap::new()
        } else {
            std::collections::HashMap::from([(
                "l1_anchors".to_string(),
                serde_json::Value::Array(anchors),
            )])
        }
    }
}
