// SPDX-License-Identifier: GPL-3.0-only
//! Field-bound personal identifiers in German and English documents: employee, customer,
//! patient, student and applicant IDs, usernames, dates of birth, account numbers.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── Anchor-gebundene Personenkennungen ─────────────────────────────────
pub(super) const EMPLOYEE_ID: PiiPattern = PiiPattern {
    name: "pii_employee_id",
    pattern: r"(?i)\b(?:personalnummer|pers(?:onal)?[ \t]*nr\.?|mitarbeiter(?:nummer|[-_ ]?id)|employee(?:[ \t_-]+)(?:id|number)|personnel[ \t]+(?:id|number)|staff[ \t]+(?:id|code|number)|kennung)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "EMPLOYEE_ID",
    validator: Some(validators::bounded_employee_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
};

pub(super) const EMPLOYEE_ID_OCR_FIELD: PiiPattern = PiiPattern {
    name: "pii_employee_id_ocr_field",
    pattern: r"(?m)(?:^|[\n|])[ \t]*ID[ \t]*[:#=\-]?[ \t]*(?P<value>[A-Z]{1,8}[ \t]{1,3}\d{2,20})\b",
    entity_group: "EMPLOYEE_ID",
    validator: Some(validators::bounded_employee_identifier),
    strength: ValidatorStrength::Format,
    base_score: 25,
    captured_value: true,
    requires_context: false,
};

pub(super) const EMPLOYEE_ID_PREFIXED: PiiPattern = PiiPattern {
    name: "pii_employee_id_prefixed",
    pattern: r"(?i)\bEMP[-_/][A-Z0-9]+[-_/][A-Z0-9](?:[A-Z0-9._/-]{1,24}[A-Z0-9])?\b",
    entity_group: "EMPLOYEE_ID",
    validator: Some(validators::bounded_employee_identifier),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: false,
    requires_context: false,
};

pub(super) const CUSTOMER_ID: PiiPattern = PiiPattern {
    name: "pii_customer_id",
    pattern: r"(?i)\b(?:kundennummer|kunden[-_ ]?id|debitor(?:ennummer)?|customer[ \t]+(?:id|number))\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "CUSTOMER_ID",
    validator: Some(validators::bounded_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
};

pub(super) const PATIENT_ID: PiiPattern = PiiPattern {
    name: "pii_patient_id",
    pattern: r"(?i)\b(?:patientennummer|patienten[-_ ]?id|patient[ \t]+(?:id|number)|mrn|medical[ \t]+record[ \t]+number)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "PATIENT_ID",
    validator: Some(validators::bounded_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
};

pub(super) const STUDENT_ID: PiiPattern = PiiPattern {
    name: "pii_student_id",
    pattern: r"(?i)\b(?:matrikelnummer|sch(?:ü|ue)ler(?:nummer|[-_ ]?id)|student(?:en)?[-_ ]?(?:id|nummer)|student[ \t]+number)\b[ \t]*(?:(?:lautet|ist|is)[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "STUDENT_ID",
    validator: Some(validators::bounded_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
};

pub(super) const APPLICANT_ID: PiiPattern = PiiPattern {
    name: "pii_applicant_id",
    pattern: r"(?i)\b(?:bewerber(?:nummer|[-_ ]?id)|applicant[ \t]+(?:id|number)|candidate[ \t]+id)\b[ \t]*(?:(?:lautet|ist|is)[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "APPLICANT_ID",
    validator: Some(validators::bounded_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
};

pub(super) const USERNAME: PiiPattern = PiiPattern {
    name: "pii_username",
    // The value must follow an explicit assignment. Prose such as "CLI login
    // token" or "login-flow" names a concept, not an account.
    pattern: r"(?i)\b(?:benutzername|benutzer|login|username|user[ \t]+name|account[ \t]+name)(?:[ \t]*[:#=][ \t]*|[ \t]+(?:is|ist|lautet)[ \t]*:?[ \t]*)(?P<value>[A-Z0-9](?:[A-Z0-9._@-]{0,62}[A-Z0-9])?)\b",
    entity_group: "USERNAME",
    validator: Some(validators::username),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
};

pub(super) const DATE_OF_BIRTH: PiiPattern = PiiPattern {
    name: "pii_date_of_birth",
    pattern: r"(?i)\b(?:geburtsdatum|geboren[ \t]+am|date[ \t]+of[ \t]+birth|dob)\b[ \t]*(?:(?:is|as|ist|lautet)[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b",
    entity_group: "DOB",
    validator: Some(validators::calendar_date),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: true,
    requires_context: false,
};

pub(super) const DATE_OF_BIRTH_WRITTEN_DAY_FIRST: PiiPattern = PiiPattern {
    name: "pii_date_of_birth_written_day_first",
    pattern: r"(?i)\b(?:geburtsdatum|geboren[ \t]+am|date[ \t]+of[ \t]+birth|dob)\b[ \t]*(?:(?:is|as|ist|lautet)[ \t]*)?[:#=\-]?[ \t]*(?P<value>\d{1,2}\.?[ \t]+(?:januar|februar|m(?:ä|ae)rz|april|mai|juni|juli|august|september|oktober|november|dezember|january|february|march|may|june|july|october|december)[ \t]+\d{4})\b",
    entity_group: "DOB",
    validator: Some(validators::written_calendar_date),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: true,
    requires_context: false,
};

pub(super) const DATE_OF_BIRTH_WRITTEN_MONTH_FIRST: PiiPattern = PiiPattern {
    name: "pii_date_of_birth_written_month_first",
    pattern: r"(?i)\b(?:geburtsdatum|geboren[ \t]+am|date[ \t]+of[ \t]+birth|dob)\b[ \t]*(?:(?:is|as|ist|lautet)[ \t]*)?[:#=\-]?[ \t]*(?P<value>(?:januar|februar|m(?:ä|ae)rz|mai|juni|juli|oktober|dezember|january|february|march|april|may|june|july|august|september|october|november|december)[ \t]+\d{1,2}(?:st|nd|rd|th)?[,]?[ \t]+\d{4})\b",
    entity_group: "DOB",
    validator: Some(validators::written_calendar_date),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: true,
    requires_context: false,
};

pub(super) const FINANCIAL_ACCOUNT_NUMBER: PiiPattern = PiiPattern {
    name: "pii_financial_account_number",
    pattern: r"(?i)\b(?:kontonummer|konto[-_ ]?nr|depotnummer|depot[-_ ]?nr|account[ \t]+number|bank[ \t]+account)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "FINANCIAL_ACCOUNT_NUMBER",
    validator: Some(validators::bounded_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
};
