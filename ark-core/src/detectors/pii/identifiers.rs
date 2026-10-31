// SPDX-License-Identifier: MIT OR Apache-2.0
//! Field-bound personal identifiers in German and English documents: employee, customer,
//! patient, student and applicant IDs, usernames, dates of birth, account numbers. Employee
//! and customer IDs, usernames, dates of birth and account numbers also accept FR/ES/IT/NL
//! field names (T26). Account numbers include the BBAN and the US routing number under
//! its field name, with or without its ABA check digit (B-ACCT).
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// An example that opens after a field name: `customer_id (e.g., C352-3474-967)`,
/// `Kundennummer (z. B. J8382610)`, `date of birth (e.g., 2003-06-14)` (Q-CONTACT).
macro_rules! example_opener {
    () => {
        r"\((?:e\.g\.|z\.[ \t]?B\.|par[ \t]+exemple)[ \t]*,?[ \t]*"
    };
}

// ── Anchor-gebundene Personenkennungen ─────────────────────────────────
pub(super) const EMPLOYEE_ID: PiiPattern = PiiPattern {
    name: "pii_employee_id",
    // The field may close a parenthesis (`folgende Angabe (Personalnummer): E11397`);
    // a value may be a short uppercase prefix and digits (`PN 062520`).
    pattern: r"(?i)\b(?:personalnummer|pers(?:onal)?[ \t]*nr\.?|mitarbeiter(?:nummer|[-_ ]?id)|employee(?:[ \t_-]+)(?:id|number)|personnel[ \t]+(?:id|number)|staff[ \t]+(?:id|code|number)|kennung|(?:num(?:é|e)ro|id|identifiant)[ \t]+(?:de[ \t]+l['’]|d['’])employ(?:é|e)e?|(?:id[ \t]+employ(?:é|e)e?|employ(?:é|e)e?[ \t]+id)|(?:n(?:ú|u)mero(?:[ \t]+de[ \t]+identificaci(?:ó|o)n)?|id|c(?:ó|o)digo)[ \t]+(?:del?[ \t]+)?empleado|(?:numero|codice|id|matricola)[ \t]+(?:del[ \t]+)?dipendente|personeelsnummer|werknemersnummer|medewerkers?nummer|(?:medewerker|werknemer)[-_ \t]?id)\b\)?[ \t]*(?:(?:is|ist|lautet)\b[ \t]*)?[:#=\-]?[ \t]*(?P<value>(?-i:[A-Z]{1,3})[ \t]\d{4,10}|[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "EMPLOYEE_ID",
    validator: Some(validators::bounded_employee_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
    scored_only: false,
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
    scored_only: false,
};

pub(super) const EMPLOYEE_ID_PREFIXED: PiiPattern = PiiPattern {
    name: "pii_employee_id_prefixed",
    // `EMP-HR-1042` in any case, or uppercase `EMP` glued to five to ten digits
    // (`EMP821659`, Q-CONTACT).
    pattern: r"(?i)\b(?:EMP[-_/][A-Z0-9]+[-_/][A-Z0-9](?:[A-Z0-9._/-]{1,24}[A-Z0-9])?|(?-i:EMP)\d{5,10})\b",
    entity_group: "EMPLOYEE_ID",
    validator: Some(validators::bounded_employee_identifier),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

pub(super) const CUSTOMER_ID: PiiPattern = PiiPattern {
    name: "pii_customer_id",
    // Prose may join field and value: "a customer ID of C736-6988-309", "the
    // customer with the ID Im-29924", "customer_id (e.g., C352-3474-967)",
    // "Kundennummer (z. B. J8382610)" (Q-CONTACT).
    pattern: concat!(
        r"(?i)\b(?:kundennummer|kunden[-_ ]?id|debitor(?:ennummer)?|customer[ \t_-]+(?:id|number)|customer[ \t]+with[ \t]+(?:the[ \t]+)?id|(?:num(?:é|e)ro|id|identifiant)[ \t]+(?:de[ \t]+|du[ \t]+)?client|r(?:é|e)f(?:é|e)rence[ \t]+client|(?:n(?:ú|u)mero|id|c(?:ó|o)digo|codice|identificador)[ \t]+(?:del?[ \t]+)?cliente|klant(?:en)?nummer|klant[-_ \t]?id)\b[ \t]*(?:(?:is|ist|lautet|of)\b[ \t]*|",
        example_opener!(),
        r")?[:#=\-]?[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b"
    ),
    entity_group: "CUSTOMER_ID",
    validator: Some(validators::bounded_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
    scored_only: false,
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
    scored_only: false,
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
    scored_only: false,
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
    scored_only: false,
};

pub(super) const USERNAME: PiiPattern = PiiPattern {
    name: "pii_username",
    // The value must follow an explicit assignment. Prose such as "CLI login
    // token" or "login-flow" names a concept, not an account, and "login issues"
    // no value. A bare `user` names the account in a log or query assignment
    // only (`auth failed user=omorgan`, Q-CONTACT).
    pattern: r"(?i)\b(?:(?:benutzername|benutzer|login|username|user[ \t]+name|account[ \t]+name)(?:[ \t]*[:#=][ \t]*|[ \t]+(?:is|ist|lautet)\b[ \t]*:?[ \t]*)|(?:nom[ \t]+d['’]utilisateur|nombre[ \t]+de[ \t]+usuario|nome[ \t]+utente|gebruikersnaam)[ \t]*[:#=][ \t]*|user=)(?P<value>[A-Z0-9](?:[A-Z0-9._@-]{0,62}[A-Z0-9])?)\b",
    entity_group: "USERNAME",
    validator: Some(validators::username),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// Pattern of a date-of-birth rule with the value regex `$value`: a birth-date
/// field name, `geb.` or `born on` before the value, also with a connective (`is`,
/// `of`, `del`, `el`), a no-break space or a structural key (Q-CONTACT).
macro_rules! date_of_birth_pattern {
    ($($value:tt)+) => {
        concat!(
            r"(?i)\b(?:(?:geburtsdatum|geboren[ \t]+am|date[ \t_-]*of[ \t_-]*birth|dob|born[ \t]+on",
            r"|date[ \t]+de[ \t]+naissance|né(?:e|\(e\))?[ \t]+le|fecha[ \t]+(?:de[ \t]+)?nacimiento",
            r"|nacid[oa][ \t]+el|data[ \t]+(?:di[ \t]+)?nascita|nat[oa][ \t]+il|geboortedatum",
            r"|geboren[ \t]+op)\b|geb\.)[ \t\x{A0}]*(?:(?:is|as|ist|lautet|est|es|è|of|del|el)\b[ \t]*|",
            example_opener!(),
            r")?",
            r"[:#=\-]?[ \t\x{A0}]*(?P<value>",
            $($value)+,
            r")\b",
        )
    };
}

/// Month names of the written birth dates (DE, EN, FR, ES, IT, NL), read by
/// [`validators::written_calendar_date`].
macro_rules! month_name {
    () => {
        concat!(
            r"(?:januar[iy]?|janvier|enero|gennaio|februar[iy]?|f(?:é|e)vrier|febrero|febbraio",
            r"|m(?:ä|ae)rz|march|mars|marzo|maart|april|avril|abril|aprile|mai|may|mayo|maggio|mei",
            r"|jun[ei]|junio|juin|giugno|jul[iy]|julio|juillet|luglio|august(?:us)?|ao(?:û|u)t|agosto",
            r"|sept?iembre|septembre|settembre|september|o[ck]tober|octobre|octubre|ottobre",
            r"|november|novembre|noviembre|de[cz]ember|d(?:é|e)cembre|diciembre|dicembre)",
        )
    };
}

pub(super) const DATE_OF_BIRTH: PiiPattern = PiiPattern {
    name: "pii_date_of_birth",
    // Day first, or the ISO order year-month-day (`1980-11-26`).
    pattern: date_of_birth_pattern!(
        r"\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2}"
    ),
    entity_group: "DOB",
    validator: Some(validators::calendar_date),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

pub(super) const DATE_OF_BIRTH_WRITTEN_DAY_FIRST: PiiPattern = PiiPattern {
    name: "pii_date_of_birth_written_day_first",
    // `21. Februar 1971`, `18th December 1983`, `26 de marzo de 1990`, `1er mars 1990`.
    pattern: date_of_birth_pattern!(
        r"\d{1,2}(?:\.|st|nd|rd|th|er)?[ \t]+(?:de[ \t]+)?",
        month_name!(),
        r"[ \t]+(?:de[ \t]+)?\d{4}"
    ),
    entity_group: "DOB",
    validator: Some(validators::written_calendar_date),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

pub(super) const DATE_OF_BIRTH_WRITTEN_MONTH_FIRST: PiiPattern = PiiPattern {
    name: "pii_date_of_birth_written_month_first",
    pattern: date_of_birth_pattern!(
        month_name!(),
        r"[ \t]+\d{1,2}(?:st|nd|rd|th)?[,]?[ \t]+\d{4}"
    ),
    entity_group: "DOB",
    validator: Some(validators::written_calendar_date),
    strength: ValidatorStrength::Format,
    base_score: 45,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// An account number after an account field name. An abbreviated name takes a
/// colon after its dot (`Konto-Nr.: 192555007`; `konto nr. 5116…` in prose stays
/// with the card rule), `ist` assigns like `is` (`Als Kontonummer ist 17404395`),
/// and `Permanent Account Number` is the Indian PAN (`context::permanent_account_number`, Q-FIN).
pub(super) const FINANCIAL_ACCOUNT_NUMBER: PiiPattern = PiiPattern {
    name: "pii_financial_account_number",
    pattern: r"(?i)\b(?:kontonummer|konto[-_ ]?nr|depotnummer|depot[-_ ]?nr|account[ \t]+number|bank[ \t]+account(?:[ \t]+on[ \t]+file)?|bban(?:[ \t]+number)?|acct[ \t]*(?:number|no|id)|(?:(?:bank|aba)[ \t]+)?routing[ \t]+(?:transit[ \t]+)?(?:number|no)|aba[ \t]+number|(?:routing|aba)[-_ ]?nummer|num(?:é|e)ro[ \t]+de[ \t]+compte(?:[ \t]+bancaire)?|compte[ \t]+bancaire|num(?:é|e)ro[ \t]+(?:de[ \t]+routage|d['’]acheminement)(?:[ \t]+de[ \t]+la[ \t]+banque)?|n(?:ú|u)mero[ \t]+(?:de[ \t]+)?cuenta(?:[ \t]+bancaria)?|cuenta[ \t]+bancaria|n(?:ú|u)mero[ \t]+de[ \t]+ruta(?:[ \t]+bancaria)?|numero[ \t]+(?:di|del)[ \t]+conto(?:[ \t]+corrente)?|conto[ \t]+corrente|numero[ \t]+di[ \t]+routing(?:[ \t]+bancario)?|(?:bank)?rekening[-_ \t]?(?:nummer|nr))\b(?:\.[ \t]*:|[ \t]*(?:ist[ \t]+|is[ \t]*)?[:#=\-]?)[ \t]*(?P<value>[A-Z0-9](?:[A-Z0-9._/-]{1,30}[A-Z0-9])?)\b",
    entity_group: "FINANCIAL_ACCOUNT_NUMBER",
    validator: Some(validators::bounded_identifier),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};
