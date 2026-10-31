// SPDX-License-Identifier: MIT OR Apache-2.0
//! Driver's licence numbers (F15): the German card number, the US state formats, the
//! Italian patente and the UK licence (B-UK).
//!
//! The four rules share one field part, so a licence field name binds every format: a
//! German letter may name a US licence (`Führerscheinnummer: T36493663`), an Italian
//! form a German one. The value decides the format and the rule. Field names are
//! DE/EN plus IT, FR, ES and NL (T26); prose joins them to the value with `is`, `of`,
//! `ist`, `lautet`, `è`, `est` or `es` ("my driver's license number is 6940579"). A note
//! in parentheses without a digit may follow the field name (`Führerscheinnummer (falls
//! relevant): …`, Q-ID), and the value may open a parenthesis (`licencia de conducir
//! (M45114072)`). A number without a licence field name or structural key (K04) is no
//! finding in any mode: none of the formats carries a check digit. The one exception is the UK licence,
//! whose sixteen characters encode surname, birth date and initials: bare, it is
//! reported in `balanced` and `recall`.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Pattern of a field-bound driver's licence rule with the value regex `$value`.
/// The word boundaries are ASCII (`(?-u:\b)`): every field name starts and ends with
/// an ASCII letter and every value with an ASCII letter or digit. With Unicode
/// boundaries the many case-insensitive field names leave the regex without a
/// literal prefilter and German text with umlauts on the slow engine (12 ms instead
/// of 0.2 ms per rule on 100 KiB).
macro_rules! driver_license_pattern {
    ($($value:tt)+) => {
        concat!(
            r"(?i)(?-u:\b)(?:",
            r"driv(?:er(?:['’]?s)?|ing)[-_ \t]?licen[cs]e(?:[-_ \t]?(?:number|num|no|nr|id))?",
            r"|dl[-_ \t]?(?:number|num|no|nr)",
            r"|f(?:ü|ue)hrerschein(?:[-‑_ \t]?(?:nummer|nr))?",
            r"|fahrerlaubnis(?:[-‑_ \t]?(?:nummer|nr))?",
            r"|(?:numero|nr|n)\.?[ \t]+(?:(?:di|della)[ \t]+)?patente(?:[ \t]+di[ \t]+guida)?",
            r"|(?:patente|licenza)[ \t]+di[ \t]+guida",
            r"|(?:num(?:é|e)ro[ \t]+(?:de[ \t]+|du[ \t]+)?)?permis[ \t]+de[ \t]+conduire",
            r"|licence[ \t]+de[ \t]+conduc(?:teur|tion)",
            r"|(?:n(?:ú|u)mero[ \t]+de[ \t]+(?:la[ \t]+)?)?(?:licencia|permiso|carn(?:é|e)t?)[ \t]+de[ \t]+conducir",
            r"|rijbewijs(?:[-_ \t]?(?:nummer|nr))?",
            r")(?-u:\b)\.?[ \t]*(?:\([^()0-9\n]{1,40}\)[ \t]*)?(?:(?:is|of|ist|lautet|è|est|es)[ \t]*)?[:#=\-]?[ \t]*\(?(?P<value>",
            $($value)+,
            r")(?-u:\b)",
        )
    };
}

/// German card licence (since 2013): eleven characters, authority code, serial,
/// check character and issue number (`B072RRE2A57`).
pub(super) const DE: PiiPattern = PiiPattern {
    name: "pii_driver_license_number_de",
    pattern: driver_license_pattern!(r"[A-Z0-9]{11}"),
    entity_group: "DRIVER_LICENSE_NUMBER",
    validator: Some(validators::de_driver_license_number),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// A US state format (`validators::us_driver_license_number`), uppercase, its digit
/// groups optionally joined by hyphens (`S530-460-72-345-0`, `D400-7836-0001`).
pub(super) const US: PiiPattern = PiiPattern {
    name: "pii_driver_license_number_us",
    pattern: driver_license_pattern!(r"(?-i:[A-Z0-9](?:-?[A-Z0-9]){4,14})"),
    entity_group: "DRIVER_LICENSE_NUMBER",
    validator: Some(validators::us_driver_license_number),
    strength: ValidatorStrength::Format,
    base_score: 25,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// Italian patente: two letters, seven digits and a letter on the card
/// (`RM5512345K`), `U1` and eight characters on the paper licence (`U1H34K56LX`).
pub(super) const IT: PiiPattern = PiiPattern {
    name: "pii_driver_license_number_it",
    pattern: driver_license_pattern!(
        r"(?-i:[A-Z]{2}[0-9]{7}[A-Z]|U1[0-9BCDEFGHJKLMNPRSTUWXYZ]{7}[A-Z])"
    ),
    entity_group: "DRIVER_LICENSE_NUMBER",
    validator: Some(validators::it_driver_license_number),
    strength: ValidatorStrength::Format,
    base_score: 30,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// The UK licence form (`MORGA657054SM9IJ`, `validators::uk_driver_license_number`).
macro_rules! uk_value {
    () => {
        r"[A-Z9]{5}[0-9]{6}[A-Z9]{2}[A-Z0-9][A-Z]{2}"
    };
}

/// UK driving licence after a licence field name.
pub(super) const UK: PiiPattern = PiiPattern {
    name: "pii_driver_license_number_uk",
    pattern: driver_license_pattern!(concat!("(?-i:", uk_value!(), ")")),
    entity_group: "DRIVER_LICENSE_NUMBER",
    validator: Some(validators::uk_driver_license_number),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// A bare UK driving licence, as presidio-analyzer reports it without context. Surname,
/// birth date and initials stand in for a check digit: the value just reaches the
/// `balanced` threshold, a nearer counter-context term drops it, and `strict` never
/// runs the rule.
pub(super) const UK_CONTEXT_FREE: PiiPattern = PiiPattern {
    name: "pii_driver_license_number_uk_context_free",
    pattern: concat!(r"(?-u:\b)", uk_value!(), r"(?-u:\b)"),
    entity_group: "DRIVER_LICENSE_NUMBER",
    validator: Some(validators::uk_driver_license_number),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
