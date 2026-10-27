// SPDX-License-Identifier: MIT OR Apache-2.0
//! Licence plates (T30): the German plate and the UK current form.
//!
//! The two rules share one field part, so a plate field name binds either form: a
//! German form may name a UK plate (`Kennzeichen: LW02 ULF`), an English one a
//! German plate (`Number plate: FÜ-CB 3876`). Field names are DE/EN, before the
//! value or as its structural key (K04: `kennzeichen`, `license_plate`); prose joins
//! them to the value with `is`, `ist`, `lautet`, `as` or `on file is` ("The vehicle
//! registration on file is …", "My car, registration …", "My car reg is …"). A
//! generic `registration number` names no plate. No form carries a check digit and
//! ARK keeps no district-code list (F16 deferred), so a value without a plate field
//! name is no finding in any mode. Values are uppercase as printed on the plate.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Pattern of a field-bound plate rule with the value regex `$value`. The word
/// boundaries are ASCII (`(?-u:\b)`), as in `driver_license`: every field name
/// starts and ends with an ASCII letter and every value ends with one or a digit.
macro_rules! plate_pattern {
    ($($value:tt)+) => {
        concat!(
            r"(?i)(?-u:\b)(?:",
            r"kfz(?:[-_ ]?(?:kennzeichen|nummer))?",
            r"|kraftfahrzeug[-_ ]?kennzeichen",
            r"|(?:amtliches[-_ ]?|auto|zulassungs)?kennzeichen",
            r"|nummern[-_ ]?schild",
            r"|vehicle[-_ \t]?registration(?:[-_ \t]?(?:number|no|mark))?",
            r"|(?:licen[cs]e|number)[-_ \t]?plate(?:[-_ \t]?(?:number|no))?",
            r"|car[ \t]+reg(?:istration)?(?:[ \t]+(?:number|no))?",
            r"|car,[ \t]+registration",
            r")(?-u:\b)\)?[ \t]*(?:(?:is|ist|lautet|as|on[ \t]+file[ \t]+is)[ \t]*)?[:#=|\-]?[ \t]*(?P<value>",
            $($value)+,
            r")(?-u:\b)",
        )
    };
}

/// German plate: district code, one or two letters, up to four digits and the
/// `E` (electric) or `H` (historic) suffix, joined by a hyphen or a space; a hyphen
/// may also stand before the digits (`B-AB 1234E`, `K-MH-2476`, `KA HW 29H`,
/// `validators::de_licence_plate`).
pub(super) const DE: PiiPattern = PiiPattern {
    name: "pii_kfz_kennzeichen_de",
    pattern: plate_pattern!(r"(?-i:[A-ZÄÖÜ]{1,3}[- ][A-Z]{1,2}[- ]?[0-9]{1,4}[EH]?)"),
    entity_group: "LICENSEPLATE",
    validator: Some(validators::de_licence_plate),
    strength: ValidatorStrength::Format,
    base_score: 25,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};

/// UK current form since 2001: two area letters, the age identifier and three
/// random letters (`AB51 ABC`, `BD62XYZ`, `validators::uk_vehicle_registration`).
pub(super) const UK: PiiPattern = PiiPattern {
    name: "pii_vehicle_registration_uk",
    pattern: plate_pattern!(r"(?-i:[A-Z]{2}[0-9]{2}[- ]?[A-Z]{3})"),
    entity_group: "LICENSEPLATE",
    validator: Some(validators::uk_vehicle_registration),
    strength: ValidatorStrength::Format,
    base_score: 25,
    captured_value: true,
    requires_context: false,
    scored_only: false,
};
