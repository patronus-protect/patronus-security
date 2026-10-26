// SPDX-License-Identifier: GPL-3.0-only
//! French, Dutch and Belgian identifiers (B-EU1: B09, B10, B11).
//!
//! Five numbering systems with a check digit, one label each: the French NIR
//! (`FR_NIR`, key mod 97), SIREN (`FR_SIREN`, Luhn) and SIRET (`FR_SIRET`, Luhn,
//! La Poste by digit sum), the Dutch BSN (`NL_BSN`, 11-proof) and the Belgian
//! national number (`BE_NATIONAL_NUMBER`, mod 97). Each label has a rule that
//! reports the value in every mode when a term of the label stands near it or is
//! its key. In `balanced` and `recall` the forms whose shape adds to the check digit
//! are also reported bare (K05): the NIR printed 1-2-2-2-3-3-2 or as fifteen
//! characters of sex 1 or 2, the SIRET in 3-3-3-5 groups, the BSN printed
//! `1234.56.782` and the national number printed `85.07.30-033.28`. Nine bare digits
//! (SIREN, BSN), fourteen (SIRET) and eleven (national number) need the term in every
//! mode; the SIREN has no context-free form, like the Australian Company Number.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const NIR: &str = "pii_nir_fr";
const NIR_CONTEXT_FREE: &str = "pii_nir_fr_context_free";
const SIREN: &str = "pii_siren_fr";
const SIRET: &str = "pii_siret_fr";
const SIRET_CONTEXT_FREE: &str = "pii_siret_fr_context_free";
const BSN: &str = "pii_bsn_nl";
const BSN_CONTEXT_FREE: &str = "pii_bsn_nl_context_free";
const NATIONAL_NUMBER: &str = "pii_national_number_be";
const NATIONAL_NUMBER_CONTEXT_FREE: &str = "pii_national_number_be_context_free";
const CONTEXT_BOUND: [&str; 5] = [NIR, SIREN, SIRET, BSN, NATIONAL_NUMBER];
const CONTEXT_FREE: [&str; 4] = [
    NIR_CONTEXT_FREE,
    SIRET_CONTEXT_FREE,
    BSN_CONTEXT_FREE,
    NATIONAL_NUMBER_CONTEXT_FREE,
];
const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];
const SCORED: [PiiMode; 2] = [PiiMode::Balanced, PiiMode::Recall];

fn pii_result(text: &str, mode: PiiMode) -> SecurityScanResult {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix {
        pii_mode: mode,
        ..Default::default()
    });
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

/// `(text, score)` of every span with `label`.
fn spans(text: &str, mode: PiiMode, label: &str) -> Vec<(String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == label)
        .map(|span| (span.text, span.score))
        .collect()
}

/// Rule ids that matched with the value text they matched.
fn rules(text: &str, mode: PiiMode) -> Vec<(String, String)> {
    let result = pii_result(text, mode);
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| {
            let start = rule["start_byte"].as_u64().unwrap() as usize;
            let end = rule["end_byte"].as_u64().unwrap() as usize;
            (
                rule["rule_id"].as_str().unwrap().to_owned(),
                text[start..end].to_owned(),
            )
        })
        .collect()
}

fn pattern(rule_id: &str) -> &'static PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

/// `rule_id` reports `value`, the only span of its label, in each of `modes`.
fn assert_reports(rule_id: &str, text: &str, value: &str, modes: &[PiiMode]) {
    let label = pattern(rule_id).entity_group;
    for &mode in modes {
        assert!(
            rules(text, mode)
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report the expected value in {text:?}"
        );
        let found = spans(text, mode, label);
        assert!(
            found.len() == 1 && found[0].0 == value,
            "{mode}: the expected value must be the only {label} span in {text:?}"
        );
    }
}

fn assert_silent(text: &str, label: &str, modes: &[PiiMode]) {
    for &mode in modes {
        assert!(
            spans(text, mode, label).is_empty(),
            "{mode}: no {label} expected in {text:?}"
        );
    }
}

// ── validators ───────────────────────────────────────────────────────────────

#[test]
fn nir_validator_checks_the_fields_and_the_mod_97_key() {
    for valid in [
        "295109912611193",
        "2 95 10 99 126 111 93",
        "1 85 05 78 006 084 91",
        "170017511501270",
        "1700175115012 70",
        // Corsica: 2A and 2B count as 19 and 18
        "2 93 11 2A 004 123 01",
        "199122B03300716",
        // registration running, provisional number, unknown month
        "385057800608488",
        "785057800608482",
        "185557800608418",
        "185307800608406",
    ] {
        assert!(validators::fr_nir(valid), "{valid}");
    }
    for invalid in [
        // key off by one
        "295109912611194",
        "2 95 10 99 126 111 92",
        // sex, month and département outside their ranges (key valid)
        "585057800608485",
        "185137800608425",
        "185007800608411",
        "185457800608452",
        "185050000608463",
        // Corsica in lower case, a letter elsewhere
        "2 93 11 2a 004 123 01",
        "2931A2A00412301",
        // length
        "29510991261119",
        "2951099126111930",
    ] {
        assert!(!validators::fr_nir(invalid), "{invalid}");
    }
}

#[test]
fn siren_validator_checks_luhn() {
    for valid in [
        "732829320",
        "732 829 320",
        "404833048",
        "707173555",
        "851 313 775",
        "356000000",
    ] {
        assert!(validators::fr_siren(valid), "{valid}");
    }
    for invalid in [
        "732829321",
        "404 833 049",
        // one repeated digit passes Luhn but is no number
        "000000000",
        // length and alphabet
        "73282932",
        "7328293200",
        "732 829 32A",
    ] {
        assert!(!validators::fr_siren(invalid), "{invalid}");
    }
}

#[test]
fn siret_validator_checks_the_siren_and_luhn_or_the_la_poste_sum() {
    for valid in [
        "73282932000074",
        "732 829 320 00074",
        "69940718549707",
        "823 022 181 06863",
        // La Poste: the digit sum is a multiple of five
        "35600000049837",
        "356 000 000 10000",
    ] {
        assert!(validators::fr_siret(valid), "{valid}");
    }
    for invalid in [
        "73282932000075",
        "699 407 185 49708",
        // the SIREN part fails Luhn although the fourteen digits pass it
        "73282932100064",
        // La Poste needs the digit sum, Luhn alone is not enough
        "35600000010013",
        // the test value of a form
        "12345678901234",
        // length and alphabet
        "7328293200007",
        "732829320000740",
        "732 829 320 0007A",
    ] {
        assert!(!validators::fr_siret(invalid), "{invalid}");
    }
}

#[test]
fn bsn_validator_checks_the_eleven_proof() {
    for valid in [
        "111222333",
        "123456782",
        "1234.56.782",
        "106165653",
        "214 069 989",
        "6459.69.175",
    ] {
        assert!(validators::nl_bsn(valid), "{valid}");
    }
    for invalid in [
        "123456783",
        "1234.56.783",
        "106165654",
        // one repeated digit
        "000000000",
        "999999999",
        // length and alphabet
        "12345678",
        "1234567820",
        "1234-56-782",
        "12345678X",
    ] {
        assert!(!validators::nl_bsn(invalid), "{invalid}");
    }
}

#[test]
fn national_number_validator_checks_the_date_serial_and_mod_97_check() {
    for valid in [
        "85073003328",
        "85.07.30-033.28",
        "850730-033.28",
        "850730 033 28",
        "75042297367",
        // born since 2000: a 2 before the nine digits
        "03011798658",
        "17.11.28-631.59",
        // BIS number: month plus 40
        "60410328112",
    ] {
        assert!(validators::be_national_number(valid), "{valid}");
    }
    for invalid in [
        // check off by one
        "85073003329",
        "85073003327",
        // month, day and serial outside their ranges (check valid)
        "85133003370",
        "85153003384",
        "85073203365",
        "85073000061",
        "85073099932",
        // length and alphabet
        "8507300332",
        "850730033280",
        "85.07.30/033.28",
    ] {
        assert!(!validators::be_national_number(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_eu_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check) in [
        (
            &[NIR, NIR_CONTEXT_FREE][..],
            "FR_NIR",
            validators::fr_nir as fn(&str) -> bool,
        ),
        (&[SIREN][..], "FR_SIREN", validators::fr_siren),
        (
            &[SIRET, SIRET_CONTEXT_FREE][..],
            "FR_SIRET",
            validators::fr_siret,
        ),
        (&[BSN, BSN_CONTEXT_FREE][..], "NL_BSN", validators::nl_bsn),
        (
            &[NATIONAL_NUMBER, NATIONAL_NUMBER_CONTEXT_FREE][..],
            "BE_NATIONAL_NUMBER",
            validators::be_national_number,
        ),
    ] {
        for rule_id in rule_ids {
            let rule = pattern(rule_id);
            assert_eq!(rule.entity_group, label, "{rule_id}");
            assert_eq!(rule.strength, ValidatorStrength::Checksum, "{rule_id}");
            assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
            assert!(!rule.captured_value, "{rule_id}");
        }
    }
    let balanced = PiiMode::Balanced.min_score().unwrap();
    let recall = PiiMode::Recall.min_score().unwrap();
    for rule_id in CONTEXT_BOUND {
        let rule = pattern(rule_id);
        assert!(rule.requires_context && !rule.scored_only, "{rule_id}");
        // The farthest term still clears the balanced threshold.
        assert!(
            score::score(rule, Context::Support { gap: 48 }) >= balanced,
            "{rule_id}"
        );
    }
    for rule_id in CONTEXT_FREE {
        let rule = pattern(rule_id);
        assert!(rule.scored_only && !rule.requires_context, "{rule_id}");
        // Bare, the check digit reaches the balanced threshold; a nearer
        // counter-context term drops it below the recall threshold.
        assert_eq!(score::rule_score(rule), 0.55, "{rule_id}");
        assert!(score::score(rule, Context::Counter) < recall, "{rule_id}");
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (
            NIR,
            "Numéro de sécurité sociale : 2 95 10 99 126 111 93",
            "2 95 10 99 126 111 93",
        ),
        (NIR, "NIR: 185057800608491", "185057800608491"),
        (
            NIR,
            "Die französische Sozialversicherungsnummer lautet 1 70 01 75 115 012 70.",
            "1 70 01 75 115 012 70",
        ),
        (NIR, "{\"nir\": \"293112A00412301\"}", "293112A00412301"),
        (NIR, "N° INSEE 385057800608488", "385057800608488"),
        (SIREN, "SIREN : 732 829 320", "732 829 320"),
        (SIREN, "Numéro SIREN 404833048", "404833048"),
        (
            SIREN,
            "The SIREN of the supplier is 851 313 775.",
            "851 313 775",
        ),
        (SIREN, "{\"siren\": \"707173555\"}", "707173555"),
        (SIREN, "Die SIREN-Nummer lautet 724984943.", "724984943"),
        (SIRET, "SIRET : 732 829 320 00074", "732 829 320 00074"),
        (SIRET, "N° SIRET 69940718549707", "69940718549707"),
        (
            SIRET,
            "Our SIRET number is 35600000049837.",
            "35600000049837",
        ),
        (SIRET, "{\"siret\": \"82302218106863\"}", "82302218106863"),
        (BSN, "BSN: 123456782", "123456782"),
        (BSN, "Burgerservicenummer 1234.56.782", "1234.56.782"),
        (
            BSN,
            "Mijn burgerservicenummer is 214 069 989.",
            "214 069 989",
        ),
        (BSN, "{\"bsn\": \"106165653\"}", "106165653"),
        (BSN, "Die BSN lautet 645969175.", "645969175"),
        (
            NATIONAL_NUMBER,
            "Rijksregisternummer: 85.07.30-033.28",
            "85.07.30-033.28",
        ),
        (
            NATIONAL_NUMBER,
            "Numéro de registre national 75042297367",
            "75042297367",
        ),
        (
            NATIONAL_NUMBER,
            "Her Belgian national number is 030117-986.58.",
            "030117-986.58",
        ),
        (
            NATIONAL_NUMBER,
            "{\"insz\": \"60410328112\"}",
            "60410328112",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (NIR, "nir,age\n295109912611193,42", "295109912611193"),
        (SIREN, "siren,code_postal\n732829320,75008", "732829320"),
        (
            SIRET,
            "siret,effectif\n73282932000074,120",
            "73282932000074",
        ),
        (BSN, "bsn,leeftijd\n123456782,42", "123456782"),
        (
            NATIONAL_NUMBER,
            "rijksregisternummer,leeftijd\n85073003328,41",
            "85073003328",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
    // A cell that holds more than the value is still part of a longer number.
    assert_silent("bsn,leeftijd\n123456782-4,42", "NL_BSN", &MODES);
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // no term: the bare forms that are never context-free
        ("FR_SIREN", "Commande 732829320 expédiée."),
        ("FR_SIREN", "Order 732 829 320 shipped."),
        ("FR_SIRET", "Reference 73282932000074"),
        ("NL_BSN", "Reference 123456782"),
        ("NL_BSN", "Call 214 069 989 today."),
        ("BE_NATIONAL_NUMBER", "Reference 85073003328"),
        ("FR_NIR", "Reference 385057800608488"),
        // check fails
        ("FR_NIR", "NIR: 2 95 10 99 126 111 94"),
        ("FR_SIREN", "SIREN : 732 829 321"),
        ("FR_SIRET", "SIRET : 732 829 320 00075"),
        ("FR_SIRET", "Numéro SIRET : 12345678901234"),
        ("NL_BSN", "BSN: 123456783"),
        ("BE_NATIONAL_NUMBER", "Rijksregisternummer: 85.07.30-033.29"),
        // one repeated digit, impossible fields
        ("NL_BSN", "BSN: 111111111"),
        ("FR_NIR", "NIR: 185137800608425"),
        ("BE_NATIONAL_NUMBER", "Numéro national : 85133003370"),
        // part of a longer value
        ("FR_SIREN", "SIREN : 732 829 320 00074"),
        ("NL_BSN", "BSN: 123456782-4"),
        ("NL_BSN", "BSN: 1234.56.782.1"),
        ("BE_NATIONAL_NUMBER", "Rijksregisternummer: 1-85073003328"),
        // a nearer counter-context term
        ("FR_SIREN", "SIREN des Kunden, Bestellnummer 732829320"),
        ("NL_BSN", "BSN-brief, Bestellnummer 123456782"),
        (
            "BE_NATIONAL_NUMBER",
            "Rijksregister, invoice number 85073003328",
        ),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare values, scored modes only ───────────────────────────────────────────

#[test]
fn bare_values_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (
            NIR_CONTEXT_FREE,
            "2 95 10 99 126 111 93",
            "2 95 10 99 126 111 93",
        ),
        (
            NIR_CONTEXT_FREE,
            "Assurée 185057800608491, Lyon",
            "185057800608491",
        ),
        (
            NIR_CONTEXT_FREE,
            "Patient 2 93 11 2A 004 123 01 admitted.",
            "2 93 11 2A 004 123 01",
        ),
        (SIRET_CONTEXT_FREE, "732 829 320 00074", "732 829 320 00074"),
        (
            SIRET_CONTEXT_FREE,
            "Fournisseur 823 022 181 06863, Paris",
            "823 022 181 06863",
        ),
        (BSN_CONTEXT_FREE, "1234.56.782", "1234.56.782"),
        (
            BSN_CONTEXT_FREE,
            "Aanvrager 6459.69.175 is goedgekeurd.",
            "6459.69.175",
        ),
        (
            NATIONAL_NUMBER_CONTEXT_FREE,
            "85.07.30-033.28",
            "85.07.30-033.28",
        ),
        (
            NATIONAL_NUMBER_CONTEXT_FREE,
            "Client 17.11.28-631.59, Bruxelles",
            "17.11.28-631.59",
        ),
    ] {
        assert_reports(rule_id, text, value, &SCORED);
        let label = pattern(rule_id).entity_group;
        assert_silent(text, label, &[PiiMode::Strict]);
        assert_eq!(
            spans(text, PiiMode::Balanced, label),
            [(value.to_owned(), 0.55)],
            "{text}"
        );
    }
}

#[test]
fn bare_lookalikes_stay_silent_in_every_mode() {
    for (label, text) in [
        // the check digit alone is too weak for nine, eleven or fourteen bare digits
        ("FR_SIREN", "732829320"),
        ("FR_SIREN", "732 829 320"),
        ("FR_SIRET", "73282932000074"),
        ("NL_BSN", "123456782"),
        ("NL_BSN", "214 069 989"),
        ("BE_NATIONAL_NUMBER", "85073003328"),
        // a NIR of a provisional number or one still being registered needs a term
        ("FR_NIR", "385057800608488"),
        ("FR_NIR", "785057800608482"),
        // invalid check
        ("FR_NIR", "2 95 10 99 126 111 94"),
        ("FR_SIRET", "732 829 320 00075"),
        ("NL_BSN", "1234.56.783"),
        ("BE_NATIONAL_NUMBER", "85.07.30-033.29"),
        // part of a longer value or a phone number
        ("FR_NIR", "+2 95 10 99 126 111 93"),
        ("FR_NIR", "1 2 95 10 99 126 111 93"),
        ("FR_SIRET", "1 732 829 320 00074"),
        ("NL_BSN", "1234.56.782.1"),
        ("BE_NATIONAL_NUMBER", "85.07.30-033.28-1"),
        // a nearer counter-context term
        ("FR_NIR", "Order number 185057800608491"),
        ("FR_SIRET", "Invoice number 732 829 320 00074"),
        ("NL_BSN", "Order number 1234.56.782"),
        ("BE_NATIONAL_NUMBER", "Rechnungsnummer 85.07.30-033.28"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

#[test]
fn a_term_decides_between_a_national_number_and_a_steuer_id() {
    // `84061497424` is a valid Belgian national number and an issued Steuer-ID;
    // in the scored modes one label wins (K07): the term of a label.
    let value = "84061497424";
    assert!(validators::steuer_id_issued(value));
    for mode in SCORED {
        for (text, label, other) in [
            (
                format!("Rijksregisternummer {value}"),
                "BE_NATIONAL_NUMBER",
                "STEUERID",
            ),
            (
                format!("Steuer-ID {value}"),
                "STEUERID",
                "BE_NATIONAL_NUMBER",
            ),
            (value.to_owned(), "STEUERID", "BE_NATIONAL_NUMBER"),
        ] {
            assert_eq!(spans(&text, mode, label).len(), 1, "{mode}: {text}");
            assert!(spans(&text, mode, other).is_empty(), "{mode}: {text}");
        }
    }
}

#[test]
fn a_siret_in_its_print_groups_is_no_card_number() {
    // `566 618 468 58431` is a valid SIRET whose fourteen digits also pass Luhn with
    // a Maestro prefix; no card scheme prints 3-3-3-5 groups.
    let value = "566 618 468 58431";
    assert!(validators::payment_card(value));
    for text in [value.to_owned(), format!("SIRET : {value}")] {
        assert_silent(&text, "CREDITCARD", &MODES);
    }
    assert_reports(SIRET, &format!("SIRET : {value}"), value, &MODES);
    assert_reports(SIRET_CONTEXT_FREE, value, value, &SCORED);
    // Without groups the term decides in the scored modes (K07); bare, the digits
    // stay a card number.
    let compact = "56661846858431";
    for mode in SCORED {
        let text = format!("SIRET {compact}");
        assert_eq!(spans(&text, mode, "FR_SIRET").len(), 1, "{mode}: {text}");
        assert!(
            spans(&text, mode, "CREDITCARD").is_empty(),
            "{mode}: {text}"
        );
        assert!(spans(compact, mode, "FR_SIRET").is_empty(), "{mode}");
        assert_eq!(spans(compact, mode, "CREDITCARD").len(), 1, "{mode}");
    }
}
