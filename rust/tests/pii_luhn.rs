// SPDX-License-Identifier: GPL-3.0-only
//! Swedish, Canadian, Turkish and South African identifiers (B-LUHN: T13, T09).
//!
//! Four numbering systems with a check digit, one label each: the Swedish
//! organisationsnummer (`SE_ORGANISATIONSNUMMER`, third digit 2 or more, Luhn),
//! the Canadian Social Insurance Number (`CA_SIN`, Luhn, first digit not 0 or 8),
//! the Turkish T.C. Kimlik No (`TR_NATIONAL_ID`, two check digits) and the South
//! African identity number (`ZA_ID_NUMBER`, birth date, citizenship, Luhn). Each
//! label has a rule that reports the value in every mode when a term of the label
//! stands near it or is its key. In `balanced` and `recall` the printed forms are
//! also reported bare (K05): the organisationsnummer `NNNNNN-NNNN`, the SIN in
//! hyphenated 3-3-3 groups and the South African ID number. Ten bare digits
//! (organisationsnummer), nine (SIN, also in 3-3-3 groups by spaces, the print
//! form of a SIREN or a BSN) and the eleven of a T.C. Kimlik No need the term in
//! every mode; the T.C. Kimlik No has no context-free form.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const ORGANISATIONSNUMMER: &str = "pii_organisationsnummer_se";
const ORGANISATIONSNUMMER_CONTEXT_FREE: &str = "pii_organisationsnummer_se_context_free";
const SIN: &str = "pii_sin_ca";
const SIN_CONTEXT_FREE: &str = "pii_sin_ca_context_free";
const NATIONAL_ID: &str = "pii_national_id_tr";
const ID_NUMBER: &str = "pii_id_number_za";
const ID_NUMBER_CONTEXT_FREE: &str = "pii_id_number_za_context_free";
const CONTEXT_BOUND: [&str; 4] = [ORGANISATIONSNUMMER, SIN, NATIONAL_ID, ID_NUMBER];
const CONTEXT_FREE: [&str; 3] = [
    ORGANISATIONSNUMMER_CONTEXT_FREE,
    SIN_CONTEXT_FREE,
    ID_NUMBER_CONTEXT_FREE,
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
fn organisationsnummer_validator_checks_the_third_digit_and_luhn() {
    for valid in [
        // presidio-analyzer test values
        "556703-7485",
        "5567037485",
        "2120000142",
        "212000-0142",
        "556016-0680",
        "823948-2196",
        "5785797548",
    ] {
        assert!(validators::se_organisationsnummer(valid), "{valid}");
    }
    for invalid in [
        // Luhn off by one
        "556703-7486",
        "5785797549",
        // third digit below 2: the birth month of a personnummer (Luhn valid)
        "551303-7480",
        "811228-9874",
        // one repeated digit, a dash elsewhere, a `+`, length and alphabet
        "0000000000",
        "55670-37485",
        "556703+7485",
        "556703-748",
        "55670374851",
        "19000309-3393",
        "556703-748A",
    ] {
        assert!(!validators::se_organisationsnummer(invalid), "{invalid}");
    }
}

#[test]
fn sin_validator_checks_the_first_digit_and_luhn() {
    for valid in [
        // presidio-analyzer test values
        "130 692 544",
        "130692544",
        "130-692-544",
        "435 418 165",
        "731-530-150",
        // a temporary resident
        "946 454 287",
    ] {
        assert!(validators::ca_sin(valid), "{valid}");
    }
    for invalid in [
        "130 692 545",
        "435-418-166",
        // Luhn valid, but 0 and 8 are not issued to persons
        "046 454 286",
        "813 069 259",
        "000000000",
        // repeated digits, length and alphabet
        "111 111 111",
        "999 999 999",
        "13069254",
        "1306925440",
        "130 692 54A",
    ] {
        assert!(!validators::ca_sin(invalid), "{invalid}");
    }
}

#[test]
fn national_id_validator_checks_both_check_digits() {
    for valid in [
        // presidio-analyzer test values
        "10000000146",
        "79059236630",
        "36493665440",
        "96828890954",
        "22845298404",
    ] {
        assert!(validators::tr_national_id(valid), "{valid}");
    }
    for invalid in [
        // tenth or eleventh digit off
        "10000000147",
        "10000000136",
        // presidio-analyzer invalid values
        "00000000000",
        "02531814694",
        "12345678900",
        "76543210780",
        "11798724308",
        "62286775983",
        "97485249605",
        // both checks valid, but one repeated digit is never issued
        "11111111110",
        // length and alphabet
        "1000000014",
        "100000001460",
        "1000000014A",
        "100 000 001 46",
    ] {
        assert!(!validators::tr_national_id(invalid), "{invalid}");
    }
}

#[test]
fn id_number_validator_checks_the_date_citizenship_and_luhn() {
    for valid in [
        // presidio-analyzer test values
        "8001015009087",
        "8001015000086",
        "9202201234088",
        "800101 5009 087",
        // born in 2007; 29 February 2000
        "0704184047089",
        "0002295009084",
        // permanent resident
        "8011273970185",
    ] {
        assert!(validators::za_id_number(valid), "{valid}");
    }
    for invalid in [
        "8001015000076",
        "8001015009088",
        // Luhn valid, but citizenship 3, twelfth digit 7, month 13, 29 February 1901/2001
        "8001015009384",
        "7204226952175",
        "8013015009082",
        "0102295009082",
        // length and alphabet
        "80010150090870",
        "800101500908",
        "800101500908A",
    ] {
        assert!(!validators::za_id_number(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_luhn_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check) in [
        (
            &[ORGANISATIONSNUMMER, ORGANISATIONSNUMMER_CONTEXT_FREE][..],
            "SE_ORGANISATIONSNUMMER",
            validators::se_organisationsnummer as fn(&str) -> bool,
        ),
        (&[SIN, SIN_CONTEXT_FREE][..], "CA_SIN", validators::ca_sin),
        (
            &[NATIONAL_ID][..],
            "TR_NATIONAL_ID",
            validators::tr_national_id,
        ),
        (
            &[ID_NUMBER, ID_NUMBER_CONTEXT_FREE][..],
            "ZA_ID_NUMBER",
            validators::za_id_number,
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
            ORGANISATIONSNUMMER,
            "Organisationsnummer: 556703-7485",
            "556703-7485",
        ),
        (
            ORGANISATIONSNUMMER,
            "The Swedish company number on file is 5560160680.",
            "5560160680",
        ),
        (
            ORGANISATIONSNUMMER,
            "Bolagets org.nr är 2120000142.",
            "2120000142",
        ),
        (
            ORGANISATIONSNUMMER,
            "{\"org_number\": \"823948-2196\"}",
            "823948-2196",
        ),
        (
            ORGANISATIONSNUMMER,
            "Die schwedische Organisationsnummer lautet 5785797548.",
            "5785797548",
        ),
        (SIN, "SIN: 130 692 544", "130 692 544"),
        (SIN, "my SIN is 130-692-544", "130-692-544"),
        (SIN, "My social insurance number is 435418165.", "435418165"),
        (
            SIN,
            "Numéro d'assurance sociale : 731 530 150",
            "731 530 150",
        ),
        (SIN, "Numéro d’assurance sociale : 731530150", "731530150"),
        (SIN, "{\"sin\": \"946-454-287\"}", "946-454-287"),
        (SIN, "Die kanadische SIN lautet 143 483 956.", "143 483 956"),
        (NATIONAL_ID, "T.C. Kimlik No: 10000000146", "10000000146"),
        (
            NATIONAL_ID,
            "Başvuru sahibinin TCKN numarası 10000000146 olarak tescil edilmiştir.",
            "10000000146",
        ),
        (
            NATIONAL_ID,
            "Türk kimlik numarası 36493665440",
            "36493665440",
        ),
        (
            NATIONAL_ID,
            "My Turkish ID number is 79059236630.",
            "79059236630",
        ),
        (
            NATIONAL_ID,
            "{\"tc_kimlik\": \"96828890954\"}",
            "96828890954",
        ),
        (
            NATIONAL_ID,
            "Als türkische Identitätsnummer ist 22845298404 hinterlegt.",
            "22845298404",
        ),
        (
            ID_NUMBER,
            "South African ID number: 8001015009087",
            "8001015009087",
        ),
        (
            ID_NUMBER,
            "My South African ID is 9202201234088.",
            "9202201234088",
        ),
        (ID_NUMBER, "RSA ID: 800101 5009 087", "800101 5009 087"),
        (ID_NUMBER, "{\"za_id\": \"0704184047089\"}", "0704184047089"),
        (
            ID_NUMBER,
            "Südafrikanische ID-Nummer: 8011273970185",
            "8011273970185",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (
            ORGANISATIONSNUMMER,
            "orgnr,anstallda\n5567037485,120",
            "5567037485",
        ),
        (SIN, "sin,age\n130692544,42", "130692544"),
        (NATIONAL_ID, "tckn,yas\n10000000146,42", "10000000146"),
        (ID_NUMBER, "za_id,age\n8001015009087,46", "8001015009087"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
    // A cell that holds more than the value is still part of a longer number.
    assert_silent("tckn,yas\n10000000146-4,42", "TR_NATIONAL_ID", &MODES);
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // no term: the bare forms that are never context-free
        ("SE_ORGANISATIONSNUMMER", "Reference 5567037485"),
        ("CA_SIN", "Order 130692544 shipped."),
        ("TR_NATIONAL_ID", "Reference 10000000146"),
        ("TR_NATIONAL_ID", "79059236630"),
        // check fails
        ("SE_ORGANISATIONSNUMMER", "Organisationsnummer: 556703-7486"),
        ("SE_ORGANISATIONSNUMMER", "Organisationsnummer: 551303-7480"),
        ("CA_SIN", "SIN: 130 692 545"),
        ("CA_SIN", "SIN: 046 454 286"),
        ("TR_NATIONAL_ID", "T.C. Kimlik No: 10000000147"),
        ("TR_NATIONAL_ID", "T.C. Kimlik No: 11111111110"),
        ("ZA_ID_NUMBER", "South African ID number: 8001015000076"),
        ("ZA_ID_NUMBER", "South African ID number: 8001015009384"),
        // part of a longer value
        (
            "SE_ORGANISATIONSNUMMER",
            "Organisationsnummer: 556703-7485-1",
        ),
        ("CA_SIN", "SIN: 130 692 544 1"),
        ("TR_NATIONAL_ID", "TCKN: 10000000146-1"),
        ("ZA_ID_NUMBER", "SA ID 80010150090870"),
        ("ZA_ID_NUMBER", "South African ID: AB8001015009087CD"),
        // a nearer counter-context term
        (
            "SE_ORGANISATIONSNUMMER",
            "Organisationsnummer, Bestellnummer 5567037485",
        ),
        ("CA_SIN", "SIN letter, invoice number 130692544"),
        ("TR_NATIONAL_ID", "TCKN letter, invoice number 96828890954"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare values, scored modes only ───────────────────────────────────────────

#[test]
fn bare_values_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (
            ORGANISATIONSNUMMER_CONTEXT_FREE,
            "556703-7485",
            "556703-7485",
        ),
        (
            ORGANISATIONSNUMMER_CONTEXT_FREE,
            "Supplier 285016-6139 from Gothenburg",
            "285016-6139",
        ),
        (SIN_CONTEXT_FREE, "130-692-544", "130-692-544"),
        (SIN_CONTEXT_FREE, "731-530-150", "731-530-150"),
        (
            SIN_CONTEXT_FREE,
            "Employee 220-297-295 starts on Monday.",
            "220-297-295",
        ),
        (ID_NUMBER_CONTEXT_FREE, "8001015009087", "8001015009087"),
        (
            ID_NUMBER_CONTEXT_FREE,
            "Applicant 800101 5009 087 has been approved.",
            "800101 5009 087",
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
        // the check digit alone is too weak for ten, nine or eleven bare digits
        ("SE_ORGANISATIONSNUMMER", "5567037485"),
        ("CA_SIN", "130692544"),
        ("TR_NATIONAL_ID", "10000000146"),
        // nine digits in 3-3-3 groups by spaces are also a SIREN, a BSN or the
        // body of a VAT ID after its country code
        ("CA_SIN", "130 692 544"),
        ("CA_SIN", "Employee 220 297 295 starts on Monday."),
        ("CA_SIN", "Supplier DE 220 297 295, Hamburg"),
        // invalid check or fields
        ("SE_ORGANISATIONSNUMMER", "556703-7486"),
        ("CA_SIN", "130 692 545"),
        ("CA_SIN", "813 069 259"),
        ("ZA_ID_NUMBER", "8001015000076"),
        ("ZA_ID_NUMBER", "8013015009082"),
        // part of a longer value or a phone number
        ("SE_ORGANISATIONSNUMMER", "Part 285016-6139-2 is in stock."),
        ("CA_SIN", "Dial 1 220-297-295 now."),
        ("CA_SIN", "+1 130-692-544"),
        ("CA_SIN", "Teil 279-180-582-1 ist lieferbar."),
        ("ZA_ID_NUMBER", "Teil 6908084342185-2 ist lieferbar."),
        // a nearer counter-context term
        ("SE_ORGANISATIONSNUMMER", "Invoice number 285016-6139"),
        ("CA_SIN", "Bestellnummer 279-180-582"),
        ("ZA_ID_NUMBER", "Order number 8011273970185"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

#[test]
fn a_term_decides_between_a_national_id_and_a_steuer_id() {
    // `49825979160` is a valid T.C. Kimlik No and an issued Steuer-ID; in the
    // scored modes one label wins (K07): the term of a label. Bare, only the
    // Steuer-ID has a context-free rule.
    let value = "49825979160";
    assert!(validators::steuer_id_issued(value));
    assert!(validators::tr_national_id(value));
    for mode in SCORED {
        for (text, label, other) in [
            (format!("TCKN {value}"), "TR_NATIONAL_ID", "STEUERID"),
            (format!("Steuer-ID {value}"), "STEUERID", "TR_NATIONAL_ID"),
            (value.to_owned(), "STEUERID", "TR_NATIONAL_ID"),
        ] {
            assert_eq!(spans(&text, mode, label).len(), 1, "{mode}: {text}");
            assert!(spans(&text, mode, other).is_empty(), "{mode}: {text}");
        }
    }
}
