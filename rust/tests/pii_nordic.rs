// SPDX-License-Identifier: GPL-3.0-only
//! Nordic personal identity numbers (B-NORD: B12, B13).
//!
//! Four numbering systems that start with the birth date and end in a check digit
//! or character, one label each: the Swedish personnummer (`SE_PERSONNUMMER`,
//! Luhn), the Danish CPR number (`DK_CPR`, weighted mod 11), the Norwegian
//! fødselsnummer (`NO_FODSELSNUMMER`, two digits mod 11) and the Finnish personal
//! identity code (`FI_PERSONAL_IDENTITY_CODE`, check character mod 31). Each label
//! has a rule that reports the value in every mode when a term of the label stands
//! near it or is its key. In `balanced` and `recall` the printed forms are also
//! reported bare (K05): `YYMMDD-NNNC`, `DDMMYY-SSSS`, `DDMMYY NNNKK` and the
//! henkilötunnus with its century sign. Bare digit runs need the term in every
//! mode. CPR numbers without the mod-11 check (issued since 2007) are not
//! accepted: without it the value has no check digit.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const PERSONNUMMER: &str = "pii_personnummer_se";
const PERSONNUMMER_CONTEXT_FREE: &str = "pii_personnummer_se_context_free";
const CPR: &str = "pii_cpr_dk";
const CPR_CONTEXT_FREE: &str = "pii_cpr_dk_context_free";
const FODSELSNUMMER: &str = "pii_fodselsnummer_no";
const FODSELSNUMMER_CONTEXT_FREE: &str = "pii_fodselsnummer_no_context_free";
const HETU: &str = "pii_hetu_fi";
const HETU_CONTEXT_FREE: &str = "pii_hetu_fi_context_free";
const CONTEXT_BOUND: [&str; 4] = [PERSONNUMMER, CPR, FODSELSNUMMER, HETU];
const CONTEXT_FREE: [&str; 4] = [
    PERSONNUMMER_CONTEXT_FREE,
    CPR_CONTEXT_FREE,
    FODSELSNUMMER_CONTEXT_FREE,
    HETU_CONTEXT_FREE,
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
fn personnummer_validator_checks_the_date_and_luhn() {
    for valid in [
        "811228-9874",
        "871220-2384",
        "8712202384",
        "471028+8210",
        // twelve digits with the century (presidio-analyzer test value)
        "200109022392",
        "19811228-9874",
        "200105140719",
        // coordination number: day plus 60
        "600484-6496",
        "861075-4296",
    ] {
        assert!(validators::se_personnummer(valid), "{valid}");
    }
    for invalid in [
        // Luhn fails
        "811228-9875",
        "871220-2385",
        "19000309-3393",
        // no such date: month 13, day 42, day 92
        "19001309-2393",
        "200504422381",
        "811292-9874",
        // century outside 1900-2099
        "18811228-9874",
        // separator elsewhere, length and alphabet
        "8112-289874",
        "811228--9874",
        "81122898740",
        "189x09179809",
    ] {
        assert!(!validators::se_personnummer(invalid), "{invalid}");
    }
}

#[test]
fn cpr_validator_checks_the_date_century_and_mod_11_sum() {
    for valid in [
        "030158-0215",
        "280751-3187",
        "1003800039",
        "080572-3300",
        // seventh digit 4: the 2000s up to year 36
        "241014-4908",
        "060305-4563",
    ] {
        assert!(validators::dk_cpr(valid), "{valid}");
    }
    for invalid in [
        // the mod-11 sum fails (also numbers issued without it since 2007)
        "030158-0216",
        "280751-3188",
        // no such date
        "300258-0215",
        "031358-0215",
        // seventh digit 5 to 8 with a year after 57: the 1800s
        "270558-6910",
        // length and alphabet
        "030158-021",
        "030158-02150",
        "030158-021X",
    ] {
        assert!(!validators::dk_cpr(invalid), "{invalid}");
    }
}

#[test]
fn fodselsnummer_validator_checks_the_date_and_both_check_digits() {
    for valid in [
        "11089733660",
        "17128629947",
        "021048 47288",
        "12084135826",
        // D-number: day plus 40
        "53077117233",
        "62066318325",
        // individual number 500-999 in the 2000s
        "16050665368",
        "01041495215",
    ] {
        assert!(validators::no_fodselsnummer(valid), "{valid}");
    }
    for invalid in [
        // the first or the second check digit fails
        "11089733650",
        "11089733661",
        // no such date
        "32089733660",
        "11139733660",
        // individual number 500-749 with a year from 54: the 1800s
        "28018474680",
        // length and alphabet
        "1108973366",
        "110897336600",
        "1108973366X",
    ] {
        assert!(!validators::no_fodselsnummer(invalid), "{invalid}");
    }
}

#[test]
fn hetu_validator_checks_the_date_sign_and_mod_31_character() {
    for valid in [
        "131052-308T",
        // presidio-analyzer test values, every century sign
        "010594Y9032",
        "020594X903P",
        "030594W903B",
        "040594V9030",
        "050594U902L",
        "010516B903X",
        "020516C902J",
        "010501E9032",
        "020503F9037",
        "020504a902e",
        "200383V0179",
        "020108B196F",
    ] {
        assert!(validators::fi_hetu(valid), "{valid}");
    }
    for invalid in [
        // wrong check character
        "131052-308U",
        "010594Y9033",
        // individual numbers 000 and 001 are never issued
        "131052-000V",
        "131052-001W",
        // no such date, the 1800s sign, an unknown sign
        "111111-111A",
        "311152-308T",
        "131052+308T",
        "131052G308T",
        // length and alphabet
        "131052-308",
        "131052-308TT",
        "13105X-308T",
    ] {
        assert!(!validators::fi_hetu(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_nordic_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check) in [
        (
            [PERSONNUMMER, PERSONNUMMER_CONTEXT_FREE],
            "SE_PERSONNUMMER",
            validators::se_personnummer as fn(&str) -> bool,
        ),
        ([CPR, CPR_CONTEXT_FREE], "DK_CPR", validators::dk_cpr),
        (
            [FODSELSNUMMER, FODSELSNUMMER_CONTEXT_FREE],
            "NO_FODSELSNUMMER",
            validators::no_fodselsnummer,
        ),
        (
            [HETU, HETU_CONTEXT_FREE],
            "FI_PERSONAL_IDENTITY_CODE",
            validators::fi_hetu,
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
        (PERSONNUMMER, "Personnummer: 811228-9874", "811228-9874"),
        (
            PERSONNUMMER,
            "Here's my personnummer 200109022392.",
            "200109022392",
        ),
        (
            PERSONNUMMER,
            "Swedish personal identity number 8712202384",
            "8712202384",
        ),
        (
            PERSONNUMMER,
            "{\"personnummer\": \"19811228-9874\"}",
            "19811228-9874",
        ),
        (
            PERSONNUMMER,
            "Die schwedische Personennummer lautet 600484-6496.",
            "600484-6496",
        ),
        (CPR, "CPR-nummer: 030158-0215", "030158-0215"),
        (CPR, "CPR 2807513187", "2807513187"),
        (CPR, "Her Danish CPR number is 080572-3300.", "080572-3300"),
        (CPR, "{\"cpr\": \"241014-4908\"}", "241014-4908"),
        (
            CPR,
            "Die dänische Personennummer ist 1003800039.",
            "1003800039",
        ),
        (FODSELSNUMMER, "Fødselsnummer: 11089733660", "11089733660"),
        (FODSELSNUMMER, "fødselsnummer 171286 29947", "171286 29947"),
        (
            FODSELSNUMMER,
            "My Norwegian national identity number is 02104847288.",
            "02104847288",
        ),
        (
            FODSELSNUMMER,
            "{\"fodselsnummer\": \"53077117233\"}",
            "53077117233",
        ),
        (
            FODSELSNUMMER,
            "Die norwegische Personennummer lautet 16050665368.",
            "16050665368",
        ),
        (HETU, "HETU: 131052-308T", "131052-308T"),
        (HETU, "Here's my henkilötunnus 020594X902N.", "020594X902N"),
        (HETU, "hetu 020504a902e", "020504a902e"),
        (HETU, "{\"hetu\": \"200383V0179\"}", "200383V0179"),
        (
            HETU,
            "Finnische Personenkennung: 020108B196F",
            "020108B196F",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    // A CSV comma before a digit is a field boundary, not a thousands separator:
    // the cell the key names is the whole value.
    for (rule_id, text, value) in [
        (
            PERSONNUMMER,
            "personnummer,age\n8112289874,42",
            "8112289874",
        ),
        (CPR, "age,cpr\n42,030158-0215", "030158-0215"),
        (
            FODSELSNUMMER,
            "fodselsnummer,age\n11089733660,42",
            "11089733660",
        ),
        (
            HETU,
            "row,vat_id,hetu,amount\n1,DE 112 014 120,091173-566S,5",
            "091173-566S",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // no term: the bare forms that are never context-free
        ("SE_PERSONNUMMER", "Reference 8112289874"),
        ("SE_PERSONNUMMER", "Build 19811228-9874 is out."),
        ("DK_CPR", "Order 0301580215 shipped."),
        ("NO_FODSELSNUMMER", "Reference 11089733660"),
        // check fails
        ("SE_PERSONNUMMER", "Personnummer: 811228-9875"),
        ("DK_CPR", "CPR: 030158-0216"),
        ("NO_FODSELSNUMMER", "Fødselsnummer: 11089733661"),
        ("FI_PERSONAL_IDENTITY_CODE", "HETU: 131052-308U"),
        // no such date
        ("SE_PERSONNUMMER", "Personnummer: 19001309-2393"),
        ("DK_CPR", "CPR: 300258-0215"),
        ("FI_PERSONAL_IDENTITY_CODE", "HETU: 111111-111A"),
        // part of a longer value
        ("SE_PERSONNUMMER", "Personnummer: 811228-9874-2"),
        ("DK_CPR", "CPR: 1/030158-0215"),
        ("NO_FODSELSNUMMER", "Fødselsnummer: 11089733660 7"),
        ("FI_PERSONAL_IDENTITY_CODE", "HETU: X131052-308T"),
        // a nearer counter-context term
        (
            "SE_PERSONNUMMER",
            "Personnummer-Liste, Bestellnummer 8112289874",
        ),
        ("DK_CPR", "CPR register, order number 0301580215"),
        (
            "NO_FODSELSNUMMER",
            "Fødselsnummer form, invoice number 11089733660",
        ),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare values, scored modes only ───────────────────────────────────────────

#[test]
fn bare_values_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (PERSONNUMMER_CONTEXT_FREE, "871220-2384", "871220-2384"),
        (
            PERSONNUMMER_CONTEXT_FREE,
            "Kunde 540326-5241 aus Malmö",
            "540326-5241",
        ),
        (PERSONNUMMER_CONTEXT_FREE, "471028+8210", "471028+8210"),
        (CPR_CONTEXT_FREE, "080572-3300", "080572-3300"),
        (
            CPR_CONTEXT_FREE,
            "Patient 240373-1490 from Aarhus",
            "240373-1490",
        ),
        (FODSELSNUMMER_CONTEXT_FREE, "110897 33660", "110897 33660"),
        (
            FODSELSNUMMER_CONTEXT_FREE,
            "Mitglied 120841 35826 aus Bergen",
            "120841 35826",
        ),
        (HETU_CONTEXT_FREE, "010594Y9032", "010594Y9032"),
        (HETU_CONTEXT_FREE, "131052-308T", "131052-308T"),
        (HETU_CONTEXT_FREE, "020504a902e", "020504a902e"),
        (
            HETU_CONTEXT_FREE,
            "Applicant 020108B196F has been approved.",
            "020108B196F",
        ),
        // a CSV row with a value that starts with a letter before it
        (
            HETU_CONTEXT_FREE,
            "1;Lukas Schäfer;IT90267750934;190487-737P;2.586,62 €",
            "190487-737P",
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
        // bare digit runs and date-stamped builds need the term
        ("SE_PERSONNUMMER", "8112289874"),
        ("SE_PERSONNUMMER", "200109022392"),
        ("SE_PERSONNUMMER", "19811228-9874"),
        ("DK_CPR", "0301580215"),
        ("NO_FODSELSNUMMER", "11089733660"),
        // invalid check
        ("SE_PERSONNUMMER", "871220-2385"),
        ("DK_CPR", "080572-3301"),
        ("NO_FODSELSNUMMER", "110897 33661"),
        ("FI_PERSONAL_IDENTITY_CODE", "010594Y9033"),
        // part of a longer value or a phone number
        ("SE_PERSONNUMMER", "+46 871220-2384"),
        ("DK_CPR", "080572-3300-1"),
        ("NO_FODSELSNUMMER", "+47 110897 33660"),
        ("FI_PERSONAL_IDENTITY_CODE", "010594Y9032-2"),
        // a nearer counter-context term
        ("SE_PERSONNUMMER", "Rechnungsnummer 871220-2384"),
        ("FI_PERSONAL_IDENTITY_CODE", "Order number 131052-308T"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

#[test]
fn a_term_decides_between_a_personnummer_and_a_cpr_number_of_the_same_form() {
    // `281019-3975` is a valid personnummer (19 October 2028 or 1928) and a valid
    // CPR number (28 October 2019); in the scored modes one label wins (K07): the
    // term of a label, else the earlier rule, the personnummer.
    let value = "281019-3975";
    for mode in SCORED {
        for (text, label, other) in [
            (format!("CPR {value}"), "DK_CPR", "SE_PERSONNUMMER"),
            (
                format!("schwedische Personennummer {value}"),
                "SE_PERSONNUMMER",
                "DK_CPR",
            ),
            (value.to_owned(), "SE_PERSONNUMMER", "DK_CPR"),
        ] {
            assert_eq!(spans(&text, mode, label).len(), 1, "{mode}: {text}");
            assert!(spans(&text, mode, other).is_empty(), "{mode}: {text}");
        }
    }
}
