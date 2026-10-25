// SPDX-License-Identifier: GPL-3.0-only
//! Australian and Singaporean identifiers (B-APAC: A08, A10).
//!
//! Six numbering systems with a check digit or check letter, one label each:
//! the Australian Business Number (`AU_ABN`, two leading check digits mod 89), the
//! Australian Company Number (`AU_ACN`, weighted mod 10), the Tax File Number
//! (`AU_TFN`, weighted mod 11), the Medicare card number (`AU_MEDICARE`, weights
//! 1-3-7-9 mod 10), the Singapore NRIC/FIN (`SG_NRIC_FIN`, check letter mod 11 per
//! series) and the Unique Entity Number (`SG_UEN`, check letter mod 11 per format).
//! Each label has a rule that reports the value in every mode when a term of the
//! label stands near it or is its key. In `balanced` and `recall` the forms whose
//! shape adds to the check digit are also reported bare (K05): the ABN in 2-3-3-3
//! groups, the Medicare number in 4-5-1 groups, an uppercase NRIC/FIN and a UEN of
//! format B or C. Nine bare digits with a mod-10 or mod-11 check (ACN, TFN), ten
//! bare digits (Medicare), eleven bare digits (ABN) and eight digits plus a letter
//! (UEN format A, also a Spanish DNI) need the term in every mode, as the NHS
//! number does (B-UK).

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const ABN: &str = "pii_abn_au";
const ABN_CONTEXT_FREE: &str = "pii_abn_au_context_free";
const ACN: &str = "pii_acn_au";
const TFN: &str = "pii_tfn_au";
const MEDICARE: &str = "pii_medicare_au";
const MEDICARE_CONTEXT_FREE: &str = "pii_medicare_au_context_free";
const NRIC_FIN: &str = "pii_nric_fin_sg";
const NRIC_FIN_CONTEXT_FREE: &str = "pii_nric_fin_sg_context_free";
const UEN: &str = "pii_uen_sg";
const UEN_CONTEXT_FREE: &str = "pii_uen_sg_context_free";
const CONTEXT_BOUND: [&str; 6] = [ABN, ACN, TFN, MEDICARE, NRIC_FIN, UEN];
const CONTEXT_FREE: [&str; 4] = [
    ABN_CONTEXT_FREE,
    MEDICARE_CONTEXT_FREE,
    NRIC_FIN_CONTEXT_FREE,
    UEN_CONTEXT_FREE,
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
fn abn_validator_checks_the_mod_89_digits() {
    for valid in [
        "51824753556",
        "51 824 753 556",
        "53 004 085 616",
        "28141006888",
        "98340661317",
        "73904830039",
        "60 312 933 011",
    ] {
        assert!(validators::au_abn(valid), "{valid}");
    }
    for invalid in [
        // one digit off
        "51824753557",
        "52824753556",
        "28141006889",
        // a leading zero is never issued
        "00000000560",
        "01824753556",
        // length and alphabet
        "5182475355",
        "518247535560",
        "52824753556AF",
        "51-824-753-55X",
    ] {
        assert!(!validators::au_abn(invalid), "{invalid}");
    }
}

#[test]
fn acn_validator_checks_the_weighted_mod_10_digit() {
    for valid in [
        "000 000 019",
        "006249976",
        "000000180",
        "005 499 981",
        "010 499 966",
        "135506071",
        "445 637 310",
    ] {
        assert!(validators::au_acn(valid), "{valid}");
    }
    for invalid in [
        "824753557",
        "135506072",
        "445 637 311",
        // one repeated digit passes the sum but is no number
        "000 000 000",
        // length and alphabet
        "13550607",
        "1355060710",
        "135 506 07A",
    ] {
        assert!(!validators::au_acn(invalid), "{invalid}");
    }
}

#[test]
fn tfn_validator_checks_the_weighted_mod_11_sum() {
    for valid in [
        "876 543 210",
        "123 456 782",
        "865414088",
        "842781633",
        "811 092 846",
        "557553644",
    ] {
        assert!(validators::au_tfn(valid), "{valid}");
    }
    for invalid in [
        "824753557",
        "876 543 211",
        "842781634",
        // one repeated digit
        "000000000",
        "111 111 111",
        // length and alphabet
        "87654321",
        "8765432100",
        "876 543 21X",
    ] {
        assert!(!validators::au_tfn(invalid), "{invalid}");
    }
}

#[test]
fn medicare_validator_checks_the_first_digit_and_the_check_digit() {
    for valid in [
        "2123 45670 1",
        "2123456701",
        "6431309681",
        "4762228909",
        "5309 78617 6",
        "2391743941",
    ] {
        assert!(validators::au_medicare(valid), "{valid}");
    }
    for invalid in [
        "2123258701",
        "2123 45671 1",
        "6431309691",
        // first digit outside 2-6
        "1123456701",
        "7123456701",
        // length and alphabet
        "212345670",
        "21234567011",
        "2123 45670 X",
    ] {
        assert!(!validators::au_medicare(invalid), "{invalid}");
    }
}

#[test]
fn nric_fin_validator_checks_the_letter_of_each_series() {
    for valid in [
        // S and T (citizens, permanent residents)
        "S0642712Z",
        "S4086377Z",
        "T1092579C",
        "T0414321Z",
        // F and G (foreigners)
        "F2346401L",
        "G0228472W",
        "F3580434W",
        // M (foreigners since 2022)
        "M1235467X",
        "M2570575T",
        "M6623248K",
        // case-insensitive after a term
        "s0642712z",
    ] {
        assert!(validators::sg_nric_fin(valid), "{valid}");
    }
    for invalid in [
        // wrong check letter
        "G1122144L",
        "S0642712A",
        "F2346401K",
        "M1235467K",
        // the S/T letter on an F/G number and back
        "F0642712Z",
        "S2346401L",
        // no series
        "B1234567Z",
        "A0642712Z",
        // length and alphabet
        "PA12348L",
        "S064271Z",
        "S06427120Z",
        "S06427I2Z",
    ] {
        assert!(!validators::sg_nric_fin(invalid), "{invalid}");
    }
}

#[test]
fn uen_validator_checks_the_letter_of_each_format() {
    for valid in [
        // A: businesses, eight digits
        "53125226D",
        "21332689B",
        "43817327M",
        // B: local companies, registration year and five digits
        "201434292D",
        "201927806H",
        "198523490N",
        // C: other entities, T/S/R, year, entity type, four digits
        "S57TU0392K",
        "T61CH8475D",
        "R42XL4110C",
    ] {
        assert!(validators::sg_uen(valid), "{valid}");
    }
    for invalid in [
        // wrong check letter
        "53125226E",
        "201434292E",
        "S57TU0392L",
        // format B before 1800
        "123456789A",
        // format C: unknown prefix or entity type
        "A57TU0392K",
        "S57ZZ0392K",
        // lowercase, length
        "53125226d",
        "53125226",
        "2014342921D",
    ] {
        assert!(!validators::sg_uen(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_apac_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check) in [
        (
            &[ABN, ABN_CONTEXT_FREE][..],
            "AU_ABN",
            validators::au_abn as fn(&str) -> bool,
        ),
        (&[ACN][..], "AU_ACN", validators::au_acn),
        (&[TFN][..], "AU_TFN", validators::au_tfn),
        (
            &[MEDICARE, MEDICARE_CONTEXT_FREE][..],
            "AU_MEDICARE",
            validators::au_medicare,
        ),
        (
            &[NRIC_FIN, NRIC_FIN_CONTEXT_FREE][..],
            "SG_NRIC_FIN",
            validators::sg_nric_fin,
        ),
        (&[UEN, UEN_CONTEXT_FREE][..], "SG_UEN", validators::sg_uen),
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
        (ABN, "ABN: 51 824 753 556", "51 824 753 556"),
        (ABN, "ABN 51824753556", "51824753556"),
        (
            ABN,
            "Our Australian Business Number is 53 004 085 616.",
            "53 004 085 616",
        ),
        (ABN, "{\"abn\": \"28141006888\"}", "28141006888"),
        (ABN, "Die ABN lautet 98 340 661 317.", "98 340 661 317"),
        (ACN, "ACN: 006 249 976", "006 249 976"),
        (ACN, "Australian Company Number 135506071", "135506071"),
        (ACN, "Als ACN ist 445 637 310 hinterlegt.", "445 637 310"),
        (ACN, "name,acn\nAcme Pty Ltd,000 000 019", "000 000 019"),
        (TFN, "TFN: 876 543 210", "876 543 210"),
        (TFN, "Tax File Number: 842781633", "842781633"),
        (TFN, "Her tax file number is 811 092 846.", "811 092 846"),
        (TFN, "{\"tfn\": \"557 553 644\"}", "557 553 644"),
        (TFN, "Die TFN lautet 865 414 088.", "865 414 088"),
        (MEDICARE, "Medicare number: 2123 45670 1", "2123 45670 1"),
        (MEDICARE, "Medicare card 6431309681", "6431309681"),
        (
            MEDICARE,
            "australische Medicare-Nummer:\t4762228909",
            "4762228909",
        ),
        (
            MEDICARE,
            "{\"medicare_number\": \"5309786176\"}",
            "5309786176",
        ),
        (NRIC_FIN, "NRIC: S0642712Z", "S0642712Z"),
        (NRIC_FIN, "The FIN on file is G0228472W.", "G0228472W"),
        (NRIC_FIN, "NRIC s0642712z", "s0642712z"),
        (NRIC_FIN, "{\"nric\": \"M1235467X\"}", "M1235467X"),
        (UEN, "UEN: 53125226D", "53125226D"),
        (
            UEN,
            "The Unique Entity Number on file is 21332689B.",
            "21332689B",
        ),
        (UEN, "UEN 201434292D", "201434292D"),
        (UEN, "{\"uen\": \"S57TU0392K\"}", "S57TU0392K"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // no term: the bare forms that are never context-free
        ("AU_ABN", "Reference 51824753556"),
        ("AU_ACN", "Order 006249976 shipped."),
        ("AU_ACN", "Vorgang 135 506 071 wurde abgeschlossen."),
        ("AU_TFN", "Call 876 543 210 today."),
        ("AU_TFN", "Reference 842781633"),
        ("AU_MEDICARE", "Reference 6431309681"),
        ("SG_UEN", "Reference 53125226D"),
        // check digit fails
        ("AU_ABN", "ABN: 51 824 753 557"),
        ("AU_ACN", "ACN: 824 753 557"),
        ("AU_TFN", "TFN: 876 543 211"),
        ("AU_MEDICARE", "Medicare number: 2123 25870 1"),
        ("SG_NRIC_FIN", "NRIC: G1122144L"),
        ("SG_UEN", "UEN: 53125226E"),
        // one repeated digit, no series
        ("AU_TFN", "TFN: 111 111 111"),
        ("SG_NRIC_FIN", "NRIC: B1234567Z"),
        // part of a longer value
        ("AU_ACN", "ACN: 006 249 976 5"),
        ("AU_TFN", "TFN: 876-543-210-4"),
        ("AU_MEDICARE", "Medicare number: 2123 45670 1/2"),
        ("SG_NRIC_FIN", "NRIC: XS0642712Z"),
        // a nearer counter-context term
        ("AU_ACN", "ACN Pty Ltd, order number 006249976"),
        ("AU_MEDICARE", "Medicare clinic, Bestellnummer 6431309681"),
        ("AU_TFN", "TFN letter, invoice number 842781633"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

// ── bare values, scored modes only ───────────────────────────────────────────

#[test]
fn bare_values_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (ABN_CONTEXT_FREE, "51 824 753 556", "51 824 753 556"),
        (
            ABN_CONTEXT_FREE,
            "Please invoice 53 004 085 616 by Friday.",
            "53 004 085 616",
        ),
        (MEDICARE_CONTEXT_FREE, "2123 45670 1", "2123 45670 1"),
        (
            MEDICARE_CONTEXT_FREE,
            "Karte 5309 78617 6 liegt vor.",
            "5309 78617 6",
        ),
        (NRIC_FIN_CONTEXT_FREE, "F2346401L", "F2346401L"),
        (
            NRIC_FIN_CONTEXT_FREE,
            "Applicant T1092579C has been approved.",
            "T1092579C",
        ),
        (NRIC_FIN_CONTEXT_FREE, "M2570575T", "M2570575T"),
        (UEN_CONTEXT_FREE, "S57TU0392K", "S57TU0392K"),
        (UEN_CONTEXT_FREE, "Firma 201434292D, Singapur", "201434292D"),
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
    // Three UENs on one line, as in the presidio-analyzer tests: format A needs a
    // term, B and C are reported bare.
    let text = "53125226D 201434292D S57TU0392K";
    assert_eq!(
        spans(text, PiiMode::Balanced, "SG_UEN")
            .into_iter()
            .map(|(value, _)| value)
            .collect::<Vec<_>>(),
        ["201434292D", "S57TU0392K"]
    );
}

#[test]
fn bare_lookalikes_stay_silent_in_every_mode() {
    for (label, text) in [
        // the checksum alone is too weak for nine, ten or eleven bare digits
        ("AU_ABN", "51824753556"),
        ("AU_ACN", "006249976"),
        ("AU_ACN", "000 000 019"),
        ("AU_TFN", "876 543 210"),
        ("AU_MEDICARE", "2123456701"),
        ("SG_UEN", "53125226D"),
        // lowercase without a term
        ("SG_NRIC_FIN", "f2346401l"),
        ("SG_UEN", "s57tu0392k"),
        // invalid check
        ("AU_ABN", "51 824 753 557"),
        ("AU_MEDICARE", "2123 45671 1"),
        ("SG_NRIC_FIN", "G1122144L"),
        ("SG_UEN", "201434292E"),
        // part of a longer value or a phone number
        ("AU_ABN", "+51 824 753 556"),
        ("AU_ABN", "1 51 824 753 556"),
        ("AU_MEDICARE", "2123 45670 1 2"),
        ("SG_NRIC_FIN", "F2346401L-2"),
        // a nearer counter-context term
        ("AU_ABN", "Rechnungsnummer 51 824 753 556"),
        ("SG_NRIC_FIN", "Order number F2346401L"),
    ] {
        assert_silent(text, label, &MODES);
    }
}

#[test]
fn a_term_decides_between_an_abn_and_a_steuer_id_in_the_same_groups() {
    // `52 842 296 017` is a valid ABN and an issued Steuer-ID in the 2-3-3-3
    // grouping both share; in the scored modes one label wins (K07): the term of
    // a label, else the earlier rule, the Steuer-ID.
    let value = "52 842 296 017";
    for mode in SCORED {
        for (text, label, other) in [
            (format!("ABN {value}"), "AU_ABN", "STEUERID"),
            (format!("Steuer-ID {value}"), "STEUERID", "AU_ABN"),
            (value.to_owned(), "STEUERID", "AU_ABN"),
        ] {
            assert_eq!(spans(&text, mode, label).len(), 1, "{mode}: {text}");
            assert!(spans(&text, mode, other).is_empty(), "{mode}: {text}");
        }
    }
}
