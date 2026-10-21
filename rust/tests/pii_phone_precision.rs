// SPDX-License-Identifier: GPL-3.0-only
//! Phone precision in strict (T17, TRIAGE 2026-W43 buckets 1 + 2).
//!
//! On Gretel Finance most phone FP were EDIFACT elements (`UNB+UNOC:3+520173321::2`,
//! `NAD+BY+987654321`), SWIFT MT tags (`{86:+33…}`) and zero-padded IDs (`:62F:/0000001234/`,
//! `ST*850*0000012345~`); on the synthetic set Swedish personal numbers in 6-4 groups
//! (`811228-9874`). `pii_phone_international` and the `+49` form of `pii_phone_de` no
//! longer start inside an alphanumeric or `:`-delimited run, and `pii_phone_us` needs
//! the area code set off by `)` or a separator. The validator is unchanged: it accepts
//! every one of these values, the position and the grouping reject them.

use patronus_ark::detectors::pii::{pii::PII_PATTERNS, score::PiiMode, validators};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use regex::Regex;

fn scan(text: &str, mode: PiiMode) -> SecurityScanResult {
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

fn phone_spans(result: &SecurityScanResult) -> Vec<String> {
    result
        .evidence_spans
        .iter()
        .filter(|span| span.label == "PHONE")
        .map(|span| span.text.clone())
        .collect()
}

fn rule(name: &str) -> Regex {
    let pattern = PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == name)
        .expect("rule must be registered");
    Regex::new(pattern.pattern).unwrap()
}

/// EDIFACT, X12, SWIFT MT and XBRL elements from the Gretel phone FP (DE/EN frames).
const ELEMENT_RUNS: [&str; 16] = [
    "Kopfsegment: UNB+UNOC:3+520173321::2+520173321::4+202202150830+1323327835++STA'",
    "Interchange header: UNB+UNOC:3+5010500154:1+5020022223:1+190101:0930+2'",
    "Käufer: NAD+BY+987654321::9'",
    "Buyer party: NAD+BY+987654321+4+Elaine Toby'",
    "Lieferant: NAD+SU+4930123456789::9'",
    "Belegdatum: DTM+137:20220215:102'\nMOA+1++520173321'",
    "BGM+220+353093789602794\nDTM+137:20230214:102",
    "LIN+1+3553 6548 1210 8739:1:PCE'\nUNT+11+1'\nUNZ+1+202201011020'",
    "UNH+IFTM:2+1234567890:923+1234567890+20220101:1020'",
    "LIN+1++89.130.7.145'\nPIA+1:07'",
    "SWIFT-Feld {86:+330105789456}",
    "X12-Bestellung: ST*850*0000012345~\nSE*13*0000012345~",
    "ISA*00*SenderID*170928*1500*U*00401*0000012345*0*T*:~",
    "Schlusssaldo: :62F:/0000001234/\n:63F:/0000001234/",
    "<xbrli:identifier scheme=\"http://www.sec.gov/CIK\">0001234567</xbrli:identifier>",
    "Claim ID: 0012345678",
];

/// Personal numbers and IDs in 6-4 groups: no NANP number.
const SIX_FOUR: [&str; 6] = [
    "Personnummer: 811228-9874",
    "Swedish personal identity number: 811228-9874",
    "My SSN is 600427-7817, issued in Sweden.",
    "\"ssn\": \"741124-4622\"",
    "Konnossement Nr. LN-293847-2023",
    "Address 493=990611-0920|448=TotalView",
];

/// `(text, value)`: the PHONE span stays exactly `value` in strict.
const KEPT: [(&str, &str); 18] = [
    ("Telefon: +49 30 1234567", "+49 30 1234567"),
    ("Tel.:+49 30 1234567", "+49 30 1234567"),
    ("tel2:+49 30 1234567", "+49 30 1234567"),
    ("Mobil2:+49 30 1234567", "+49 30 1234567"),
    ("Phone:+1 415 555 2671", "+1 415 555 2671"),
    ("Rückruf unter +49 170 1234567 (Handy)", "+49 170 1234567"),
    (
        "Platzhalter in der Vorlage: +1 000-000-0000",
        "+1 000-000-0000",
    ),
    (
        "Placeholder in the template: +1 000-000-0000",
        "+1 000-000-0000",
    ),
    ("Telefon (USA): 212-555-0100", "212-555-0100"),
    ("Office: 212-555-0147", "212-555-0147"),
    ("Office:(646)555-0199", "(646)555-0199"),
    ("Fax: (617) 5550183", "(617) 5550183"),
    ("Telefoon: 020-1234567", "020-1234567"),
    ("Phone: 415.555.2671", "415.555.2671"),
    ("{\"phone\": \"+44 20 7946 0958\"}", "+44 20 7946 0958"),
    (
        "Kommunikationssegment: COM+0049 30 1234567:TE'",
        "0049 30 1234567",
    ),
    ("**+49 89 2019 4400**", "+49 89 2019 4400"),
    ("Mobil (+49 170 1234567)", "+49 170 1234567"),
];

#[test]
fn validator_vectors_are_unchanged() {
    // Every rejected value still passes the format validator: no validator was relaxed
    // or tightened, the rule position and grouping decide.
    for value in [
        "+520173321",
        "+1323327835",
        "+330105789456",
        "0000012345",
        "0012345678",
        "811228-9874",
        "600427-7817",
    ] {
        assert!(validators::unanchored_phone(value), "{value}");
    }
    for (_, value) in KEPT {
        assert!(validators::unanchored_phone(value), "{value}");
    }
    // Invalid vectors stay invalid: repeated digits, too short, no separator.
    for value in ["111-111-1111", "+1 111 111 1111", "+12345", "4155552671"] {
        assert!(!validators::unanchored_phone(value), "{value}");
    }
}

#[test]
fn element_runs_report_no_phone_in_any_mode() {
    for text in ELEMENT_RUNS {
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            let result = scan(text, mode);
            assert!(phone_spans(&result).is_empty(), "{mode:?}: {text:?}");
        }
    }
}

#[test]
fn six_four_groups_report_no_phone_in_any_mode() {
    for text in SIX_FOUR {
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            let result = scan(text, mode);
            assert!(phone_spans(&result).is_empty(), "{mode:?}: {text:?}");
        }
    }
}

#[test]
fn phone_numbers_after_field_names_and_placeholders_stay() {
    for (text, value) in KEPT {
        let result = scan(text, PiiMode::Strict);
        assert_eq!(phone_spans(&result), vec![value.to_owned()], "{text:?}");
    }
}

#[test]
fn a_tel_uri_after_a_number_keeps_both() {
    let text = "Call our desk at [+31 6 12345678](tel:+31612345678).";
    let result = scan(text, PiiMode::Strict);
    assert_eq!(
        phone_spans(&result),
        vec!["+31 6 12345678".to_owned(), "+31612345678".to_owned()]
    );
}

#[test]
fn us_rule_needs_the_area_code_set_off() {
    let us = rule("pii_phone_us");
    for value in [
        "415-555-2671",
        "415 555 2671",
        "415.555.2671",
        "(415) 555-2671",
        "(415)555-2671",
        "415) 555-2671",
        "415-5552671",
        "(415) 5552671",
    ] {
        assert_eq!(
            us.find(value).map(|found| found.as_str()),
            Some(value),
            "{value}"
        );
    }
    for value in ["415555-2671", "4155552671", "0000012345", "811228-9874"] {
        assert!(!us.is_match(value), "{value}");
    }
}
