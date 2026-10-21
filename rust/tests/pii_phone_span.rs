// SPDX-License-Identifier: GPL-3.0-only
//! Span of a US phone number with a parenthesized area code (T04, TRIAGE 2026-W42
//! bucket 2).
//!
//! `pii_phone_us` opened with `\b`, which never holds before `(` after a space or at
//! the start of the text, so `(415) 555-2671` was reported as `415) 555-2671` and
//! missed every exact-span gold. A balanced `(NXX)` is now part of the span in every
//! mode. Unbalanced forms keep their previous span, the validator is unchanged:
//! too few digits, repeated digits and masked numbers stay silent with parentheses.

use patronus_ark::detectors::pii::{score::PiiMode, validators};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::Value;

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

/// `(rule_id, value)` of every matched rule.
fn rules(text: &str, result: &SecurityScanResult) -> Vec<(String, String)> {
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

fn phone_spans(result: &SecurityScanResult) -> Vec<String> {
    result
        .evidence_spans
        .iter()
        .filter(|span| span.label == "PHONE")
        .map(|span| span.text.clone())
        .collect()
}

fn balanced_parentheses(value: &str) -> bool {
    value.matches('(').count() == value.matches(')').count()
}

/// `(text, value)`: `pii_phone_us` reports `value` exactly, the only PHONE span.
const PARENTHESIZED: [(&str, &str); 12] = [
    ("US-Büro: (212) 736-4410", "(212) 736-4410"),
    (
        "Rufen Sie unser Büro in Boston unter (617) 555-0183 an.",
        "(617) 555-0183",
    ),
    ("Telefon (USA): (415) 555-2671", "(415) 555-2671"),
    ("{\"telefon_us\": \"(303) 499-7111\"}", "(303) 499-7111"),
    ("Name;Telefon\nMiller;(206) 386-4636", "(206) 386-4636"),
    ("(312) 744-5000 ist die Zentrale.", "(312) 744-5000"),
    ("Call me at (415) 555-2671 tomorrow.", "(415) 555-2671"),
    ("Phone: (212) 736-4410", "(212) 736-4410"),
    ("Office:(646)555-0199", "(646)555-0199"),
    ("contact:\n  phone: (720) 913-1311\n", "(720) 913-1311"),
    (
        "| Name | Phone |\n|---|---|\n| R. Patel | (213) 485-2121 |",
        "(213) 485-2121",
    ),
    (
        "Placeholder line (212) 555-0100 in the template.",
        "(212) 555-0100",
    ),
];

/// Parenthesized lookalikes that `unanchored_phone` or the 3-3-4 shape rejects: no PII span.
const REJECTED: [&str; 10] = [
    "Rückfrage: (111) 111-1111",
    "Telefon: (XXX) XXX-XXXX",
    "Abschnitt (12) 345-67 der Satzung",
    "Siehe Anhang (3) auf Seite 12.",
    "Telefon: (000) 000-0000",
    "Phone: (999) 999-9999",
    "Phone: (XXX) 555-XXXX",
    "See note (2) on page 14.",
    "Area code (415) only, number withheld.",
    "Order (12) 345-678 shipped.",
];

#[test]
fn rejected_vectors_fail_the_unchanged_validator() {
    for (_, value) in PARENTHESIZED {
        assert!(validators::unanchored_phone(value), "{value}");
    }
    for value in ["(111) 111-1111", "(000) 000-0000", "(999) 999-9999"] {
        assert!(!validators::unanchored_phone(value), "{value}");
    }
    // Too few digits; `(12) 345-67` has seven, but no 3-3-4 shape for the rule.
    assert!(!validators::unanchored_phone("(415)"));
    assert!(!validators::unanchored_phone("(12) 345"));
}

#[test]
fn parenthesized_area_code_is_part_of_the_span_in_strict() {
    for (text, value) in PARENTHESIZED {
        let result = scan(text, PiiMode::Strict);
        assert!(
            rules(text, &result).contains(&("pii_phone_us".to_owned(), value.to_owned())),
            "{text}: {:?}",
            rules(text, &result)
        );
        assert_eq!(phone_spans(&result), vec![value.to_owned()], "{text}");
    }
}

#[test]
fn parenthesized_area_code_is_part_of_the_span_in_scored_modes() {
    for mode in [PiiMode::Balanced, PiiMode::Recall] {
        for (text, value) in [
            ("Phone: (212) 736-4410", "(212) 736-4410"),
            ("Telefon: (415) 555-2671", "(415) 555-2671"),
            ("Call our office at (617) 555-0183.", "(617) 555-0183"),
        ] {
            let result = scan(text, mode);
            assert_eq!(
                phone_spans(&result),
                vec![value.to_owned()],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn parenthesized_lookalikes_stay_silent() {
    for text in REJECTED {
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            let result = scan(text, mode);
            assert!(
                result.evidence_spans.is_empty(),
                "{mode:?}: {text}: {:?}",
                phone_spans(&result)
            );
        }
    }
}

#[test]
fn no_us_phone_span_is_cut_inside_parentheses() {
    // The country code is the international rule's part; the US rule reports the
    // balanced national form, never a half-open `415) …`.
    for (text, us, international) in [
        (
            "Phone: +1 (415) 555-2671",
            "(415) 555-2671",
            "+1 (415) 555-2671",
        ),
        (
            "Telefon: +1 (212) 736-4410",
            "(212) 736-4410",
            "+1 (212) 736-4410",
        ),
    ] {
        let result = scan(text, PiiMode::Strict);
        let found = rules(text, &result);
        assert!(
            found.contains(&("pii_phone_us".to_owned(), us.to_owned()))
                && found.contains(&(
                    "pii_phone_international".to_owned(),
                    international.to_owned()
                )),
            "{text}: {found:?}"
        );
        assert!(
            found.iter().all(|(_, value)| balanced_parentheses(value)),
            "{text}: {found:?}"
        );
    }
}

#[test]
fn unbalanced_forms_keep_their_span() {
    // Without a closing parenthesis nothing changes: the digits from the area code on.
    for (text, value) in [
        ("Telefon: (415 555-2671", "415 555-2671"),
        ("Phone: (212 736 4410", "212 736 4410"),
        ("Phone: 415) 555-2671", "415) 555-2671"),
    ] {
        let result = scan(text, PiiMode::Strict);
        assert_eq!(phone_spans(&result), vec![value.to_owned()], "{text}");
    }
}

#[derive(Deserialize)]
struct Probe {
    category: String,
    rule_id: String,
    #[serde(default)]
    span: Option<SpanProbe>,
}

#[derive(Deserialize)]
struct SpanProbe {
    de: ExactSpan,
    en: ExactSpan,
}

#[derive(Deserialize)]
struct ExactSpan {
    text: String,
    value: String,
}

#[test]
fn bilingual_span_probes_report_the_exact_value() {
    let probes: Vec<Probe> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let mut probed = Vec::new();
    for probe in probes.iter().filter(|probe| probe.category == "pii") {
        let Some(span) = &probe.span else {
            continue;
        };
        assert_ne!(span.de.text, span.en.text, "translate {}", probe.rule_id);
        for ExactSpan { text, value } in [&span.de, &span.en] {
            let result = scan(text, PiiMode::Strict);
            assert!(
                rules(text, &result).contains(&(probe.rule_id.clone(), value.clone())),
                "{}: {text:?}: {:?}",
                probe.rule_id,
                rules(text, &result)
            );
        }
        probed.push(probe.rule_id.as_str());
    }
    assert_eq!(probed, ["pii_phone_us"]);
}
