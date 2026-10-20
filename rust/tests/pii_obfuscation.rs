//! Obfuscation with offset back-mapping (K06).
//!
//! Zero-width characters inside a value, full-width forms and defanged separators
//! (`[.]`, `(@)`) leave a value readable. In every mode the scanner normalizes them,
//! runs the rules and validators on the normalized value and reports the original
//! span, with `matched_rules[].obfuscation` naming what it undid. Spelled-out e-mail
//! separators (`[at]`, `ät`, `dot`, `punkt`) and numbers spaced character by
//! character are undone in `recall` only, 10 points below the plain form; `strict`
//! and `balanced` keep them negative (gold convention T01). Validators are not relaxed: a checksum that
//! fails behind the obfuscation stays rejected.

use patronus_ark::detectors::pii::score::{PiiMode, SPELLED_OUT_PENALTY_POINTS};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::Value;

const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];

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

fn matched_rules(result: &SecurityScanResult) -> Vec<Value> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array().cloned())
        .unwrap_or_default()
}

/// `(label, text)` of every evidence span.
fn spans(text: &str, mode: PiiMode) -> Vec<(String, String)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .map(|span| (span.label, span.text))
        .collect()
}

/// The `matched_rules` entry of `rule_id` on exactly `value` in `text`.
fn rule_on<'a>(rules: &'a [Value], text: &str, rule_id: &str, value: &str) -> Option<&'a Value> {
    rules.iter().find(|rule| {
        rule["rule_id"] == rule_id
            && text.get(
                rule["start_byte"].as_u64().unwrap() as usize
                    ..rule["end_byte"].as_u64().unwrap() as usize,
            ) == Some(value)
    })
}

/// Asserts that `rule_id` reports `value` (a substring of `text`) as `label` in
/// `mode` with original byte and character offsets, and returns its rule entry.
fn assert_reported(text: &str, label: &str, rule_id: &str, value: &str, mode: PiiMode) -> Value {
    let result = pii_result(text, mode);
    let start = text.find(value).unwrap();
    let span = result
        .evidence_spans
        .iter()
        .find(|span| span.label == label && span.text == value)
        .unwrap_or_else(|| panic!("{mode}: {text:?}: {:?}", result.evidence_spans));
    assert_eq!(
        (span.start_byte, span.end_byte),
        (start, start + value.len())
    );
    assert_eq!(
        (span.start_char, span.end_char),
        (
            text[..start].chars().count(),
            text[..start + value.len()].chars().count()
        ),
        "{text:?}"
    );
    let rules = matched_rules(&result);
    let rule = rule_on(&rules, text, rule_id, value)
        .unwrap_or_else(|| panic!("{mode}: {rule_id} on {value:?}: {rules:#?}"))
        .clone();
    for component in rule["components"].as_array().unwrap() {
        let start = component["start_byte"].as_u64().unwrap() as usize;
        let end = component["end_byte"].as_u64().unwrap() as usize;
        assert!(
            start < end && text.get(start..end).is_some(),
            "{text:?}: {component}"
        );
    }
    rule
}

fn obfuscation(rule: &Value) -> Vec<&str> {
    rule["obfuscation"]
        .as_array()
        .map(|kinds| kinds.iter().map(|kind| kind.as_str().unwrap()).collect())
        .unwrap_or_default()
}

#[test]
fn invisible_obfuscation_reports_the_original_span_in_every_mode() {
    let cases = [
        (
            "E-Mail: anna.berg@firma\u{200B}.de",
            "EMAIL",
            "pii_email",
            "anna.berg@firma\u{200B}.de",
            "zero_width",
        ),
        (
            "Reply to m\u{200B}ara.lee@north\u{200B}wind.com today.",
            "EMAIL",
            "pii_email",
            "m\u{200B}ara.lee@north\u{200B}wind.com",
            "zero_width",
        ),
        (
            "Email: ada.wong＠northwind.com",
            "EMAIL",
            "pii_email",
            "ada.wong＠northwind.com",
            "full_width",
        ),
        (
            "Bitte an jana.roth＠beispiel．de schreiben.",
            "EMAIL",
            "pii_email",
            "jana.roth＠beispiel．de",
            "full_width",
        ),
        (
            "Mail ops(@)example[.]com",
            "EMAIL",
            "pii_email",
            "ops(@)example[.]com",
            "defanged",
        ),
        (
            "Quelle: １９８．５１．１００．７",
            "IP_ADDRESS",
            "pii_ipv4",
            "１９８．５１．１００．７",
            "full_width",
        ),
        (
            "Source IP: 203[.]0[.]113[.]5",
            "IP_ADDRESS",
            "pii_ipv4",
            "203[.]0[.]113[.]5",
            "defanged",
        ),
        (
            "Mobile: +44\u{200B}7700\u{200B}900123",
            "PHONE",
            "pii_phone_international",
            "+44\u{200B}7700\u{200B}900123",
            "zero_width",
        ),
        (
            "Telefon: ０３０ １２３４５６７８",
            "PHONE",
            "pii_phone_de_national_context",
            "０３０ １２３４５６７８",
            "full_width",
        ),
        (
            "Karte 4111\u{200B}1111\u{200B}1111\u{200B}1111",
            "CREDITCARD",
            "pii_credit_card",
            "4111\u{200B}1111\u{200B}1111\u{200B}1111",
            "zero_width",
        ),
        (
            "Card number: ４１１１ １１１１ １１１１ １１１１",
            "CREDITCARD",
            "pii_credit_card",
            "４１１１ １１１１ １１１１ １１１１",
            "full_width",
        ),
        (
            "IBAN: DE02\u{200B}3705\u{200B}0299\u{200B}0000\u{200B}6847\u{200B}12",
            "IBAN",
            "pii_iban_de",
            "DE02\u{200B}3705\u{200B}0299\u{200B}0000\u{200B}6847\u{200B}12",
            "zero_width",
        ),
        (
            "IBAN: ＤＥ８９ ３７０４ ００４４ ０５３２ ０１３０ ００",
            "IBAN",
            "pii_iban_de",
            "ＤＥ８９ ３７０４ ００４４ ０５３２ ０１３０ ００",
            "full_width",
        ),
        (
            "Steuer-ID: ８６０９５７４２７１９",
            "STEUERID",
            "pii_steuer_id_de",
            "８６０９５７４２７１９",
            "full_width",
        ),
        (
            "SSN: ５３２-８７-１０９４",
            "SSN",
            "pii_ssn_us",
            "５３２-８７-１０９４",
            "full_width",
        ),
    ];
    for (text, label, rule_id, value, kind) in cases {
        for mode in MODES {
            let rule = assert_reported(text, label, rule_id, value, mode);
            assert_eq!(obfuscation(&rule), vec![kind], "{mode}: {text:?}");
        }
    }
}

#[test]
fn checksums_decide_behind_the_obfuscation() {
    // (valid, invalid): the same obfuscation, one check digit apart.
    let vectors = [
        (
            "Karte 4111\u{200B}1111\u{200B}1111\u{200B}1111",
            "Karte 4111\u{200B}1111\u{200B}1111\u{200B}1112",
            "CREDITCARD",
        ),
        (
            "Card: ５５５５ ５５５５ ５５５５ ４４４４",
            "Card: ５５５５ ５５５５ ５５５５ ４４４５",
            "CREDITCARD",
        ),
        (
            "IBAN: ＤＥ８９３７０４００４４０５３２０１３０００",
            "IBAN: ＤＥ８９３７０４００４４０５３２０１３００１",
            "IBAN",
        ),
        (
            "IBAN: DE89\u{200B}3704\u{200B}0044\u{200B}0532\u{200B}0130\u{200B}00",
            "IBAN: DE89\u{200B}3704\u{200B}0044\u{200B}0532\u{200B}0130\u{200B}01",
            "IBAN",
        ),
        (
            "Steuer-ID: ８６０９５７４２７１９",
            "Steuer-ID: ８６０９５７４２７１８",
            "STEUERID",
        ),
    ];
    for (valid, invalid, label) in vectors {
        for mode in MODES {
            assert!(
                spans(valid, mode).iter().any(|(found, _)| found == label),
                "{mode}: {valid:?}"
            );
            assert!(
                spans(invalid, mode).is_empty(),
                "{mode}: {invalid:?}: {:?}",
                spans(invalid, mode)
            );
        }
    }
    // Spaced digits are undone in recall only; the check digit still decides there.
    let (valid, invalid) = (
        "IBAN: D E 8 9 3 7 0 4 0 0 4 4 0 5 3 2 0 1 3 0 0 0",
        "IBAN: D E 8 9 3 7 0 4 0 0 4 4 0 5 3 2 0 1 3 0 0 1",
    );
    assert_reported(
        valid,
        "IBAN",
        "pii_iban_de",
        "D E 8 9 3 7 0 4 0 0 4 4 0 5 3 2 0 1 3 0 0 0",
        PiiMode::Recall,
    );
    assert!(spans(invalid, PiiMode::Recall).is_empty());
}

#[test]
fn spaced_card_digits_keep_their_plain_finding() {
    // The card rule already accepts digits spaced one by one; recall does not
    // report them a second time or below their plain score.
    let text = "Card: 5 5 5 5 5 5 5 5 5 5 5 5 4 4 4 4";
    for mode in MODES {
        let rule = assert_reported(text, "CREDITCARD", "pii_credit_card", &text[6..], mode);
        assert!(rule.get("obfuscation").is_none(), "{mode}");
        assert_eq!(pii_result(text, mode).evidence_spans.len(), 1, "{mode}");
    }
}

#[test]
fn spelled_out_forms_are_reported_in_recall_only_below_the_plain_score() {
    let cases = [
        (
            "Kontakt: max punkt mustermann ät firma punkt de",
            "EMAIL",
            "pii_email",
            "max punkt mustermann ät firma punkt de",
            "max.mustermann@firma.de",
            "spelled_out",
        ),
        (
            "Mail ada [at] northwind [dot] com for access.",
            "EMAIL",
            "pii_email",
            "ada [at] northwind [dot] com",
            "ada@northwind.com",
            "spelled_out",
        ),
        (
            "Write to john.smith at example dot com.",
            "EMAIL",
            "pii_email",
            "john.smith at example dot com",
            "john.smith@example.com",
            "spelled_out",
        ),
        (
            "Schreiben Sie an lena(at)musterfirma(punkt)de",
            "EMAIL",
            "pii_email",
            "lena(at)musterfirma(punkt)de",
            "lena@musterfirma.de",
            "spelled_out",
        ),
        (
            "Schreiben Sie an info @ firma . de",
            "EMAIL",
            "pii_email",
            "info @ firma . de",
            "info@firma.de",
            "spelled_out",
        ),
        (
            "IBAN: D E 8 9 3 7 0 4 0 0 4 4 0 5 3 2 0 1 3 0 0 0",
            "IBAN",
            "pii_iban_de",
            "D E 8 9 3 7 0 4 0 0 4 4 0 5 3 2 0 1 3 0 0 0",
            "DE89370400440532013000",
            "spaced_digits",
        ),
        (
            "Passport number: C 0 1 X 0 0 T 4 7",
            "PASSPORT_NUMBER",
            "pii_passport_number_de",
            "C 0 1 X 0 0 T 4 7",
            "C01X00T47",
            "spaced_digits",
        ),
    ];
    for (text, label, rule_id, value, plain, kind) in cases {
        for mode in [PiiMode::Strict, PiiMode::Balanced] {
            assert!(
                spans(text, mode).iter().all(|(found, _)| found != label),
                "{mode}: {text:?}: {:?}",
                spans(text, mode)
            );
        }
        let rule = assert_reported(text, label, rule_id, value, PiiMode::Recall);
        assert_eq!(obfuscation(&rule), vec![kind], "{text:?}");
        let plain_text = text.replace(value, plain);
        let plain_rule = assert_reported(&plain_text, label, rule_id, plain, PiiMode::Recall);
        let penalty = f64::from(SPELLED_OUT_PENALTY_POINTS) / 100.0;
        let (score, plain_score) = (
            rule["score"].as_f64().unwrap(),
            plain_rule["score"].as_f64().unwrap(),
        );
        assert!(
            (plain_score - penalty - score).abs() < 1e-9,
            "{text:?}: {score} vs {plain_score}"
        );
        let span = pii_result(text, PiiMode::Recall)
            .evidence_spans
            .into_iter()
            .find(|span| span.label == label)
            .unwrap();
        assert!((span.score - score).abs() < 1e-9, "{text:?}");
    }
}

#[test]
fn prose_masks_and_lookalikes_stay_negative_in_every_mode() {
    for text in [
        "Read the docs at example dot com.",
        "Look at the dot product of both vectors.",
        "Infos unter firma punkt de.",
        "Treffpunkt ist um 10 Uhr ät der Rezeption.",
        "Version 1[.]2[.]3 ist veröffentlicht.",
        "Phone: ＸＸＸ-ＸＸＸ-ＸＸＸＸ",
        "Kartennummer: ＊＊＊＊ ＊＊＊＊ ＊＊＊＊ １１１１",
        "Team 👩\u{200D}💻 trifft sich um 10 Uhr.",
        "Reihe 1 2 3 4 5 6 7 im Saal.",
        "Kosten [at] 3 [dot] 50 Euro.",
    ] {
        for mode in MODES {
            assert!(
                spans(text, mode).is_empty(),
                "{mode}: {text:?}: {:?}",
                spans(text, mode)
            );
        }
    }
}

#[test]
fn plain_findings_next_to_obfuscated_ones_stay_unchanged() {
    let plain = "IBAN: DE89 3704 0044 0532 0130 00";
    let text = format!("{plain}\nE-Mail: anna.berg@firma\u{200B}.de");
    for mode in MODES {
        let alone = matched_rules(&pii_result(plain, mode));
        let rules = matched_rules(&pii_result(&text, mode));
        let iban = rule_on(&rules, &text, "pii_iban_de", "DE89 3704 0044 0532 0130 00").unwrap();
        assert_eq!(
            Some(iban),
            rule_on(&alone, plain, "pii_iban_de", "DE89 3704 0044 0532 0130 00")
        );
        assert!(iban.get("obfuscation").is_none());
        assert_reported(
            &text,
            "EMAIL",
            "pii_email",
            "anna.berg@firma\u{200B}.de",
            mode,
        );
        let result = pii_result(&text, mode);
        assert_eq!(
            result.evidence_spans.len(),
            2,
            "{mode}: {:?}",
            result.evidence_spans
        );
        assert_eq!(result.evidence_spans[0].label, "IBAN");
    }
}

#[derive(Deserialize)]
struct Probe {
    category: String,
    rule_id: String,
    #[serde(default)]
    obfuscated: Option<ObfuscatedProbe>,
}

#[derive(Deserialize)]
struct ObfuscatedProbe {
    de: String,
    en: String,
}

#[test]
fn bilingual_obfuscated_probes_report_in_strict() {
    let probes: Vec<Probe> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let mut probed = 0;
    for probe in probes.iter().filter(|probe| probe.category == "pii") {
        let Some(obfuscated) = &probe.obfuscated else {
            continue;
        };
        assert_ne!(obfuscated.de, obfuscated.en, "translate {}", probe.rule_id);
        for text in [&obfuscated.de, &obfuscated.en] {
            let rules = matched_rules(&pii_result(text, PiiMode::Strict));
            assert!(
                rules.iter().any(|rule| {
                    rule["rule_id"] == probe.rule_id.as_str() && !obfuscation(rule).is_empty()
                }),
                "{}: {text:?}: {rules:#?}",
                probe.rule_id
            );
        }
        probed += 1;
    }
    assert!(probed >= 8, "only {probed} obfuscated probes");
}
