//! Structure awareness (K04).
//!
//! A JSON key, a `key: value` or `key=value` line, an XML element or attribute, a
//! CSV header or a Markdown/HTML table header names the value it holds, like a field
//! name right before it. In every mode a key binds a field-bound rule when the rule
//! accepts the normalized key as its field name and the value matches the rule's
//! value form in full; the validator decides as for a regex match. Such findings
//! carry `matched_rules[].structure` (the carrier) and a `structure_key` component.
//! For unbound rules the key is context: in `balanced`/`recall` a key of the label
//! scores as field, a counter-context key (order, invoice … number) as counter, and
//! a context-bound rule takes its required context from the key.

use patronus_ark::detectors::pii::score::PiiMode;
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::Value;

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

fn matched_rules(text: &str, mode: PiiMode) -> Vec<Value> {
    pii_result(text, mode).layers[0]
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

/// The structural match of `rule_id` on `value`, if any.
fn structural(text: &str, rule_id: &str, value: &str, mode: PiiMode) -> Option<Value> {
    matched_rules(text, mode).into_iter().find(|rule| {
        rule["rule_id"] == rule_id
            && rule.get("structure").is_some()
            && text.get(
                rule["start_byte"].as_u64().unwrap() as usize
                    ..rule["end_byte"].as_u64().unwrap() as usize,
            ) == Some(value)
    })
}

#[test]
fn every_carrier_binds_its_value_to_the_rule_in_strict() {
    let cases = [
        ("json", "pii_customer_id", r#"{"kundennummer": "KD-99120"}"#, "KD-99120"),
        ("json", "pii_customer_id", r#"{"customerId": "CUS-88412"}"#, "CUS-88412"),
        ("json", "pii_student_id", r#"{"matrikelNummer": "5520931"}"#, "5520931"),
        ("kv", "pii_customer_id", "customer:\n  customer_id: C-104882\n", "C-104882"),
        ("kv", "pii_financial_account_number", "[payout]\naccount_number = ACC-55120", "ACC-55120"),
        ("xml", "pii_employee_id", "<employee><id>E-77121</id></employee>", "E-77121"),
        ("xml", "pii_customer_id", r#"<customer id="CUST-9001"/>"#, "CUST-9001"),
        ("xml", "pii_swift_bic_context", "<bank><bic>BARCGB22</bic></bank>", "BARCGB22"),
        ("csv", "pii_student_id", "Name;Matrikelnummer\nLea Brandt;4718205", "4718205"),
        ("csv", "pii_employee_id", "employee_id,name\nE-40512,Maya Patel", "E-40512"),
        ("csv", "pii_username", "user_name\tteam\nm.chen\tplatform", "m.chen"),
        ("table", "pii_patient_id", "| MRN | Ward |\n|---|---|\n| MRN-981134 | 7 |", "MRN-981134"),
        ("table", "pii_ssn_us", "| SSN | 219-09-9997 |", "219-09-9997"),
        (
            "table",
            "pii_phone_de_national_context",
            "<table><tr><th>Name</th><th>Telefon</th></tr><tr><td>Jana</td><td>030 4471230</td></tr></table>",
            "030 4471230",
        ),
    ];
    for (carrier, rule_id, text, value) in cases {
        let rule = structural(text, rule_id, value, PiiMode::Strict)
            .unwrap_or_else(|| panic!("{rule_id} via {carrier}: {text:?}"));
        assert_eq!(rule["structure"], carrier, "{text:?}");
        let components = rule["components"].as_array().unwrap();
        assert_eq!(components[0]["component_id"], "structure_key", "{text:?}");
        assert_eq!(components[1]["component_id"], "value", "{text:?}");
        let found = spans(text, PiiMode::Strict);
        assert!(
            found.iter().any(|(_, span)| span == value),
            "{text:?}: {found:?}"
        );
    }
}

#[test]
fn a_key_the_rule_does_not_accept_binds_nothing() {
    for text in [
        // Lexicon terms that the rules exclude on purpose.
        r#"{"arztnummer": "123456789"}"#,
        "| Kennung | XY-3096 |",
        "| Doctor ID | 123456789 |",
        // Order, product and reference keys.
        "Bestellnummer;Artikel\nBN-55120;Bürostuhl",
        "order_id,product\nORD-55120,Desk",
        "<order><id>E-77121</id></order>",
        r#"{"bankname": "DEUTDEFF500"}"#,
        // An `iban` key is not a second finding as account number.
        r#"{"iban": "KTO-30202"}"#,
    ] {
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            assert!(
                spans(text, mode).is_empty(),
                "{mode}: {text:?}: {:?}",
                matched_rules(text, mode)
            );
        }
    }
}

#[test]
fn the_value_must_match_the_rule_form_in_full() {
    // A key names its whole value: no prefix, no suffix, no fragment.
    for text in [
        "Kundennummer;Ort\nKD 991 20 (alt);Kassel",
        r#"{"telefon": "Zentrale 030 4471230"}"#,
        "| SSN | 219-09-9997 (old) |",
    ] {
        let rules = matched_rules(text, PiiMode::Strict);
        assert!(
            rules.iter().all(|rule| rule.get("structure").is_none()),
            "{text:?}: {rules:?}"
        );
    }
}

#[test]
fn validators_decide_structural_values_with_checksum_vectors() {
    // Steuer-ID (ISO 7064 MOD 11,10): valid and broken check digit.
    let valid = r#"{"steuer_id": "82736451927"}"#;
    assert!(structural(valid, "pii_steuer_id_de", "82736451927", PiiMode::Strict).is_some());
    for invalid in [
        r#"{"steuer_id": "82736451928"}"#,
        "<person><steuer-id>11111111111</steuer-id></person>",
    ] {
        assert!(spans(invalid, PiiMode::Strict).is_empty(), "{invalid}");
    }
    // Format validators: SSN area 666, impossible dates, document alphabet.
    for invalid in [
        "| SSN | 666-12-3456 |",
        "Name;Geburtsdatum\nJana Roth;31.02.1987",
        r#"<traveler passportNumber="A01X00T47"/>"#,
        r#"{"username": "required"}"#,
    ] {
        assert!(spans(invalid, PiiMode::Strict).is_empty(), "{invalid}");
    }
    // Luhn: a card column does not make a broken card number a finding.
    assert!(spans(
        "Kartennummer;Inhaber\n4111111111111112;Jana",
        PiiMode::Strict
    )
    .is_empty());
    assert_eq!(
        spans(
            "Kartennummer;Inhaber\n4111111111111111;Jana",
            PiiMode::Strict
        ),
        [("CREDITCARD".to_string(), "4111111111111111".to_string())]
    );
}

#[test]
fn a_value_is_reported_once_and_whole() {
    // The key-value line and the rule's regex find the same value: one entry,
    // with the regex evidence of the field name.
    let text = "Kundennummer: KD-10293";
    let rules: Vec<_> = matched_rules(text, PiiMode::Strict)
        .into_iter()
        .filter(|rule| rule["rule_id"] == "pii_customer_id")
        .collect();
    assert_eq!(rules.len(), 1, "{rules:?}");
    assert!(rules[0].get("structure").is_none(), "{rules:?}");
    assert_eq!(rules[0]["components"][0]["component_id"], "anchor_prefix");
    // The key names the whole cell, not the part after the rule's own field name.
    let table = "| MRN | Ward |\n|---|---|\n| MRN-981134 | 7 |";
    assert_eq!(
        spans(table, PiiMode::Strict),
        [("PATIENT_ID".to_string(), "MRN-981134".to_string())]
    );
}

#[test]
fn a_structural_key_scores_as_field_and_explains_itself() {
    let text = r#"{"kundennummer": "KD-99120"}"#;
    let rule = structural(text, "pii_customer_id", "KD-99120", PiiMode::Balanced).unwrap();
    assert_eq!(rule["context"]["bonus"], 25);
    assert_eq!(rule["context"]["side"], "key");
    assert_eq!(rule["context"]["anchor"], "pii.customer_identifier");
    // 30 base + 15 format + 25 field.
    assert_eq!(rule["score"], 0.7);
}

#[test]
fn keys_give_unbound_values_their_context_in_scored_modes() {
    // A phone column scores the value as field; a counter-context column drops it.
    let phone = "Name;Telefon\nJana;202-604-7110";
    let rule = matched_rules(phone, PiiMode::Balanced)
        .into_iter()
        .find(|rule| rule["rule_id"] == "pii_phone_us")
        .expect("phone column");
    assert_eq!(rule["context"]["side"], "key");
    assert_eq!(rule["context"]["anchor"], "pii.telephone");
    assert_eq!(rule["context"]["bonus"], 25);
    let order = "Bestellnummer;Menge\n202-604-7110;2";
    assert!(spans(order, PiiMode::Balanced).is_empty());
    let rule = matched_rules(order, PiiMode::Recall)
        .into_iter()
        .find(|rule| rule["rule_id"] == "pii_phone_us");
    assert!(rule.is_none(), "35 + 15 - 30 is below recall");
    // Strict keeps its acceptance for unbound rules.
    assert_eq!(
        spans(order, PiiMode::Strict),
        [("PHONE".to_string(), "202-604-7110".to_string())]
    );
}

#[test]
fn a_context_bound_rule_takes_its_context_from_the_key() {
    // No phone term on the value's line: the CSV header supplies it.
    let mobile = "Name;Handy\nJana;0151 2345678";
    assert!(matched_rules(mobile, PiiMode::Strict)
        .iter()
        .any(|rule| rule["rule_id"] == "pii_phone_de_national_proximity"));
    let order = "Name;Bestellnummer\nJana;0151 2345678";
    assert!(spans(order, PiiMode::Strict).is_empty());
    // A number inside a longer field value is not the value the key names.
    let fragment = "Phone: (987) 012-3456";
    assert!(matched_rules(fragment, PiiMode::Strict)
        .iter()
        .all(|rule| rule["rule_id"] != "pii_phone_de_national_proximity"));
}

#[derive(Deserialize)]
struct Probe {
    category: String,
    rule_id: String,
    #[serde(default)]
    structure: Option<StructureProbe>,
}

#[derive(Deserialize)]
struct StructureProbe {
    de: String,
    en: String,
}

#[test]
fn bilingual_structure_probes_report_through_the_structure() {
    let probes: Vec<Probe> = serde_json::from_str(include_str!(
        "../../ark-core/tests/fixtures/l1_bilingual_rules.json"
    ))
    .unwrap();
    let mut probed = 0;
    for probe in probes.iter().filter(|probe| probe.category == "pii") {
        let Some(structure) = &probe.structure else {
            continue;
        };
        assert_ne!(structure.de, structure.en, "translate {}", probe.rule_id);
        for text in [&structure.de, &structure.en] {
            assert!(
                matched_rules(text, PiiMode::Strict).iter().any(|rule| {
                    rule["rule_id"] == probe.rule_id.as_str() && rule.get("structure").is_some()
                }),
                "{}: {text:?}",
                probe.rule_id
            );
        }
        probed += 1;
    }
    assert!(probed >= 10, "only {probed} structure probes");
}
