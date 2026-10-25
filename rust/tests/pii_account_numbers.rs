// SPDX-License-Identifier: GPL-3.0-only
//! Account numbers (B-ACCT: A04, F14).
//!
//! The ABA routing number carries a check digit: the first two digits are a
//! Federal Reserve routing symbol and the sum weighted 3-7-1 is divisible by 10.
//! Nine bare digits pass it one time in ten, so `pii_aba_routing_number_us`
//! reports the value in every mode only with a routing or account term near it or
//! as its key; in `balanced` and `recall` the printed 4-4-1 form is also reported
//! bare (K05). The field-bound account rule binds the BBAN, the routing number
//! and `acct` fields too, with their name before the value or as a structural key
//! (JSON, XML, CSV, key-value), and does not check a digit. All of them report
//! `FINANCIAL_ACCOUNT_NUMBER`.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const ABA: &str = "pii_aba_routing_number_us";
const ABA_CONTEXT_FREE: &str = "pii_aba_routing_number_us_context_free";
const ACCOUNT: &str = "pii_financial_account_number";
const LABEL: &str = "FINANCIAL_ACCOUNT_NUMBER";
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

// ── validator ────────────────────────────────────────────────────────────────

#[test]
fn aba_routing_number_validator_checks_the_symbol_and_the_3_7_1_digit() {
    for valid in [
        // presidio-analyzer tests
        "121000358",
        "121042882",
        "0711-0130-7",
        "3222-7162-7",
        // published routing numbers: Federal Reserve districts 01–12, a thrift
        // (21–32), an electronic one (61–72) and the US government (00)
        "011000015",
        "021000021",
        "026009593",
        "111000025",
        "322271627",
        "256074974",
        "061000052",
        "091000019",
        "000000518",
    ] {
        assert!(validators::aba_routing_number(valid), "{valid}");
    }
    for invalid in [
        // one digit off
        "121000359",
        "021000022",
        "0711-0130-8",
        // the check digit fits, the routing symbol is never issued (13–20, 33–60,
        // 73–79, 81–99); the presidio-analyzer negative 421042111 fails both
        "131000351",
        "421042113",
        "501000350",
        "731000353",
        "811000354",
        "901000358",
        "421042111",
        "331000355",
        // one repeated digit
        "000000000",
        // length and alphabet
        "12100035",
        "1210003580",
        "12100035A",
    ] {
        assert!(!validators::aba_routing_number(invalid), "{invalid}");
    }
}

// ── rule properties ──────────────────────────────────────────────────────────

#[test]
fn the_aba_rules_have_their_label_validator_and_mode() {
    let check = validators::aba_routing_number as fn(&str) -> bool;
    for rule_id in [ABA, ABA_CONTEXT_FREE] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, LABEL, "{rule_id}");
        assert_eq!(rule.strength, ValidatorStrength::Checksum, "{rule_id}");
        assert_eq!(
            rule.validator.map(|validator| validator as usize),
            Some(check as usize),
            "{rule_id}"
        );
        assert!(!rule.captured_value, "{rule_id}");
    }
    let balanced = PiiMode::Balanced.min_score().unwrap();
    let recall = PiiMode::Recall.min_score().unwrap();
    let bound = pattern(ABA);
    assert!(bound.requires_context && !bound.scored_only);
    // The farthest term still clears the balanced threshold.
    assert!(score::score(bound, Context::Support { gap: 48 }) >= balanced);
    let free = pattern(ABA_CONTEXT_FREE);
    assert!(free.scored_only && !free.requires_context);
    // Bare, the check digit reaches the balanced threshold; a nearer
    // counter-context term drops it below the recall threshold.
    assert_eq!(score::rule_score(free), 0.55);
    assert!(score::score(free, Context::Counter) < recall);
    // The account rule stays a field-bound format rule.
    let account = pattern(ACCOUNT);
    assert_eq!(account.strength, ValidatorStrength::Format);
    assert!(account.captured_value && !account.requires_context && !account.scored_only);
}

// ── ABA routing number with a term, every mode ───────────────────────────────

#[test]
fn a_routing_number_near_its_term_or_under_its_key_is_reported_in_every_mode() {
    for (text, value) in [
        ("ABA 121000358", "121000358"),
        ("The bank's ABA routing number is 026009593.", "026009593"),
        (
            "Wire to 011000015 (bank routing number) by Friday.",
            "011000015",
        ),
        (
            "We may also collect bank routing numbers, such as 021000021.",
            "021000021",
        ),
        ("Routing: ABA 0711-0130-7", "0711-0130-7"),
        (
            "Die Routingnummer der US-Bank lautet 111000025.",
            "111000025",
        ),
        ("{\"aba\": \"121042882\"}", "121042882"),
        ("rtn,amount\n061000052,42", "061000052"),
    ] {
        assert_reports(ABA, text, value, &MODES);
    }
}

#[test]
fn a_routing_number_needs_its_term_a_valid_check_digit_and_digits_of_its_own() {
    for text in [
        // no term: nine digits pass the check one time in ten
        "121000358",
        "Order 021000021 shipped.",
        // a nearer counter-context term
        "ABA, order number 121000358",
        "Bestellnummer 026009593",
        // check digit, routing symbol, repeated digit
        "ABA 121000359",
        "ABA 421042111",
        "ABA 901000358",
        "ABA 000000000",
        // part of a longer number
        "ABA 1210003580",
        "ABA 121000358-2",
        "ABA 0711-0130-7-1",
    ] {
        assert_silent(text, LABEL, &MODES);
    }
}

// ── bare 4-4-1 form, scored modes only ───────────────────────────────────────

#[test]
fn a_bare_routing_number_in_4_4_1_groups_is_reported_in_the_scored_modes_only() {
    for (text, value) in [
        ("0711-0130-7", "0711-0130-7"),
        ("3222-7162-7", "3222-7162-7"),
        ("Please send the wire to 1210-0035-8 today.", "1210-0035-8"),
        ("Bitte überweisen Sie an 0260-0959-3.", "0260-0959-3"),
        ("Transfer via 0110-0001-5, thanks.", "0110-0001-5"),
    ] {
        assert_reports(ABA_CONTEXT_FREE, text, value, &SCORED);
        assert_silent(text, LABEL, &[PiiMode::Strict]);
    }
    assert_eq!(
        spans("0711-0130-7", PiiMode::Balanced, LABEL),
        [("0711-0130-7".to_owned(), 0.55)]
    );
    // Nine bare digits stay with the context-bound rule.
    assert_silent("121000358", LABEL, &MODES);
}

#[test]
fn bare_4_4_1_lookalikes_stay_silent() {
    for text in [
        // check digit or routing symbol fails
        "0711-0130-8",
        "4210-4211-3",
        // a nearer counter-context term
        "Rechnungsnummer 0711-0130-7",
        "Ticket number 3222-7162-7",
        // part of a longer value
        "0711-0130-75",
        "+1 0711-0130-7",
        "X0711-0130-7",
    ] {
        assert_silent(text, LABEL, &MODES);
    }
}

// ── account and routing fields, every mode ──────────────────────────────────

#[test]
fn bban_routing_and_acct_fields_bind_their_value_in_every_mode() {
    for (text, value) in [
        ("BBAN: ZFJR88590163492773", "ZFJR88590163492773"),
        (
            "Brandon Carr, with the BBAN number NQTZ73395804946160, resides here.",
            "NQTZ73395804946160",
        ),
        ("* BBAN : YVPB41434347080416", "YVPB41434347080416"),
        // under its field name the routing number needs no check digit
        ("Bank Routing Number: 932049652", "932049652"),
        ("Routing Number: 282593791", "282593791"),
        (
            "My bank routing number is 885327936, as requested.",
            "885327936",
        ),
        ("Acct No: 55120443", "55120443"),
        ("Numéro de routage de la banque : 919057875", "919057875"),
        (
            "Numéro d'acheminement de la banque : 147870166",
            "147870166",
        ),
        ("Numero di routing bancario: 167463426", "167463426"),
        ("Número de ruta bancaria: 302303320", "302303320"),
        ("Routing-Nummer: 512345678", "512345678"),
    ] {
        assert_reports(ACCOUNT, text, value, &MODES);
    }
}

#[test]
fn account_and_routing_keys_bind_their_value_in_every_mode() {
    for (text, value) in [
        ("{\"bban\": \"ADXO08034447307440\"}", "ADXO08034447307440"),
        ("<AcctNumber>823754616</AcctNumber>", "823754616"),
        ("<RoutingNumber>823754616</RoutingNumber>", "823754616"),
        (
            "<AcctId>H0873491448510040803748</AcctId>",
            "H0873491448510040803748",
        ),
        (
            "<es:numeroCuentaBancaria>O3530546004716570975444</es:numeroCuentaBancaria>",
            "O3530546004716570975444",
        ),
        (
            "\"name\",\"bank_routing_number\"\n\"Charlotte Schneider\",\"174518479\"",
            "174518479",
        ),
        ("bban=RVHC19892216923275", "RVHC19892216923275"),
        ("routing_number: 259255680", "259255680"),
    ] {
        assert_reports(ACCOUNT, text, value, &MODES);
    }
}

#[test]
fn account_and_routing_fields_without_a_value_stay_silent() {
    for text in [
        "BBAN: siehe Anlage",
        "Bank routing number: on file",
        "Routing number: ****",
        "Enter the routing number without dashes.",
        "Die BBAN ist Teil der IBAN.",
        "Network routing table updated for 10 hosts.",
        "Routing number for direct deposit is printed on the cheque.",
        "Bestellnummer: 932049652",
    ] {
        assert_silent(text, LABEL, &MODES);
    }
}

// ── customer IDs under a field name with an underscore (F14) ────────────────

#[test]
fn customer_id_fields_with_an_underscore_bind_their_value() {
    for (text, value) in [
        ("57=customer_id:K7430771|57=password:x", "K7430771"),
        ("Services: braces. Customer_ID: T-397878-G", "T-397878-G"),
        ("customer-number = C150-5439-416", "C150-5439-416"),
    ] {
        assert_reports("pii_customer_id", text, value, &MODES);
    }
    for text in ["customer_id: none", "customer_id=42"] {
        assert_silent(text, "CUSTOMER_ID", &MODES);
    }
}
