//! PII context engine v2 (K03).
//!
//! Support terms of a label and counter-context terms (order, invoice, tracking,
//! ticket, reference, serial numbers) come from the DE/EN lexicon in
//! `anchor_lexicons/pii.json`. The nearest term on either side of a value
//! decides: a support term adds proximity points, a strictly nearer counter term
//! removes 30. `strict` keeps its acceptance for every existing rule; only
//! context-bound rules (`requires_context`) consult the engine there. In
//! `balanced` and `recall`, `matched_rules[].context` explains every score:
//! bonus, penalty and the deciding lexicon term with its side and distance.

use patronus_ark::detectors::lexical_anchors::LexicalAnchorScanner;
use patronus_ark::detectors::pii::{
    context::{self, Side, AFTER_WINDOW, BEFORE_WINDOW, COUNTER_LEXICON, SUPPORT_LEXICON},
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, COUNTER_CONTEXT_POINTS, FIELD_CONTEXT_POINTS},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;

const PROXIMITY_RULE: &str = "pii_phone_de_national_proximity";

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

fn spans(text: &str, mode: PiiMode) -> Vec<(String, String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .map(|span| (span.label, span.text, span.score))
        .collect()
}

fn rules(text: &str, mode: PiiMode) -> Vec<String> {
    pii_result(text, mode).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|rule| rule["rule_id"].as_str().unwrap().to_string())
        .collect()
}

/// Context of the first occurrence of `value` in `text`.
fn context_of(text: &str, value: &str, label: &str) -> Context {
    let start = text
        .find(value)
        .unwrap_or_else(|| panic!("{value} in {text}"));
    context::proximity(text, (start, start + value.len()), label)
}

fn pattern(rule_id: &str) -> &'static PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

fn matched_rules(result: &SecurityScanResult) -> Vec<serde_json::Value> {
    result.layers[0]
        .details
        .get("matched_rules")
        .map(|rules| rules.as_array().unwrap().clone())
        .unwrap_or_default()
}

fn rule<'a>(rules: &'a [serde_json::Value], rule_id: &str) -> Option<&'a serde_json::Value> {
    rules.iter().find(|rule| rule["rule_id"] == rule_id)
}

fn span_score(result: &SecurityScanResult, label: &str) -> Option<f64> {
    result
        .evidence_spans
        .iter()
        .find(|span| span.label == label)
        .map(|span| span.score)
}

/// Context evidence for the first occurrence of `value` in `text`.
fn evidence(text: &str, value: &str, label: &str) -> context::Evidence {
    let start = text
        .find(value)
        .unwrap_or_else(|| panic!("{value} in {text}"));
    context::evidence(text, (start, start + value.len()), label)
}

/// Model score of `pattern` with `bonus` context points and `penalty` counter points.
fn model_score(pattern: &PiiPattern, bonus: u8, penalty: u8) -> f64 {
    let points =
        i16::from(pattern.base_score) + i16::from(pattern.strength.points()) + i16::from(bonus)
            - i16::from(penalty);
    f64::from(points.clamp(0, 100)) / 100.0
}

#[test]
fn lexicon_ids_come_from_pii_json_and_cover_every_label() {
    let definitions = LexicalAnchorScanner::shared().definitions();
    let known = |id: &str| {
        definitions
            .iter()
            .any(|definition| definition.id == id && id.starts_with("pii."))
    };
    for (label, ids) in SUPPORT_LEXICON {
        assert!(!ids.is_empty(), "{label}");
        for id in *ids {
            assert!(known(id), "{label}: {id} missing in pii.json");
            assert!(!COUNTER_LEXICON.contains(id), "{id} is support and counter");
        }
    }
    for id in COUNTER_LEXICON {
        assert!(known(id), "counter {id} missing in pii.json");
    }
    for pattern in PII_PATTERNS {
        assert!(
            SUPPORT_LEXICON
                .iter()
                .any(|(label, _)| *label == pattern.entity_group),
            "{} ({}) has no support lexicon",
            pattern.name,
            pattern.entity_group
        );
    }
}

#[test]
fn support_terms_count_on_both_sides_of_the_value() {
    // Before: field name or phrase; after: "(Handy)", "erreichbar".
    for (text, value) in [
        (
            "Frau Weber ist unter 0176 90817263 erreichbar.",
            "0176 90817263",
        ),
        ("Rückruf bitte unter (030) 1234567.", "(030) 1234567"),
        ("0221 4711230 (Handy)", "0221 4711230"),
        ("You can reach her at 0176 90817263", "0176 90817263"),
        ("Office line 0711 2223334 (telephone)", "0711 2223334"),
    ] {
        assert!(
            context_of(text, value, "PHONE").supports(),
            "{text}: {:?}",
            context_of(text, value, "PHONE")
        );
        let found = spans(text, PiiMode::Strict);
        assert_eq!(
            found,
            vec![("PHONE".to_string(), value.to_string(), 1.0)],
            "{text}"
        );
        assert!(rules(text, PiiMode::Strict).contains(&PROXIMITY_RULE.to_string()));
    }
}

#[test]
fn proximity_points_fall_with_the_distance_to_the_term() {
    assert_eq!(
        score::PROXIMITY_CONTEXT_POINTS,
        [(16, 25), (32, 20), (48, 15)]
    );
    assert_eq!(BEFORE_WINDOW, 48);
    assert_eq!(AFTER_WINDOW, 32);
    let near = "Handy: 0151 2345678";
    let middle = "Handy (bitte nur abends): 0151 2345678";
    let far = "Handy, bitte nur abends und am Wochenende: 0151 2345678";
    let outside = "Handy, bitte nur abends und am Wochenende, sonst gerne per Brief: 0151 2345678";
    assert_eq!(
        context_of(near, "0151", "PHONE"),
        Context::Support { gap: 2 }
    );
    assert_eq!(
        context_of(middle, "0151", "PHONE"),
        Context::Support { gap: 21 }
    );
    assert_eq!(
        context_of(far, "0151", "PHONE"),
        Context::Support { gap: 38 }
    );
    assert_eq!(context_of(outside, "0151", "PHONE"), Context::None);
    assert_eq!(Context::Support { gap: 2 }.points(), 25);
    assert_eq!(Context::Support { gap: 20 }.points(), 20);
    assert_eq!(Context::Support { gap: 37 }.points(), 15);
    assert_eq!(Context::Field.points(), 25);
    assert_eq!(Context::Counter.points(), -30);
    assert_eq!(Context::None.points(), 0);

    // The context-bound rule scores base + format + proximity in balanced.
    let rule = pattern(PROXIMITY_RULE);
    for (text, expected) in [(middle, 0.55), (far, 0.50)] {
        let value = "0151 2345678";
        assert_eq!(
            score::score(rule, context_of(text, value, "PHONE")),
            expected,
            "{text}"
        );
        assert_eq!(
            spans(text, PiiMode::Balanced),
            vec![("PHONE".to_string(), value.to_string(), expected)],
            "{text}"
        );
    }
    assert!(spans(outside, PiiMode::Recall).is_empty());
}

#[test]
fn a_nearer_counter_term_outranks_support() {
    for (text, value) in [
        (
            "Bestellnummer 0176 90817263, Rückfragen bitte telefonisch.",
            "0176 90817263",
        ),
        (
            "Aktenzeichen 0711 2223334 – Rückruf erbeten.",
            "0711 2223334",
        ),
        (
            "Serial number 0711 2223334 of the mobile router",
            "0711 2223334",
        ),
        ("Tracking number 0151 23456789 (parcel)", "0151 23456789"),
    ] {
        assert_eq!(context_of(text, value, "PHONE"), Context::Counter, "{text}");
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            assert!(spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
    // The support term is nearer: the counter term elsewhere does not matter.
    let text = "Handy 0151 2345678 (Bestellnummer siehe unten)";
    assert_eq!(
        context_of(text, "0151 2345678", "PHONE"),
        Context::Support { gap: 1 }
    );
}

#[test]
fn terms_of_other_fields_lines_or_words_are_no_context() {
    for text in [
        // The next field's name after a comma, or followed by its own value.
        "Vertrag 0123 4567890, Telefon folgt.",
        "Contract 0123 4567890 phone: unknown",
        // Another line.
        "Telefon:\nVertrag 0123 4567890",
        // Part of a longer word.
        "Vertrag 0123 4567890 telefonisch",
        "Vertrag 0123 4567890 des Handys",
        // Another value between term and number.
        "Telefon 1, Vertrag 0123 4567890",
    ] {
        assert_eq!(
            context_of(text, "0123 4567890", "PHONE"),
            Context::None,
            "{text}"
        );
        assert!(
            !rules(text, PiiMode::Recall).contains(&PROXIMITY_RULE.to_string()),
            "{text}"
        );
    }
    // A counter term with its own value is not context of the next value either.
    let text = "Bestellnummer 4711, bezahlt mit Kreditkarte 5555 5555 5555 4444";
    assert_eq!(
        context_of(text, "5555 5555 5555 4444", "CREDITCARD"),
        Context::Support { gap: 1 }
    );
}

#[test]
fn counter_context_lowers_existing_rules_only_in_scored_modes() {
    for (text, label, balanced, recall) in [
        (
            "Order number 4111 1111 1111 1111 shipped today.",
            "CREDITCARD",
            None,
            Some(0.45),
        ),
        (
            "Bestellnummer 4111 1111 1111 1111 wurde versandt.",
            "CREDITCARD",
            None,
            Some(0.45),
        ),
        ("Invoice no. 415-555-2671 is overdue.", "PHONE", None, None),
        ("Sendungsnummer +49 30 12345678", "PHONE", None, Some(0.30)),
        (
            "Rechnungsnummer: DE89370400440532013000",
            "IBAN",
            Some(0.60),
            Some(0.60),
        ),
    ] {
        let strict = spans(text, PiiMode::Strict);
        assert_eq!(strict.len(), 1, "{text}: {strict:?}");
        assert_eq!(strict[0].0, label, "{text}");
        assert_eq!(strict[0].2, 1.0, "{text}");
        for (mode, expected) in [(PiiMode::Balanced, balanced), (PiiMode::Recall, recall)] {
            let scored = spans(text, mode);
            assert_eq!(
                scored.first().map(|span| span.2),
                expected,
                "{mode:?}: {text}: {scored:?}"
            );
        }
    }
}

#[test]
fn support_terms_raise_unbound_rules_in_scored_modes() {
    for (text, label, expected) in [
        ("Card 4111 1111 1111 1111 expires soon.", "CREDITCARD", 1.0),
        ("Charge it to 3714 496353 98431 please.", "CREDITCARD", 0.75),
        ("Call me at 415-555-2671 tomorrow.", "PHONE", 0.75),
        ("Write to mira@example.com today.", "EMAIL", 0.70),
        ("E-Mail an mira@example.com", "EMAIL", 0.95),
        ("Client IP 198.51.100.23 was blocked.", "IP_ADDRESS", 0.90),
        ("IBAN DE89370400440532013000", "IBAN", 1.0),
    ] {
        let found = spans(text, PiiMode::Balanced);
        assert_eq!(found.len(), 1, "{text}: {found:?}");
        assert_eq!(
            (found[0].0.as_str(), found[0].2),
            (label, expected),
            "{text}"
        );
        assert_eq!(spans(text, PiiMode::Strict)[0].2, 1.0, "{text}");
    }
}

#[test]
fn field_bound_rules_keep_the_field_bonus_next_to_counter_terms() {
    // The value is bound to its own field name; a counter term elsewhere is irrelevant.
    let text = "Bestellnummer 4711, Steuer-ID: 86095742719";
    assert_eq!(
        spans(text, PiiMode::Balanced),
        vec![("STEUERID".to_string(), "86095742719".to_string(), 1.0)]
    );
}

#[test]
fn checksum_and_format_vectors_decide_with_any_context() {
    // Context never rescues a value its validator rejects.
    for (valid, invalid, label, value_of_valid, validator) in [
        (
            "Kreditkarte 4111 1111 1111 1111",
            "Kreditkarte 4111 1111 1111 1112",
            "CREDITCARD",
            "4111 1111 1111 1111",
            validators::luhn as fn(&str) -> bool,
        ),
        (
            "IBAN DE89370400440532013000",
            "IBAN DE88370400440532013000",
            "IBAN",
            "DE89370400440532013000",
            validators::mod97,
        ),
        (
            "Frau Weber ist unter 0176 90817263 erreichbar.",
            "Frau Weber ist unter 0000 00000000 erreichbar.",
            "PHONE",
            "0176 90817263",
            validators::phone,
        ),
    ] {
        let invalid_value = invalid
            .split_whitespace()
            .filter(|part| part.chars().any(|ch| ch.is_ascii_digit()))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(validator(value_of_valid), "{valid}");
        assert!(!validator(&invalid_value), "{invalid}");
        for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
            assert!(
                spans(valid, mode).iter().any(|span| span.0 == label),
                "{mode:?}: {valid}"
            );
            assert!(
                spans(invalid, mode).iter().all(|span| span.0 != label),
                "{mode:?}: {invalid}"
            );
        }
    }
}

#[test]
fn context_bound_rules_score_at_least_the_balanced_threshold_with_support() {
    // A context-bound rule emits only with support, so balanced keeps every
    // strict finding of it.
    let weakest = Context::Support {
        gap: score::PROXIMITY_CONTEXT_POINTS.last().unwrap().0,
    };
    let bound: Vec<_> = PII_PATTERNS
        .iter()
        .filter(|pattern| pattern.requires_context)
        .collect();
    assert_eq!(
        bound.iter().map(|pattern| pattern.name).collect::<Vec<_>>(),
        [
            PROXIMITY_RULE,
            "pii_ssn_us_proximity",
            "pii_nhs_number_uk",
            "pii_passport_number_uk",
            "pii_vat_id_it_proximity",
            "pii_passport_number_de_legacy",
            "pii_identity_card_number_de_legacy"
        ]
    );
    for pattern in bound {
        assert!(!pattern.captured_value, "{}", pattern.name);
        assert!(
            score::score(pattern, weakest) >= PiiMode::Balanced.min_score().unwrap(),
            "{}",
            pattern.name
        );
    }
}

#[test]
fn every_label_has_de_and_en_terms_and_counter_terms_cover_both_languages() {
    let definitions = LexicalAnchorScanner::shared().definitions();
    let words = |ids: &[&str]| {
        let entries: Vec<_> = definitions
            .iter()
            .filter(|definition| ids.contains(&definition.id.as_str()))
            .collect();
        let de = entries
            .iter()
            .map(|e| e.de.len() + e.shared.len())
            .sum::<usize>();
        let en = entries
            .iter()
            .map(|e| e.en.len() + e.shared.len())
            .sum::<usize>();
        (de, en)
    };
    for (label, ids) in SUPPORT_LEXICON {
        let (de, en) = words(ids);
        assert!(de > 0 && en > 0, "{label}: {de} DE / {en} EN terms");
    }
    for id in [
        "pii.order_number",
        "pii.invoice_number",
        "pii.reference_number",
        "pii.product_number",
    ] {
        assert!(COUNTER_LEXICON.contains(&id), "{id}");
        let (de, en) = words(&[id]);
        assert!(de > 0 && en > 0, "{id}: {de} DE / {en} EN terms");
    }
}

#[test]
fn evidence_names_the_deciding_term_its_side_and_distance() {
    let phone = "+49 30 1234567";
    for (text, bonus, anchor, side, distance) in [
        (
            "Telefon: +49 30 1234567",
            25,
            "pii.telephone",
            Side::Before,
            2,
        ),
        ("Phone +49 30 1234567", 25, "pii.telephone", Side::Before, 1),
        (
            "+49 30 1234567 (mobil)",
            25,
            "pii.mobile_phone",
            Side::After,
            2,
        ),
        (
            "+49 30 1234567 (mobile)",
            25,
            "pii.mobile_phone",
            Side::After,
            2,
        ),
        (
            "Phone, during office hours only +49 30 1234567",
            20,
            "pii.telephone",
            Side::Before,
            27,
        ),
        (
            "Telefon (nur werktags, nicht am Wochenende): +49 30 1234567",
            15,
            "pii.telephone",
            Side::Before,
            38,
        ),
        (
            "+49 30 1234567 – rund um die Uhr per Handy",
            20,
            "pii.mobile_phone",
            Side::After,
            23,
        ),
    ] {
        let found = evidence(text, phone, "PHONE");
        assert!(
            matches!(found.context, Context::Support { .. }),
            "{text}: {found:?}"
        );
        assert_eq!((found.bonus(), found.penalty()), (bonus, 0), "{text}");
        assert_eq!(found.anchor, Some(anchor), "{text}");
        assert_eq!(found.side, Some(side), "{text}");
        assert_eq!(found.distance, Some(distance), "{text}");
    }
    for text in [
        "+49 30 1234567",
        "Telefon, aber erst nach Rücksprache mit der Zentrale und nur im Notfall: +49 30 1234567",
        "+49 30 1234567 gilt nur für Rückfragen zum Vertrag, sonst bitte per Handy",
    ] {
        let found = evidence(text, phone, "PHONE");
        assert_eq!(found.context, Context::None, "{text}");
        assert_eq!((found.bonus(), found.penalty()), (0, 0), "{text}");
        assert_eq!(
            (found.anchor, found.side, found.distance),
            (None, None, None),
            "{text}"
        );
    }
}

#[test]
fn context_is_label_specific_case_insensitive_and_unicode_safe() {
    let phone = "+49 30 1234567";
    assert_eq!(
        evidence("TELEFON: +49 30 1234567", phone, "PHONE").bonus(),
        25
    );
    assert_eq!(
        evidence(
            "Grüße – Rückruf über Telefon: +49 30 1234567",
            phone,
            "PHONE"
        )
        .bonus(),
        25
    );
    assert_eq!(
        evidence("Grüße – Telefon: +49 30 1234567", phone, "PHONE").distance,
        Some(2)
    );
    // A phone field name says nothing about an e-mail address.
    let found = evidence("Telefon: ada@example.com", "ada@example.com", "EMAIL");
    assert_eq!((found.bonus(), found.penalty()), (0, 0));
    assert_eq!(
        evidence("E-Mail: ada@example.com", "ada@example.com", "EMAIL").bonus(),
        25
    );
    // The value itself is never its own context.
    let found = evidence("email@example.com", "email@example.com", "EMAIL");
    assert_eq!(found.anchor, None);
}

#[test]
fn context_stops_at_line_breaks() {
    let phone = "+49 30 1234567";
    for text in [
        "Telefon\n+49 30 1234567",
        "Bestellnummer\n+49 30 1234567",
        "+49 30 1234567\r\n(mobil)",
    ] {
        let found = evidence(text, phone, "PHONE");
        assert_eq!((found.bonus(), found.penalty()), (0, 0), "{text:?}");
    }
}

#[test]
fn short_terms_count_only_as_words_of_their_own() {
    let phone = "212-736-4410";
    for (text, bonus) in [
        ("Fax 212-736-4410", 25),
        ("Telefonnummer 212-736-4410", 25),
        ("Hotelfaxe 212-736-4410", 0),
        ("Taxfax212-736-4410", 0),
    ] {
        assert_eq!(evidence(text, phone, "PHONE").bonus(), bonus, "{text}");
    }
    // `sku` is counter-context only as a word of its own.
    assert_eq!(
        evidence("SKU 212-736-4410", phone, "PHONE").penalty(),
        COUNTER_CONTEXT_POINTS
    );
    assert_eq!(
        evidence("Muskuläre 212-736-4410", phone, "PHONE").penalty(),
        0
    );
}

#[test]
fn counter_context_names_its_lexicon_entry() {
    let phone = "202-604-7110";
    for (text, anchor) in [
        ("Bestellnummer 202-604-7110", "pii.order_number"),
        ("Order number 202-604-7110", "pii.order_number"),
        ("Rechnungsnummer: 202-604-7110", "pii.invoice_number"),
        ("Invoice no. 202-604-7110", "pii.invoice_number"),
        ("Sendungsnummer 202-604-7110", "pii.shipment_number"),
        ("Tracking number: 202-604-7110", "pii.shipment_number"),
        ("Vorgangsnummer 202-604-7110", "pii.ticket_number"),
        ("Transaction ID 202-604-7110", "pii.reference_number"),
        ("Seriennummer 202-604-7110", "pii.product_number"),
        ("Serial number 202-604-7110", "pii.product_number"),
    ] {
        let found = evidence(text, phone, "PHONE");
        assert_eq!(found.context, Context::Counter, "{text}");
        assert_eq!(
            (found.bonus(), found.penalty()),
            (0, COUNTER_CONTEXT_POINTS),
            "{text}"
        );
        assert_eq!(found.anchor, Some(anchor), "{text}");
        assert_eq!(found.side, Some(Side::Before), "{text}");
    }
}

#[test]
fn the_nearest_term_decides() {
    let phone = "+49 30 1234567";
    // Support nearer than the counter term, or the counter term names another value.
    for text in [
        "Bestellnummer 4711, Rückfragen unter Telefon +49 30 1234567",
        "Telefon +49 30 1234567, Rechnungsnummer 88213",
        "+49 30 1234567 (mobil), Auftragsnummer 2026-118",
    ] {
        let found = evidence(text, phone, "PHONE");
        assert!(found.bonus() > 0, "{text}");
        assert_eq!(found.penalty(), 0, "{text}");
    }
    // The counter term is nearer: only the penalty counts.
    let found = evidence(
        "Telefon-Hotline, Bestellnummer +49 30 1234567",
        phone,
        "PHONE",
    );
    assert_eq!(
        (found.bonus(), found.penalty()),
        (0, COUNTER_CONTEXT_POINTS)
    );
    assert_eq!(found.anchor, Some("pii.order_number"));
    // Equal distance: support wins.
    let found = evidence("Telefon +49 30 1234567 Bestellnummer", phone, "PHONE");
    assert_eq!((found.bonus(), found.penalty()), (25, 0));
}

#[test]
fn balanced_scores_follow_the_context_and_strict_ignores_it() {
    for (text, label, rule_id, bonus, penalty) in [
        ("Tel. 212-736-4410", "PHONE", "pii_phone_us", 25, 0),
        ("212-736-4410 (Festnetz)", "PHONE", "pii_phone_us", 25, 0),
        ("Call 212-736-4410", "PHONE", "pii_phone_us", 0, 0),
        (
            "Kreditkarte 4111 1111 1111 1111",
            "CREDITCARD",
            "pii_credit_card",
            25,
            0,
        ),
        ("IBAN DE89370400440532013000", "IBAN", "pii_iban_de", 25, 0),
        ("E-Mail: ada@example.com", "EMAIL", "pii_email", 25, 0),
        (
            "Bestellnummer 4532 0151 1283 0366",
            "CREDITCARD",
            "pii_credit_card",
            0,
            30,
        ),
    ] {
        let expected = model_score(pattern(rule_id), bonus, penalty);
        for mode in [PiiMode::Balanced, PiiMode::Recall] {
            let result = pii_result(text, mode);
            let rules = matched_rules(&result);
            if expected < mode.min_score().unwrap() {
                assert_eq!(span_score(&result, label), None, "{mode:?}: {text}");
                assert!(rule(&rules, rule_id).is_none(), "{mode:?}: {text}");
                continue;
            }
            assert_eq!(
                span_score(&result, label),
                Some(expected),
                "{mode:?}: {text}"
            );
            let matched = rule(&rules, rule_id).unwrap_or_else(|| panic!("{mode:?}: {text}"));
            assert_eq!(matched["score"], expected, "{mode:?}: {text}");
            assert_eq!(matched["context"]["bonus"], bonus, "{mode:?}: {text}");
            assert_eq!(matched["context"]["penalty"], penalty, "{mode:?}: {text}");
        }
        let strict = pii_result(text, PiiMode::Strict);
        assert_eq!(span_score(&strict, label), Some(1.0), "strict: {text}");
        for matched in matched_rules(&strict) {
            assert!(matched.get("score").is_none(), "strict: {text}");
            assert!(matched.get("context").is_none(), "strict: {text}");
        }
    }
}

#[test]
fn matched_rules_explain_the_deciding_context() {
    let result = pii_result("Rückfragen unter Telefon +49 30 1234567", PiiMode::Balanced);
    let rules = matched_rules(&result);
    let context = &rule(&rules, "pii_phone_de").unwrap()["context"];
    assert_eq!(context["bonus"], 25);
    assert_eq!(context["penalty"], 0);
    assert_eq!(context["anchor"], "pii.telephone");
    assert_eq!(context["side"], "before");
    assert_eq!(context["distance"], 1);

    // A counter term names itself.
    let result = pii_result("Bestellnummer 4111 1111 1111 1111", PiiMode::Recall);
    let rules = matched_rules(&result);
    let context = &rule(&rules, "pii_credit_card").unwrap()["context"];
    assert_eq!(context["bonus"], 0);
    assert_eq!(context["penalty"], COUNTER_CONTEXT_POINTS);
    assert_eq!(context["anchor"], "pii.order_number");
    assert_eq!(context["side"], "before");
    assert_eq!(context["distance"], 1);

    // Field-bound rules name their own field.
    let result = pii_result(
        "Bestellnummer 4711, Steuer-ID: 86095742719",
        PiiMode::Balanced,
    );
    let rules = matched_rules(&result);
    let context = &rule(&rules, "pii_steuer_id_de").unwrap()["context"];
    assert_eq!(context["bonus"], FIELD_CONTEXT_POINTS);
    assert_eq!(context["penalty"], 0);
    assert_eq!(context["anchor"], "field");

    let result = pii_result("Call 212-736-4410", PiiMode::Balanced);
    let rules = matched_rules(&result);
    let context = &rule(&rules, "pii_phone_us").unwrap()["context"];
    assert_eq!(context["bonus"], 0);
    assert!(context.get("anchor").is_none());
}

#[test]
fn field_bound_values_never_take_a_penalty() {
    for (text, label) in [
        ("Bestellnummer 4711, Steuer-ID: 86095742719", "STEUERID"),
        (
            "Rechnungsnummer 88213, Kontonummer: 1234567890",
            "FINANCIAL_ACCOUNT_NUMBER",
        ),
        ("Order number 4711, SSN: 123-45-6789", "SSN"),
    ] {
        let strict = pii_result(text, PiiMode::Strict);
        let balanced = pii_result(text, PiiMode::Balanced);
        assert!(span_score(&strict, label).is_some(), "{text}");
        let field_score = PII_PATTERNS
            .iter()
            .filter(|p| p.entity_group == label && p.captured_value)
            .map(score::rule_score)
            .fold(0.0, f64::max);
        assert_eq!(span_score(&balanced, label), Some(field_score), "{text}");
    }
}

#[test]
fn checksum_vectors_decide_emission_next_to_any_context() {
    // Valid and invalid check digits next to strong context and next to
    // counter-context: context moves the score, never the validator.
    for (valid, invalid, label, validator) in [
        (
            "4111 1111 1111 1111",
            "4111 1111 1111 1112",
            "CREDITCARD",
            validators::luhn as fn(&str) -> bool,
        ),
        (
            "DE89370400440532013000",
            "DE88370400440532013000",
            "IBAN",
            validators::mod97,
        ),
    ] {
        assert!(validator(valid), "{valid}");
        assert!(!validator(invalid), "{invalid}");
        for prefix in [
            "Kreditkarte ",
            "Bankkonto ",
            "Bestellnummer ",
            "Invoice no. ",
        ] {
            for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
                let rejected = pii_result(&format!("{prefix}{invalid}"), mode);
                assert_eq!(
                    span_score(&rejected, label),
                    None,
                    "{mode:?}: {prefix}{invalid}"
                );
            }
            let strict = pii_result(&format!("{prefix}{valid}"), PiiMode::Strict);
            assert_eq!(span_score(&strict, label), Some(1.0), "{prefix}{valid}");
        }
    }
    // Steuer-ID: valid after its field stays in every mode, invalid never appears.
    for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
        let valid = pii_result("Rechnungsnummer 88213, Steuer-ID: 86095742719", mode);
        assert!(span_score(&valid, "STEUERID").is_some(), "{mode:?}");
        let invalid = pii_result("Rechnungsnummer 88213, Steuer-ID: 86095742718", mode);
        assert_eq!(span_score(&invalid, "STEUERID"), None, "{mode:?}");
    }
}

#[derive(Deserialize)]
struct Probes {
    de: String,
    en: String,
}

#[derive(Deserialize)]
struct BalancedProbes {
    context: Probes,
    counter: Option<Probes>,
}

#[derive(Deserialize)]
struct Case {
    category: String,
    rule_id: String,
    balanced: Option<BalancedProbes>,
}

#[test]
fn bilingual_rule_fixture_probes_context_and_counter_context() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let probed: Vec<_> = cases
        .iter()
        .filter(|case| case.category == "pii")
        .filter_map(|case| case.balanced.as_ref().map(|probes| (case, probes)))
        .collect();
    assert!(probed.len() >= 6, "{} probed rules", probed.len());
    assert!(
        probed
            .iter()
            .filter(|(_, probes)| probes.counter.is_some())
            .count()
            >= 3
    );
    for (case, probes) in probed {
        for text in [&probes.context.de, &probes.context.en] {
            let result = pii_result(text, PiiMode::Balanced);
            let rules = matched_rules(&result);
            let matched =
                rule(&rules, &case.rule_id).unwrap_or_else(|| panic!("{}: {text}", case.rule_id));
            assert!(
                matched["context"]["bonus"].as_u64().unwrap() > 0,
                "{}: {text}: {matched}",
                case.rule_id
            );
        }
        if let Some(counter) = &probes.counter {
            for text in [&counter.de, &counter.en] {
                let strict = matched_rules(&pii_result(text, PiiMode::Strict));
                assert!(
                    rule(&strict, &case.rule_id).is_some(),
                    "strict {}: {text}",
                    case.rule_id
                );
                let balanced = pii_result(text, PiiMode::Balanced);
                assert!(
                    rule(&matched_rules(&balanced), &case.rule_id).is_none(),
                    "balanced {}: {text}",
                    case.rule_id
                );
            }
        }
    }
}
