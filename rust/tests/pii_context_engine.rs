//! PII context engine v2 (K03).
//!
//! Support terms of a label and counter-context terms (order, invoice, tracking,
//! ticket, reference, serial numbers) come from the DE/EN lexicon in
//! `anchor_lexicons/pii.json`. The nearest term on either side of a value
//! decides: a support term adds proximity points, a strictly nearer counter term
//! removes 30. `strict` keeps its acceptance for every existing rule; only
//! context-bound rules (`requires_context`) consult the engine there.

use patronus_ark::detectors::lexical_anchors::LexicalAnchorScanner;
use patronus_ark::detectors::pii::{
    context::{self, AFTER_WINDOW, BEFORE_WINDOW, COUNTER_LEXICON, SUPPORT_LEXICON},
    pii::PII_PATTERNS,
    score::{self, Context, PiiMode},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

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

fn pattern(rule_id: &str) -> &'static patronus_ark::detectors::pii::pii::PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
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
        [PROXIMITY_RULE]
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
