// SPDX-License-Identifier: GPL-3.0-only
//! Licence plates (T30, Q-M1).
//!
//! A plate carries no check digit, and ARK keeps no district-code list (F16 stays
//! deferred): in `strict` both plate rules are field-bound. They share one field
//! part, the DE/EN plate field names before the value (`Kfz-Kennzeichen:`,
//! `Number plate |`, `The Vehicle registration on file is`, `My car, registration`,
//! `My car reg is`) or as its structural key (`kennzeichen`, `license_plate`). The
//! German value may carry a hyphen before the digits (`K-MH-2476`) and the `E`/`H`
//! suffix; the UK current form (`AB51 ABC`) needs an issued age identifier. A bare
//! value without a plate term is no finding in `strict`, also the TR, IN and NG
//! values of the presidio-analyzer tests. In `balanced` and `recall` (Q-M1) the UK
//! current form is also reported bare at the threshold, and the Nigerian plate
//! (`APP-456CV`) with a plate term near it, a later plate of a list with the term
//! of the first.
//!
//! T36 adds the older UK prefix (`A123 BCD`, `K1 ABC`) and suffix (`ABC 1D`)
//! forms and the Indian plate without separators (`KA53ME3456`, a state code
//! instead of a district list) with a plate term near them in the scored modes;
//! their bare forms and the lower-case Nigerian plate are opt-in rules
//! (`rust/tests/pii_bare_rules.rs`).

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, ValidatorStrength},
    validators,
};
use patronus_ark::ScoreMode;
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const DE: &str = "pii_kfz_kennzeichen_de";
const UK: &str = "pii_vehicle_registration_uk";
const UK_CONTEXT_FREE: &str = "pii_vehicle_registration_uk_context_free";
const NG: &str = "pii_vehicle_registration_ng";
const UK_PREFIX: &str = "pii_vehicle_registration_uk_prefix";
const UK_SUFFIX: &str = "pii_vehicle_registration_uk_suffix";
const IN: &str = "pii_vehicle_registration_in";
const SCORED: [ScoreMode; 2] = [ScoreMode::Balanced, ScoreMode::Recall];
const LABEL: &str = "LICENSEPLATE";
const MODES: [ScoreMode; 3] = [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall];

fn pii_result(text: &str, mode: ScoreMode) -> SecurityScanResult {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix {
        native: patronus_ark::NativeGates {
            pii_mode: mode,
            ..Default::default()
        },
        ..Default::default()
    });
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

/// `(text, score)` of every plate span.
fn plates(text: &str, mode: ScoreMode) -> Vec<(String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == LABEL)
        .map(|span| (span.text, span.score))
        .collect()
}

/// Rule ids that matched with the value text they matched.
fn rules(text: &str, mode: ScoreMode) -> Vec<(String, String)> {
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

/// `rule_id` reports `value`, the only plate span, in every mode.
fn assert_reports(rule_id: &str, text: &str, value: &str) {
    for mode in MODES {
        assert!(
            rules(text, mode)
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report {value:?} in {text:?}"
        );
        let found = plates(text, mode);
        assert!(
            found.len() == 1 && found[0].0 == value,
            "{mode}: {value:?} must be the only plate in {text:?}, got {found:?}"
        );
    }
}

fn assert_silent(text: &str) {
    assert_silent_in(text, &MODES);
}

fn assert_silent_in(text: &str, modes: &[ScoreMode]) {
    for &mode in modes {
        assert!(
            plates(text, mode).is_empty(),
            "{mode}: no plate expected in {text:?}"
        );
    }
}

// ── validator ────────────────────────────────────────────────────────────────

#[test]
fn de_licence_plate_validator_checks_length_and_number() {
    for valid in [
        "B-AB 1234E",
        "M XY 42",
        "K-A 778H",
        "K-MH-2476",
        "H-J-6815E",
        "FÜ-EJ 3281H",
        "KA HW 29H",
        "BÖ-GR-3108E",
        "HH-MU 4720",
        "B-A 1",
        "DO-AB 1234H",
    ] {
        assert!(validators::de_licence_plate(valid), "{valid} must be valid");
    }
    for invalid in [
        // more than eight characters without separators and suffix
        "ABC-DE 1234",
        "ABC-DE 1234E",
        "LÖW-AB 1234",
        // a number with a leading zero
        "B-AB 0123",
        "K-MH-0476",
        "M XY 0",
    ] {
        assert!(
            !validators::de_licence_plate(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn uk_vehicle_registration_validator_checks_the_age_identifier() {
    for valid in [
        // presidio-analyzer tests and its current-format range
        "AB51 ABC", "BD62XYZ", "AB02 ABC", "AB29 ABC", "AB79 ABC", "AB51-ABC",
        // ark_authored dev forms
        "LW02 ULF", "KS54 WLS", "YB68 TXM",
    ] {
        assert!(
            validators::uk_vehicle_registration(valid),
            "{valid} must be valid"
        );
    }
    for invalid in [
        // presidio-analyzer negatives: never issued area letters and age identifiers
        "IB51 ABC",
        "AQ51 ABC",
        "AB00 ABC",
        "AB80 ABC",
        // age identifiers outside 02–29 and 51–79
        "AB01 ABC",
        "AB30 ABC",
        "AB50 ABC",
        "AB99 ABC",
        // I and Q are no random letters; lowercase, short, long or mixed forms
        "AB51 IBC",
        "AB51 AQC",
        "ab51 abc",
        "AB51 AB",
        "AB51 ABCD",
        "A51 ABC",
        "AB5 ABC",
        "AB51  ABC",
        "AB51_ABC",
        "",
    ] {
        assert!(
            !validators::uk_vehicle_registration(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn ng_vehicle_registration_validator_checks_the_form() {
    for valid in ["APP-456CV", "KJA-999PZ", "ABJ-001AA", "LSR 123AB"] {
        assert!(
            validators::ng_vehicle_registration(valid),
            "{valid} must be valid"
        );
    }
    for invalid in [
        "APP-000CV",
        "app-456cv",
        "APP456CV",
        "APP_456CV",
        "AP-456CV",
        "APP-4567CV",
        "APP-456C",
        "AP1-456CV",
        "",
    ] {
        assert!(
            !validators::ng_vehicle_registration(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn ng_vehicle_registration_lowercase_validator_checks_the_form() {
    for valid in ["app-456cv", "kja-999pz", "abj-001aa"] {
        assert!(
            validators::ng_vehicle_registration_lowercase(valid),
            "{valid} must be valid"
        );
    }
    for invalid in [
        "APP-456CV",
        "app-000cv",
        "app 456cv",
        "App-456cv",
        "app-456Cv",
        "app456cv",
        "ap-456cv",
        "app-4567cv",
        "",
    ] {
        assert!(
            !validators::ng_vehicle_registration_lowercase(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn uk_prefix_and_suffix_validators_check_the_letter_sets() {
    // Prefix form 1983–2001: age letter, serial 1–999, three letters.
    for valid in ["A123 BCD", "K1 ABC", "P999XYW", "Y45 HJK", "R7 ABW"] {
        assert!(
            validators::uk_vehicle_registration_prefix(valid),
            "{valid} must be valid"
        );
    }
    for invalid in [
        "I123 BCD",
        "O123 BCD",
        "Q123 BCD",
        "U123 BCD",
        "Z123 BCD",
        "A0 BCD",
        "A012 BCD",
        "A1234 BCD",
        "A123 BID",
        "A123 BCQ",
        "A123 ZCD",
        "A123  BCD",
        "A123-BCD",
        "a123 bcd",
        "",
    ] {
        assert!(
            !validators::uk_vehicle_registration_prefix(invalid),
            "{invalid} must be invalid"
        );
    }
    // Suffix form 1963–1983: three letters, serial 1–999, year letter.
    for valid in ["ABC 1D", "ABC 123D", "XYW999Y", "HJK 45A"] {
        assert!(
            validators::uk_vehicle_registration_suffix(valid),
            "{valid} must be valid"
        );
    }
    for invalid in [
        "ABC 123I",
        "ABC 123Z",
        "ABC 123O",
        "ABC 123Q",
        "ABC 123U",
        "ABC 0D",
        "ABC 012D",
        "ABC 1234D",
        "AIC 123D",
        "QBC 123D",
        "ABZ 123D",
        "ABC 12 3D",
        "abc 1d",
        "",
    ] {
        assert!(
            !validators::uk_vehicle_registration_suffix(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn in_vehicle_registration_validator_checks_the_state_code() {
    for valid in [
        "KA53ME3456",
        "MH12AB1234",
        "DL3C1234",
        "TN07BZ9999",
        "UP16ABC1001",
        "WB2A0001",
    ] {
        assert!(
            validators::in_vehicle_registration(valid),
            "{valid} must be valid"
        );
    }
    for invalid in [
        // no state code
        "AB53ME3456",
        "XY12AB1234",
        // district 0/00, number 0000, series with I or O, lengths
        "KA00ME3456",
        "KA0ME3456",
        "KA53ME0000",
        "KA53IE3456",
        "KA53MO3456",
        "KA53ME34567",
        "KA53ME345",
        "KA53ABCD3456",
        "KA533ME3456",
        "KA53 ME 3456",
        "ka53me3456",
        "",
    ] {
        assert!(
            !validators::in_vehicle_registration(invalid),
            "{invalid} must be invalid"
        );
    }
}

#[test]
fn plate_rules_are_field_bound_format_rules_in_every_mode() {
    for rule_id in [DE, UK] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, LABEL);
        assert!(rule.captured_value, "{rule_id} binds a field name");
        assert!(!rule.requires_context && !rule.scored_only, "{rule_id}");
        // Field bonus: both rules reach the same score in the scored modes.
        assert_eq!(score::rule_score(rule), 0.65, "{rule_id}");
        assert_eq!(rule.strength, ValidatorStrength::Format, "{rule_id}");
        assert!(rule.validator.is_some(), "{rule_id}");
    }
}

// ── German plates ────────────────────────────────────────────────────────────

#[test]
fn de_plates_with_a_hyphen_before_the_digits_and_a_suffix() {
    for (text, value) in [
        ("Kfz-Kennzeichen: AC-F-1471", "AC-F-1471"),
        ("Kennzeichen:\tE-L-3328", "E-L-3328"),
        ("Kfz-Kennzeichen: MS-DX 3004E", "MS-DX 3004E"),
        (
            "Nachtrag zu meinen Daten, Kfz-Kennzeichen HH-MU 4720.",
            "HH-MU 4720",
        ),
        (
            "Unsere Unterlagen nennen als Kennzeichen: KA HW 29H.",
            "KA HW 29H",
        ),
        (
            "Ich bestätige folgende Angabe (Kennzeichen): BÖ-GR-3108E.",
            "BÖ-GR-3108E",
        ),
        ("Als Kennzeichen ist DD-S-4934 hinterlegt.", "DD-S-4934"),
        ("Kennzeichen | H-J-6815E", "H-J-6815E"),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plates_after_english_plate_field_names_and_prose() {
    for (text, value) in [
        ("Number plate: FÜ-CB 3876", "FÜ-CB 3876"),
        ("Number plate | HH-M 2328H", "HH-M 2328H"),
        (
            "The Vehicle registration on file is MA-A 1879H.",
            "MA-A 1879H",
        ),
        (
            "My car, registration FÜ-EJ 3281H, was parked outside.",
            "FÜ-EJ 3281H",
        ),
        (
            "Our records list the Number plate as K-MH-2476.",
            "K-MH-2476",
        ),
        ("Licence plate number: F-RF-8363H", "F-RF-8363H"),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plates_under_a_structural_key() {
    for (text, value) in [
        (r#"{"kennzeichen": "K-MH-2476"}"#, "K-MH-2476"),
        (r#"{"license_plate": "F-RF-8363H"}"#, "F-RF-8363H"),
        (r#"{"kfzKennzeichen": "BÖ-GR-3108E"}"#, "BÖ-GR-3108E"),
        ("<numberPlate>DD-S-4934</numberPlate>", "DD-S-4934"),
        (
            "nr;name;kennzeichen\n1;Jonas Weber;HH AW 7914H",
            "HH AW 7914H",
        ),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plates_keep_the_existing_forms() {
    for (text, value) in [
        ("KFZ-Kennzeichen: B-AB 1234E", "B-AB 1234E"),
        ("Vehicle registration M XY 42", "M XY 42"),
        ("Nummernschild: K-A 778H", "K-A 778H"),
        (
            "Mein Wagen mit dem Kennzeichen BN-Y 2890 stand vor dem Haus.",
            "BN-Y 2890",
        ),
    ] {
        assert_reports(DE, text, value);
    }
}

#[test]
fn de_plate_lookalikes_stay_silent() {
    for text in [
        // bare values and other field names
        "K-MH-2476",
        "Bestellnummer: AB-CD-1234",
        "Order number: K-MZ-2471",
        "Parkplatz B-AB 1234E",
        // words after the field name, too many digits, too long a prefix
        "Das Kennzeichen ist am 12. Mai abgelaufen.",
        "Kennzeichen: K-MZ-24710",
        "Kennzeichen: BERLIN-123",
        "Kennzeichen: B-12 345",
        "Kennzeichen: ABC-DE 1234",
        "Kennzeichen: B-AB 0123",
        // a lowercase value is no printed plate
        "Kennzeichen: ab-cd 12",
        // a generic registration number names no plate
        "Registration number: K-MH-2476",
    ] {
        assert_silent(text);
    }
}

// ── UK plates ────────────────────────────────────────────────────────────────

#[test]
fn uk_plates_after_plate_field_names_and_prose() {
    for (text, value) in [
        ("The Vehicle registration on file is LW02 ULF.", "LW02 ULF"),
        (
            "My car, registration YB68 TXM, was parked outside.",
            "YB68 TXM",
        ),
        // presidio-analyzer test case
        ("My car reg is AB51 ABC and it expires", "AB51 ABC"),
        ("Number plate | BD62XYZ", "BD62XYZ"),
        ("Kennzeichen: LW02 ULG", "LW02 ULG"),
        ("Car registration number: KS54 WLS", "KS54 WLS"),
    ] {
        assert_reports(UK, text, value);
    }
}

#[test]
fn uk_plates_under_a_structural_key() {
    for (text, value) in [
        (r#"{"license_plate": "KS54 WLS"}"#, "KS54 WLS"),
        (r#"{"licensePlate": "KS54 WLT"}"#, "KS54 WLT"),
        (r#"{"kennzeichen": "LW02 ULF"}"#, "LW02 ULF"),
        ("row,name,license_plate\n1,Ada Weber,YB68 TXM", "YB68 TXM"),
    ] {
        assert_reports(UK, text, value);
    }
}

#[test]
fn uk_plate_lookalikes_stay_silent() {
    // presidio-analyzer values reported bare in the scored modes only (Q-M1)
    for text in ["AB51 ABC", "BD62XYZ"] {
        assert_silent_in(text, &[ScoreMode::Strict]);
    }
    for text in [
        // presidio-analyzer negatives
        "IB51 ABC",
        "AQ51 ABC",
        "AB00 ABC",
        "AB80 ABC",
        // invalid forms after a plate field name
        "Vehicle registration: AB80 ABC",
        "Number plate: IB51 ABC",
        "Licence plate: AB51 ABCD",
        // other field names
        "Order number: AB51 ABC",
        "Bestellnummer: AB51 ABC",
        "My car registration is overdue.",
    ] {
        assert_silent(text);
    }
}

#[test]
fn bare_plates_of_other_countries_stay_silent() {
    // presidio_favored TR, IN, NG and UK prefix/suffix values: without a plate
    // term only the opt-in bare rules report them (T36).
    for text in [
        "34 ABC 1234",
        "34ABC1234",
        "07 AB 123",
        "KA53ME3456",
        "MN2412",
        "APP-456CV",
        "ABJ-001AA",
        "APP-456CV and KJA-999PZ",
        "A123 BCD",
        "K1 ABC",
        "ABC 1D",
    ] {
        assert_silent(text);
    }
    // A Nigerian plate with a plate term is a scored-mode finding only (Q-M1).
    assert_silent_in("Plates: APP-456CV and KJA-999PZ", &[ScoreMode::Strict]);
}

// ── Scored modes: bare UK plates, Nigerian plates with a plate term (Q-M1) ──

#[test]
fn scored_plate_rules_run_in_balanced_and_recall_only() {
    let bare = pattern(UK_CONTEXT_FREE);
    assert!(bare.scored_only && !bare.requires_context && !bare.captured_value);
    assert!(bare
        .validator
        .is_some_and(|check| check("AB51 ABC") && !check("AB80 ABC")));
    // Without context the bare form just reaches the balanced threshold.
    assert_eq!(score::rule_score(bare), 0.50);
    let ng = pattern(NG);
    assert!(ng.scored_only && ng.requires_context && !ng.captured_value);
    assert_eq!(score::rule_score(ng), 0.40);
    assert_eq!(bare.strength, ValidatorStrength::Format);
    for rule in [bare, ng] {
        assert_eq!(rule.entity_group, LABEL);
        assert_eq!(rule.strength, ValidatorStrength::Format);
    }
}

/// `rule_id` reports exactly `values` as the plate spans of `text` in the scored
/// modes, at `score`, and `strict` reports none.
fn assert_scored(rule_id: &str, text: &str, values: &[&str], score: f64) {
    for mode in SCORED {
        let found = plates(text, mode);
        let expected: Vec<(String, f64)> = values
            .iter()
            .map(|value| (value.to_string(), score))
            .collect();
        assert_eq!(found, expected, "{mode}: plates of {text:?}");
        for value in values {
            assert!(
                rules(text, mode)
                    .iter()
                    .any(|(rule, found)| rule == rule_id && found == value),
                "{mode}: {rule_id} must report {value:?} in {text:?}"
            );
        }
    }
    assert_silent_in(text, &[ScoreMode::Strict]);
}

#[test]
fn bare_uk_plates_in_the_scored_modes() {
    for (text, value) in [
        // presidio-analyzer test cases
        ("AB51 ABC", "AB51 ABC"),
        ("BD62XYZ", "BD62XYZ"),
        (
            "The blue van LW02 ULF was seen leaving at noon.",
            "LW02 ULF",
        ),
        ("Der Transporter KS54 WLS stand vor dem Tor.", "KS54 WLS"),
        ("YB68-TXM", "YB68-TXM"),
    ] {
        assert_scored(UK_CONTEXT_FREE, text, &[value], 0.50);
    }
}

#[test]
fn bare_uk_plate_lookalikes_stay_silent_in_the_scored_modes() {
    for text in [
        // never issued area letters and age identifiers, I/Q as random letters
        "IB51 ABC",
        "AQ51 ABC",
        "AB00 ABC",
        "AB80 ABC",
        "AB51 IBC",
        // a nearer counter-context term, lowercase, part of a longer value
        "Order number: AB51 ABC",
        "Bestellnummer: AB51 ABC",
        "ab51 abc",
        "AB51 ABCD",
        "XAB51 ABC",
        "AB51 ABC-7",
    ] {
        assert_silent(text);
    }
}

#[test]
fn nigerian_plates_with_a_plate_term_in_the_scored_modes() {
    for (text, values) in [
        // presidio-analyzer test case: the second plate takes the term of the first
        (
            "Plates: APP-456CV and KJA-999PZ",
            &["APP-456CV", "KJA-999PZ"][..],
        ),
        (
            "Plates: APP-456CV, KJA-999PZ, ABJ-001AA",
            &["APP-456CV", "KJA-999PZ", "ABJ-001AA"],
        ),
        (
            "Kennzeichen: APP-456CV und KJA-999PZ",
            &["APP-456CV", "KJA-999PZ"],
        ),
        (
            "The car with number plate ABJ-001AA was towed.",
            &["ABJ-001AA"],
        ),
        ("Plates: APP 456CV", &["APP 456CV"]),
        (
            "Das Fahrzeug mit dem Kennzeichen ABJ-001AA stand im Halteverbot.",
            &["ABJ-001AA"],
        ),
    ] {
        assert_scored(NG, text, values, 0.65);
    }
}

#[test]
fn nigerian_plate_lookalikes_stay_silent() {
    for text in [
        // no plate term, also for a list
        "APP-456CV",
        "APP-456CV and KJA-999PZ",
        "Artikel ABJ-001AA und KJA-999PZ",
        "Order number: APP-456CV",
        "Bestellnummer: KJA-999PZ",
        // lowercase, no separator, four digits, part of a longer value
        "Plates: app-456cv",
        "Plates: APP456CV",
        "Kennzeichen: APP-4567CV",
        "Plates: XAPP-456CV",
        // a list joined by something other than a comma, `and`, `und` or `&`
        "Plates: APP-456CV or KJA-999PZ",
    ] {
        let found = plates(text, ScoreMode::Recall);
        assert!(
            found
                .iter()
                .all(|(value, _)| value == "APP-456CV" && text.starts_with("Plates: APP-456CV")),
            "unexpected plates in {text:?}: {found:?}"
        );
    }
    for text in [
        "APP-456CV",
        "APP-456CV and KJA-999PZ",
        "Order number: APP-456CV",
        "Plates: app-456cv",
    ] {
        assert_silent(text);
    }
}

// ── T36: UK prefix and suffix forms, Indian plates with a plate term ─────────

#[test]
fn t36_plate_rules_need_a_plate_term_in_the_scored_modes() {
    for rule_id in [UK_PREFIX, UK_SUFFIX, IN] {
        let rule = pattern(rule_id);
        assert!(
            rule.scored_only && rule.requires_context && !rule.captured_value,
            "{rule_id}"
        );
        assert_eq!(rule.entity_group, LABEL);
        assert_eq!(rule.strength, ValidatorStrength::Format);
        assert_eq!(score::rule_score(rule), 0.40, "{rule_id}");
        let bare = pattern(&format!("{rule_id}_bare"));
        assert_eq!(bare.pattern, rule.pattern, "{rule_id}");
        assert_eq!(score::rule_score(bare), 0.50, "{rule_id}");
    }
}

#[test]
fn t36_plates_with_a_plate_term_in_the_scored_modes() {
    for (rule_id, text, value) in [
        (
            UK_PREFIX,
            "My number plate is A123 BCD and it expires.",
            "A123 BCD",
        ),
        (UK_PREFIX, "Number plate K1 ABC", "K1 ABC"),
        (UK_PREFIX, "Kennzeichen: P999 XYW", "P999 XYW"),
        (
            UK_PREFIX,
            "Das Fahrzeug mit dem Kennzeichen Y45 HJK stand im Halteverbot.",
            "Y45 HJK",
        ),
        (UK_SUFFIX, "Number plate: ABC 1D", "ABC 1D"),
        (
            UK_SUFFIX,
            "The classic car with registration plate HJK 45A was sold.",
            "HJK 45A",
        ),
        (UK_SUFFIX, "Nummernschild XYW 999Y", "XYW 999Y"),
        (IN, "Vehicle registration KA53ME3456", "KA53ME3456"),
        (
            IN,
            "The car with number plate MH12AB1234 was towed.",
            "MH12AB1234",
        ),
        (IN, "Kennzeichen: DL3C1234", "DL3C1234"),
    ] {
        assert_scored(rule_id, text, &[value], 0.65);
    }
}

#[test]
fn t36_plate_lookalikes_stay_silent() {
    for text in [
        // bare values with the default gates (opt-in: pii_bare_rules.rs)
        "A123 BCD",
        "K1 ABC",
        "ABC 1D",
        "KA53ME3456",
        "app-456cv",
        // letter sets, serials and state codes that are never issued
        "Number plate: I123 BCD",
        "Number plate: O123 BCD",
        "Number plate: ABC 123I",
        "Number plate: ABC 123Z",
        "Number plate: A1234 BCD",
        "Kennzeichen: AB53ME3456",
        "Kennzeichen: KA00ME3456",
        // UK postcodes and product codes near a plate term
        "Number plate delivery to SW1A 1AA",
        "Kennzeichen-Versand an M1 1AE",
        "Number plate: CR2 6XH",
        "Order number: A123 BCD",
        "Bestellnummer: KA53ME3456",
        "Artikelnummer ABC 123D",
        // part of a longer value
        "Number plate: XA123 BCD",
        "Number plate: KA53ME3456-7",
    ] {
        assert_silent(text);
    }
}
