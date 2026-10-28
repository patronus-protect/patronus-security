// SPDX-License-Identifier: GPL-3.0-only
//! Spanish and Italian identifiers (B-ESIT: A11, A12).
//!
//! Three personal numbers with a check letter, one label each: the Spanish DNI/NIF
//! (`ES_NIF`, eight digits and a control letter mod 23), the Spanish NIE
//! (`ES_NIE`, `X`/`Y`/`Z`, seven digits, the same control letter) and the Italian
//! codice fiscale (`IT_FISCAL_CODE`, sixteen characters, check letter mod 26,
//! omocodia). Each label has a rule that reports the value in every mode when a
//! term of the label stands near it or is its key, and a rule for the bare
//! uppercase value in `balanced` and `recall` (K05). The Spanish CIF and the
//! Partita IVA are the VAT IDs of B01 without their country prefix: same labels
//! and validators, scored modes only and with a term.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const NIF: &str = "pii_nif_es";
const NIF_CONTEXT_FREE: &str = "pii_nif_es_context_free";
const NIE: &str = "pii_nie_es";
const NIE_CONTEXT_FREE: &str = "pii_nie_es_context_free";
const FISCAL_CODE: &str = "pii_fiscal_code_it";
const FISCAL_CODE_CONTEXT_FREE: &str = "pii_fiscal_code_it_context_free";
const CIF: &str = "pii_vat_id_es_proximity";
const PARTITA_IVA: &str = "pii_vat_id_it_proximity";
const CONTEXT_BOUND: [&str; 3] = [NIF, NIE, FISCAL_CODE];
const CONTEXT_FREE: [&str; 3] = [NIF_CONTEXT_FREE, NIE_CONTEXT_FREE, FISCAL_CODE_CONTEXT_FREE];
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
fn nif_validator_checks_the_control_letter() {
    for valid in [
        // presidio-analyzer test values (seven digits of an older DNI included)
        "55555555K",
        "1111111G",
        "01111111G",
        "12345678Z",
        "12345678z",
        "12345678-Z",
        "87654321X",
        "07654321J",
    ] {
        assert!(validators::es_nif(valid), "{valid}");
    }
    for invalid in [
        // wrong control letter (presidio-analyzer negative included)
        "12345678a",
        "12345678A",
        "87654321Y",
        // an NIE or a CIF is no DNI
        "X1234567L",
        "B12345674",
        // length and alphabet
        "123456Z",
        "123456789Z",
        "1234567AZ",
        "12345678-",
        "12345678",
    ] {
        assert!(!validators::es_nif(invalid), "{invalid}");
    }
}

#[test]
fn nie_validator_checks_the_prefix_and_control_letter() {
    for valid in [
        // presidio-analyzer test values
        "Z8078221M",
        "X9613851N",
        "Y8063915Z",
        "z8078221m",
        "X1234567L",
        "Y2345678Z",
        "Z-3456789-D",
    ] {
        assert!(validators::es_nie(valid), "{valid}");
    }
    for invalid in [
        // presidio-analyzer negatives: six digits, prefix `W`
        "Y806391Q",
        "W8063915Q",
        // wrong control letter
        "X1234567M",
        "Z8078221N",
        // a DNI is no NIE
        "12345678Z",
        "01234567L",
        "X12345678L",
    ] {
        assert!(!validators::es_nie(invalid), "{invalid}");
    }
}

#[test]
fn fiscal_code_validator_checks_month_day_omocodia_and_check_letter() {
    for valid in [
        "RSSMRA85T10A562S",
        "rssmra85t10a562s",
        "BNCLRA90E45H501A",
        "VRDGPP80A01F205X",
        "FRRLCU75M22L219D",
        "CLMNNA88D52G273G",
        // omocodia: `N` for the 2 of the place code
        "RSSMRA85T10A56NH",
        // presidio-analyzer test value with a valid check letter
        "AAAAAA00B11C333Y",
    ] {
        assert!(validators::it_fiscal_code(valid), "{valid}");
    }
    for invalid in [
        // wrong check letter (presidio-analyzer reports it all the same)
        "RSSMRA85T10A562T",
        "AAAAAA00B11C333N",
        // month letter `F` does not exist, day 32 and 00
        "RSSMRA85F10A562S",
        "RSSMRA85T32A562S",
        "RSSMRA85T00A562S",
        // a letter outside the omocodia set in a digit position, a digit in a letter one
        "RSSMRA85T10A56ZS",
        "RSSMR185T10A562S",
        // length
        "RSSMRA85T10A562",
        "RSSMRA85T10A562SS",
    ] {
        assert!(!validators::it_fiscal_code(invalid), "{invalid}");
    }
}

#[test]
fn the_cif_and_partita_iva_reuse_the_vat_validators() {
    // B01 validators without the country prefix: one unit with the VAT ID each.
    for valid in [
        "A58818501",
        "B58378431",
        "B12345674",
        "B-1234567-4",
        "Q2826000H",
    ] {
        assert!(validators::es_vat_id(valid), "{valid}");
    }
    for invalid in ["A58818502", "B1234567A", "Q2826000I"] {
        assert!(!validators::es_vat_id(invalid), "{invalid}");
    }
    let validator = |rule_id: &str| pattern(rule_id).validator.map(|check| check as usize);
    assert_eq!(validator(CIF), validator("pii_vat_id_es"));
    assert_eq!(validator(PARTITA_IVA), validator("pii_vat_id_it"));
    for rule_id in [CIF, PARTITA_IVA] {
        let rule = pattern(rule_id);
        assert!(rule.requires_context && rule.scored_only, "{rule_id}");
    }
    assert_eq!(pattern(CIF).entity_group, "VAT_ID_ES");
}

#[test]
fn the_spanish_and_italian_rules_have_their_label_validator_and_mode() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    for (rule_ids, label, check) in [
        (
            [NIF, NIF_CONTEXT_FREE],
            "ES_NIF",
            validators::es_nif as fn(&str) -> bool,
        ),
        ([NIE, NIE_CONTEXT_FREE], "ES_NIE", validators::es_nie),
        (
            [FISCAL_CODE, FISCAL_CODE_CONTEXT_FREE],
            "IT_FISCAL_CODE",
            validators::it_fiscal_code,
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
        assert!(
            score::score(rule, Context::Support { gap: 48 }) >= balanced,
            "{rule_id}"
        );
    }
    for rule_id in CONTEXT_FREE {
        let rule = pattern(rule_id);
        assert!(rule.scored_only && !rule.requires_context, "{rule_id}");
        assert_eq!(score::rule_score(rule), 0.55, "{rule_id}");
        assert!(score::score(rule, Context::Counter) < recall, "{rule_id}");
    }
}

// ── values with a term or key, every mode ────────────────────────────────────

#[test]
fn values_with_a_term_or_key_are_reported_in_every_mode() {
    for (rule_id, text, value) in [
        (NIF, "Mi DNI es 87654321X", "87654321X"),
        (NIF, "NIF: 45678912-S", "45678912-S"),
        (NIF, "{\"dni\": \"30495817w\"}", "30495817w"),
        (
            NIF,
            "Die spanische Steuernummer lautet 7654321J.",
            "7654321J",
        ),
        (NIE, "Mi NIE es X9613851N", "X9613851N"),
        (NIE, "Foreigner identity number: y2345678z", "y2345678z"),
        (NIE, "{\"nie\": \"Z-3456789-D\"}", "Z-3456789-D"),
        (
            FISCAL_CODE,
            "Codice fiscale: RSSMRA85T10A562S",
            "RSSMRA85T10A562S",
        ),
        (
            FISCAL_CODE,
            "Italian fiscal code bnclra90e45h501a on file",
            "bnclra90e45h501a",
        ),
        (
            FISCAL_CODE,
            "{\"codice_fiscale\": \"RSSMRA85T10A56NH\"}",
            "RSSMRA85T10A56NH",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_structural_cell_is_a_value_of_its_own_next_to_numeric_cells() {
    for (rule_id, text, value) in [
        (NIF, "dni,age\n87654321X,42", "87654321X"),
        (NIE, "nie,age\nX1234567L,31", "X1234567L"),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn values_need_a_term_a_valid_check_and_a_value_of_their_own() {
    for (label, text) in [
        // check fails
        ("ES_NIF", "DNI: 87654321Y"),
        ("ES_NIE", "NIE: W8063915Q"),
        ("ES_NIE", "NIE: X1234567M"),
        ("IT_FISCAL_CODE", "Codice fiscale: RSSMRA85T10A562T"),
        ("IT_FISCAL_CODE", "Codice fiscale: RSSMRA85F10A562S"),
        // lowercase needs a term, also in the scored modes
        ("ES_NIF", "Reference 87654321x"),
        ("IT_FISCAL_CODE", "token rssmra85t10a562s"),
        // part of a longer value
        ("ES_NIF", "DNI: 87654321X-7"),
        ("IT_FISCAL_CODE", "Codice fiscale: RSSMRA85T10A562S1"),
        // the body of a Spanish VAT ID
        ("ES_NIF", "NIF-IVA: ES 12345678Z"),
        ("ES_NIE", "NIF-IVA: ES X1234567L"),
        ("ES_NIE", "ES-X1234567L"),
        ("ES_NIF", "VAT: CY-51032288A"),
        ("ES_NIF", "CY 51032288A"),
    ] {
        assert_silent(text, label, &MODES);
    }
    // The body of a VAT ID is the VAT ID.
    assert_reports("pii_vat_id_es", "ES 12345678Z", "ES 12345678Z", &SCORED);
}

// ── bare values, scored modes only ───────────────────────────────────────────

#[test]
fn bare_values_are_reported_in_the_scored_modes_only() {
    for (rule_id, text, value) in [
        (NIF_CONTEXT_FREE, "55555555K", "55555555K"),
        (
            NIF_CONTEXT_FREE,
            "Applicant 12345678Z has been approved.",
            "12345678Z",
        ),
        (NIE_CONTEXT_FREE, "Z8078221M", "Z8078221M"),
        (
            NIE_CONTEXT_FREE,
            "Bewerber Y8063915Z wurde angenommen.",
            "Y8063915Z",
        ),
        (
            FISCAL_CODE_CONTEXT_FREE,
            "AAAAAA00B11C333Y",
            "AAAAAA00B11C333Y",
        ),
        (
            FISCAL_CODE_CONTEXT_FREE,
            "Cliente VRDGPP80A01F205X registrato.",
            "VRDGPP80A01F205X",
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
fn bare_cif_and_partita_iva_need_a_term() {
    for (rule_id, text, value) in [
        (CIF, "CIF: A58818501", "A58818501"),
        (CIF, "{\"cif\": \"B-1234567-4\"}", "B-1234567-4"),
        (
            CIF,
            "Código de identificación fiscal Q2826000H",
            "Q2826000H",
        ),
        (PARTITA_IVA, "Partita IVA: 00743110157", "00743110157"),
    ] {
        assert_reports(rule_id, text, value, &SCORED);
        let label = pattern(rule_id).entity_group;
        assert_silent(text, label, &[PiiMode::Strict]);
    }
    for text in ["A58818501", "Reference B58378431", "CIF: A58818502"] {
        assert_silent(text, "VAT_ID_ES", &MODES);
    }
    // The body of a prefixed VAT ID is no bare CIF of its own.
    for text in ["{\"vat_id\": \"ES B58378431\"}", "CIF: ES-A58818501"] {
        for mode in SCORED {
            assert!(
                !rules(text, mode).iter().any(|(rule, _)| rule == CIF),
                "{mode}: {text}"
            );
        }
    }
}

#[test]
fn bare_lookalikes_stay_silent_in_every_mode() {
    for (label, text) in [
        // presidio-analyzer negatives
        ("ES_NIE", "Y806391Q"),
        ("ES_NIE", "W8063915Q"),
        ("ES_NIF", "12345678a"),
        ("IT_FISCAL_CODE", "AAAAAA - 00B11C333N"),
        // wrong check letter
        ("ES_NIF", "87654321Y"),
        ("IT_FISCAL_CODE", "AAAAAA00B11C333N"),
        // seven digits need a term
        ("ES_NIF", "7654321J"),
        // part of a longer value
        ("ES_NIF", "Part 12345678Z-2 is in stock."),
        ("ES_NIE", "Teil X1234567L9 ist lieferbar."),
    ] {
        assert_silent(text, label, &MODES);
    }
}
