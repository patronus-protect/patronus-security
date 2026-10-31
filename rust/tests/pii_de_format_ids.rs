// SPDX-License-Identifier: GPL-3.0-only
//! German format identifiers (B-DEFMT): the Steuernummer in the forms of the
//! Länder and the 13-digit ELSTER form (F13), the commercial register number
//! HRA/HRB (B03).
//!
//! A Steuernummer is the Finanzamt number, the district and the serial with its
//! check digit. Each Land prints it in its own groups: `FF/BBB/UUUUP` (BE, HB,
//! HH, NI, RP, SH), `FFBBB/UUUUP` (BW), `FFF/BBB/UUUUP` led by 0, 1 or 2 (BY,
//! BB, HE, MV, SL, SN, ST, TH) and `FFF/BBBB/UUUP` led by 1, 2 or 3 (NW). The
//! ELSTER form puts the four-digit Bundesfinanzamtsnummer (Land prefix) and a
//! `0` in front of district and serial. The commercial register number is
//! reported with a register or local court term in every mode and bare in
//! `balanced` and `recall`.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const REGISTER: &str = "pii_commercial_register_de";
const REGISTER_BARE: &str = "pii_commercial_register_de_context_free";
const LABEL: &str = "COMMERCIAL_REGISTER_DE";
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

fn pattern(rule_id: &str) -> &'static PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

fn values(text: &str, mode: PiiMode, label: &str) -> Vec<String> {
    spans(text, mode, label)
        .into_iter()
        .map(|(value, _)| value)
        .collect()
}

// ── Steuernummer ─────────────────────────────────────────────────────────────

#[test]
fn tax_number_validator_accepts_the_forms_of_the_laender() {
    for valid in [
        // FF/BBB/UUUUP: BE, HH, NI, RP; HB and SH with spaces
        "21/815/08150",
        "02/815/08156",
        "24/815/08151",
        "22/815/08154",
        "75 815 08152",
        "29 815 08158",
        // FFBBB/UUUUP: BW
        "93815/08152",
        // FFF/BBB/UUUUP: BY, BB, HE (spaces), MV, SL, SN, ST, TH
        "181/815/08155",
        "048/815/08155",
        "013 815 08153",
        "079/815/08151",
        "010/815/08182",
        "201/123/12340",
        "101/815/08154",
        "151/815/08156",
        // FFF/BBBB/UUUP: NW
        "133/8150/8159",
        "324/0307/4258",
        // without separators
        "2181508150",
        "18181508155",
        // the presidio-analyzer value
        "123/456/78901",
    ] {
        assert!(validators::de_tax_number(valid), "{valid}");
    }
}

#[test]
fn tax_number_validator_accepts_the_elster_form_of_every_land() {
    for valid in [
        "2893081508152", // BW
        "9181081508155", // BY
        "1121081508150", // BE
        "3048081508155", // BB
        "2475081508152", // HB
        "2202081508156", // HH
        "2613081508153", // HE
        "4079081508151", // MV
        "2324081508151", // NI
        "5133081508159", // NW
        "2722081508154", // RP
        "1010081508182", // SL
        "3201012312340", // SN
        "3101081508154", // ST
        "2129081508158", // SH
        "4151081508156", // TH
        // grouped
        "2893/0815/08152",
        "2893 0 815 08152",
    ] {
        assert!(validators::de_tax_number(valid), "{valid}");
    }
}

#[test]
fn tax_number_validator_rejects_forms_no_land_prints() {
    for invalid in [
        // repeated digits
        "000/000/00000",
        "111/111/11111",
        // ELSTER: no Land prefix 01, 00, 17, 50 or 93; no 0 after the Finanzamt number
        "0181508150000",
        "0081508150001",
        "1781508150001",
        "5033081508159",
        "9381081508155",
        "2893181508152",
        // twelve digits in any grouping
        "028150815012",
        "2893/081/50812",
        "1234/567/89012",
        // FFF/BBB/UUUUP led by 3 to 9, FFF/BBBB/UUUP led by 0 or 4 to 9
        "456/789/01234",
        "987/654/32109",
        "033/8150/8159",
        "433/8150/8159",
        "45678901234",
        // other groups
        "2181/508/150",
        "12/34/56789",
        "123/456/7890",
        // too short or too long
        "123/456",
        "1234567890123456",
    ] {
        assert!(!validators::de_tax_number(invalid), "{invalid}");
    }
}

#[test]
fn tax_number_after_its_field_name_follows_the_forms_of_the_laender() {
    for (text, value) in [
        ("Steuernummer: 2893081508152", "2893081508152"),
        ("Steuernummer: 5133081508159", "5133081508159"),
        ("Tax number: 9181081508155", "9181081508155"),
        ("Steuernummer: 75 815 08152", "75 815 08152"),
        ("Steuernummer: 133/8150/8159", "133/8150/8159"),
    ] {
        for mode in MODES {
            assert_eq!(values(text, mode, "TAX_NUMBER_DE"), [value], "{mode:?}: {text}");
        }
    }
    for text in [
        "Steuernummer: 0181508150000",
        "Steuernummer: 1781508150001",
        "Steuernummer: 2893181508152",
        "German Steuernummer: 1234/567/89012",
        "Tax number: 456/789/01234",
        "Tax number: 028150815012",
    ] {
        for mode in MODES {
            assert!(
                spans(text, mode, "TAX_NUMBER_DE").is_empty(),
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn bare_elster_form_stays_silent() {
    // 13 bare digits are as often a timestamp in milliseconds or an EAN-13.
    for text in [
        "2893081508152",
        "Bitte 5133081508159 übernehmen.",
        "Zeitstempel 1698234567890",
    ] {
        for mode in MODES {
            assert!(
                spans(text, mode, "TAX_NUMBER_DE").is_empty(),
                "{mode:?}: {text}"
            );
        }
    }
}

// ── Handelsregister ──────────────────────────────────────────────────────────

#[test]
fn commercial_register_rules_carry_the_form_in_the_regex() {
    let bound = pattern(REGISTER);
    assert_eq!(bound.entity_group, LABEL);
    assert_eq!(bound.strength, ValidatorStrength::None);
    assert!(bound.requires_context && !bound.scored_only && !bound.captured_value);
    let bare = pattern(REGISTER_BARE);
    assert_eq!(bare.entity_group, LABEL);
    assert_eq!(bare.strength, ValidatorStrength::None);
    assert!(!bare.requires_context && bare.scored_only && !bare.captured_value);
    assert_eq!(bound.pattern, bare.pattern);
}

#[test]
fn commercial_register_with_a_court_or_register_term_is_reported_in_every_mode() {
    for (text, value) in [
        ("Amtsgericht München, HRB 123456", "HRB 123456"),
        ("Sitz: Köln · Amtsgericht Köln HRA 14773", "HRA 14773"),
        (
            "Registergericht: Amtsgericht Charlottenburg HRB 98765 B",
            "HRB 98765 B",
        ),
        ("Amtsgericht Kiel HRB 1234 KI", "HRB 1234 KI"),
        ("Handelsregister: HRB12345", "HRB12345"),
        ("Registernummer: HRA 2136", "HRA 2136"),
        ("Commercial register: HRB 208472", "HRB 208472"),
        ("Registered at the local court of Hamburg, HRB 32375", "HRB 32375"),
        ("Die Firma ist im Handelsregister unter HRB 44020 eingetragen.", "HRB 44020"),
        (r#"{"commercial_register": "HRB 143241"}"#, "HRB 143241"),
        ("nr;name;handelsregister\n1;Grace Davies;HRB 32461", "HRB 32461"),
    ] {
        for mode in MODES {
            assert_eq!(values(text, mode, LABEL), [value], "{mode:?}: {text}");
        }
    }
}

#[test]
fn bare_commercial_register_is_reported_in_the_scored_modes_only() {
    for (text, value) in [
        ("HRA12345", "HRA12345"),
        ("HRB 123456", "HRB 123456"),
        ("Die Schmidt GmbH (HRB 71234) liefert.", "HRB 71234"),
        ("Supplier HRA 9012 confirmed the order.", "HRA 9012"),
    ] {
        for mode in SCORED {
            assert_eq!(
                spans(text, mode, LABEL),
                [(value.to_string(), 0.50)],
                "{mode:?}: {text}"
            );
        }
        assert!(spans(text, PiiMode::Strict, LABEL).is_empty(), "{text}");
    }
    for mode in SCORED {
        assert_eq!(
            spans("Amtsgericht Hamburg HRB 32375", mode, LABEL),
            [("HRB 32375".to_string(), 0.75)],
            "{mode:?}"
        );
    }
}

#[test]
fn commercial_register_lookalikes_stay_silent() {
    for text in [
        // other register types and prefixes (presidio-analyzer hard negatives)
        "HRC 12345",
        "HR 12345",
        "Amtsgericht München HRC 12345",
        // lower case, a leading zero, seven digits
        "Amtsgericht München hrb 12345",
        "Amtsgericht München HRB 012345",
        "Amtsgericht München HRB 1234567",
        // part of a longer token
        "Amtsgericht München XHRB 12345",
        "Ticket HRB-12345",
        // a field that names another value
        "Aktenzeichen: HRB 12345",
    ] {
        for mode in MODES {
            assert!(spans(text, mode, LABEL).is_empty(), "{mode:?}: {text}");
        }
    }
}

#[test]
fn commercial_register_suffix_is_a_known_court_suffix_only() {
    for mode in SCORED {
        // "AG" after the number names the court, not part of the value
        assert_eq!(
            values("HRB 12345 AG München", mode, LABEL),
            ["HRB 12345"],
            "{mode:?}"
        );
        assert_eq!(values("HRB 12345 B", mode, LABEL), ["HRB 12345 B"], "{mode:?}");
    }
}
