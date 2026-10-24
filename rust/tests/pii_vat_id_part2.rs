// SPDX-License-Identifier: GPL-3.0-only
//! VAT identification numbers, part 2: BG, CY, CZ, DK, EE, EL, FI, HR, HU, IE,
//! LT (B02).
//!
//! Same structure as part 1 (B01, `pii_vat_id.rs`): each country has its own
//! label (`VAT_ID_BG` …) and validator with a real check digit, so each counts
//! as one M3 unit. The rules are scored-only (K05): strict stays bit-identical,
//! `balanced` and `recall` report a prefixed VAT ID without a field name
//! (`CZ25123891`, `DK 13 58 56 28`, `IE6433435OA`). A value must stand alone,
//! and a nearer counter-context term (invoice, order number …) drops it below
//! both thresholds. Validators are never relaxed: forms that carry no check
//! digit (a nine-digit Czech birth number from before 1954) and all-zero
//! numbers are rejected.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

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

/// `(label, text, score)` of every span.
fn spans(text: &str, mode: PiiMode) -> Vec<(String, String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .map(|span| (span.label, span.text, span.score))
        .collect()
}

fn pattern(rule_id: &str) -> &'static PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

const SCORED: [PiiMode; 2] = [PiiMode::Balanced, PiiMode::Recall];

type Validator = fn(&str) -> bool;

/// Rule, label and validator of every part-2 VAT rule, in registry order.
const RULES: [(&str, &str, Validator); 11] = [
    ("pii_vat_id_bg", "VAT_ID_BG", validators::bg_vat_id),
    ("pii_vat_id_cy", "VAT_ID_CY", validators::cy_vat_id),
    ("pii_vat_id_cz", "VAT_ID_CZ", validators::cz_vat_id),
    ("pii_vat_id_dk", "VAT_ID_DK", validators::dk_vat_id),
    ("pii_vat_id_ee", "VAT_ID_EE", validators::ee_vat_id),
    ("pii_vat_id_el", "VAT_ID_EL", validators::el_vat_id),
    ("pii_vat_id_fi", "VAT_ID_FI", validators::fi_vat_id),
    ("pii_vat_id_hr", "VAT_ID_HR", validators::hr_vat_id),
    ("pii_vat_id_hu", "VAT_ID_HU", validators::hu_vat_id),
    ("pii_vat_id_ie", "VAT_ID_IE", validators::ie_vat_id),
    ("pii_vat_id_lt", "VAT_ID_LT", validators::lt_vat_id),
];

/// The part-1 validators (B01): none of them accepts a part-2 value.
const PART_1: [Validator; 8] = [
    validators::de_vat_id,
    validators::at_vat_id,
    validators::ch_vat_id,
    validators::fr_vat_id,
    validators::nl_vat_id,
    validators::be_vat_id,
    validators::it_vat_id,
    validators::es_vat_id,
];

/// Valid VAT IDs per label: published examples (python-stdnum) and generated
/// values with a correct check digit, in the printed forms.
const VALID: &[(&str, &[&str])] = &[
    (
        "VAT_ID_BG",
        &[
            "BG175074752",
            "BG 175074752",
            "BG436687597",  // nine digits, remainder 10: weights 3…10
            "BG9111146569", // ЕГН, born 1991-11-14
            "BG2852728877", // ЛНЧ of a foreigner
            "BG0326991023", // other ten-digit number
            "BG170090208",
        ],
    ),
    (
        "VAT_ID_CY",
        &[
            "CY10259033P",
            "CY-10259033P",
            "CY 10259033P",
            "CY18715842G",
            "CY01400589T",
            "CY40164215F",
        ],
    ),
    (
        "VAT_ID_CZ",
        &[
            "CZ25123891",
            "CZ 25123891",
            "CZ69170100",
            "CZ640903926", // special case: nine digits starting with 6
            "CZ641628066",
            "CZ7103192745", // birth number
            "CZ 7103192745",
        ],
    ),
    (
        "VAT_ID_DK",
        &[
            "DK13585628",
            "DK 13585628",
            "DK 13 58 56 28",
            "DK77384235",
            "DK30638050",
            "DK80830394",
        ],
    ),
    (
        "VAT_ID_EE",
        &[
            "EE100931558",
            "EE 100931558",
            "EE100594102",
            "EE100018442",
            "EE104985335",
        ],
    ),
    (
        "VAT_ID_EL",
        &[
            "EL094259216",
            "EL 094259216",
            "GR094259216",
            "EL009331143",
            "EL213907000",
            "EL045837735",
        ],
    ),
    (
        "VAT_ID_FI",
        &[
            "FI20774740",
            "FI 20774740",
            "FI58392596",
            "FI10796110",
            "FI80840201",
        ],
    ),
    (
        "VAT_ID_HR",
        &[
            "HR33392005961",
            "HR 33392005961",
            "HR93154366775",
            "HR49523163127",
            "HR84510984400",
        ],
    ),
    (
        "VAT_ID_HU",
        &[
            "HU12892312",
            "HU-12892312",
            "HU 12892312",
            "HU73831275",
            "HU69782927",
        ],
    ),
    (
        "VAT_ID_IE",
        &[
            "IE6433435F",
            "IE 6433435F",
            "IE6433435OA", // since 2013: second letter
            "IE8D79739I",  // old form: digit, letter, five digits
            "IE8*79739I",  // old form with `*` as the second character
            "IE 8+79739I", // old form with `+` as the second character
            "IE2710022OH",
            "IE1868254J",
            "IE0138719V",
        ],
    ),
    (
        "VAT_ID_LT",
        &[
            "LT119511515",
            "LT 119511515",
            "LT500326715",    // remainder 10: weights shifted by two
            "LT100001919017", // temporary taxpayer
            "LT100004801610",
            "LT475444717",
            "LT081501061015",
        ],
    ),
];

/// Values in the regex form whose check digit or component fails, per label.
const INVALID: &[(&str, &[(&str, &str)])] = &[
    (
        "VAT_ID_BG",
        &[
            ("BG175074751", "check digit fails"),
            ("BG436687598", "check digit fails (weights 3…10)"),
            ("BG9111146566", "no ten-digit check fits"),
            ("BG000000000", "zero number"),
        ],
    ),
    (
        "VAT_ID_CY",
        &[
            ("CY10259033Z", "check letter fails"),
            ("CY12945807E", "check letter fits, 12 is never issued"),
            ("CY00000000E", "zero number"),
        ],
    ),
    (
        "VAT_ID_CZ",
        &[
            ("CZ25123890", "check digit fails"),
            (
                "CZ92193081",
                "check digit fits, 9 never opens a legal entity",
            ),
            ("CZ640903927", "special check digit fails"),
            ("CZ7103192746", "birth number not divisible by 11"),
            ("CZ4538323647", "divisible by 11, 38 is no birth month"),
            (
                "CZ401231123",
                "nine-digit birth number carries no check digit",
            ),
        ],
    ),
    (
        "VAT_ID_DK",
        &[
            ("DK13585627", "check digit fails"),
            ("DK02061597", "sum fits, a leading zero is never issued"),
        ],
    ),
    (
        "VAT_ID_EE",
        &[
            ("EE100931559", "check digit fails"),
            ("EE347140694", "sum fits, does not start with 10"),
        ],
    ),
    (
        "VAT_ID_EL",
        &[
            ("EL094259217", "check digit fails"),
            ("EL123456781", "check digit fails"),
            ("EL000000000", "zero number"),
        ],
    ),
    (
        "VAT_ID_FI",
        &[
            ("FI20774741", "check digit fails"),
            ("FI00000000", "zero number"),
        ],
    ),
    (
        "VAT_ID_HR",
        &[
            ("HR33392005962", "check digit fails"),
            ("HR00000000000", "zero number"),
        ],
    ),
    (
        "VAT_ID_HU",
        &[
            ("HU12892313", "check digit fails"),
            ("HU00000000", "zero number"),
        ],
    ),
    (
        "VAT_ID_IE",
        &[
            ("IE6433435E", "check letter fails"),
            ("IE6433435OB", "check letter fails for the second letter"),
            ("IE8D79739J", "old form check letter fails"),
            ("IE8*79739J", "old form with `*`, check letter fails"),
            ("IE8+7973I", "old form with `+`, too short"),
            ("IE6433435*", "symbol in place of the check letter"),
            ("IE64334+5F", "symbol in the new form"),
            ("IE0000000W", "zero number"),
        ],
    ),
    (
        "VAT_ID_LT",
        &[
            ("LT119511516", "check digit fails"),
            ("LT018800102", "check digit fits, eighth digit is not 1"),
            ("LT100001919018", "check digit fails"),
        ],
    ),
];

fn validator_of(label: &str) -> Validator {
    RULES
        .iter()
        .find(|(_, rule_label, _)| *rule_label == label)
        .map(|(.., validator)| *validator)
        .unwrap()
}

#[test]
fn every_country_has_its_own_scored_only_checksum_rule() {
    for (rule, label, _) in RULES {
        let pattern = pattern(rule);
        assert_eq!(pattern.entity_group, label, "{rule}");
        assert_eq!(pattern.strength, ValidatorStrength::Checksum, "{rule}");
        assert!(pattern.scored_only, "{rule}: strict stays bit-identical");
        assert!(!pattern.captured_value, "{rule}");
        assert!(!pattern.requires_context, "{rule}: the prefix carries it");
        assert!(pattern.validator.is_some(), "{rule}");
        assert!(
            score::rule_score(pattern) >= PiiMode::Balanced.min_score().unwrap(),
            "{rule}"
        );
        assert!(
            score::score(pattern, Context::Counter) < PiiMode::Recall.min_score().unwrap(),
            "{rule}"
        );
    }
}

#[test]
fn validators_accept_valid_vat_ids_in_every_printed_form() {
    for (label, values) in VALID {
        let validator = validator_of(label);
        for value in *values {
            assert!(validator(value), "{label}: {value}");
        }
    }
}

#[test]
fn validators_reject_failing_check_digits_and_components() {
    for (label, values) in INVALID {
        let validator = validator_of(label);
        for (value, reason) in *values {
            assert!(!validator(value), "{label}: {value} ({reason})");
        }
    }
    for value in ["", "BG", "BG17507475", "BG17507475201", "17507475X"] {
        assert!(!validators::bg_vat_id(value), "{value}");
    }
    assert!(!validators::cy_vat_id("CY102590331"));
    assert!(!validators::cz_vat_id("CZ2512389"));
    assert!(!validators::ie_vat_id("IE6433435"));
    assert!(!validators::ie_vat_id("IE6433435FX"));
    assert!(!validators::lt_vat_id("LT1195115150"));
}

#[test]
fn validators_do_not_accept_another_country_prefix() {
    for (label, values) in VALID {
        for (other, ..) in VALID.iter().filter(|(other, _)| other != label) {
            let validator = validator_of(other);
            for value in *values {
                assert!(!validator(value), "{other} accepts {label} {value}");
            }
        }
        for value in *values {
            assert!(
                !PART_1.iter().any(|validator| validator(value)),
                "a part-1 validator accepts {label} {value}"
            );
        }
    }
}

#[test]
fn strict_reports_no_vat_id() {
    for (label, values) in VALID {
        for value in *values {
            let text = format!("USt-IdNr. {value}");
            assert!(
                !spans(&text, PiiMode::Strict)
                    .iter()
                    .any(|(span_label, ..)| span_label.starts_with("VAT_ID")),
                "{label}: {text}"
            );
        }
    }
}

#[test]
fn scored_modes_report_prefixed_vat_ids_without_a_field_name() {
    for mode in SCORED {
        for (label, values) in VALID {
            for value in *values {
                let text = format!("Bitte {value} übernehmen.");
                assert_eq!(
                    spans(&text, mode),
                    [(label.to_string(), value.to_string(), 0.55)],
                    "{mode:?}: {text}"
                );
            }
        }
    }
}

#[test]
fn a_vat_term_raises_the_score_and_a_counter_term_drops_the_value() {
    for (text, label, value) in [
        ("ИН по ДДС: BG175074752", "VAT_ID_BG", "BG175074752"),
        ("Αριθμός ΦΠΑ CY10259033P", "VAT_ID_CY", "CY10259033P"),
        ("DIČ: CZ25123891", "VAT_ID_CZ", "CZ25123891"),
        ("CVR-nr. DK13585628", "VAT_ID_DK", "DK13585628"),
        ("KMKR nr EE100931558", "VAT_ID_EE", "EE100931558"),
        ("ΑΦΜ: EL094259216", "VAT_ID_EL", "EL094259216"),
        ("ALV-numero FI20774740", "VAT_ID_FI", "FI20774740"),
        ("OIB: HR33392005961", "VAT_ID_HR", "HR33392005961"),
        ("Közösségi adószám: HU12892312", "VAT_ID_HU", "HU12892312"),
        ("Irish VAT number IE6433435OA", "VAT_ID_IE", "IE6433435OA"),
        ("PVM kodas LT119511515", "VAT_ID_LT", "LT119511515"),
        ("USt-IdNr. CZ7103192745", "VAT_ID_CZ", "CZ7103192745"),
        ("VAT number: DK 13 58 56 28", "VAT_ID_DK", "DK 13 58 56 28"),
    ] {
        for mode in SCORED {
            assert_eq!(
                spans(text, mode),
                [(label.to_string(), value.to_string(), 0.80)],
                "{mode:?}: {text}"
            );
        }
    }
    for text in [
        "Rechnungsnummer CZ25123891",
        "Invoice number DK13585628",
        "Order number HR33392005961",
        "Bestellnummer IE6433435F",
        "Tracking number LT100001919017",
        "Ticket number EE100931558",
    ] {
        for mode in SCORED {
            assert!(spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}

#[test]
fn checksum_failures_and_values_inside_longer_tokens_stay_silent() {
    for mode in SCORED {
        for (label, values) in INVALID {
            for (value, reason) in *values {
                let text = format!("USt-IdNr. {value}");
                assert!(
                    spans(&text, mode).is_empty(),
                    "{mode:?} {label}: {text} ({reason})"
                );
            }
        }
        for text in [
            "Artikel XCZ25123891 bestellt",
            "Code HU128923120 im Log",
            "Range FI20774740-1 reserviert",
            "SKU IE6433435FA9",
            "Pfad /srv/HR33392005961/2026",
            "Version 3.DK13585628",
            "Konto DK5000400440116243",
            "Konto FI2112345600000785",
            "Konto HR1210010051863000160",
            "Konto LT121000011101001000",
            "Konto BG80BNBG96611020345678",
            "Konto CY17002001280000001200527600",
            "Konto HU42117730161111101800000000",
            "Konto IE29AIBK93115212345678",
            "Konto EE382200221020145685",
            "Konto GR1601101250000000012300695",
            "Konto CZ6508000000192000145399",
            "dk13585628 is lower case",
        ] {
            assert!(
                !spans(text, mode)
                    .iter()
                    .any(|(label, ..)| label.starts_with("VAT_ID")),
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn a_comma_delimits_a_prefixed_value_in_a_csv_row() {
    for mode in SCORED {
        assert_eq!(
            spans("7,Jana Nováková,CZ25123891,HU12892312,2026", mode)
                .into_iter()
                .filter(|(label, ..)| label.starts_with("VAT_ID"))
                .collect::<Vec<_>>(),
            [
                ("VAT_ID_CZ".into(), "CZ25123891".into(), 0.55),
                ("VAT_ID_HU".into(), "HU12892312".into(), 0.55),
            ],
            "{mode:?}"
        );
    }
}
