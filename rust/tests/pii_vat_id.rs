// SPDX-License-Identifier: GPL-3.0-only
//! VAT identification numbers, part 1: DE, AT, CH, FR, NL, BE, IT, ES (B01).
//!
//! Each country has its own label (`VAT_ID_DE` …) and validator with a real check
//! digit, so each counts as one M3 unit. The rules are scored-only (K05): strict
//! stays bit-identical, `balanced` and `recall` report a prefixed VAT ID without a
//! field name (`DE136695976`, `CHE-100.155.212 MWST`, `FR 40 303 265 045`). A bare
//! Partita IVA (11 digits without `IT`) needs a VAT term nearby or as its key. A
//! value must stand alone, and a nearer counter-context term (invoice, order
//! number …) drops it below both thresholds. Validators are never relaxed.

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

/// Rule, label and validator of every VAT rule, in registry order.
const RULES: [(&str, &str, Validator); 9] = [
    ("pii_vat_id_de", "VAT_ID_DE", validators::de_vat_id),
    ("pii_vat_id_at", "VAT_ID_AT", validators::at_vat_id),
    ("pii_vat_id_ch", "VAT_ID_CH", validators::ch_vat_id),
    ("pii_vat_id_fr", "VAT_ID_FR", validators::fr_vat_id),
    ("pii_vat_id_nl", "VAT_ID_NL", validators::nl_vat_id),
    ("pii_vat_id_be", "VAT_ID_BE", validators::be_vat_id),
    ("pii_vat_id_it", "VAT_ID_IT", validators::it_vat_id),
    (
        "pii_vat_id_it_proximity",
        "VAT_ID_IT",
        validators::it_vat_id,
    ),
    ("pii_vat_id_es", "VAT_ID_ES", validators::es_vat_id),
];

/// Valid VAT IDs per label: published examples (python-stdnum, BZSt, Presidio)
/// and generated values with a correct check digit, in the printed forms.
const VALID: &[(&str, &[&str])] = &[
    (
        "VAT_ID_DE",
        &[
            "DE136695976",
            "DE 136 695 976",
            "DE.136.695.976",
            "DE-136-695-976",
            "DE123456788",
            "DE700133890",
            "DE425288095",
            "DE131051834",
        ],
    ),
    (
        "VAT_ID_AT",
        &[
            "ATU13585627",
            "ATU 13585627",
            "ATU68044369",
            "ATU16719022",
            "ATU80715451",
            "ATU58404499",
        ],
    ),
    (
        "VAT_ID_CH",
        &[
            "CHE-100.155.212",
            "CHE100155212",
            "CHE 100 155 212",
            "CHE-712.368.516",
            "CHE-249.985.698",
            "CHE-244.550.229",
        ],
    ),
    (
        "VAT_ID_FR",
        &[
            "FR40303265045",
            "FR 40 303 265 045",
            "FR40 303265045",
            "FR78610357972",
            "FR36749261764",
            "FR17061713665",
        ],
    ),
    (
        "VAT_ID_NL",
        &[
            "NL004495445B01",
            "NL 004495445B01",
            "NL000099998B57",
            "NL434938713B02",
            "NL784437610B03",
            "NL181623092B02",
        ],
    ),
    (
        "VAT_ID_BE",
        &[
            "BE0403019261",
            "BE 0403.019.261",
            "BE0403 019 261",
            "BE0776091951",
            "BE0308669341",
            "BE0163131135",
        ],
    ),
    (
        "VAT_ID_IT",
        &[
            "IT00743110157",
            "IT 00743110157",
            "IT24442930335",
            "IT30205590372",
            "IT44625650252",
            "IT31934860854",
        ],
    ),
    (
        "VAT_ID_ES",
        &[
            "ESA13585625",
            "ESX5253868R",
            "ES54362315K",
            "ESB58378431",
            "ES B58378431",
            "ESY0327331D",
            "ESA6439595G",
            "ESM1234567L",
        ],
    ),
];

/// Values in the regex form whose check digit or component fails, per label.
const INVALID: &[(&str, &[(&str, &str)])] = &[
    (
        "VAT_ID_DE",
        &[
            ("DE136695977", "check digit fails"),
            ("DE987654321", "check digit fails"),
            ("DE100000001", "check digit fails"),
            ("DE036695976", "a leading zero is never issued"),
        ],
    ),
    (
        "VAT_ID_AT",
        &[
            ("ATU13585626", "check digit fails"),
            ("ATU68044368", "check digit fails"),
            ("ATU00000000", "check digit fails"),
        ],
    ),
    (
        "VAT_ID_CH",
        &[
            ("CHE-100.155.213", "check digit fails"),
            ("CHE-712.368.517", "check digit fails"),
            ("CHE-000.000.001", "check digit fails"),
        ],
    ),
    (
        "VAT_ID_FR",
        &[
            ("FR41303265045", "key fails"),
            ("FR40303265046", "key and SIREN Luhn fail"),
            ("FR12345678901", "key fails"),
            ("FR43303265046", "key fits, SIREN fails Luhn"),
        ],
    ),
    (
        "VAT_ID_NL",
        &[
            ("NL004495446B01", "check digit fails"),
            ("NL004495445B00", "branch number 00 is never issued"),
            ("NL000000000B01", "zero number"),
        ],
    ),
    (
        "VAT_ID_BE",
        &[
            ("BE0403019262", "check digits fail"),
            ("BE1403019261", "check digits fail"),
            ("BE0000000097", "zero company number"),
        ],
    ),
    (
        "VAT_ID_IT",
        &[
            ("IT00743110158", "Luhn fails"),
            ("IT00000000000", "zero company number"),
            (
                "IT12345670009",
                "Luhn holds, office code 000 is never issued",
            ),
            (
                "IT12345675008",
                "Luhn holds, office code 500 is never issued",
            ),
        ],
    ),
    (
        "VAT_ID_ES",
        &[
            ("ESA13585626", "CIF control digit fails"),
            ("ESX5253868Q", "NIE control letter fails"),
            ("ES54362315L", "DNI control letter fails"),
            ("ESI1234567L", "no CIF, NIF or NIE starts with I"),
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
    // Only the bare Partita IVA (11 digits without `IT`) needs a VAT term.
    let bound: Vec<_> = RULES
        .iter()
        .filter(|(rule, ..)| pattern(rule).requires_context)
        .map(|(rule, ..)| *rule)
        .collect();
    assert_eq!(bound, ["pii_vat_id_it_proximity"]);
}

#[test]
fn validators_accept_valid_vat_ids_in_every_printed_form() {
    for (label, values) in VALID {
        let validator = validator_of(label);
        for value in *values {
            assert!(validator(value), "{label}: {value}");
        }
    }
    // The bare Partita IVA and the IT form share one validator.
    assert!(validators::it_vat_id("00743110157"));
    assert!(validators::it_vat_id("01333550323"));
}

#[test]
fn validators_reject_failing_check_digits_and_components() {
    for (label, values) in INVALID {
        let validator = validator_of(label);
        for (value, reason) in *values {
            assert!(!validator(value), "{label}: {value} ({reason})");
        }
    }
    for value in ["", "DE", "DE13669597", "DE1366959766", "13669597X"] {
        assert!(!validators::de_vat_id(value), "{value}");
    }
    assert!(!validators::it_vat_id("0074311015"));
    assert!(!validators::nl_vat_id("NL004495445X01"));
    assert!(!validators::be_vat_id("BE2403019261"));
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
        ("USt-IdNr. DE136695976", "VAT_ID_DE", "DE136695976"),
        ("VAT number: ATU13585627", "VAT_ID_AT", "ATU13585627"),
        ("MWST-Nr. CHE-100.155.212", "VAT_ID_CH", "CHE-100.155.212"),
        (
            "N° TVA intracommunautaire : FR40303265045",
            "VAT_ID_FR",
            "FR40303265045",
        ),
        ("Btw-nummer NL004495445B01", "VAT_ID_NL", "NL004495445B01"),
        ("BTW BE0403019261", "VAT_ID_BE", "BE0403019261"),
        ("Partita IVA IT00743110157", "VAT_ID_IT", "IT00743110157"),
        ("NIF-IVA: ESA13585625", "VAT_ID_ES", "ESA13585625"),
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
        "Rechnungsnummer DE136695976",
        "Invoice number ATU13585627",
        "Order number FR40303265045",
        "Bestellnummer ESA13585625",
        "Tracking number NL004495445B01",
    ] {
        for mode in SCORED {
            assert!(spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}

#[test]
fn printed_forms_keep_the_whole_number_and_no_trailing_suffix() {
    for mode in SCORED {
        assert_eq!(
            spans("UID: CHE-100.155.212 MWST", mode),
            [("VAT_ID_CH".into(), "CHE-100.155.212".into(), 0.80)],
        );
        assert_eq!(
            spans("Numéro de TVA FR 40 303 265 045.", mode),
            [("VAT_ID_FR".into(), "FR 40 303 265 045".into(), 0.80)],
        );
        assert_eq!(
            spans("USt-IdNr.: DE 136 695 976 · Steuernummer folgt", mode),
            [("VAT_ID_DE".into(), "DE 136 695 976".into(), 0.80)],
        );
    }
}

#[test]
fn a_comma_delimits_a_prefixed_value_in_a_csv_row() {
    // A value that starts with its country prefix is no decimal: `,` next to a
    // digit is the CSV delimiter, not a joined number as for a bare Steuer-ID.
    for mode in SCORED {
        assert_eq!(
            spans("2,Emily Wright,447-12-55430,DE396839779,150279-0487", mode)
                .into_iter()
                .filter(|(label, ..)| label.starts_with("VAT_ID"))
                .collect::<Vec<_>>(),
            [("VAT_ID_DE".into(), "DE396839779".into(), 0.55)],
            "{mode:?}"
        );
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
            "Artikel XDE136695976 bestellt",
            "Code DE1366959761 im Log",
            "Range DE136695976-7 reserviert",
            "SKU ATU13585627X",
            "Pfad /srv/FR40303265045/2026",
            "Version 3.CHE100155212",
            "Konto DE89370400440532013000",
            "Gläubiger-ID DE98ZZZ09999999999",
            "Messwert 00743110157 im Log",
            "Telefon 01333550323",
            "de136695976 is lower case",
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
fn a_bare_partita_iva_needs_a_vat_term_or_key() {
    for mode in SCORED {
        for (text, score) in [
            ("Partita IVA: 00743110157", 0.80),
            ("P.IVA 00743110157", 0.80),
            ("Italian VAT number: 00743110157", 0.80),
            ("{\"partita_iva\": \"00743110157\"}", 0.80),
            ("name;it_vat\nRossi Srl;00743110157", 0.80),
        ] {
            assert_eq!(
                spans(text, mode),
                [("VAT_ID_IT".into(), "00743110157".into(), score)],
                "{mode:?}: {text}"
            );
        }
        for text in [
            "Bitte 00743110157 übernehmen.",
            "Rechnungsnummer 00743110157, Partita IVA folgt",
            "Partita IVA: 00743110158",
            "{\"order_id\": \"00743110157\"}",
        ] {
            assert!(spans(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}

#[test]
fn a_partita_iva_wins_over_a_bare_steuer_id_on_the_same_digits() {
    // 26858780310 passes both the Partita IVA and the issued Steuer-ID check;
    // the VAT term decides (K07 overlap: context before checksum and score).
    assert!(validators::it_vat_id("26858780310"));
    assert!(validators::steuer_id_issued("26858780310"));
    for mode in SCORED {
        let found = spans("Partita IVA: 26858780310", mode);
        assert_eq!(
            found,
            [("VAT_ID_IT".into(), "26858780310".into(), 0.80)],
            "{mode:?}"
        );
    }
}
