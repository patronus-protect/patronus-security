// SPDX-License-Identifier: GPL-3.0-only
//! Context-free output of checksum-strong values (K05).
//!
//! In `balanced` and `recall` a value whose validator proves a real check digit
//! needs no field name. IBAN and card numbers report bare already; scored-only
//! rules (`PiiPattern::scored_only`) add the bare form of checksum values that
//! strict reports only after their field name, first the Steuer-ID. Strict never
//! runs a scored-only rule (decision K02). A bare value stands alone (not part
//! of a longer number, range or date) and drops below both thresholds when a
//! counter-context term is nearer than any support term. A bare Steuer-ID also
//! has to follow the digit distribution of issued IDs; validators are never
//! relaxed. Four scored-only rules check a form without a check digit
//! (`FORMAT_RULES`): the grouped US SSN (`AAA-GG-SSSS`, B-SSN), whose SSA ranges
//! and separators stand in for one, the UK NINO and driving licence (B-UK),
//! whose issuing rules (prefix and suffix letters; surname, birth date and
//! initials) do, and the German Steuernummer in the slashed groups of the
//! Länder (`123/456/78901`, Q-DE).

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

fn scanner(mode: PiiMode) -> SecurityGateway {
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
}

fn scan(scanner: &SecurityGateway, text: &str) -> SecurityScanResult {
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

fn pii_result(text: &str, mode: PiiMode) -> SecurityScanResult {
    scan(&scanner(mode), text)
}

fn matched_rules(result: &SecurityScanResult) -> Vec<serde_json::Value> {
    result.layers[0]
        .details
        .get("matched_rules")
        .map(|rules| rules.as_array().unwrap().clone())
        .unwrap_or_default()
}

/// `(text, score)` of the spans of `label`.
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

const SCORED: [PiiMode; 2] = [PiiMode::Balanced, PiiMode::Recall];
const STEUER_ID: &str = "pii_steuer_id_de_context_free";
const TAX_NUMBER: &str = "pii_steuernummer_de_context_free";
/// The checksum labels without a context-free rule: the NHS number (B-UK), the
/// Australian Company Number and the Tax File Number (B-APAC), the LANR (B-DE1).
const CONTEXT_BOUND_LABELS: [&str; 4] = ["NHS_NUMBER", "AU_ACN", "AU_TFN", "PHYSICIAN_NUMBER_LANR"];
/// Scored-only rules whose validator checks a form, not a check digit.
const FORMAT_RULES: [&str; 4] = [
    "pii_driver_license_number_uk_context_free",
    "pii_ssn_us_context_free",
    "pii_ni_uk_context_free",
    TAX_NUMBER,
];

/// Issued Steuer-IDs: check digit valid, one digit twice or three times (not
/// three in a row) in the first ten digits, every other digit at most once.
const ISSUED: &[&str] = &[
    "86095742719",
    "82736451927",
    "65929970489",
    "57549285017",
    "25768131411",
    "47426548904",
    "39662845670",
    "86794425307",
    "86231292506",
    "95082467219",
    "74265832011",
    "29046789957",
    "28540106973",
    "86055742197",
];

#[test]
fn scored_only_rules_are_unbound_checksum_rules() {
    let scored_only: Vec<_> = PII_PATTERNS
        .iter()
        .filter(|pattern| pattern.scored_only)
        .collect();
    assert_eq!(
        scored_only
            .iter()
            .map(|pattern| pattern.name)
            .collect::<Vec<_>>(),
        [
            STEUER_ID,
            "pii_driver_license_number_uk_context_free",
            "pii_ssn_us_context_free",
            "pii_ni_uk_context_free",
            "pii_vat_id_de",
            "pii_vat_id_at",
            "pii_vat_id_ch",
            "pii_vat_id_fr",
            "pii_vat_id_nl",
            "pii_vat_id_be",
            "pii_vat_id_it",
            "pii_vat_id_it_proximity",
            "pii_vat_id_es",
            "pii_vat_id_lu",
            "pii_vat_id_lv",
            "pii_vat_id_mt",
            "pii_vat_id_pl",
            "pii_vat_id_pt",
            "pii_vat_id_ro",
            "pii_vat_id_se",
            "pii_vat_id_si",
            "pii_vat_id_sk",
            "pii_vat_id_no",
            "pii_vat_id_gb",
            "pii_passport_number_de_context_free",
            "pii_passport_number_de_legacy",
            "pii_identity_card_number_de_context_free",
            "pii_identity_card_number_de_legacy",
            "pii_vat_id_bg",
            "pii_vat_id_cy",
            "pii_vat_id_cz",
            "pii_vat_id_dk",
            "pii_vat_id_ee",
            "pii_vat_id_el",
            "pii_vat_id_fi",
            "pii_vat_id_hr",
            "pii_vat_id_hu",
            "pii_vat_id_ie",
            "pii_vat_id_lt",
            "pii_abn_au_context_free",
            "pii_medicare_au_context_free",
            "pii_nric_fin_sg_context_free",
            "pii_uen_sg_context_free",
            "pii_rentenversicherung_de_context_free",
            "pii_health_insurance_number_de_context_free",
            "pii_physician_number_lanr_de_proximity",
            "pii_personnummer_se_context_free",
            "pii_cpr_dk_context_free",
            "pii_fodselsnummer_no_context_free",
            "pii_hetu_fi_context_free",
            TAX_NUMBER,
            "pii_aba_routing_number_us_context_free",
        ]
    );
    for pattern in scored_only {
        let strength = if FORMAT_RULES.contains(&pattern.name) {
            ValidatorStrength::Format
        } else {
            ValidatorStrength::Checksum
        };
        assert_eq!(pattern.strength, strength, "{}", pattern.name);
        assert!(!pattern.captured_value, "{}", pattern.name);
        // The bare Partita IVA (B01), the old numeric document serial (F08) and the
        // LANR (B-DE1) are the unbound checksum rules that need a term; 11 bare
        // digits with a Luhn digit, 10 with a 7-3-1 digit or 9 with a mod-10 digit
        // prove too little alone.
        assert_eq!(
            pattern.requires_context,
            [
                "pii_vat_id_it_proximity",
                "pii_passport_number_de_legacy",
                "pii_identity_card_number_de_legacy",
                "pii_physician_number_lanr_de_proximity",
            ]
            .contains(&pattern.name),
            "{}",
            pattern.name
        );
        // Bare, the checksum alone reaches the balanced threshold ...
        assert!(
            score::rule_score(pattern) >= PiiMode::Balanced.min_score().unwrap(),
            "{}",
            pattern.name
        );
        // ... and a nearer counter-context term drops it in every scored mode.
        assert!(
            score::score(pattern, Context::Counter) < PiiMode::Recall.min_score().unwrap(),
            "{}",
            pattern.name
        );
    }
    // Every checksum label has an unbound rule: a checksum value never needs its
    // field name in the scored modes. Only four need a term: ten digits in phone
    // groups (3-3-4) pass the mod-11 digit of the NHS number (B-UK) one time in
    // eleven, nine digits in 3-3-3 groups the ACN mod-10 digit one time in ten and
    // the TFN mod-11 sum one time in eleven (B-APAC), nine bare digits the LANR
    // mod-10 digit one time in ten (B-DE1).
    for bound in PII_PATTERNS
        .iter()
        .filter(|pattern| pattern.strength == ValidatorStrength::Checksum)
        .filter(|pattern| !CONTEXT_BOUND_LABELS.contains(&pattern.entity_group))
    {
        assert!(
            PII_PATTERNS.iter().any(|pattern| {
                pattern.entity_group == bound.entity_group
                    && pattern.strength == ValidatorStrength::Checksum
                    && !pattern.captured_value
                    && !pattern.requires_context
            }),
            "{} has no context-free rule",
            bound.entity_group
        );
    }
}

#[test]
fn every_checksum_label_reports_a_bare_value_in_the_scored_modes() {
    let bare = [
        ("IBAN", "DE89370400440532013000", 0.90),
        ("IBAN", "GB82WEST12345698765432", 0.80),
        ("CREDITCARD", "4111 1111 1111 1111", 0.75),
        ("STEUERID", "86095742719", 0.55),
        ("STEUERID", "86 095 742 719", 0.55),
        ("VAT_ID_DE", "DE136695976", 0.55),
        ("VAT_ID_AT", "ATU13585627", 0.55),
        ("VAT_ID_CH", "CHE-100.155.212", 0.55),
        ("VAT_ID_FR", "FR40303265045", 0.55),
        ("VAT_ID_NL", "NL004495445B01", 0.55),
        ("VAT_ID_BE", "BE0403019261", 0.55),
        ("VAT_ID_IT", "IT00743110157", 0.55),
        ("VAT_ID_ES", "ESA13585625", 0.55),
        ("VAT_ID_BG", "BG175074752", 0.55),
        ("VAT_ID_CY", "CY10259033P", 0.55),
        ("VAT_ID_CZ", "CZ25123891", 0.55),
        ("VAT_ID_DK", "DK13585628", 0.55),
        ("VAT_ID_EE", "EE100931558", 0.55),
        ("VAT_ID_EL", "EL094259216", 0.55),
        ("VAT_ID_FI", "FI20774740", 0.55),
        ("VAT_ID_HR", "HR33392005961", 0.55),
        ("VAT_ID_HU", "HU12892312", 0.55),
        ("VAT_ID_IE", "IE6433435F", 0.55),
        ("VAT_ID_LT", "LT119511515", 0.55),
        ("VAT_ID_LU", "LU15027442", 0.55),
        ("VAT_ID_LV", "LV40003521600", 0.55),
        ("VAT_ID_MT", "MT11679112", 0.55),
        ("VAT_ID_PL", "PL8567346215", 0.55),
        ("VAT_ID_PT", "PT501964843", 0.55),
        ("VAT_ID_RO", "RO18547290", 0.55),
        ("VAT_ID_SE", "SE556677889901", 0.55),
        ("VAT_ID_SI", "SI50223054", 0.55),
        ("VAT_ID_SK", "SK2022749619", 0.55),
        ("VAT_ID_NO", "NO995525828MVA", 0.55),
        ("VAT_ID_GB", "GB980780684", 0.55),
        ("PASSPORT_NUMBER", "C01X00T41", 0.55),
        ("PASSPORT_NUMBER", "C01X00T478", 0.55),
        ("IDENTITY_CARD_NUMBER", "L01X00T44", 0.55),
        ("IDENTITY_CARD_NUMBER", "T220001293", 0.55),
        ("AU_ABN", "51 824 753 556", 0.55),
        ("AU_MEDICARE", "2123 45670 1", 0.55),
        ("SG_NRIC_FIN", "S0642712Z", 0.55),
        ("SG_UEN", "201434292D", 0.55),
        ("SG_UEN", "S57TU0392K", 0.55),
        ("SOCIALID", "15070649C103", 0.55),
        ("SOCIALID", "65 230109 Z 872", 0.55),
        ("HEALTH_INSURANCE_NUMBER", "A123456780", 0.55),
        ("SE_PERSONNUMMER", "811228-9874", 0.55),
        ("DK_CPR", "080572-3300", 0.55),
        ("NO_FODSELSNUMMER", "110897 33660", 0.55),
        ("FI_PERSONAL_IDENTITY_CODE", "131052-308T", 0.55),
        ("HEALTH_INSURANCE_NUMBER", "a123456780", 0.55),
        ("FINANCIAL_ACCOUNT_NUMBER", "0711-0130-7", 0.55),
    ];
    for label in PII_PATTERNS
        .iter()
        .filter(|pattern| pattern.strength == ValidatorStrength::Checksum)
        .map(|pattern| pattern.entity_group)
        .filter(|label| !CONTEXT_BOUND_LABELS.contains(label))
    {
        assert!(
            bare.iter().any(|(known, _, _)| *known == label),
            "{label}: no bare sample"
        );
    }
    for (label, value, expected) in bare {
        for mode in SCORED {
            assert_eq!(
                spans(value, mode, label),
                [(value.to_string(), expected)],
                "{mode:?}: {value}"
            );
        }
    }
    // Strict keeps the field-name rule for the Steuer-ID (K02).
    assert!(spans("86095742719", PiiMode::Strict, "STEUERID").is_empty());
    assert_eq!(
        spans("DE89370400440532013000", PiiMode::Strict, "IBAN"),
        [("DE89370400440532013000".to_string(), 1.0)]
    );
}

#[test]
fn strict_never_runs_a_scored_only_rule() {
    let mut texts: Vec<String> = ISSUED
        .iter()
        .flat_map(|value| {
            [
                value.to_string(),
                format!("Ihre Steuer-ID ist {value}."),
                format!("{value} is the German tax ID on file."),
                format!("{{\"steuer_id\": \"{value}\"}}"),
            ]
        })
        .collect();
    let goldens = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/pii_l1.jsonl");
    for line in std::fs::read_to_string(goldens).unwrap().lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        texts.push(row["text"].as_str().unwrap().to_string());
    }
    let strict = scanner(PiiMode::Strict);
    for text in texts {
        for rule in matched_rules(&scan(&strict, &text)) {
            assert!(
                !pattern(rule["rule_id"].as_str().unwrap()).scored_only,
                "{text}: {rule}"
            );
        }
    }
}

#[test]
fn bare_steuer_id_scores_its_context() {
    let rule_of = |text: &str, mode: PiiMode| {
        matched_rules(&pii_result(text, mode))
            .into_iter()
            .find(|rule| rule["rule_id"] == STEUER_ID)
    };
    for mode in SCORED {
        // No context: base 20 + checksum 35.
        assert_eq!(
            spans("Bitte noch 47426548904 nachtragen.", mode, "STEUERID"),
            [("47426548904".to_string(), 0.55)],
            "{mode:?}"
        );
        // A support term before or after the value raises it.
        let before = rule_of("Ihre Steuer-ID ist 39662845670.", mode).unwrap();
        assert_eq!(before["score"], 0.8, "{mode:?}");
        assert_eq!(before["context"]["anchor"], "pii.tax_identifier");
        assert_eq!(before["context"]["side"], "before");
        let after = rule_of("29046789957 is the German tax ID on file.", mode).unwrap();
        assert_eq!(after["context"]["side"], "after");
        assert!(after["score"].as_f64().unwrap() > 0.55, "{mode:?}");
        // A nearer counter-context term drops it in balanced and recall.
        for text in [
            "Rechnungsnummer 86095742719 bitte bei Zahlung angeben.",
            "Bestellnummer: 65929970489",
            "Invoice number 86095742719 is overdue.",
            "Tracking number 25768131411 is in transit.",
            r#"{"order_id": "86095742719"}"#,
        ] {
            assert!(spans(text, mode, "STEUERID").is_empty(), "{mode:?}: {text}");
        }
        // After its field name the field-bound rule keeps the span and its score.
        assert_eq!(
            spans("Steuer-ID: 86095742719", mode, "STEUERID"),
            [("86095742719".to_string(), 1.0)],
            "{mode:?}"
        );
    }
}

#[test]
fn bare_steuer_id_stands_alone() {
    for text in [
        "Messwert 860957427190 im Log.",
        "Aktenzeile 86095742719/2026 abgelegt.",
        "Range 86095742719-86095742720 reserved.",
        "Faktor 3,86095742719 berechnet.",
        "Version 1.86095742719 released.",
        "Kennung DE86095742719",
        "Code X86095742719Y",
        "Zeile 12 86 095 742 719 im Export.",
        "Gruppe 86 095 742 719 12 im Export.",
        "Konto 2026/86095742719",
        "+86095742719",
    ] {
        for mode in SCORED {
            assert!(spans(text, mode, "STEUERID").is_empty(), "{mode:?}: {text}");
        }
    }
    for (text, value) in [
        ("(47426548904)", "47426548904"),
        ("Nummer: 47426548904.", "47426548904"),
        ("Name;Nummer\nJonas Weber;86231292506", "86231292506"),
        ("name,tin\nAda Weber,28540106973", "28540106973"),
        ("Jonas\t86231292506\t4711", "86231292506"),
        ("„86 794 425 307“ übernehmen", "86 794 425 307"),
    ] {
        for mode in SCORED {
            assert_eq!(
                spans(text, mode, "STEUERID")
                    .into_iter()
                    .map(|(text, _)| text)
                    .collect::<Vec<_>>(),
                [value],
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn issued_steuer_id_checksum_vectors() {
    for value in ISSUED {
        assert!(validators::steuer_id(value), "{value}");
        assert!(validators::steuer_id_issued(value), "{value}");
        for mode in SCORED {
            assert_eq!(
                spans(&format!("Bitte {value} übernehmen."), mode, "STEUERID"),
                [(value.to_string(), 0.55)],
                "{mode:?}: {value}"
            );
        }
    }
    assert!(validators::steuer_id_issued("86 095 742 719"));
    for (value, reason) in [
        ("86095742718", "check digit fails"),
        ("47426548905", "check digit fails"),
        ("06095742719", "leading zero"),
        ("8609574271", "ten digits"),
        ("860957427190", "twelve digits"),
        ("12345678903", "ten distinct digits, check digit valid"),
        ("67890123455", "ten distinct digits, check digit valid"),
        ("98765432106", "ten distinct digits, check digit valid"),
        ("47110815008", "two digits repeated, check digit valid"),
        (
            "86555742194",
            "a digit three times in a row, check digit valid",
        ),
        ("11111111111", "one digit only"),
    ] {
        assert!(!validators::steuer_id_issued(value), "{value}: {reason}");
        for mode in SCORED {
            assert!(
                spans(&format!("Bitte {value} übernehmen."), mode, "STEUERID").is_empty(),
                "{mode:?}: {value}: {reason}"
            );
        }
    }
    // The issued check only tightens the Steuer-ID validator.
    for body in (1_000_000_000u64..10_000_000_000).step_by(7_919_993) {
        for check in 0..10 {
            let value = format!("{body}{check}");
            assert!(
                !validators::steuer_id_issued(&value) || validators::steuer_id(&value),
                "{value}"
            );
        }
    }
}

// ── bare Steuernummer in the slashed groups of the Länder (Q-DE) ────────────

#[test]
fn bare_slashed_tax_number_is_reported_in_the_scored_modes_only() {
    let rule = pattern(TAX_NUMBER);
    assert_eq!(rule.entity_group, "TAX_NUMBER_DE");
    assert_eq!(rule.strength, ValidatorStrength::Format);
    assert_eq!(
        rule.validator.map(|validator| validator as usize),
        Some(validators::de_tax_number as fn(&str) -> bool as usize)
    );
    for (text, value) in [
        // 3/3/5 (BW, BY, BB, MV, SN, ST, TH), the presidio-analyzer value
        ("123/456/78901", "123/456/78901"),
        (
            "Bitte 151/815/08156 im Formular eintragen.",
            "151/815/08156",
        ),
        // 2/3/5 (BE, HB, HH, NI, SH)
        ("Please file 21/815/08150 with the return.", "21/815/08150"),
        // 3/4/4 (NW)
        ("Bitte 133/8150/8159 übernehmen.", "133/8150/8159"),
        ("(048/815/08153)", "048/815/08153"),
    ] {
        for mode in SCORED {
            assert_eq!(
                spans(text, mode, "TAX_NUMBER_DE"),
                [(value.to_string(), 0.50)],
                "{mode:?}: {text}"
            );
        }
        assert!(
            spans(text, PiiMode::Strict, "TAX_NUMBER_DE").is_empty(),
            "{text}"
        );
    }
    // A tax number term near the value raises it; after its field name the
    // field-bound rule keeps the span in every mode.
    for mode in SCORED {
        assert_eq!(
            spans(
                "Die Steuernummer der Praxis ist 143/208/30142.",
                mode,
                "TAX_NUMBER_DE"
            ),
            [("143/208/30142".to_string(), 0.75)],
            "{mode:?}"
        );
        assert_eq!(
            spans("Steuernummer: 123/456/78901", mode, "TAX_NUMBER_DE"),
            [("123/456/78901".to_string(), 0.75)],
            "{mode:?}"
        );
    }
}

#[test]
fn bare_tax_number_lookalikes_stay_silent() {
    for text in [
        // the field names another value
        "Aktenzeichen: 123/456/78901",
        "Case number: 123/456/78901",
        r#"{"order_id": "123/456/78901"}"#,
        // a nearer counter-context term
        "Rechnungsnummer 123/456/78901",
        "Invoice number 21/815/08150",
        // other group lengths
        "Version 12/34/56789",
        "Bitte 123/456/7890 prüfen.",
        "Bitte 1234/567/89012 prüfen.",
        "Datum 12/03/2026",
        // repeated digits are never issued
        "Bitte 111/111/11111 prüfen.",
        // part of a longer number or path
        "Pfad 2026/123/456/78901",
        "Ref 123/456/78901/2",
        "Ref 123/456/78901-2",
        // no ELSTER form without slashes: 13 digits are as often a timestamp
        "0181508150000",
        "Zeitstempel 1698234567890",
    ] {
        for mode in SCORED {
            assert!(
                spans(text, mode, "TAX_NUMBER_DE").is_empty(),
                "{mode:?}: {text}"
            );
        }
    }
}
