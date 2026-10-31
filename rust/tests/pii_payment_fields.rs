// SPDX-License-Identifier: GPL-3.0-only
//! Payment fields of the quality pass Q-FIN (floor F1 80, decided 2026-10-25).
//!
//! - A card verification code whose field names the card (`Credit Card Security Code: 279`,
//!   `Creditcardveiligheidscode: 713`, `Código de Seguridad de Tarjeta de Crédito: 599`)
//!   belongs to a card without the card number in the text. A bare `CVV:`, `Security code:`
//!   or `Sicherheitscode:` still needs a reported card or a CVV column.
//! - SWIFT/BIC field names: `Swift/BIC-code:`, `swift_bic_code`, `<swiftBIC>`, a note in
//!   parentheses before the colon, and `BIC X` or `SWIFT BIC code X` in prose. The BIC
//!   validator is unchanged.

use patronus_ark::detectors::pii::score::PiiMode;
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const MODES: [PiiMode; 2] = [PiiMode::Strict, PiiMode::Balanced];

fn scan(text: &str, mode: PiiMode) -> SecurityScanResult {
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

fn values(text: &str, label: &str, mode: PiiMode) -> Vec<String> {
    scan(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == label)
        .map(|span| span.text)
        .collect()
}

fn assert_found(cases: &[(&str, &str)], label: &str) {
    for (text, value) in cases {
        for mode in MODES {
            assert_eq!(
                values(text, label, mode),
                vec![value.to_string()],
                "{mode:?}: {text}"
            );
        }
    }
}

fn assert_silent(cases: &[&str], label: &str) {
    for text in cases {
        for mode in MODES {
            assert!(
                values(text, label, mode).is_empty(),
                "{mode:?}: {text}: {:?}",
                values(text, label, mode)
            );
        }
    }
}

#[test]
fn a_security_code_whose_field_names_the_card_needs_no_card_number() {
    assert_found(
        &[
            ("Credit Card Security Code: 279", "279"),
            ("**Credit Card Security Code:** 438", "438"),
            (
                "The insured has provided the credit card security code 545 for the premium.",
                "545",
            ),
            (
                "Please do not share your credit card security code (050) with anyone.",
                "050",
            ),
            (
                "It shipped with a credit card security code of 983 and a signature.",
                "983",
            ),
            ("Kreditkarte, Sicherheitscode: 123", "123"),
            ("Kreditkarte – Kartenprüfnummer: 481", "481"),
            ("Kreditkarte (Visa), CVV: 552", "552"),
            ("Debitkarte CVC: 315", "315"),
            ("Creditcardveiligheidscode: 713", "713"),
            ("Je creditcard-beveiligingscode is 513.", "513"),
            ("Code de sécurité de la carte de crédit : 965", "965"),
            ("Codice di sicurezza della carta di credito: 674", "674"),
            ("Código de Seguridad de Tarjeta de Crédito: 599", "599"),
        ],
        "CREDITCARD_CVV",
    );
}

#[test]
fn a_security_code_without_a_card_term_or_number_stays_silent() {
    assert_silent(
        &[
            "Security code: 123",
            "Security code 4821 for the building door.",
            "The alarm security code is 7731.",
            "Gift card balance: 250, security code 123",
            "Credit card on file.\nSecurity code: 445",
            "Credit card security code: ***",
            "Tresor-Sicherheitscode: 9182",
            "Sicherheitscode: 4711 (Alarmanlage)",
            "Kreditkarte beantragt; Sicherheitscode: 5531",
            "Kundenkarte, Sicherheitscode 12",
            "cvc: 309",
        ],
        "CREDITCARD_CVV",
    );
}

#[test]
fn combined_swift_bic_field_names_bind_the_bic() {
    assert_found(
        &[
            (
                "Bank details: IBAN DE89 3704 0044 0532 0130 00, BIC COBADEFFXXX",
                "COBADEFFXXX",
            ),
            (
                "Swift BIC Code (for international transactions): DEUTDEFF500",
                "DEUTDEFF500",
            ),
            (
                "Payments go to the bank with the SWIFT BIC code BARCGB22.",
                "BARCGB22",
            ),
            ("swift_bic_code: CHASUS33", "CHASUS33"),
            (
                "<party><swiftBIC>UBSWCHZH80A</swiftBIC></party>",
                "UBSWCHZH80A",
            ),
            ("Swift/BIC-Code: INGDDEFFXXX", "INGDDEFFXXX"),
            ("Nachtrag zu meinen Daten, BIC WNCCIT6D.", "WNCCIT6D"),
            ("SWIFT-BIC: BYLADEM1001", "BYLADEM1001"),
            ("BIC (Empfängerbank): GENODEF1M04", "GENODEF1M04"),
            ("Swift/BIC-code: RABONL2U", "RABONL2U"),
        ],
        "SWIFT_CODE",
    );
    for mode in MODES {
        let text = "swift_bic_code,name\nNKQMDEEV043,Nicole Ingram\nBIYNDECX364,Andre Acker\n";
        assert_eq!(
            values(text, "SWIFT_CODE", mode),
            vec!["NKQMDEEV043".to_string(), "BIYNDECX364".to_string()],
            "{mode:?}"
        );
    }
}

#[test]
fn swift_without_a_bic_field_or_value_stays_silent() {
    assert_silent(
        &[
            "SWIFT BIC code missing from the form.",
            "BIC 1234ABCD",
            "We route SWIFT PAYMENTS through the hub.",
            "Swift BIC Code (2 of 3): DEUTDEFF500",
            "swift_bic_code: DEUTD3",
            "BIC siehe Kontoauszug",
            "Swift/BIC-Code: ****DEFF",
            "BIC (Empfängerbank): folgt",
            "Wir wickeln SWIFT ZAHLUNG ab.",
            "SWIFT-BIC: DEUTDEFF5",
            "Swift code is powerful.",
        ],
        "SWIFT_CODE",
    );
}
