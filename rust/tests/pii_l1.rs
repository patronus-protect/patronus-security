use std::collections::BTreeSet;

use patronus_ark::detectors::pii::{pii::PiiPipeline, validators};
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult};

fn pii_result(text: &str) -> SecurityScanResult {
    SecurityGateway::with_max_level(vec![SecurityCategory::Pii], SecurityLevel::L1, None, false)
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

macro_rules! pii_golden {
    ($name:ident, $label:literal, $text:literal) => {
        #[test]
        fn $name() {
            assert_eq!(PiiPipeline::new().evaluate($text).class_name, $label);
        }
    };
}

pii_golden!(detects_email, "EMAIL", "E-Mail: ada@example.com");
pii_golden!(detects_phone, "PHONE", "Telefon: +491701234567");
pii_golden!(
    detects_hyphenated_international_phone,
    "PHONE",
    "Phone: +76-532-1520"
);
pii_golden!(detects_ip_address, "IP_ADDRESS", "IP: 203.0.113.42");
pii_golden!(detects_mac_address, "MAC_ADDRESS", "MAC: 02:42:ac:11:00:02");
pii_golden!(
    detects_payment_card_pan,
    "CREDITCARD",
    "Karte: 4111 1111 1111 1111"
);
pii_golden!(detects_payment_card_cvv, "CREDITCARD_CVV", "CVV: 123");
pii_golden!(
    detects_payment_card_expiry,
    "CREDITCARD_EXPIRY",
    "Ablaufdatum: 12/29"
);
pii_golden!(detects_iban, "IBAN", "IBAN: DE89370400440532013000");
pii_golden!(detects_bic, "SWIFT_CODE", "BIC: DEUTDEFF500");
pii_golden!(
    detects_employee_id,
    "EMPLOYEE_ID",
    "Personalnummer: EMP-4711"
);
pii_golden!(
    detects_english_employee_id,
    "EMPLOYEE_ID",
    "Employee ID EMP-2042"
);
pii_golden!(detects_customer_id, "CUSTOMER_ID", "Kundennummer: KD-88231");
pii_golden!(
    detects_english_customer_id,
    "CUSTOMER_ID",
    "Customer ID CUST-88231"
);
pii_golden!(
    detects_patient_id,
    "PATIENT_ID",
    "Patientennummer: PAT-2048"
);
pii_golden!(
    detects_english_patient_id,
    "PATIENT_ID",
    "Medical record number MRN-204817"
);
pii_golden!(detects_student_id, "STUDENT_ID", "Matrikelnummer: STU-9911");
pii_golden!(
    detects_english_student_id,
    "STUDENT_ID",
    "Student ID STU-9911"
);
pii_golden!(
    detects_applicant_id,
    "APPLICANT_ID",
    "Bewerbernummer: BEW-713"
);
pii_golden!(
    detects_english_applicant_id,
    "APPLICANT_ID",
    "Applicant number APP-713"
);
pii_golden!(
    detects_german_applicant_copula,
    "APPLICANT_ID",
    "Ihre Bewerbernummer ist BEW-2026-10482"
);
pii_golden!(detects_username, "USERNAME", "Benutzername: ada.lovelace");
pii_golden!(detects_date_of_birth, "DOB", "Geburtsdatum: 29.02.2000");
pii_golden!(
    detects_written_german_date_of_birth,
    "DOB",
    "Geburtsdatum: 28. Februar 1985"
);
pii_golden!(
    detects_english_date_of_birth,
    "DOB",
    "Date of birth: 29/02/2000"
);
pii_golden!(
    detects_written_english_date_of_birth_day_first,
    "DOB",
    "The patient record lists her date of birth as 14 March 1985 in the intake form."
);
pii_golden!(
    detects_written_english_date_of_birth_month_first,
    "DOB",
    "DOB: February 29th, 2000"
);
pii_golden!(
    detects_financial_account,
    "FINANCIAL_ACCOUNT_NUMBER",
    "Kontonummer: ACC-44001234"
);
pii_golden!(
    detects_english_financial_account,
    "FINANCIAL_ACCOUNT_NUMBER",
    "Account number ACC-44001234"
);
pii_golden!(detects_de_tax_id, "STEUERID", "Steuer-ID: 86095742719");
pii_golden!(
    detects_de_tax_number,
    "TAX_NUMBER_DE",
    "Steuernummer: 123/456/78901"
);
pii_golden!(
    detects_de_tax_number_abbreviation,
    "TAX_NUMBER_DE",
    "Steuer Nr. 12/345/67890"
);
pii_golden!(
    detects_de_social_security_id,
    "SOCIALID",
    "Sozialversicherungsnummer: 12123456A123"
);
pii_golden!(
    detects_de_social_security_id_abbreviation,
    "SOCIALID",
    "SV-Nr.: 12 123456 A 123"
);
pii_golden!(
    detects_de_health_insurance_id,
    "HEALTH_INSURANCE_NUMBER",
    "Versichertennummer: A123456789"
);
pii_golden!(
    detects_english_health_insurance_id,
    "HEALTH_INSURANCE_NUMBER",
    "Health insurance number X123456789"
);
pii_golden!(
    detects_de_physician_lanr,
    "PHYSICIAN_NUMBER_LANR",
    "LANR: 123456789"
);
pii_golden!(
    detects_de_passport,
    "PASSPORT_NUMBER",
    "Passnummer: C01X00T47"
);
pii_golden!(
    detects_english_passport,
    "PASSPORT_NUMBER",
    "Passport number C01X00T47"
);
pii_golden!(
    detects_de_identity_card,
    "IDENTITY_CARD_NUMBER",
    "Personalausweisnummer: L01X00T47"
);
pii_golden!(
    detects_de_driver_license,
    "DRIVER_LICENSE_NUMBER",
    "Führerscheinnummer: B072RRE2A57"
);
pii_golden!(
    detects_de_license_plate,
    "LICENSEPLATE",
    "KFZ-Kennzeichen: B-AB 1234E"
);
pii_golden!(detects_us_ssn, "SSN", "SSN: 123-45-6789");
pii_golden!(detects_uk_nino, "NATIONALID", "NINO: AB123456C");

#[test]
fn rejects_invalid_values_and_identifiers_without_the_right_anchor() {
    let pipeline = PiiPipeline::new();
    for text in [
        "Karte: 4111 1111 1111 1112",
        "CVV: 12",
        "Ablaufdatum: 13/29",
        "MAC: 00:00:00:00:00:00",
        "Geburtsdatum: 31.02.2000",
        "Geburtsdatum: 31. Februar 2000",
        "DOB: February 29th, 2001",
        "Steuer-ID: 86095742718",
        "SSN: 000-12-3456",
        "NINO: BG123456A",
        "Build: EMP-4711",
        "Rechnungsnummer: KD-88231",
        "Ticket: PAT-2048",
        "Kursnummer: STU-9911",
        "Vorgangsnummer: BEW-713",
        "Release: 123-45-6789",
        "AB123456C",
        "B-AB 1234E",
    ] {
        assert_eq!(
            pipeline.evaluate(text).class_name,
            "safe",
            "matched {text:?}"
        );
    }
}

#[test]
fn validators_reject_malformed_or_reserved_values() {
    assert!(!validators::phone("+0000000"));
    assert!(!validators::mac_address("00:00:00:00:00:00"));
    assert!(!validators::luhn("4111 1111 1111 1112"));
    assert!(!validators::cvv("12"));
    assert!(!validators::card_expiry("13/29"));
    assert!(!validators::bic("DEUTD3"));
    assert!(!validators::mod97("DE89370400440532013001"));
    assert!(!validators::bounded_identifier("EMPLOYEE"));
    assert!(!validators::username("admin"));
    assert!(!validators::calendar_date("31.02.2000"));
    assert!(!validators::written_calendar_date("31. Februar 2000"));
    assert!(!validators::written_calendar_date("February 29th, 2001"));
    assert!(!validators::steuer_id("86095742718"));
    assert!(!validators::de_tax_number("000/000/00000"));
    assert!(!validators::de_social_security_number("12123456-123"));
    assert!(!validators::de_health_insurance_number("A000000000"));
    assert!(!validators::lanr("000000000"));
    assert!(!validators::de_document_number("B01X00T47"));
    assert!(!validators::de_driver_license_number("B072RRE2A5"));
    assert!(!validators::us_ssn("000-12-3456"));
    assert!(!validators::uk_nino("BG123456A"));
}

#[test]
fn anchor_bound_findings_emit_only_the_value_with_utf8_offsets() {
    let text = "Grüße – Personalnummer: EMP-4711.";
    let expected_start = text.find("EMP-4711").unwrap();
    let result = pii_result(text);

    assert_eq!(result.class_name, "EMPLOYEE_ID");
    assert_eq!(result.evidence_spans.len(), 1);
    let span = &result.evidence_spans[0];
    assert_eq!(span.label, "EMPLOYEE_ID");
    assert_eq!(span.text, "EMP-4711");
    assert_eq!(span.start_byte, expected_start);
    assert_eq!(span.end_byte, expected_start + "EMP-4711".len());
    assert_eq!(span.start_char, text[..expected_start].chars().count());
    assert_eq!(
        span.end_char,
        text[..expected_start].chars().count() + "EMP-4711".chars().count()
    );
}

#[test]
fn direct_and_contextual_findings_keep_exact_value_boundaries() {
    for (text, label, expected) in [
        ("BIC code is DEUTDEFF500.", "SWIFT_CODE", "DEUTDEFF500"),
        ("CVV: 123", "CREDITCARD_CVV", "123"),
        ("Geburtsdatum: 29.02.2000", "DOB", "29.02.2000"),
        ("Kontakt: ada@example.com", "EMAIL", "ada@example.com"),
    ] {
        let result = pii_result(text);
        let span = result
            .evidence_spans
            .iter()
            .find(|span| span.label == label)
            .unwrap_or_else(|| panic!("missing {label} span for {text:?}"));
        assert_eq!(span.text, expected);
        assert_eq!(&text[span.start_byte..span.end_byte], expected);
    }
}

#[test]
fn contextual_fields_are_exposed_as_anchor_facts_without_fake_findings() {
    let text = "Name: Ada; Anschrift: Berlin; Diagnose: vertraulich; Religion: keine Angabe; Gehalt: offen";
    let result = pii_result(text);

    assert_eq!(result.class_name, "safe");
    assert!(result.evidence_spans.is_empty());
    let anchors = result.layers[0].details["l1_anchors"]
        .as_array()
        .expect("PII L1 anchors must be exposed as an array");
    let categories = anchors
        .iter()
        .map(|anchor| anchor["category"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        categories,
        [
            "person_identity",
            "address",
            "medical",
            "special_category",
            "employment_compensation",
        ]
    );
    for anchor in anchors {
        assert_eq!(anchor["anchor_kind"], "lexical");
        assert!(matches!(
            anchor["strength"].as_str(),
            Some("weak" | "medium" | "strong")
        ));
        let start = anchor["start_byte"].as_u64().unwrap() as usize;
        let end = anchor["end_byte"].as_u64().unwrap() as usize;
        assert_eq!(text.get(start..end), anchor["text"].as_str());
        assert_eq!(text[..start].chars().count(), anchor["start_char"]);
        assert_eq!(text[..end].chars().count(), anchor["end_char"]);
    }
}

#[test]
fn reference_derived_anchor_families_are_exposed_without_findings() {
    let text = "Patientenname; Mobilnummer; Rechnungsadresse; geboren am; MRN; Steuer-ID; Patientenakte; Payroll";
    let result = pii_result(text);

    assert_eq!(result.class_name, "safe");
    let categories = result.layers[0].details["l1_anchors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|anchor| anchor["category"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        categories,
        BTreeSet::from([
            "person_identity",
            "contact",
            "address",
            "date_of_birth",
            "person_identifier",
            "government_identifier",
            "medical",
            "employment_compensation",
        ])
    );
}

#[test]
fn german_and_english_anchor_variants_have_exact_metadata() {
    let cases = [
        ("Rufname", "person_identity", "weak"),
        ("maiden_name", "person_identity", "weak"),
        ("Kontoinhaberin", "person_role", "weak"),
        ("policy-holder", "person_role", "weak"),
        ("Tel_Nr", "contact", "medium"),
        ("cellular phone", "contact", "medium"),
        ("Korrespondenzadresse", "address", "weak"),
        ("permanent_address", "address", "weak"),
        ("Geb.-Dat", "date_of_birth", "strong"),
        ("D.O.B", "date_of_birth", "strong"),
        ("Personnel Number", "person_identifier", "strong"),
        ("Candidate_ID", "person_identifier", "strong"),
        ("Schüler-ID", "person_identifier", "strong"),
        ("Debitor", "person_identifier", "strong"),
        ("Pupil Number", "person_identifier", "strong"),
        ("Application-ID", "person_identifier", "strong"),
        ("Benutzerkennung", "account_identifier", "medium"),
        ("login_name", "account_identifier", "medium"),
        ("Kartenprüfziffer", "payment_card", "strong"),
        ("card security code", "payment_card", "strong"),
        ("Depot-Nr", "financial_identifier", "strong"),
        ("brokerage account number", "financial_identifier", "strong"),
        ("RV_Nr", "government_identifier", "strong"),
        ("passport no", "government_identifier", "strong"),
        ("driver licence no", "government_identifier", "strong"),
        ("amtliches Kennzeichen", "vehicle_identifier", "strong"),
        ("license_plate", "vehicle_identifier", "strong"),
        ("Entlassungsbericht", "medical", "medium"),
        ("electronic health record", "medical", "medium"),
        ("Gewerkschaftsmitgliedschaft", "special_category", "medium"),
        ("gender_identity", "special_category", "medium"),
        ("Gesamtvergütung", "employment_compensation", "weak"),
        ("restricted stock units", "employment_compensation", "weak"),
    ];

    for (variant, expected_category, expected_strength) in cases {
        let text = format!("Präfix – {variant} – suffix");
        let expected_start = text.find(variant).unwrap();
        let result = pii_result(&text);

        assert_eq!(
            result.class_name, "safe",
            "anchor became finding: {variant}"
        );
        assert!(
            result.evidence_spans.is_empty(),
            "anchor became evidence: {variant}"
        );
        let anchor = result.layers[0]
            .details
            .get("l1_anchors")
            .unwrap_or_else(|| panic!("no anchors for {variant:?}"))
            .as_array()
            .unwrap_or_else(|| panic!("anchors are not an array for {variant:?}"))
            .iter()
            .find(|anchor| anchor["text"] == variant && anchor["category"] == expected_category)
            .unwrap_or_else(|| {
                panic!("missing {expected_category}/{expected_strength} for {variant:?}")
            });

        assert_eq!(anchor["kind"], "anchor");
        assert_eq!(anchor["anchor_kind"], "lexical");
        assert_eq!(anchor["strength"], expected_strength);
        assert_eq!(anchor["start_byte"], expected_start);
        assert_eq!(anchor["end_byte"], expected_start + variant.len());
        assert_eq!(anchor["start_char"], text[..expected_start].chars().count());
        assert_eq!(
            anchor["end_char"],
            text[..expected_start + variant.len()].chars().count()
        );
    }
}

#[test]
fn anchor_lookalikes_remain_safe_without_anchor_facts() {
    for text in [
        "Die Personalnummerierung beginnt bei eins.",
        "Der Kundennummernkreis wurde erweitert.",
        "Die Geburt verlief ohne Komplikationen.",
        "The employeeIdentifier field is deprecated.",
        "The passport numbering scheme changed.",
        "The CVValue variable is internal.",
        "Die Diagnosesoftware wurde aktualisiert.",
        "Das Gehaltsband wurde veröffentlicht.",
    ] {
        let result = pii_result(text);
        assert_eq!(
            result.class_name, "safe",
            "lookalike became finding: {text}"
        );
        assert!(
            result.evidence_spans.is_empty(),
            "lookalike became evidence: {text}"
        );
        assert!(
            !result.layers[0].details.contains_key("l1_anchors"),
            "lookalike became anchor: {text}"
        );
    }
}
