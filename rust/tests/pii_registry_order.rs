//! The order of `PII_PATTERNS` is behaviour: the first matching rule sets
//! `class_name`, and among same-label overlaps the earlier rule keeps its span
//! (IBAN before card, DE phone before US phone). The rules live in regional
//! modules (K01); this test keeps the registry order fixed across such moves.
//! A new rule is appended here at the position it takes in the registry.

use patronus_ark::detectors::pii::pii::PII_PATTERNS;

const EXPECTED_ORDER: &[(&str, &str)] = &[
    ("pii_email", "EMAIL"),
    ("pii_ipv4", "IP_ADDRESS"),
    ("pii_ipv6_full", "IP_ADDRESS"),
    ("pii_ipv6_compressed", "IP_ADDRESS"),
    ("pii_ipv6_loopback", "IP_ADDRESS"),
    ("pii_phone_international", "PHONE"),
    ("pii_phone_de", "PHONE"),
    ("pii_phone_de_national_context", "PHONE"),
    ("pii_phone_de_national_proximity", "PHONE"),
    ("pii_phone_us", "PHONE"),
    ("pii_mac_address", "MAC_ADDRESS"),
    ("pii_iban_de", "IBAN"),
    ("pii_iban_generic", "IBAN"),
    ("pii_credit_card", "CREDITCARD"),
    ("pii_credit_card_cvv", "CREDITCARD_CVV"),
    ("pii_credit_card_expiry", "CREDITCARD_EXPIRY"),
    ("pii_swift_bic_context", "SWIFT_CODE"),
    ("pii_employee_id", "EMPLOYEE_ID"),
    ("pii_employee_id_ocr_field", "EMPLOYEE_ID"),
    ("pii_employee_id_prefixed", "EMPLOYEE_ID"),
    ("pii_customer_id", "CUSTOMER_ID"),
    ("pii_patient_id", "PATIENT_ID"),
    ("pii_student_id", "STUDENT_ID"),
    ("pii_applicant_id", "APPLICANT_ID"),
    ("pii_username", "USERNAME"),
    ("pii_date_of_birth", "DOB"),
    ("pii_date_of_birth_written_day_first", "DOB"),
    ("pii_date_of_birth_written_month_first", "DOB"),
    ("pii_financial_account_number", "FINANCIAL_ACCOUNT_NUMBER"),
    ("pii_steuer_id_de", "STEUERID"),
    ("pii_steuer_id_de_context_free", "STEUERID"),
    ("pii_steuernummer_de", "TAX_NUMBER_DE"),
    ("pii_rentenversicherung_de", "SOCIALID"),
    ("pii_health_insurance_number_de", "HEALTH_INSURANCE_NUMBER"),
    ("pii_physician_number_lanr_de", "PHYSICIAN_NUMBER_LANR"),
    ("pii_passport_number_de", "PASSPORT_NUMBER"),
    ("pii_identity_card_number_de", "IDENTITY_CARD_NUMBER"),
    ("pii_driver_license_number_de", "DRIVER_LICENSE_NUMBER"),
    ("pii_kfz_kennzeichen_de", "LICENSEPLATE"),
    ("pii_ssn_us", "SSN"),
    ("pii_ni_uk", "NATIONALID"),
    ("pii_vat_id_de", "VAT_ID_DE"),
    ("pii_vat_id_at", "VAT_ID_AT"),
    ("pii_vat_id_ch", "VAT_ID_CH"),
    ("pii_vat_id_fr", "VAT_ID_FR"),
    ("pii_vat_id_nl", "VAT_ID_NL"),
    ("pii_vat_id_be", "VAT_ID_BE"),
    ("pii_vat_id_it", "VAT_ID_IT"),
    ("pii_vat_id_it_proximity", "VAT_ID_IT"),
    ("pii_vat_id_es", "VAT_ID_ES"),
];

#[test]
fn pii_registry_keeps_rule_order_and_labels() {
    let actual: Vec<_> = PII_PATTERNS
        .iter()
        .map(|pattern| (pattern.name, pattern.entity_group))
        .collect();
    assert_eq!(actual, EXPECTED_ORDER);
}

#[test]
fn pii_rule_ids_are_unique() {
    let mut names: Vec<_> = PII_PATTERNS.iter().map(|pattern| pattern.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), PII_PATTERNS.len());
}
