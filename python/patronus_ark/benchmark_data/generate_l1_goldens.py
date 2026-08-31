"""Generate deterministic native-L1 PII and DLP regression fixtures.

Run from the repository root with::

    .venv/bin/python python/patronus_ark/benchmark_data/generate_l1_goldens.py

The generated offsets are Python Unicode-code-point offsets and use half-open
``[start, end)`` intervals. All values are invented or copied from the existing
synthetic ``dynamic_pii.jsonl`` fixture; no sensitive document content is used.
"""

from __future__ import annotations

import json
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parent


def positive(
    label: str,
    language: str,
    prefix: str,
    value: str,
    suffix: str = "",
    *,
    source_fixture_id: str | None = None,
) -> dict:
    text = f"{prefix}{value}{suffix}"
    start = len(prefix)
    origin = "derived_existing_fixture" if source_fixture_id else "synthetic"
    provenance = {
        "origin": origin,
        "source": "python/patronus_ark/benchmark_data/dynamic_pii.jsonl"
        if source_fixture_id
        else "hand-authored Ark L1 capability regression",
    }
    if source_fixture_id:
        provenance["source_fixture_id"] = source_fixture_id
    return {
        "language": language,
        "case_type": "positive",
        "target_label": label,
        "text": text,
        "entities": [
            {
                "label": label,
                "text": value,
                "start": start,
                "end": start + len(value),
            }
        ],
        "span_unit": "unicode_code_point",
        "provenance": provenance,
    }


def negative(label: str, language: str, text: str, reason: str) -> dict:
    return {
        "language": language,
        "case_type": "hard_negative",
        "target_label": label,
        "text": text,
        "entities": [],
        "span_unit": "unicode_code_point",
        "negative_reason": reason,
        "provenance": {
            "origin": "synthetic",
            "source": "hand-authored Ark L1 hard-negative regression",
        },
    }


def p(label: str, language: str, prefix: str, value: str, suffix: str = "", **kwargs) -> dict:
    return positive(label, language, prefix, value, suffix, **kwargs)


def n(label: str, language: str, text: str, reason: str) -> dict:
    return negative(label, language, text, reason)


PII_CASES = {
    "EMAIL": [
        p("EMAIL", "en", "Contact support at +76-532-1520 or write to ", "john.doe@email.org", ".", source_fixture_id="base-0003"),
        p("EMAIL", "de", "E-Mail: ", "anna.beispiel@firma.de"),
        p("EMAIL", "en", "Reply to ", "ops+alerts@example.co.uk"),
        n("EMAIL", "de", "E-Mail: anna.beispiel@localhost", "domain has no public-style suffix"),
        n("EMAIL", "en", "Write to user [at] example [dot] com.", "obfuscated address is not a direct identifier"),
    ],
    "IP_ADDRESS": [
        p("IP_ADDRESS", "en", "IP ", "163.186.83.95", " belongs to the host.", source_fixture_id="base-0015"),
        p("IP_ADDRESS", "de", "Quell-IP: ", "203.0.113.42"),
        p("IP_ADDRESS", "en", "Client address: ", "2001:db8:85a3::8a2e:370:7334"),
        n("IP_ADDRESS", "de", "IP: 999.10.10.10", "octet exceeds 255"),
        n("IP_ADDRESS", "en", "IP: 127.0.0.1", "loopback is deliberately excluded"),
    ],
    "PHONE": [
        p("PHONE", "en", "Their phone number changed to ", "+65-716-1434", ".", source_fixture_id="base-0004"),
        p("PHONE", "de", "Telefon: ", "+49 170 1234567"),
        p("PHONE", "en", "Mobile: ", "+44 (20) 7946 0958"),
        n("PHONE", "de", "Telefon: +00 0000000", "invalid country prefix and repeated digits"),
        n("PHONE", "en", "Version 1.234.567", "version-like number has no international prefix"),
    ],
    "MAC_ADDRESS": [
        p("MAC_ADDRESS", "de", "MAC: ", "02:42:ac:11:00:02"),
        p("MAC_ADDRESS", "en", "Adapter: ", "A4-5E-60-12-34-56"),
        p("MAC_ADDRESS", "de", "Geräteadresse ", "F0:9F:C2:AA:10:7B"),
        n("MAC_ADDRESS", "en", "MAC: 00:00:00:00:00:00", "all-zero address is excluded"),
        n("MAC_ADDRESS", "de", "MAC: 02:42:AC:11:00", "only five octets"),
    ],
    "CREDITCARD": [
        p("CREDITCARD", "en", "My card number is ", "4111 1111 1111 1111", "."),
        p("CREDITCARD", "de", "Kartennummer: ", "4111-1111-1111-1111"),
        p("CREDITCARD", "en", "PAN ", "5555555555554444"),
        n("CREDITCARD", "de", "Kartennummer: 4111 1111 1111 1112", "Luhn checksum fails"),
        n("CREDITCARD", "en", "Reference: 1111 1111 1111 1111", "repeated digits are excluded"),
    ],
    "CREDITCARD_CVV": [
        p("CREDITCARD_CVV", "de", "CVV: ", "123"),
        p("CREDITCARD_CVV", "en", "CVC2 is ", "884"),
        p("CREDITCARD_CVV", "en", "Card verification code: ", "1234"),
        n("CREDITCARD_CVV", "de", "CVV: 12", "too short"),
        n("CREDITCARD_CVV", "en", "Security code: 123", "unsupported ambiguous anchor"),
    ],
    "CREDITCARD_EXPIRY": [
        p("CREDITCARD_EXPIRY", "de", "Ablaufdatum: ", "12/29"),
        p("CREDITCARD_EXPIRY", "en", "Expiry date is ", "01-2030"),
        p("CREDITCARD_EXPIRY", "de", "Gültig bis ", "7/2028"),
        n("CREDITCARD_EXPIRY", "en", "Expiration: 13/29", "month exceeds 12"),
        n("CREDITCARD_EXPIRY", "de", "Zeitraum: 12/29", "date-like value lacks a card-expiry anchor"),
    ],
    "IBAN": [
        p("IBAN", "de", "IBAN: ", "DE89370400440532013000"),
        p("IBAN", "en", "Bank account: ", "GB82WEST12345698765432"),
        p("IBAN", "de", "Zahlung an ", "DE89 3704 0044 0532 0130 00"),
        n("IBAN", "de", "IBAN: DE89370400440532013001", "MOD-97 checksum fails"),
        n("IBAN", "en", "Reference DE001234", "too short for an IBAN"),
    ],
    "SWIFT_CODE": [
        p("SWIFT_CODE", "de", "BIC: ", "DEUTDEFF500"),
        p("SWIFT_CODE", "en", "SWIFT code is ", "NEDSZAJJ"),
        p("SWIFT_CODE", "de", "BIC = ", "MARKDEF1100"),
        n("SWIFT_CODE", "en", "SWIFT: DEUTD3", "invalid BIC length"),
        n("SWIFT_CODE", "de", "Bankcode DEUTDEFF500", "missing BIC or SWIFT anchor"),
    ],
    "EMPLOYEE_ID": [
        p("EMPLOYEE_ID", "en", "Employee ID ", "EMP-1042", " belongs to the new hire.", source_fixture_id="specific-0007"),
        p("EMPLOYEE_ID", "de", "Personalnummer: ", "P-4711"),
        p("EMPLOYEE_ID", "en", "Personnel number is ", "STAFF/2048"),
        n("EMPLOYEE_ID", "de", "Build: EMP-4711", "identifier lacks an employee anchor"),
        n("EMPLOYEE_ID", "en", "Employee ID EMPLOYEE", "value contains no digit"),
    ],
    "CUSTOMER_ID": [
        p("CUSTOMER_ID", "de", "Kundennummer: ", "KD-88231"),
        p("CUSTOMER_ID", "en", "Customer ID ", "CUST-2048"),
        p("CUSTOMER_ID", "de", "Debitorennummer = ", "DEB/4711"),
        n("CUSTOMER_ID", "de", "Rechnungsnummer: KD-88231", "wrong identifier anchor"),
        n("CUSTOMER_ID", "en", "Customer ID CUSTOMER", "value contains no digit"),
    ],
    "PATIENT_ID": [
        p("PATIENT_ID", "en", "Medical record number ", "MRN-204817", " belongs to this patient.", source_fixture_id="specific-medical-record-number-01"),
        p("PATIENT_ID", "de", "Patientennummer: ", "PAT-2048"),
        p("PATIENT_ID", "en", "MRN = ", "HOSP/7781"),
        n("PATIENT_ID", "de", "Ticket: PAT-2048", "identifier lacks a patient anchor"),
        n("PATIENT_ID", "en", "Patient ID PATIENT", "value contains no digit"),
    ],
    "STUDENT_ID": [
        p("STUDENT_ID", "de", "Die Matrikelnummer lautet ", "S89750921", ".", source_fixture_id="school-student-id-01"),
        p("STUDENT_ID", "en", "Student ID ", "STU-9911"),
        p("STUDENT_ID", "de", "Schülernummer: ", "SCH/2042"),
        n("STUDENT_ID", "de", "Kursnummer: STU-9911", "wrong identifier anchor"),
        n("STUDENT_ID", "en", "Student ID STUDENT", "value contains no digit"),
    ],
    "APPLICANT_ID": [
        p("APPLICANT_ID", "de", "Ihre Bewerbernummer ist ", "BEW-2026-10482", ".", source_fixture_id="school-applicant-id-01"),
        p("APPLICANT_ID", "en", "Applicant number ", "APP-713"),
        p("APPLICANT_ID", "en", "Candidate ID: ", "CAN/5581"),
        n("APPLICANT_ID", "de", "Vorgangsnummer: BEW-713", "wrong identifier anchor"),
        n("APPLICANT_ID", "en", "Applicant ID APPLICANT", "value contains no digit"),
    ],
    "USERNAME": [
        p("USERNAME", "de", "Benutzername: ", "ada.lovelace"),
        p("USERNAME", "en", "Username is ", "maria_ops_24"),
        p("USERNAME", "en", "Account name: ", "svc-build-7"),
        n("USERNAME", "de", "Benutzername: admin", "reserved generic username"),
        n("USERNAME", "en", "Owner maria_ops_24", "value lacks a username anchor"),
    ],
    "DOB": [
        p("DOB", "de", "Geburtsdatum: ", "29.02.2000"),
        p("DOB", "en", "The patient record lists her date of birth as ", "14 March 1985", " in the intake form.", source_fixture_id="general-dob-01"),
        p("DOB", "de", "Geboren am ", "14. März 1985"),
        n("DOB", "de", "Geburtsdatum: 31. Februar 1985", "invalid calendar date"),
        n("DOB", "en", "The archive covers 14 March 1985.", "date lacks a birth anchor"),
    ],
    "FINANCIAL_ACCOUNT_NUMBER": [
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "Kontonummer: ", "ACC-44001234"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "Account number ", "A/778811"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "Depot-Nr: ", "DEP-2026-42"),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "Bestellnummer: ACC-44001234", "wrong identifier anchor"),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "Account number ACCOUNT", "value contains no digit"),
    ],
    "STEUERID": [
        p("STEUERID", "de", "Steuer-ID: ", "86095742719"),
        p("STEUERID", "de", "IdNr. ", "86 095 742 719"),
        p("STEUERID", "en", "German Steueridentifikationsnummer: ", "86095742719"),
        n("STEUERID", "de", "Steuer-ID: 86095742718", "checksum fails"),
        n("STEUERID", "de", "Nummer: 86095742719", "missing tax-ID anchor"),
    ],
    "TAX_NUMBER_DE": [
        p("TAX_NUMBER_DE", "de", "Steuernummer: ", "123/456/78901"),
        p("TAX_NUMBER_DE", "de", "Steuer Nr. ", "12/345/67890"),
        p("TAX_NUMBER_DE", "en", "German Steuernummer: ", "1234/567/89012"),
        n("TAX_NUMBER_DE", "de", "Steuernummer: 000/000/00000", "all-zero value is excluded"),
        n("TAX_NUMBER_DE", "en", "Tax number: 123/456/78901", "unsupported English-only anchor"),
    ],
    "SOCIALID": [
        p("SOCIALID", "de", "Sozialversicherungsnummer: ", "12123456A123"),
        p("SOCIALID", "de", "Rentenversicherungsnummer ", "65 432109 Z 876"),
        p("SOCIALID", "en", "German SV-Nr.: ", "12 123456 A 123"),
        n("SOCIALID", "de", "Sozialversicherungsnummer: 12123456-123", "letter position is missing"),
        n("SOCIALID", "de", "Referenz 12123456A123", "missing social-insurance anchor"),
    ],
    "HEALTH_INSURANCE_NUMBER": [
        p("HEALTH_INSURANCE_NUMBER", "en", "Health insurance number ", "X123456789", " is in the claim.", source_fixture_id="specific-health-insurance-number-01"),
        p("HEALTH_INSURANCE_NUMBER", "de", "Versichertennummer: ", "A123456789"),
        p("HEALTH_INSURANCE_NUMBER", "de", "KVNR = ", "Z987654321"),
        n("HEALTH_INSURANCE_NUMBER", "de", "KVNR: A000000000", "all-zero numeric part is excluded"),
        n("HEALTH_INSURANCE_NUMBER", "en", "Member number X123456789", "unsupported generic member anchor"),
    ],
    "PHYSICIAN_NUMBER_LANR": [
        p("PHYSICIAN_NUMBER_LANR", "de", "LANR: ", "123456789"),
        p("PHYSICIAN_NUMBER_LANR", "de", "Lebenslange Arztnummer ", "987654321"),
        p("PHYSICIAN_NUMBER_LANR", "en", "German LANR = ", "246813579"),
        n("PHYSICIAN_NUMBER_LANR", "de", "LANR: 000000000", "all-zero value is excluded"),
        n("PHYSICIAN_NUMBER_LANR", "de", "Arztnummer: 123456789", "unsupported generic anchor"),
    ],
    "PASSPORT_NUMBER": [
        p("PASSPORT_NUMBER", "en", "Passport number ", "C01X00T47", " was copied into the case file.", source_fixture_id="specific-passport-number-01"),
        p("PASSPORT_NUMBER", "de", "Passnummer: ", "F22M11P88"),
        p("PASSPORT_NUMBER", "de", "Reisepassnummer = ", "L01X00T47"),
        n("PASSPORT_NUMBER", "de", "Passnummer: B01X00T47", "B is excluded from German document numbers"),
        n("PASSPORT_NUMBER", "en", "Document C01X00T47", "missing passport anchor"),
    ],
    "IDENTITY_CARD_NUMBER": [
        p("IDENTITY_CARD_NUMBER", "de", "Personalausweisnummer: ", "L01X00T47"),
        p("IDENTITY_CARD_NUMBER", "en", "Identity card number ", "C01X00T47"),
        p("IDENTITY_CARD_NUMBER", "de", "Ausweisnummer = ", "F22M11P88"),
        n("IDENTITY_CARD_NUMBER", "de", "Ausweisnummer: B01X00T47", "B is excluded from German document numbers"),
        n("IDENTITY_CARD_NUMBER", "en", "Card C01X00T47", "missing identity-card anchor"),
    ],
    "DRIVER_LICENSE_NUMBER": [
        p("DRIVER_LICENSE_NUMBER", "de", "Führerscheinnummer: ", "B072RRE2A57"),
        p("DRIVER_LICENSE_NUMBER", "en", "Driver's license number ", "D1234567890"),
        p("DRIVER_LICENSE_NUMBER", "de", "Fahrerlaubnisnummer = ", "A12BC34DE56"),
        n("DRIVER_LICENSE_NUMBER", "de", "Führerscheinnummer: B072RRE2A5", "only ten characters"),
        n("DRIVER_LICENSE_NUMBER", "en", "License D1234567890", "missing driver's-license anchor"),
    ],
    "LICENSEPLATE": [
        p("LICENSEPLATE", "de", "KFZ-Kennzeichen: ", "B-AB 1234E"),
        p("LICENSEPLATE", "en", "Vehicle registration ", "M XY 42"),
        p("LICENSEPLATE", "de", "Nummernschild: ", "K-A 778H"),
        n("LICENSEPLATE", "de", "Kennzeichen: BERLIN-123", "prefix is too long"),
        n("LICENSEPLATE", "en", "Parkplatz B-AB 1234E", "missing registration anchor"),
    ],
    "SSN": [
        p("SSN", "en", "SSN: ", "123-45-6789"),
        p("SSN", "en", "Social security number is ", "212 34 5678"),
        p("SSN", "de", "US-SSN: ", "665-12-3456"),
        n("SSN", "en", "SSN: 000-12-3456", "reserved area number"),
        n("SSN", "en", "Release 123-45-6789", "missing SSN anchor"),
    ],
    "NATIONALID": [
        p("NATIONALID", "en", "NINO: ", "AB123456C"),
        p("NATIONALID", "en", "National Insurance number ", "CE 123456 A"),
        p("NATIONALID", "de", "UK-NINO: ", "HJ987654D"),
        n("NATIONALID", "en", "NINO: BG123456A", "forbidden prefix"),
        n("NATIONALID", "en", "Reference AB123456C", "missing NINO anchor"),
    ],
}


DLP_CASES = {
    "API_KEY": [
        p("API_KEY", "en", "OPENAI_API_KEY=", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"),
        p("API_KEY", "de", "Modellschlüssel: ", "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ12"),
        p("API_KEY", "en", "GROQ_API_KEY=", "gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"),
        n("API_KEY", "en", "OPENAI_API_KEY=sk-proj-short", "provider token is too short"),
        n("API_KEY", "de", "API-Schlüssel: [REDACTED]", "redacted placeholder"),
    ],
    "CLOUD_KEY": [
        p("CLOUD_KEY", "en", "AWS_ACCESS_KEY_ID=", "AKIAIOSFODNN7EXAMPLE"),
        p("CLOUD_KEY", "de", "Google API Key: ", "AIzaSyDUMMY1234567890abcdefghijklmnopqr"),
        p("CLOUD_KEY", "en", "AWS_SECRET_ACCESS_KEY=", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        n("CLOUD_KEY", "en", "AWS_ACCESS_KEY_ID=AKIA123", "cloud key is too short"),
        n("CLOUD_KEY", "de", "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}", "environment reference is not secret material"),
    ],
    "CREDENTIAL": [
        p("CREDENTIAL", "de", "Passwort = ", "Sommer2026!"),
        p("CREDENTIAL", "en", "https://example.test?token=", "actual-secret"),
        p("CREDENTIAL", "en", "Authorization: Basic ", "YWRhOnNlY3JldC04ODQy"),
        n("CREDENTIAL", "de", "Passwort = ${PASSWORD}", "environment reference"),
        n("CREDENTIAL", "en", "token = [REDACTED]", "redacted placeholder"),
    ],
    "CRYPTO_KEY": [
        p("CRYPTO_KEY", "en", "Ethereum private key: ", "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        p("CRYPTO_KEY", "de", "Wallet-Schlüssel: ", "5HueCGU8rMjxEXxiPuD5BDuRaKsz5on8CcuHNZ1rQdZQzQpWmZ1"),
        p("CRYPTO_KEY", "en", "Signing scalar ", "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        n("CRYPTO_KEY", "en", "Ethereum address: 0x0123456789abcdef0123456789abcdef01234567", "address is not a private key"),
        n("CRYPTO_KEY", "de", "Wallet-Schlüssel: 0x1234", "value is too short"),
    ],
    "PASSWORD_HASH": [
        p("PASSWORD_HASH", "en", "password_hash = ", "$2b$12$abcdefghijklmnopqrstuuVIXU7y0N7XmxmCN5QYGl1R9vO2"),
        p("PASSWORD_HASH", "de", "Passwort-Hash: ", "$argon2id$v=19$m=65536,t=3,p=4$ZmFrZXNhbHQ$ZmFrZWhhc2h2YWx1ZQ"),
        p("PASSWORD_HASH", "en", "passwd_hash = ", "0123456789abcdef0123456789abcdef"),
        n("PASSWORD_HASH", "de", "Passwort-Hash: [REDACTED]", "redacted placeholder"),
        n("PASSWORD_HASH", "en", "checksum = 0123456789abcdef0123456789abcdef", "missing password-hash anchor"),
    ],
    "PAYMENT_KEY": [
        p("PAYMENT_KEY", "en", "STRIPE_SECRET_KEY=", "sk_live_abcdefghijklmnopqrstuvwxyz"),
        p("PAYMENT_KEY", "de", "Stripe Testschlüssel: ", "rk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        p("PAYMENT_KEY", "en", "Webhook secret: ", "whsec_abcdefghijklmnopqrstuvwx"),
        n("PAYMENT_KEY", "en", "STRIPE_SECRET_KEY=sk_live_short", "provider token is too short"),
        n("PAYMENT_KEY", "de", "Stripe-Schlüssel: [REDACTED]", "redacted placeholder"),
    ],
    "PRIVATE_KEY": [
        p("PRIVATE_KEY", "en", "", "-----BEGIN PRIVATE KEY-----\ncHJpdmF0ZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----"),
        p("PRIVATE_KEY", "de", "Schlüsseldatei:\n", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        p("PRIVATE_KEY", "en", "", "-----BEGIN RSA PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END RSA PRIVATE KEY-----"),
        n("PRIVATE_KEY", "en", "-----BEGIN PUBLIC KEY-----", "public key is not private material"),
        n("PRIVATE_KEY", "de", "BEGIN PRIVATE KEY", "PEM delimiters are incomplete"),
    ],
    "SECRET_TOKEN": [
        p("SECRET_TOKEN", "en", "GITHUB_TOKEN=", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"),
        p("SECRET_TOKEN", "de", "GitLab Token: ", "glpat-abcdefghijklmnopqrstuv"),
        p("SECRET_TOKEN", "en", "Authorization: Bearer ", "eyJhbGciOiJIUzI1NiJ9.payload.signature"),
        n("SECRET_TOKEN", "en", "GITHUB_TOKEN=ghp_short", "provider token is too short"),
        n("SECRET_TOKEN", "de", "Token: your-token-here", "documented placeholder"),
    ],
    "dlp.de.vat_id": [
        p("dlp.de.vat_id", "de", "USt-IdNr.: ", "DE 123 456 789"),
        p("dlp.de.vat_id", "en", "VAT ID: ", "DE987654321"),
        p("dlp.de.vat_id", "de", "Umsatzsteuer-Identifikationsnummer = ", "DE 111222333"),
        n("dlp.de.vat_id", "de", "USt-IdNr.: FR123456789", "current detector covers German VAT IDs"),
        n("dlp.de.vat_id", "en", "Reference DE123456789", "missing VAT anchor"),
    ],
    "dlp.de.commercial_register_number": [
        p("dlp.de.commercial_register_number", "de", "Amtsgericht Berlin ", "HRB 12345"),
        p("dlp.de.commercial_register_number", "en", "Register entry ", "HRA 77881"),
        p("dlp.de.commercial_register_number", "de", "Vereinsregister ", "VR 2048"),
        n("dlp.de.commercial_register_number", "de", "Register: HRX 12345", "unknown register prefix"),
        n("dlp.de.commercial_register_number", "en", "Register entry HRB ABC", "value contains no digits"),
    ],
    "dlp.de.facility_number_bsnr": [
        p("dlp.de.facility_number_bsnr", "de", "BSNR: ", "123456789"),
        p("dlp.de.facility_number_bsnr", "de", "Betriebsstättennummer = ", "987654321"),
        p("dlp.de.facility_number_bsnr", "en", "German BSNR lautet ", "246813579"),
        n("dlp.de.facility_number_bsnr", "de", "BSNR: 12345678", "only eight digits"),
        n("dlp.de.facility_number_bsnr", "en", "Facility number 123456789", "missing BSNR anchor"),
    ],
    "dlp.record.case_id": [
        p("dlp.record.case_id", "de", "Fallnummer: ", "CASE-2026/481"),
        p("dlp.record.case_id", "en", "Case ID ", "CV-2026-8842"),
        p("dlp.record.case_id", "de", "Aktenzeichen = ", "17-A/2048"),
        n("dlp.record.case_id", "de", "Fallnummer: ABC", "value contains no digit"),
        n("dlp.record.case_id", "en", "Ticket CASE-2026/481", "missing case anchor"),
    ],
    "dlp.record.contract_id": [
        p("dlp.record.contract_id", "de", "Vertragsnummer ", "V-2026-8842"),
        p("dlp.record.contract_id", "en", "Contract ID ", "CONTRACT-8842"),
        p("dlp.record.contract_id", "de", "Vertrags-ID: ", "VK/2048"),
        n("dlp.record.contract_id", "de", "Vertragsnummer: VERTRAG", "value contains no digit"),
        n("dlp.record.contract_id", "en", "Agreement CONTRACT-8842", "missing contract-ID anchor"),
    ],
    "dlp.record.claim_id": [
        p("dlp.record.claim_id", "de", "Schadennummer: ", "SCH-44119"),
        p("dlp.record.claim_id", "en", "Claim ID ", "CLAIM-2048"),
        p("dlp.record.claim_id", "de", "Leistungsfallnummer = ", "LF/7781"),
        n("dlp.record.claim_id", "de", "Schadennummer: SCHADEN", "value contains no digit"),
        n("dlp.record.claim_id", "en", "Ticket CLAIM-2048", "missing claim anchor"),
    ],
    "dlp.record.order_id": [
        p("dlp.record.order_id", "de", "Bestellnummer ", "ORD-77881"),
        p("dlp.record.order_id", "en", "Order ID ", "ORDER-2048"),
        p("dlp.record.order_id", "de", "Auftragsnummer = ", "AUF/4711"),
        n("dlp.record.order_id", "de", "Bestellnummer: ORDER", "value contains no digit"),
        n("dlp.record.order_id", "en", "Shipment ORDER-2048", "missing order anchor"),
    ],
    "dlp.record.invoice_id": [
        p("dlp.record.invoice_id", "de", "Rechnungsnummer: ", "RE-2026-190"),
        p("dlp.record.invoice_id", "en", "Invoice ID ", "INV-2026-190"),
        p("dlp.record.invoice_id", "de", "Rechnungs-ID = ", "R/77881"),
        n("dlp.record.invoice_id", "de", "Rechnungsnummer: RECHNUNG", "value contains no digit"),
        n("dlp.record.invoice_id", "en", "Document INV-2026-190", "missing invoice anchor"),
    ],
    "dlp.project_id": [
        p("dlp.project_id", "de", "Projekt-ID ", "P-ARK-2026"),
        p("dlp.project_id", "en", "Project ID ", "PROJECT-2048"),
        p("dlp.project_id", "de", "Projektnummer = ", "PRJ/7781"),
        n("dlp.project_id", "de", "Projekt-ID: PROJEKT", "value contains no digit"),
        n("dlp.project_id", "en", "Folder PROJECT-2048", "missing project anchor"),
    ],
    "dlp.organization_id": [
        p("dlp.organization_id", "de", "Mandanten-ID: ", "TENANT-742"),
        p("dlp.organization_id", "en", "Organization ID ", "ORG-2048"),
        p("dlp.organization_id", "de", "Unternehmens-ID = ", "UNT/7781"),
        n("dlp.organization_id", "de", "Mandanten-ID: TENANT", "value contains no digit"),
        n("dlp.organization_id", "en", "Account ORG-2048", "missing organization anchor"),
    ],
    "dlp.internal.business_metric": [
        p("dlp.internal.business_metric", "de", "", "EBITDA-Marge: 6,1 Prozent"),
        p("dlp.internal.business_metric", "en", "", "Forecast: 12 Mio. EUR"),
        p("dlp.internal.business_metric", "de", "", "Umsatz beträgt 4.200 TEUR"),
        n("dlp.internal.business_metric", "de", "Umsatzbericht für August", "metric has no numeric value"),
        n("dlp.internal.business_metric", "en", "Margin improved considerably.", "unsupported English lexical anchor and no value"),
    ],
    "dlp.content.source_code": [
        p("dlp.content.source_code", "en", "", "```python\nprint('internal')\n```"),
        p("dlp.content.source_code", "de", "", "const client = new Client();"),
        p("dlp.content.source_code", "en", "", "from pathlib import Path"),
        n("dlp.content.source_code", "de", "Der Client wird morgen aktualisiert.", "natural language is not source code"),
        n("dlp.content.source_code", "en", "print the internal report", "prose lacks code syntax"),
    ],
    "dlp.content.sql": [
        p("dlp.content.sql", "de", "", "SELECT * FROM kunden WHERE aktiv = true;"),
        p("dlp.content.sql", "en", "", "UPDATE accounts SET active = false;"),
        p("dlp.content.sql", "en", "", "DELETE FROM sessions WHERE expired = true;"),
        n("dlp.content.sql", "de", "Bitte Kunden aus der Liste auswählen.", "natural language is not SQL"),
        n("dlp.content.sql", "en", "SELECT the best option FROM the list", "no terminating SQL statement structure"),
    ],
    "dlp.content.database_dump": [
        p("dlp.content.database_dump", "en", "", "-- PostgreSQL database dump"),
        p("dlp.content.database_dump", "de", "", "INSERT INTO kunden VALUES (1, 'Ada');"),
        p("dlp.content.database_dump", "en", "", "PRAGMA foreign_keys = ON;"),
        n("dlp.content.database_dump", "de", "Datenbankexport wurde abgeschlossen.", "natural language is not a dump"),
        n("dlp.content.database_dump", "en", "INSERT the row into the table", "prose lacks SQL dump syntax"),
    ],
    "dlp.content.system_log": [
        p("dlp.content.system_log", "en", "", "2026-08-30T10:15:00Z ERROR database connection failed"),
        p("dlp.content.system_log", "de", "", "2026-08-30 10:15:00 CRITICAL Speicherlimit erreicht"),
        p("dlp.content.system_log", "en", "", "Traceback (most recent call last):\n  File \"app.py\", line 4, in run"),
        n("dlp.content.system_log", "de", "Der Fehler wurde gestern behoben.", "prose is not a structured log"),
        n("dlp.content.system_log", "en", "2026-08-30 INFO service started", "non-sensitive INFO level is excluded"),
    ],
}


def flatten(suite: str, cases: dict[str, list[dict]]) -> list[dict]:
    rows = []
    for label, label_cases in cases.items():
        for index, row in enumerate(label_cases, start=1):
            sign = "pos" if row["case_type"] == "positive" else "neg"
            slug = label.lower().replace(".", "-").replace("_", "-")
            rows.append({"id": f"{suite}-{slug}-{sign}-{index:02d}", "suite": suite, **row})
    return rows


def write(name: str, rows: list[dict]) -> None:
    path = DATA_DIR / f"{name}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    write("pii_l1", flatten("pii_l1", PII_CASES))
    write("dlp_l1", flatten("dlp_l1", DLP_CASES))
