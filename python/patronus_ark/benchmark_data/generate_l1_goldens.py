"""Generate deterministic native-L1 PII and DLP regression fixtures.

Run from the repository root with::

    .venv/bin/python python/patronus_ark/benchmark_data/generate_l1_goldens.py

The generated offsets are Python Unicode-code-point offsets and use half-open
``[start, end)`` intervals. All values are invented or copied from the existing
synthetic ``dynamic_pii.jsonl`` fixture; no sensitive document content is used.

DLP secret values are never written in clear: secret positives store a generator
recipe and a carrier template (see ``patronus_ark.dlp_synth.recipes``); offsets refer
to the materialized text, whose SHA-256 fingerprint is recorded for the Rust parity test.
"""

from __future__ import annotations

import json
from pathlib import Path

from patronus_ark.dlp_synth import recipes


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


def secret_template_positive(label: str, language: str, template: str, secrets: list[dict]) -> dict:
    text, fragments = recipes.materialize_fragments(template, secrets)
    split = {fragment["secret"] for fragment in fragments if fragment["part"]}
    entities = []
    for fragment in fragments:
        entity = {"label": label, "start": fragment["start"], "end": fragment["end"], "secret": fragment["secret"]}
        if fragment["secret"] in split:
            entity["part"] = fragment["part"]
        if fragment["encoding"]:
            entity["encoding"] = [fragment["encoding"]]
        entities.append(entity)
    return {
        "language": language,
        "case_type": "positive",
        "target_label": label,
        "template": template,
        "secrets": secrets,
        "text_fingerprint": recipes.fingerprint(text),
        "entities": entities,
        "span_unit": "unicode_code_point",
        "provenance": {
            "origin": "synthetic",
            "source": "generator recipe (patronus_ark.dlp_synth), materialized at test time",
        },
    }


def secret_positive(
    label: str, language: str, prefix: str, generator: str, seed: int, suffix: str = ""
) -> dict:
    template = f"{prefix}<<secret:0>>{suffix}"
    return secret_template_positive(label, language, template, [{"gen": generator, "seed": seed}])


def p(label: str, language: str, prefix: str, value: str, suffix: str = "", **kwargs) -> dict:
    return positive(label, language, prefix, value, suffix, **kwargs)


def n(label: str, language: str, text: str, reason: str) -> dict:
    return negative(label, language, text, reason)


PII_CASES = {
    "EMAIL": [
        p("EMAIL", "en", "Contact support at +76-532-1520 or write to ", "john.doe@email.org", ".", source_fixture_id="base-0003"),
        p("EMAIL", "de", "E-Mail: ", "anna.beispiel@firma.de"),
        p("EMAIL", "en", "Reply to ", "ops+alerts@example.co.uk"),
        n("EMAIL", "de", "E-Mail: anna.beispiel@mailserver", "single-label host has no domain suffix"),
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
        p("CREDITCARD_CVV", "de", "Karte 4111 1111 1111 1111, CVV: ", "123"),
        p("CREDITCARD_CVV", "en", "Card 5555 5555 5555 4444, CVC2 is ", "884"),
        p("CREDITCARD_CVV", "en", "Amex 3782 822463 10005. Card verification code: ", "1234"),
        n("CREDITCARD_CVV", "de", "CVV: 12", "too short"),
        n("CREDITCARD_CVV", "en", "Security code: 123", "unsupported ambiguous anchor"),
    ],
    "CREDITCARD_EXPIRY": [
        p("CREDITCARD_EXPIRY", "de", "Kreditkarte Ablaufdatum: ", "12/29"),
        p("CREDITCARD_EXPIRY", "en", "Credit card expiry date is ", "01-2030"),
        p("CREDITCARD_EXPIRY", "de", "Kreditkarte gültig bis ", "7/2028"),
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
        n("TAX_NUMBER_DE", "en", "Tax number: 123/456", "too few digits for a German tax number"),
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


# DLP golden schema v2 (E13). Every DLP row names the rule it exercises (`rule_id`), the
# document that carries the value (`carrier`), its difficulty `tags` and whether it is a
# `known_gap`: a positive the detector misses today, reported by 13_l1_golden_eval but
# not gated. `carrier` and `prose` follow from the carrier, `encoded` and `split` from the
# placeholders of positives; `no_context` is set by hand.
DLP_SCHEMA_VERSION = 2
DLP_TAGS = ("carrier", "no_context", "encoded", "split", "prose")
DLP_CARRIERS = (
    "line", "env", "yaml", "json", "toml", "ini", "xml", "code", "log", "cli", "http", "csv",
    "sql", "markdown", "prose",
)
# Minimum gated positives and hard negatives per target label and language.
DLP_MIN_PER_LANGUAGE = 5


def dlp_row(row: dict, rule: str, carrier: str, tags: tuple[str, ...], known_gap: bool) -> dict:
    tags = set(tags)
    if carrier not in DLP_CARRIERS or not tags <= {"no_context", "encoded", "split"}:
        raise ValueError(f"bad carrier {carrier!r} or hand-set tags {sorted(tags)}")
    if known_gap and row["case_type"] != "positive":
        raise ValueError("only positives can be known gaps")
    if carrier not in ("line", "prose"):
        tags.add("carrier")
    if carrier == "prose":
        tags.add("prose")
    for entity in row["entities"]:
        if "encoding" in entity:
            tags.add("encoded")
        if "part" in entity:
            tags.add("split")
    head = {
        "schema_version": DLP_SCHEMA_VERSION,
        "language": row["language"],
        "case_type": row["case_type"],
        "target_label": row["target_label"],
        "rule_id": rule,
        "carrier": carrier,
        "tags": [tag for tag in DLP_TAGS if tag in tags],
        "known_gap": known_gap,
    }
    return {**head, **{key: value for key, value in row.items() if key not in head}}


def ds(
    label: str,
    language: str,
    rule: str,
    template: str,
    generator: str,
    seed: int,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
    gap: bool = False,
) -> dict:
    """Secret positive: one generator recipe placed by `template`."""
    row = secret_template_positive(label, language, template, [{"gen": generator, "seed": seed}])
    return dlp_row(row, rule, carrier, tags, gap)


def dp(
    label: str,
    language: str,
    rule: str,
    prefix: str,
    value: str,
    suffix: str = "",
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
    gap: bool = False,
) -> dict:
    """Literal positive for the default-off identifier and content classes."""
    return dlp_row(positive(label, language, prefix, value, suffix), rule, carrier, tags, gap)


def dn(
    label: str,
    language: str,
    rule: str,
    text: str,
    reason: str,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
) -> dict:
    """Hard negative: a lookalike for `rule` that no DLP rule may report."""
    return dlp_row(negative(label, language, text, reason), rule, carrier, tags, False)


DLP_CASES = {
    "API_KEY": [
        ds("API_KEY", "en", "dlp_openai_key", "OPENAI_API_KEY=<<secret:0>>", "openai_project_key", 101),
        ds("API_KEY", "de", "dlp_huggingface", "Modellschlüssel: <<secret:0>>", "huggingface_token", 102),
        ds("API_KEY", "en", "dlp_groq_key", "GROQ_API_KEY=<<secret:0>>", "groq_key", 103),
        dn("API_KEY", "en", "dlp_openai_key", "Truncated OpenAI prefix in the docs: sk-proj-short", "provider token is too short"),
        dn("API_KEY", "de", "dlp_generic_credential_assignment", "API-Schlüssel: [REDACTED]", "redacted placeholder"),
        ds(
            "API_KEY", "de", "dlp_anthropic_key",
            "# Produktivkonfiguration, nicht einchecken\nAPP_ENV=production\nLOG_LEVEL=warn\n"
            "ANTHROPIC_API_KEY=<<secret:0>>\nMAX_TOKENS=4096\n",
            "anthropic_api_key", 1001, carrier="env",
        ),
        ds(
            "API_KEY", "de", "dlp_openai_svc",
            "Hallo Team, der Service-Account der Pipeline nutzt jetzt <<secret:0>>. "
            "Bitte nur im Vault ablegen und nicht weiterleiten.",
            "openai_service_account_key", 1002, carrier="prose",
        ),
        ds(
            "API_KEY", "de", "dlp_openai_legacy",
            "# Altes Skript, wird im dritten Quartal migriert\nimport openai\n\n"
            "openai.api_key = \"<<secret:0>>\"\nantwort = openai.Completion.create(prompt=\"Hallo\")\n",
            "openai_legacy_key", 1003, carrier="code",
        ),
        ds(
            "API_KEY", "de", "dlp_groq_key",
            "Gefunden in Zeile 14 der Shell-Historie: <<secret:0>>",
            "groq_key", 1004, tags=("no_context",),
        ),
        ds(
            "API_KEY", "de", "dlp_replicate",
            "# Modell-Deployment (Staging)\nreplicate:\n  modell: stability-ai/sdxl\n  zugang: <<secret:0>>\n  timeout: 30\n",
            "replicate_api_token", 1005, carrier="yaml",
        ),
        ds(
            "API_KEY", "de", "dlp_xai_key",
            "[llm.grok]\n# Schlüssel des Forschungsteams\nendpoint = \"https://api.x.ai/v1\"\nschluessel = \"<<secret:0>>\"\n",
            "xai_api_key", 1006, carrier="toml",
        ),
        ds(
            "API_KEY", "de", "dlp_openai_key",
            "$ export OPENAI_API_KEY='<<secret:0>>'\n$ python bericht.py --sprache de\n",
            "openai_project_api_key", 1007, carrier="cli",
        ),
        ds(
            "API_KEY", "de", "dlp_anthropic_key",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: llm-zugang\ndata:\n  ANTHROPIC_API_KEY: <<secret:0|base64>>\n",
            "anthropic_admin_key", 1008, carrier="yaml", gap=True,
        ),
        ds(
            "API_KEY", "de", "dlp_xai_key",
            "# Schlüssel aufgeteilt, damit der Scanner ihn nicht findet\n"
            "XAI_TEIL_A = \"<<secret:0[0:44]>>\"\nXAI_TEIL_B = \"<<secret:0[44:84]>>\"\nschluessel = XAI_TEIL_A + XAI_TEIL_B\n",
            "xai_api_key", 1009, carrier="code", gap=True,
        ),
        ds(
            "API_KEY", "en", "dlp_anthropic_key",
            "{\n  \"provider\": \"anthropic\",\n  \"model\": \"claude\",\n  \"credentials\": {\"value\": \"<<secret:0>>\"}\n}\n",
            "anthropic_api_key", 1010, carrier="json",
        ),
        ds(
            "API_KEY", "en", "dlp_openai_legacy",
            "Hi Sam, I found our old OpenAI key <<secret:0>> in the wiki history. Can you revoke it today?",
            "openai_legacy_key", 1011, carrier="prose",
        ),
        ds(
            "API_KEY", "en", "dlp_openai_svc",
            "2026-10-02T08:14:03Z WARN worker-3 retrying request with <<secret:0>> after 429\n"
            "2026-10-02T08:14:05Z INFO worker-3 request succeeded\n",
            "openai_service_account_key", 1012, carrier="log", tags=("no_context",),
        ),
        ds(
            "API_KEY", "en", "dlp_huggingface",
            "$ huggingface-cli login --token <<secret:0>>\nToken is valid (permission: write).\n",
            "huggingface_token", 1013, carrier="cli",
        ),
        ds(
            "API_KEY", "en", "dlp_xai_key",
            "XAI_API_KEY=<<secret:0>>",
            "xai_api_key", 1014,
        ),
        ds(
            "API_KEY", "en", "dlp_replicate",
            "import replicate\n\nclient = replicate.Client(api_token=\"<<secret:0>>\")\noutput = client.run(\"stability-ai/sdxl\")\n",
            "replicate_api_token", 1015, carrier="code",
        ),
        ds(
            "API_KEY", "en", "dlp_huggingface",
            "<<secret:0>>",
            "huggingface_token", 1016, tags=("no_context",),
        ),
        ds(
            "API_KEY", "en", "dlp_groq_key",
            "Authorization header (base64 by the proxy): <<secret:0|base64>>",
            "groq_key", 1017, gap=True,
        ),
        ds(
            "API_KEY", "en", "dlp_openai_key",
            "const key = \"<<secret:0[0:40]>>\" +\n  \"<<secret:0[40:164]>>\";\n",
            "openai_project_api_key", 1018, carrier="code", gap=True,
        ),
        dn(
            "API_KEY", "de", "dlp_anthropic_key",
            "# Lokale Entwicklung\nAPP_ENV=development\nANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "API_KEY", "de", "dlp_openai_key",
            "Der OpenAI-Schlüssel beginnt immer mit sk-proj- und liegt nur im Vault.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "de", "dlp_groq_key",
            "# Schlüssel kommt aus der Umgebung\nclient = Groq(api_key=os.getenv(\"GROQ_API_KEY\"))\n",
            "environment reference in code", carrier="code",
        ),
        dn(
            "API_KEY", "de", "dlp_huggingface",
            "huggingface:\n  # eigenen Token eintragen\n  token: <dein-hf-token>\n",
            "template placeholder", carrier="yaml",
        ),
        dn(
            "API_KEY", "de", "dlp_replicate",
            "Laut Doku beginnen Replicate-Tokens mit r8_ und haben 40 Zeichen.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "en", "dlp_xai_key",
            "xAI keys start with xai- and are 84 characters long.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "en", "dlp_openai_svc",
            "{\"openai\": {\"service_account_key\": \"${OPENAI_SVC_KEY}\"}}",
            "environment reference", carrier="json",
        ),
        dn(
            "API_KEY", "en", "dlp_openai_legacy",
            "Legacy OpenAI keys were sk- followed by 48 letters and digits; ours were all revoked.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "en", "dlp_anthropic_key",
            "const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });",
            "environment reference in code", carrier="code",
        ),
        dn(
            "API_KEY", "en", "dlp_groq_key",
            "$ export GROQ_API_KEY='<your-groq-key>'\n$ python chat.py\n",
            "template placeholder", carrier="cli",
        ),
    ],
    "CLOUD_KEY": [
        ds("CLOUD_KEY", "en", "dlp_aws_access_key", "AWS_ACCESS_KEY_ID=<<secret:0>>", "aws_access_key_id", 201),
        ds("CLOUD_KEY", "de", "dlp_google_api_key", "Google API Key: <<secret:0>>", "google_api_key", 202),
        ds("CLOUD_KEY", "en", "dlp_aws_secret_key", "AWS_SECRET_ACCESS_KEY=<<secret:0>>", "aws_secret_access_key", 203),
        dn("CLOUD_KEY", "en", "dlp_aws_access_key", "AWS_ACCESS_KEY_ID=AKIA123", "cloud key is too short"),
        dn("CLOUD_KEY", "de", "dlp_aws_secret_key", "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}", "environment reference is not secret material"),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "# ~/.aws/credentials (Buchhaltung)\n[buchhaltung]\naws_access_key_id = <<secret:0>>\nregion = eu-central-1\n",
            "aws_access_key_id", 2001, carrier="ini",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "[export]\n# geheimer Teil, nicht teilen\naws_secret_access_key = <<secret:0>>\noutput = json\n",
            "aws_secret_access_key", 2002, carrier="ini",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_google_oauth_token",
            "Kurze Info: das Access-Token <<secret:0>> läuft in einer Stunde ab, danach bitte neu anmelden.",
            "google_oauth_access_token", 2003, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_gcp_client_secret",
            "{\n  \"installed\": {\n    \"client_id\": \"4711-abc.apps.googleusercontent.com\",\n"
            "    \"geheimnis\": \"<<secret:0>>\"\n  }\n}\n",
            "gcp_oauth_client_secret", 2004, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "datum;benutzer;wert\n2026-10-01;deploy;<<secret:0>>\n",
            "aws_session_access_key_id", 2005, carrier="csv", tags=("no_context",),
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_google_api_key",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: karten\ndata:\n  GOOGLE_API_KEY: <<secret:0|base64>>\n",
            "google_api_key", 2006, carrier="yaml", gap=True,
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_google_oauth_token",
            "GET /drive/v3/files HTTP/1.1\r\nHost: www.googleapis.com\r\nAuthorization: Bearer <<secret:0>>\r\nAccept: application/json\r\n\r\n",
            "google_oauth_access_token", 2007, carrier="http",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_gcp_client_secret",
            "# OAuth client for the admin console\nGOOGLE_CLIENT_ID=4711-abc.apps.googleusercontent.com\nGOOGLE_CLIENT_SECRET=<<secret:0>>\n",
            "gcp_oauth_client_secret", 2008, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_google_api_key",
            "const fallbacks = [\"<<secret:0>>\", \"offline\"];\n",
            "google_api_key", 2009, carrier="code", tags=("no_context",),
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "{\"Credentials\": {\"AccessKeyId\": \"ASIA-redacted\", \"SecretAccessKey\": \"<<secret:0>>\", \"Expiration\": \"2026-10-02T10:00:00Z\"}}",
            "aws_secret_access_key", 2010, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_gcp_client_secret",
            "Our OAuth client secret is <<secret:0>>, please store it in Secret Manager.",
            "gcp_oauth_client_secret", 2011, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "key_id = \"<<secret:0[0:4]>>\" + \"<<secret:0[4:20]>>\"\n",
            "aws_access_key_id", 2012, carrier="code", gap=True,
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "Die Access Key ID beginnt mit AKIA und ist 20 Zeichen lang.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_gcp_client_secret",
            "{\"web\": {\"client_id\": \"4711-abc.apps.googleusercontent.com\", \"client_secret\": \"<CLIENT_SECRET>\"}}",
            "template placeholder", carrier="json",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_google_oauth_token",
            "Ein Google-Access-Token sieht so aus: ya29.… (im Ticket gekürzt).",
            "truncated value", carrier="prose",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_google_api_key",
            "# Karten-API, Wert kommt aus dem Deployment\nMAPS_REGION=eu\nGOOGLE_API_KEY=${GOOGLE_API_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_gcp_client_secret",
            "2026-10-02 10:00:01 INFO oauth client secret prefix=GOCSPX-*** rotated\n",
            "masked value", carrier="log",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "[default]\naws_access_key_id = <your-access-key-id>\naws_secret_access_key = <your-secret-access-key>\n",
            "template placeholder", carrier="ini",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_google_oauth_token",
            "# ya29 access tokens expire after one hour\nrefresh_interval_seconds = 3600\n",
            "comment about the format without a value", carrier="code",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_google_api_key",
            "<script src=\"https://maps.googleapis.com/maps/api/js?key=YOUR_API_KEY\"></script>",
            "documented placeholder", carrier="xml",
        ),
    ],
    "CREDENTIAL": [
        ds("CREDENTIAL", "de", "dlp_password_assignment", "Passwort = <<secret:0>>", "password", 301),
        ds("CREDENTIAL", "en", "dlp_credential_in_url", "https://example.test?token=<<secret:0>>", "url_token", 302),
        ds("CREDENTIAL", "en", "dlp_basic_auth", "Authorization: Basic <<secret:0>>", "http_basic_credentials", 303),
        dn("CREDENTIAL", "de", "dlp_password_assignment", "Passwort = ${PASSWORD}", "environment reference"),
        dn("CREDENTIAL", "en", "dlp_generic_credential_assignment", "token = [REDACTED]", "redacted placeholder"),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Mailversand\nSMTP_HOST=mail.intern\nSMTP_PASSWORT=<<secret:0>>\n",
            "password", 3001, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "Der API-Schlüssel ist <<secret:0>>, bitte nicht ins Wiki kopieren.",
            "generic_api_secret", 3002, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_basic_auth",
            "# Testaufruf gegen die Staging-API\ncurl -H \"Authorization: Basic <<secret:0>>\" https://staging.example.de/api/v1/status\n",
            "http_basic_auth", 3003, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_signed_url_signature",
            "Download-Link (15 Minuten gültig): https://files.example.de/bericht.zip?Expires=1767225600&Signature=<<secret:0>>",
            "aws_sigv4_signature", 3004, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "GET /konto HTTP/1.1\r\nHost: shop.example.de\r\nCookie: sprache=de; PHPSESSID=<<secret:0>>\r\n\r\n",
            "php_session_id", 3005, carrier="http",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "datenbank:\n  # Reporting-Replik\n  url: postgres://bericht:<<secret:0>>@db.intern:5432/bericht\n",
            "url_userinfo_password", 3006, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_credential_in_url",
            "Link aus dem Ticket: https://intranet.example.de/report?id=7&token=<<secret:0>>",
            "url_token", 3007,
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "Verbindung: mysql://bericht:<<secret:0|url>>@db1.intern/bericht",
            "password", 3008,
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: datenbank\ndata:\n  DB_PASSWORD: <<secret:0|base64>>\n",
            "password", 3009, carrier="yaml", gap=True,
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# worker settings\nREDIS_URL=redis://cache:6379/0\nQUEUE_API_TOKEN=<<secret:0>>\n",
            "generic_api_secret", 3010, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "database:\n  host: db.internal\n  user: app\n  password: <<secret:0>>\n",
            "password", 3011, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "oauth:\n  client_id: dashboard\n  client_secret: <<secret:0>>\n",
            "generic_api_secret", 3012, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_signed_url_signature",
            "2026-10-02T09:00:00Z INFO upload url=https://bucket.s3.eu-central-1.amazonaws.com/report.pdf"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature=<<secret:0>>\n",
            "aws_sigv4_signature", 3013, carrier="log",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_session_cookie",
            "HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: JSESSIONID=<<secret:0>>; Path=/; HttpOnly\r\n\r\n",
            "java_session_id", 3014, carrier="http",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "engine = create_engine(\"postgresql://app:<<secret:0>>@db.internal/app\")\n",
            "url_userinfo_password", 3015, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "Hey, my VPN password is <<secret:0>> in case you need to log in while I am away.",
            "password", 3016, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<<secret:0>>",
            "password", 3017, tags=("no_context",), gap=True,
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Bitte das Passwort nie per Mail verschicken.",
            "prose about passwords without a value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "# Wert kommt aus dem Vault\nDATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "GET /konto HTTP/1.1\r\nCookie: sprache=de; JSESSIONID=<entfernt>\r\n\r\n",
            "redacted value", carrier="http",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "SMTP_HOST=mail.intern\nSMTP_PASSWORT=${SMTP_PASSWORT}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "password = os.getenv(\"DB_PASSWORD\")\n",
            "environment reference in code", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "api_key: \"<insert-key>\"",
            "template placeholder",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "Connection string format: postgres://app:<password>@db/app",
            "documented placeholder", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_signed_url_signature",
            "https://cdn.example.com/img/logo.png?w=200&sig=abc",
            "short image-resize parameter",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "Authorization: Basic <base64 of user:password>",
            "documented placeholder",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_credential_in_url",
            "curl \"https://api.example.com/export?format=csv&token=${EXPORT_TOKEN}\"",
            "shell variable reference", carrier="cli",
        ),
    ],
    "CRYPTO_KEY": [
        ds("CRYPTO_KEY", "en", "dlp_eth_private_key", "Ethereum private key: <<secret:0>>", "eth_private_key_hex", 401),
        ds("CRYPTO_KEY", "de", "dlp_btc_wif", "Wallet-Schlüssel: <<secret:0>>", "btc_wif_uncompressed", 402),
        ds("CRYPTO_KEY", "en", "dlp_eth_private_key", "Signing scalar <<secret:0>>", "eth_private_key_hex", 403),
        dn("CRYPTO_KEY", "en", "dlp_eth_private_key", "Ethereum address: 0x0123456789abcdef0123456789abcdef01234567", "address is not a private key"),
        dn("CRYPTO_KEY", "de", "dlp_eth_private_key", "Wallet-Schlüssel: 0x1234", "value is too short"),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "# Deployment-Wallet (Testnetz)\nRPC_URL=https://rpc.example.de\nWALLET_PRIVATE_KEY=<<secret:0>>\n",
            "eth_private_key_hex", 4001, carrier="env",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Für die Wiederherstellung brauchst du den WIF-Schlüssel <<secret:0>> aus dem Tresor.",
            "btc_wif_mainnet_compressed", 4002, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "{\n  \"wallet\": \"kalt\",\n  \"wif\": \"<<secret:0>>\"\n}\n",
            "btc_wif_mainnet_uncompressed", 4003, carrier="json",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "// Hardhat-Konfiguration für das Testnetz\nmodule.exports = {\n  networks: {\n"
            "    sepolia: { accounts: [\"<<secret:0>>\"] },\n  },\n};\n",
            "eth_private_key_hex", 4004, carrier="code", tags=("no_context",),
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "signer:\n  # Schlüssel des Relayers\n  schluessel: <<secret:0>>\n",
            "eth_private_key_hex", 4005, carrier="yaml",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "WIF als Hex im Backup: <<secret:0|hex>>",
            "btc_wif_mainnet_compressed", 4006, gap=True,
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "$ bitcoin-cli importprivkey <<secret:0>> \"cold-storage\" false\n",
            "btc_wif_mainnet_compressed", 4007, carrier="cli",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "Grandpa wrote the key on the back of the photo: <<secret:0>>. Please move the coins.",
            "btc_wif_mainnet_uncompressed", 4008, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "{\"address\": \"relayer\", \"privateKey\": \"<<secret:0>>\", \"chainId\": 11155111}",
            "eth_private_key_hex", 4009, carrier="json",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "<<secret:0>>",
            "btc_wif_mainnet_compressed", 4010, tags=("no_context",),
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "const pk = \"<<secret:0[0:34]>>\" +\n  \"<<secret:0[34:66]>>\";\n",
            "eth_private_key_hex", 4011, carrier="code", gap=True,
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Die Spendenadresse 0x52908400098527886e0f7030069857d2e4169ee7 gehört zur Kampagne.",
            "address is not a private key", carrier="prose",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "RPC_URL=https://rpc.example.de\nWALLET_PRIVATE_KEY=${WALLET_PRIVATE_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Bitcoin-Adresse für Rückzahlungen: <Empfängeradresse einsetzen>",
            "template placeholder",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "SHA-256 der Firmware: 9f2c4b7e1a0d8e3f6b5c2a1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f",
            "file digest is not a private key",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "PRIVATE_KEY=<wallet-private-key>\nNETWORK=sepolia\n",
            "template placeholder", carrier="env",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "commit 4c1f0e9a7d2b8c3e6f5a4b3c2d1e0f9a8b7c6d5e\nAuthor: Dev <dev@example.org>\n",
            "commit hash is not a private key", carrier="log",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "A WIF key starts with 5, K or L and is 51 or 52 characters long.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "wallet id 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "UUID is not a key",
        ),
    ],
    "PASSWORD_HASH": [
        ds("PASSWORD_HASH", "en", "dlp_password_hash", "password_hash = <<secret:0>>", "bcrypt_hash", 501),
        ds("PASSWORD_HASH", "de", "dlp_password_hash", "Passwort-Hash: <<secret:0>>", "argon2id_hash", 502),
        ds("PASSWORD_HASH", "en", "dlp_password_hash", "passwd_hash = <<secret:0>>", "md5_hex", 503),
        dn("PASSWORD_HASH", "de", "dlp_password_hash", "Passwort-Hash: [REDACTED]", "redacted placeholder"),
        dn("PASSWORD_HASH", "en", "dlp_password_hash", "checksum = 0123456789abcdef0123456789abcdef", "missing password-hash anchor"),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "benutzer:\n  - name: ada\n    rolle: admin\n    password_hash: <<secret:0>>\n",
            "bcrypt_2b_hash", 5001, carrier="yaml",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "# Notfallzugang\nADMIN_USER=notfall\nPASSWORT_HASH=<<secret:0>>\n",
            "sha256_hex", 5002, carrier="env",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "2026-10-03 12:00:00 WARN Benutzer ada angelegt, passwort_hash=<<secret:0>>\n",
            "argon2id_phc_hash", 5003, carrier="log",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "Im Ticket steht der Passwort-Hash: <<secret:0>> – bitte sofort entfernen.",
            "bcrypt_2b_hash", 5004, carrier="prose",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "[benutzer.alt]\npasswd_hash = <<secret:0>>\n",
            "md5_hex", 5005, carrier="ini",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "Der Passwort-Hash lautet <<secret:0>>.",
            "bcrypt_2b_hash", 5006, carrier="prose", gap=True,
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "ada:<<secret:0>>:19700:0:99999:7:::\n",
            "bcrypt_2b_hash", 5007, tags=("no_context",), gap=True,
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "user = User(email=\"ada@example.org\")\nuser.password_hash = \"<<secret:0>>\"\ndb.session.add(user)\n",
            "argon2id_phc_hash", 5008, carrier="code",
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "[legacy]\npassword_hash = <<secret:0>>\n",
            "sha256_hex", 5009, carrier="ini",
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "FYI the leaked password hash: <<secret:0>> came from the old forum database.",
            "bcrypt_2b_hash", 5010, carrier="prose",
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "{\"email\": \"ada@example.org\", \"password_hash\": \"<<secret:0>>\"}",
            "argon2id_phc_hash", 5011, carrier="json", gap=True,
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "Passwort-Hash: noch nicht gesetzt",
            "no hash value",
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "sha256sum: 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b  release.tar.gz",
            "file checksum without a password-hash anchor", carrier="cli",
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "benutzer:\n  password_hash: ${ADMIN_HASH}\n",
            "environment reference", carrier="yaml",
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "bcrypt-Hashes beginnen mit $2b$12$ und haben 60 Zeichen.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "user.password_hash = None  # set on first login\n",
            "no hash value", carrier="code",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "password_hash: \"<bcrypt hash>\"",
            "template placeholder",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "Argon2 parameters: $argon2id$v=19$m=65536,t=3,p=4$",
            "parameter prefix without a password-hash anchor",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "ETag: \"5d41402abc4b2a76b9719d911017c592\"",
            "content hash without a password-hash anchor", carrier="http",
        ),
    ],
    "PAYMENT_KEY": [
        ds("PAYMENT_KEY", "en", "dlp_stripe_key", "STRIPE_SECRET_KEY=<<secret:0>>", "stripe_secret_live", 601),
        ds("PAYMENT_KEY", "de", "dlp_stripe_key", "Stripe Testschlüssel: <<secret:0>>", "stripe_restricted_test", 602),
        ds("PAYMENT_KEY", "en", "dlp_stripe_webhook", "Webhook secret: <<secret:0>>", "stripe_webhook_secret", 603),
        dn("PAYMENT_KEY", "en", "dlp_stripe_key", "Truncated Stripe prefix in the docs: sk_live_short", "provider token is too short"),
        dn("PAYMENT_KEY", "de", "dlp_stripe_key", "Stripe-Schlüssel: [REDACTED]", "redacted placeholder"),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_webhook",
            "# Zahlungsdienst\nSTRIPE_KONTO=shop-de\nSTRIPE_WEBHOOK_SECRET=<<secret:0>>\n",
            "stripe_webhook_secret", 6001, carrier="env",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "<?php\n// Testumgebung des Shops\n\\Stripe\\Stripe::setApiKey('<<secret:0>>');\n",
            "stripe_secret_test_long", 6002, carrier="code",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "Kannst du kurz prüfen, ob <<secret:0>> noch aktiv ist? Der Kunde meldet Fehler beim Bezahlen.",
            "stripe_secret_live", 6003, carrier="prose",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "zahlung:\n  anbieter: stripe\n  schluessel: <<secret:0>>\n",
            "stripe_restricted_test", 6004, carrier="yaml",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "datum;shop;wert\n2026-10-01;de;<<secret:0>>\n",
            "stripe_secret_live", 6005, carrier="csv", tags=("no_context",),
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_webhook",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: zahlung\ndata:\n  STRIPE_WEBHOOK_SECRET: <<secret:0|base64>>\n",
            "stripe_webhook_secret", 6006, carrier="yaml", gap=True,
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_webhook",
            "const event = stripe.webhooks.constructEvent(body, signature, \"<<secret:0>>\");\n",
            "stripe_webhook_secret", 6007, carrier="code", tags=("no_context",),
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "{\"payments\": {\"provider\": \"stripe\", \"secret\": \"<<secret:0>>\"}}",
            "stripe_secret_live", 6008, carrier="json",
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "$ curl https://api.stripe.com/v1/charges -u <<secret:0>>:\n",
            "stripe_secret_test_long", 6009, carrier="cli",
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "Quick one: is <<secret:0>> the restricted key for the reporting job?",
            "stripe_restricted_test", 6010, carrier="prose",
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "STRIPE_KEY = \"<<secret:0[0:12]>>\" + \"<<secret:0[12:32]>>\"\n",
            "stripe_secret_live", 6011, carrier="code", gap=True,
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "Stripe-Schlüssel beginnen mit sk_live_ oder sk_test_.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "# Wert aus dem Vault\nSTRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_webhook",
            "STRIPE_WEBHOOK_SECRET=<aus dem Dashboard kopieren>",
            "template placeholder",
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "zahlung:\n  # öffentlicher Schlüssel für das Frontend\n  publishable: pk_test_51ExampleExampleExample00\n",
            "publishable key is public", carrier="yaml",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "{\"stripe\": {\"publishableKey\": \"pk_live_51ExampleExampleExample00\"}}",
            "publishable key is public", carrier="json",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_webhook",
            "const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;\n",
            "environment reference in code", carrier="code",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_webhook",
            "Webhook signing secrets start with whsec_ and are shown once in the dashboard.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "Use the test card 4242 4242 4242 4242 with any future date.",
            "test card number is not a key", carrier="prose",
        ),
    ],
    "PRIVATE_KEY": [
        ds("PRIVATE_KEY", "en", "dlp_private_key_block", "<<secret:0>>", "pem_pkcs8_private_key", 701),
        ds("PRIVATE_KEY", "de", "dlp_private_key_header", "Schlüsseldatei:\n<<secret:0>>", "pem_openssh_private_key_header", 702),
        ds("PRIVATE_KEY", "en", "dlp_private_key_block", "<<secret:0>>", "pem_rsa_private_key", 703),
        dn("PRIVATE_KEY", "en", "dlp_private_key_header", "-----BEGIN PUBLIC KEY-----", "public key is not private material"),
        dn("PRIVATE_KEY", "de", "dlp_private_key_header", "BEGIN PRIVATE KEY", "PEM delimiters are incomplete"),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "$ cat ~/.ssh/id_ed25519\n<<secret:0>>\n$ ls -l ~/.ssh\n",
            "pem_openssh_ed25519_private_key", 7001, carrier="cli",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "Hallo, anbei der Schlüssel für den Server:\n\n<<secret:0>>\n\nBitte nach dem Import löschen.",
            "pem_sec1_ec_private_key", 7002, carrier="prose",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "# TLS für den internen Dienst\nTLS_KEY=\"<<secret:0>>\"\nTLS_PORT=8443\n",
            "pem_dsa_private_key", 7003, carrier="env",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "{\n  \"type\": \"service_account\",\n  \"projekt\": \"buchhaltung\",\n  \"private_key\": \"<<secret:0|json>>\"\n}\n",
            "pem_pkcs8_ed25519_private_key", 7004, carrier="json",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "Die Datei beginnt mit <<secret:0>> und wurde versehentlich eingecheckt.",
            "pem_openssh_private_key_header", 7005, carrier="prose",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n  tls.key: <<secret:0|base64>>\n",
            "pem_pkcs1_rsa_private_key", 7006, carrier="yaml", gap=True,
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "SIGNING_KEY = \"\"\"<<secret:0>>\"\"\"\n\ndef sign(payload):\n    return jwt.encode(payload, SIGNING_KEY, algorithm=\"RS256\")\n",
            "pem_pkcs1_rsa_private_key", 7007, carrier="code",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "$ cat deploy/id_ed25519\n<<secret:0>>\n",
            "pem_openssh_ed25519_private_key", 7008, carrier="cli",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "2026-10-02 11:00:00 WARN config loader found <<secret:0>> in uploads/key.txt\n",
            "pem_openssh_private_key_header", 7009, carrier="log",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "{\"kid\": \"edge-1\", \"pem\": \"<<secret:0|json>>\"}",
            "pem_sec1_ec_private_key", 7010, carrier="json",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "Hi Lee, here is the old DSA key from the build box:\n<<secret:0>>\nPlease rotate it.",
            "pem_dsa_private_key", 7011, carrier="prose",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n  tls.key: <<secret:0|base64>>\n",
            "pem_sec1_ec_private_key", 7012, carrier="yaml", gap=True,
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2VydGlmaWthdA==\n-----END CERTIFICATE-----",
            "certificate is public", carrier="cli",
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAb2VmZmVudGxpY2hlciBTY2hsw7xzc2Vs\n-----END PUBLIC KEY-----",
            "public key block", carrier="cli",
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG9mZmVudGxpY2hlciBTY2hsdWVzc2Vs ada@laptop",
            "public SSH key",
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "Den privaten Schlüssel findest du unter ~/.ssh/id_ed25519, bitte nie kopieren.",
            "path reference without key material", carrier="prose",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "-----BEGIN CERTIFICATE REQUEST-----",
            "certificate request is public",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDMEZQAAABYJKwYBBAHaRw8BAQdAcHVibGljIGtleQ==\n-----END PGP PUBLIC KEY BLOCK-----",
            "public PGP key block", carrier="cli",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "# .gitignore\n*.pem\nid_rsa\nid_ed25519\n",
            "file names without key material", carrier="code",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCpdWJsaWMga2V5IG9ubHk= deploy@ci",
            "public SSH key",
        ),
    ],
    "SECRET_TOKEN": [
        ds("SECRET_TOKEN", "en", "dlp_github_token", "GITHUB_TOKEN=<<secret:0>>", "github_pat_classic", 801),
        ds("SECRET_TOKEN", "de", "dlp_gitlab_pat", "GitLab Token: <<secret:0>>", "gitlab_pat", 802),
        ds("SECRET_TOKEN", "en", "dlp_jwt_token", "Authorization: Bearer <<secret:0>>", "jwt_hs256", 803),
        dn("SECRET_TOKEN", "en", "dlp_github_token", "Truncated GitHub prefix in the docs: ghp_short", "provider token is too short"),
        dn("SECRET_TOKEN", "de", "dlp_generic_credential_assignment", "Token: your-token-here", "documented placeholder"),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_pat",
            "# CI-Zugang für das Release-Skript\nGH_REPO=acme/app\nGH_TOKEN=<<secret:0>>\n",
            "github_fine_grained_pat", 8001, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "; Registry für interne Pakete\n//registry.npmjs.org/:_authToken=<<secret:0>>\nalways-auth=true\n",
            "npm_access_token", 8002, carrier="ini",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_slack_token",
            "Bitte den Slack-Token <<secret:0>> heute noch widerrufen, er stand im Wiki.",
            "slack_bot_token", 8003, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_discord_token",
            "# Bot für den Community-Server\nimport discord\n\nclient = discord.Client(intents=discord.Intents.default())\nclient.run('<<secret:0>>')\n",
            "discord_bot_token", 8004, carrier="code",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "GET /api/v1/konten HTTP/1.1\r\nHost: api.example.de\r\nAuthorization: Bearer <<secret:0>>\r\n\r\n",
            "bearer_opaque_token", 8005, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_csrf_token",
            "POST /profil HTTP/1.1\r\nHost: portal.example.de\r\nX-CSRF-Token: <<secret:0>>\r\n\r\nname=Ada",
            "csrf_token", 8006, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "datum;job;wert\n2026-10-01;release;<<secret:0>>\n",
            "github_gho_token", 8007, carrier="csv", tags=("no_context",),
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_jwt_token",
            "2026-10-02 10:15:00 INFO Anmeldung erfolgreich, Sitzung <<secret:0>>\n",
            "jwt_signed_hs256", 8008, carrier="log", tags=("no_context",),
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_pat",
            "deploy:\n  stage: deploy\n  variables:\n    GITLAB_TOKEN: <<secret:0>>\n  script:\n    - ./deploy.sh\n",
            "gitlab_pat", 8009, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "Token als Hex im Backup: <<secret:0|hex>>",
            "github_ghp_token", 8010, gap=True,
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "$ git clone https://x-access-token:<<secret:0>>@github.com/acme/app.git\nCloning into 'app'...\n",
            "github_ghs_token", 8011, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_pat",
            "{\"github\": {\"owner\": \"acme\", \"pat\": \"<<secret:0>>\"}}",
            "github_fine_grained_pat", 8012, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "# publish settings\nNPM_REGISTRY=https://registry.npmjs.org\nNPM_TOKEN=<<secret:0>>\n",
            "npm_access_token", 8013, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_slack_token",
            "notifications:\n  slack:\n    channel: \"#alerts\"\n    token: <<secret:0>>\n",
            "slack_user_token", 8014, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_discord_token",
            "DISCORD_TOKEN=<<secret:0>>",
            "discord_bot_token", 8015,
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "username=ada&csrf_token=<<secret:0>>",
            "csrf_token", 8016,
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "$ curl -H 'Authorization: Bearer <<secret:0>>' https://api.example.com/v1/me\n",
            "bearer_opaque_token", 8017, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_jwt_token",
            "{\"session\": \"<<secret:0>>\"}",
            "jwt_signed_rs256", 8018, carrier="json", tags=("no_context",),
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_pat",
            "Hey, the GitLab token for the runner is <<secret:0>>, it expires next week.",
            "gitlab_pat", 8019, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "TOKEN = \"<<secret:0[0:4]>>\" + \"<<secret:0[4:40]>>\"\n",
            "github_ghp_token", 8020, carrier="code", gap=True,
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "GitHub-Tokens beginnen mit ghp_, gho_ oder github_pat_.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_gitlab_pat",
            "deploy:\n  variables:\n    GITLAB_TOKEN: ${CI_JOB_TOKEN}\n",
            "CI variable reference", carrier="yaml",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "Authorization: Bearer <TOKEN>",
            "template placeholder",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_slack_token",
            "Slack-Bot-Tokens beginnen mit xoxb- und werden in der App-Verwaltung erzeugt.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "curl -H \"Authorization: Bearer ${API_TOKEN}\" https://api.example.com/v1/me",
            "environment reference", carrier="cli",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "<meta name=\"csrf-token\" content=\"{{ csrf_token() }}\">",
            "template expression", carrier="xml",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_jwt_token",
            "The JWT header eyJhbGciOiJIUzI1NiJ9 decodes to {\"alg\":\"HS256\"}.",
            "header segment only", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
            "environment reference", carrier="ini",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_discord_token",
            "Discord bot tokens have three dot-separated parts; never paste them into issues.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_github_pat",
            "- uses: actions/checkout@v4\n  with:\n    token: ${{ secrets.GH_PAT }}\n",
            "CI secret reference", carrier="yaml",
        ),
    ],
    "dlp.de.vat_id": [
        dp("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: ", "DE 123 456 789"),
        dp("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT ID: ", "DE987654321"),
        dp("dlp.de.vat_id", "de", "dlp_de_vat_id", "Umsatzsteuer-Identifikationsnummer = ", "DE 111222333"),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: FR123456789", "current detector covers German VAT IDs"),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "Reference DE123456789", "missing VAT anchor"),
        dp(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "Mit freundlichen Grüßen\nBeispiel Handels GmbH · Hauptstraße 1 · 10115 Berlin\nUSt-IdNr.: ", "DE 812 345 670",
            "\n", carrier="prose",
        ),
        dp(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "firma:\n  name: Beispiel AG\n  ust-idnr: ", "DE298765432", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "Unsere Umsatzsteuer-Identifikationsnummer lautet ", "DE 123456788", ", bitte auf der Rechnung angeben.",
            carrier="prose",
        ),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: beantragt, Nummer folgt", "no value yet"),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: DE 123 45", "too few digits"),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: DE1234567890", "too many digits"),
        dn(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "Bitte tragen Sie Ihre USt-IdNr. im Kundenportal ein.", "anchor without a value", carrier="prose",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "Supplier details\nName: Example Trading GmbH\nVAT-ID ", "DE 135 792 468", "\n", carrier="prose",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "supplier:\n  country: DE\n  vat id: ", "DE246813579", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "2026-10-01T09:00:00Z INFO invoice created vat id=", "DE112233445", "\n", carrier="log",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "Please put our VAT ID ", "DE998877665", " on every invoice.", carrier="prose",
        ),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT ID: ATU12345678", "Austrian VAT ID is out of scope"),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT ID: pending", "no value yet"),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT rate: 19 %", "rate is not an identifier"),
        dn(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "Enter your VAT ID in the billing settings.", "anchor without a value", carrier="prose",
        ),
    ],
    "dlp.de.commercial_register_number": [
        dp("dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number", "Amtsgericht Berlin ", "HRB 12345"),
        dp("dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number", "Register entry ", "HRA 77881"),
        dp("dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number", "Vereinsregister ", "VR 2048"),
        dn("dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number", "Register: HRX 12345", "unknown register prefix"),
        dn("dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number", "Register entry HRB ABC", "value contains no digits"),
        dp(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Eingetragen im Handelsregister des Amtsgerichts Köln unter ", "HRB 98765", ".", carrier="prose",
        ),
        dp(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "impressum:\n  firma: Beispiel eG\n  register: ", "GnR 123", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Partnerschaftsregister ", "PR 815",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Handelsregister: Eintragung wird beantragt", "no value yet",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Die HRB-Nummer folgt nach der Eintragung.", "anchor without a value", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Zuständig ist das Registergericht München.", "court without a register number", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Bestellnummer HRZ-2048", "unknown register prefix",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "Registered at Charlottenburg District Court, ", "HRB 123456", " B.", carrier="prose",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "{\"company\": \"Example GmbH\", \"register\": \"", "HRA 5544", "\"}", carrier="json",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "2026-10-01 INFO onboarding vendor register=", "HRB 70421", "\n", carrier="log",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "The club is listed in the association register as ", "VR 4471", ".", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "We are hiring an HRBP for the Berlin office.", "role abbreviation", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "The VRAM budget is 16 GB per GPU.", "hardware term", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "Commercial register: registration pending", "no value yet",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "GnRH levels were normal.", "medical abbreviation", carrier="prose",
        ),
    ],
    "dlp.de.facility_number_bsnr": [
        dp("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: ", "123456789"),
        dp("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "Betriebsstättennummer = ", "987654321"),
        dp("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "German BSNR lautet ", "246813579"),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: 12345678", "only eight digits"),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Inventory number 123456789", "missing BSNR anchor"),
        dp(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "Praxis Dr. Beispiel\nAllgemeinmedizin\nBSNR ", "381234500", "\n", carrier="prose",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "praxis:\n  name: MVZ Beispiel\n  bsnr: ", "721234567", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "Die Betriebsstättennummer lautet ", "123450001", ", bitte im Abrechnungsformular eintragen.",
            carrier="prose",
        ),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: 1234567890", "ten digits"),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: folgt nach Zulassung", "no value yet"),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "Telefon der Praxis: 030 123456789", "phone number without BSNR anchor"),
        dn(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "Die BSNR steht auf dem Praxisstempel.", "anchor without a value", carrier="prose",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "Facility number ", "246813570",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "Referral form\nPractice: Example Clinic\nMedical facility number: ", "987650123", "\n", carrier="prose",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "clinic:\n  facility number: ", "555012345", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "2026-10-01 INFO claim export BSNR=", "112233445", "\n", carrier="log",
        ),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Facility number: pending", "no value yet"),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Facility number: 1234", "too few digits"),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Room 123456789 is on the third floor.", "missing BSNR anchor", carrier="prose"),
        dn(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "Ask the practice for its BSNR before billing.", "anchor without a value", carrier="prose",
        ),
    ],
    "dlp.record.case_id": [
        dp("dlp.record.case_id", "de", "dlp_record_case_id", "Fallnummer: ", "CASE-2026/481"),
        dp("dlp.record.case_id", "en", "dlp_record_case_id", "Case ID ", "CV-2026-8842"),
        dp("dlp.record.case_id", "de", "dlp_record_case_id", "Aktenzeichen = ", "17-A/2048"),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Fallnummer: ABC", "value contains no digit"),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Ticket CASE-2026/481", "missing case anchor"),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Sehr geehrte Frau Beispiel,\nin Ihrer Sache (Aktenzeichen ", "3 O 112/26", ") ...", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "vorgang:\n  vorgangsnummer: ", "VG-2026-0042", "\n  status: offen\n", carrier="yaml",
        ),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Ihre Fallnummer lautet ", "F-88123", ". Bitte bei Rückfragen angeben.", carrier="prose",
        ),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Betreff: Widerspruch, Aktenzeichen: ", "AZ-7781/26", "\n", carrier="prose",
        ),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Aktenzeichen: bitte angeben", "no value"),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Kundennummer: F-88123", "wrong identifier anchor"),
        dn(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Die Fallnummer finden Sie oben rechts im Schreiben.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Vorgangsnummer: <wird vergeben>", "template placeholder"),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Support summary\nCase-ID: ", "SR-77120", "\nPriority: high\n", carrier="prose",
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "2026-10-02 INFO escalated case id=", "CS-2026-0193", "\n", carrier="log",
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "case:\n  case id: ", "C-4471", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Your case ID is ", "CX-2048-77", ", keep it for your records.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Case ID: ", "INC0012345",
        ),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Case ID: unknown", "value contains no digit"),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Order number CX-2048-77", "wrong identifier anchor"),
        dn(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Please include the case ID in every reply.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Case ID: <case-id>", "template placeholder"),
    ],
    "dlp.record.contract_id": [
        dp("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer ", "V-2026-8842"),
        dp("dlp.record.contract_id", "en", "dlp_record_contract_id", "Contract ID ", "CONTRACT-8842"),
        dp("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertrags-ID: ", "VK/2048"),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer: VERTRAG", "value contains no digit"),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Agreement CONTRACT-8842", "missing contract-ID anchor"),
        dp(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "Hallo Herr Beispiel,\nIhre Vertragsnummer lautet ", "KV-55120", ".\nViele Grüße", carrier="prose",
        ),
        dp(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "vertrag:\n  vertragsnummer: ", "LV-2026-0007", "\n  laufzeit: 24\n", carrier="yaml",
        ),
        dp(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "2026-10-02 INFO Kündigung erfasst, Vertrags-ID=", "MV/7781", "\n", carrier="log",
        ),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer: siehe Anlage", "value contains no digit"),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Rechnungsnummer KV-55120", "wrong identifier anchor"),
        dn(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "Bitte geben Sie immer Ihre Vertragsnummer an.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer: <eintragen>", "template placeholder"),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "Dear customer,\nyour contract ID is ", "SUB-2026-4471", ".\nRegards", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "contract:\n  contract id: ", "MSA-0815", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "2026-10-02 INFO renewal scheduled contract-id=", "C2026-118", "\n", carrier="log",
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "Contract-ID: ", "LEASE/2048",
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "Contract ID = ", "SUB/2026/7",
        ),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Contract ID: TBD", "value contains no digit"),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Invoice SUB-2026-4471", "wrong identifier anchor"),
        dn(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "The contract ID is printed on page one.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Contract ID: <contract-id>", "template placeholder"),
    ],
    "dlp.record.claim_id": [
        dp("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: ", "SCH-44119"),
        dp("dlp.record.claim_id", "en", "dlp_record_claim_id", "Claim ID ", "CLAIM-2048"),
        dp("dlp.record.claim_id", "de", "dlp_record_claim_id", "Leistungsfallnummer = ", "LF/7781"),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: SCHADEN", "value contains no digit"),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Ticket CLAIM-2048", "missing claim anchor"),
        dp(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "Sehr geehrte Damen und Herren,\nzur Schadennummer ", "KFZ-2026-3310", " reiche ich die Fotos nach.", carrier="prose",
        ),
        dp(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "schaden:\n  schadennummer: ", "HR-77120", "\n  status: offen\n", carrier="yaml",
        ),
        dp(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "2026-10-02 INFO Regulierung gestartet, Leistungsfallnummer=", "LF-2026-55", "\n", carrier="log",
        ),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: wird nachgereicht", "value contains no digit"),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Vertragsnummer KFZ-2026-3310", "wrong identifier anchor"),
        dn(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "Die Schadennummer erhalten Sie per Post.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: <neu>", "template placeholder"),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "Hello,\nregarding claim ID ", "WC-2026-0091", ", the adjuster will call you.", carrier="prose",
        ),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "claim:\n  claim id: ", "AUTO-5512", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "2026-10-02 INFO payout approved claim-id=", "HC/2048", "\n", carrier="log",
        ),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "Claim-ID: ", "PRP-77-120",
        ),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Claim ID: none", "value contains no digit"),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Order ID none for WC-2026-0091", "wrong identifier anchor"),
        dn(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "You will get a claim ID by email.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Claim ID: <claim-id>", "template placeholder"),
    ],
    "dlp.record.order_id": [
        dp("dlp.record.order_id", "de", "dlp_record_order_id", "Bestellnummer ", "ORD-77881"),
        dp("dlp.record.order_id", "en", "dlp_record_order_id", "Order ID ", "ORDER-2048"),
        dp("dlp.record.order_id", "de", "dlp_record_order_id", "Auftragsnummer = ", "AUF/4711"),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Bestellnummer: ORDER", "value contains no digit"),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Shipment ORDER-2048", "missing order anchor"),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Hallo,\nmeine Bestellnummer ist ", "B-2026-11872", ", die Lieferung fehlt noch.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "auftrag:\n  auftragsnummer: ", "A-55012", "\n  menge: 3\n", carrier="yaml",
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "2026-10-02 INFO Versand angestoßen, Bestellnummer=", "WEB-88213", "\n", carrier="log",
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Ihre Bestellnummer lautet ", "DE-2026-4471", ".", carrier="prose",
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Auftragsnummer: ", "FA/2026/31",
        ),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Bestellnummer: folgt per Mail", "value contains no digit"),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Paketnummer WEB-88213", "wrong identifier anchor"),
        dn(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Die Bestellnummer steht in der Bestätigungsmail.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Auftragsnummer: <neu>", "template placeholder"),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Hi,\nmy order ID is ", "WEB-55-1202", " and the parcel never arrived.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "order:\n  order id: ", "PO-2026-0815", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "2026-10-02 INFO payment captured order-id=", "SO/77120", "\n", carrier="log",
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Order-ID: ", "AMZ-114-2048",
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Order ID = ", "B2B/4471",
        ),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Order ID: pending", "value contains no digit"),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Tracking number SO/77120", "wrong identifier anchor"),
        dn(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Your order ID is in the confirmation email.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Order ID: <order-id>", "template placeholder"),
    ],
    "dlp.record.invoice_id": [
        dp("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: ", "RE-2026-190"),
        dp("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Invoice ID ", "INV-2026-190"),
        dp("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungs-ID = ", "R/77881"),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: RECHNUNG", "value contains no digit"),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Document INV-2026-190", "missing invoice anchor"),
        dp(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "Guten Tag,\nzur Rechnungsnummer ", "RG-2026-0412", " fehlt noch die Zahlung.", carrier="prose",
        ),
        dp(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "rechnung:\n  rechnungsnummer: ", "2026-10-0042", "\n  betrag: 120\n", carrier="yaml",
        ),
        dp(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "2026-10-02 INFO Mahnung erstellt, Rechnungs-ID=", "RE/55120", "\n", carrier="log",
        ),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: siehe oben", "value contains no digit"),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Lieferscheinnummer RG-2026-0412", "wrong identifier anchor"),
        dn(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "Bitte bei Zahlung die Rechnungsnummer angeben.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: <automatisch>", "template placeholder"),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "Hi,\ninvoice ID ", "AR-2026-7781", " is still unpaid.", carrier="prose",
        ),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "invoice:\n  invoice id: ", "INV/0815", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "2026-10-02 INFO reminder sent invoice-id=", "BILL-4471", "\n", carrier="log",
        ),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "Invoice-ID: ", "2026-INV-31",
        ),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Invoice ID: draft", "value contains no digit"),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Shipment AR-2026-7781", "wrong identifier anchor"),
        dn(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "Quote the invoice ID when you pay.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Invoice ID: <invoice-id>", "template placeholder"),
    ],
    "dlp.project_id": [
        dp("dlp.project_id", "de", "dlp_project_id", "Projekt-ID ", "P-ARK-2026"),
        dp("dlp.project_id", "en", "dlp_project_id", "Project ID ", "PROJECT-2048"),
        dp("dlp.project_id", "de", "dlp_project_id", "Projektnummer = ", "PRJ/7781"),
        dn("dlp.project_id", "de", "dlp_project_id", "Projekt-ID: PROJEKT", "value contains no digit"),
        dn("dlp.project_id", "en", "dlp_project_id", "Folder PROJECT-2048", "missing project anchor"),
        dp(
            "dlp.project_id", "de", "dlp_project_id",
            "Hallo zusammen,\nbitte Stunden auf Projektnummer ", "PN-2026-114", " buchen.", carrier="prose",
        ),
        dp(
            "dlp.project_id", "de", "dlp_project_id",
            "projekt:\n  projekt-id: ", "ERP-4471", "\n  leitung: Ada\n", carrier="yaml",
        ),
        dp(
            "dlp.project_id", "de", "dlp_project_id",
            "2026-10-02 INFO Budget freigegeben, Projekt-ID=", "INT/0815", "\n", carrier="log",
        ),
        dn("dlp.project_id", "de", "dlp_project_id", "Projektnummer: noch offen", "value contains no digit"),
        dn("dlp.project_id", "de", "dlp_project_id", "Kostenstelle PN-2026-114", "wrong identifier anchor"),
        dn(
            "dlp.project_id", "de", "dlp_project_id",
            "Die Projekt-ID vergibt das PMO.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.project_id", "de", "dlp_project_id", "Projekt-ID: <neu>", "template placeholder"),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "Hi team,\nplease log your hours on project ID ", "OPS-2026-77", ".", carrier="prose",
        ),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "project:\n  project id: ", "MIG-5512", "\n", carrier="yaml",
        ),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "2026-10-02 INFO budget approved project-id=", "RND/2048", "\n", carrier="log",
        ),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "Project-ID: ", "X-2026-31",
        ),
        dn("dlp.project_id", "en", "dlp_project_id", "Project ID: tbd", "value contains no digit"),
        dn("dlp.project_id", "en", "dlp_project_id", "Cost center OPS-2026-77", "wrong identifier anchor"),
        dn(
            "dlp.project_id", "en", "dlp_project_id",
            "Ask the PMO for a project ID.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.project_id", "en", "dlp_project_id", "Project ID: <project-id>", "template placeholder"),
    ],
    "dlp.organization_id": [
        dp("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: ", "TENANT-742"),
        dp("dlp.organization_id", "en", "dlp_organization_id", "Organization ID ", "ORG-2048"),
        dp("dlp.organization_id", "de", "dlp_organization_id", "Unternehmens-ID = ", "UNT/7781"),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: TENANT", "value contains no digit"),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Account ORG-2048", "missing organization anchor"),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Hallo Support,\nunsere Mandanten-ID ist ", "M-55012", ", der Login schlägt fehl.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "mandant:\n  organisations-id: ", "ORG-DE-4471", "\n", carrier="yaml",
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "2026-10-02 INFO Synchronisation gestartet, Mandanten-ID=", "T/0815", "\n", carrier="log",
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Die Unternehmens-ID lautet ", "U-2026-118", ".", carrier="prose",
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Organisations-ID: ", "ORG-77120",
        ),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: unbekannt", "value contains no digit"),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Kundennummer M-55012", "wrong identifier anchor"),
        dn(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Die Mandanten-ID steht in den Einstellungen.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: <mandant>", "template placeholder"),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "Hi,\nour tenant ID is ", "ten-4471-eu", " and SSO stopped working.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "account:\n  tenant id: ", "TEN-2026-31", "\n", carrier="yaml",
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "2026-10-02 INFO sync started organization-id=", "ORG/5512", "\n", carrier="log",
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "Tenant-ID: ", "T-77120",
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "Organization ID = ", "ACME-0815",
        ),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Tenant ID: unknown", "value contains no digit"),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Customer number T-77120", "wrong identifier anchor"),
        dn(
            "dlp.organization_id", "en", "dlp_organization_id",
            "You can find the tenant ID in the admin console.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Tenant ID: <tenant-id>", "template placeholder"),
    ],
    "dlp.internal.business_metric": [
        dp("dlp.internal.business_metric", "de", "dlp_internal_business_metric", "", "EBITDA-Marge: 6,1 Prozent"),
        dp("dlp.internal.business_metric", "en", "dlp_internal_business_metric", "", "Forecast: 12 Mio. EUR"),
        dp("dlp.internal.business_metric", "de", "dlp_internal_business_metric", "", "Umsatz beträgt 4.200 TEUR"),
        dn("dlp.internal.business_metric", "de", "dlp_internal_business_metric", "Umsatzbericht für August", "metric has no numeric value"),
        dn("dlp.internal.business_metric", "en", "dlp_internal_business_metric", "Margin improved considerably.", "unsupported English lexical anchor and no value"),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Vertraulich: Im dritten Quartal lag der ", "Umsatz bei 4,2 Mio. EUR", ", deutlich über Plan.", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "kennzahlen:\n  ", "rohertragsmarge: 38 %", "\n", carrier="yaml",
        ),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Hallo Ada, dein ", "Grundgehalt liegt ab Januar bei 72.000 EUR", ". Viele Grüße", carrier="prose", gap=True,
        ),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "| Kennzahl | Wert |\n|---|---|\n| ", "Deckungsbeitrag: 1.250 TEUR", " |\n", carrier="markdown",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Der Umsatz ist im Vergleich zum Vorjahr gestiegen.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Die Marge wird im nächsten Meeting besprochen.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Gehaltsabrechnung: Fragen bitte an die Personalabteilung.", "anchor without a value",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Der Rabatt beträgt 10 Prozent auf alle Artikel.", "public price information", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Confidential: Q3 ", "Revenue at 18 Mio. EUR", ", ahead of plan.", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "metrics:\n  ", "gross margin: 41 %", "\n", carrier="yaml",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Hi Sam, your new ", "Base Salary is 85.000 EUR", " from January.", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "| Metric | Value |\n|---|---|\n| ", "EBITDA: 3.400 TEUR", " |\n", carrier="markdown",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Revenue grew faster than expected this year.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "The salary review happens every spring.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Shipping is free for orders above 50 EUR.", "public price information", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "The forecast for tomorrow is sunny.", "weather forecast without a value", carrier="prose",
        ),
    ],
    "dlp.content.source_code": [
        dp("dlp.content.source_code", "en", "dlp_source_code_fence", "", "```python\nprint('internal')\n```"),
        dp("dlp.content.source_code", "de", "dlp_source_code_statement", "", "const client = new Client();"),
        dp("dlp.content.source_code", "en", "dlp_source_code_import", "", "from pathlib import Path"),
        dn("dlp.content.source_code", "de", "dlp_source_code_statement", "Der Client wird morgen aktualisiert.", "natural language is not source code"),
        dn("dlp.content.source_code", "en", "dlp_source_code_fence", "print the internal report", "prose lacks code syntax"),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_fence",
            "Kannst du kurz drüberschauen?\n", "```js\nconsole.log(kunde)\n```", "\nDanke!", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_import",
            "Fehlermeldung beim Start, die erste Zeile im Skript ist\n", "import pandas as pd", "\nund dann bricht es ab.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_declaration",
            "Ticket 4711: Die Funktion\n", "def berechne_rabatt(kunde):", "\nliefert negative Werte.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_python_rust_assignment",
            "Im Patch steht nur\n", "let mut zaehler = 0;", "\nmehr nicht.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_statement",
            "Bitte diese Zeile ersetzen:\n", "let kunden = await ladeKunden(filiale);", "\n", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_import",
            "Import und Export laufen über das Portal.", "prose about imports", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_declaration",
            "Die Klasse 4b fährt am Freitag ins Museum.", "prose with a code keyword", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_python_rust_assignment",
            "Ergebnis = gut, Aufwand = gering", "prose with assignments",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_fence",
            "Bitte den Code als Block mit drei Backticks einfügen.", "prose about code formatting", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_declaration",
            "Can someone review this?\n", "class InvoiceExporter:", "\nIt fails on empty rows.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_statement",
            "The bug is in this line:\n", "var total = items.reduce(sum, 0);", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_python_rust_assignment",
            "Config snippet from the service:\n", "retries = 5", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_import",
            "The traceback starts at\n", "import internal.billing.core", "\n", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_import",
            "Import duties apply to all shipments outside the EU.", "prose about imports", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_declaration",
            "The class starts at nine and ends at noon.", "prose with a code keyword", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_statement",
            "Let the team know when the build is green.", "prose with a code keyword", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_python_rust_assignment",
            "Result = fine, effort = low", "prose with assignments",
        ),
    ],
    "dlp.content.sql": [
        dp("dlp.content.sql", "de", "dlp_sql_statement", "", "SELECT * FROM kunden WHERE aktiv = true;"),
        dp("dlp.content.sql", "en", "dlp_sql_statement", "", "UPDATE accounts SET active = false;"),
        dp("dlp.content.sql", "en", "dlp_sql_statement", "", "DELETE FROM sessions WHERE expired = true;"),
        dn("dlp.content.sql", "de", "dlp_sql_statement", "Bitte Kunden aus der Liste auswählen.", "natural language is not SQL"),
        dn("dlp.content.sql", "en", "dlp_sql_multiline_statement", "SELECT the best option FROM the list", "no terminating SQL statement structure"),
        dp(
            "dlp.content.sql", "de", "dlp_sql_multiline_statement",
            "Kannst du mal ", "SELECT name FROM bestellungen WHERE status = 'offen';", " ausführen und mir das Ergebnis schicken?",
            carrier="prose",
        ),
        dp(
            "dlp.content.sql", "de", "dlp_sql_statement",
            "", "-- Bereinigung der Testdaten\nDELETE FROM kunden\nWHERE erstellt < '2026-01-01';", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.sql", "de", "dlp_sql_statement",
            "Migration für die Filialen:\n", "ALTER TABLE filialen ADD COLUMN region TEXT;", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.sql", "de", "dlp_sql_multiline_statement",
            "query = \"", "SELECT iban FROM konten WHERE kunde_id = %s;", "\"\n", carrier="code",
        ),
        dn("dlp.content.sql", "de", "dlp_sql_multiline_statement", "Wähle aus der Liste und klicke auf Update.", "natural language is not SQL", carrier="prose"),
        dn("dlp.content.sql", "de", "dlp_sql_statement", "Die Tabelle wurde gestern gelöscht.", "natural language is not SQL", carrier="prose"),
        dn("dlp.content.sql", "de", "dlp_sql_statement", "SQL-Kurs: Abfragen mit Filtern und Sortierung", "topic title without a statement"),
        dn("dlp.content.sql", "de", "dlp_sql_multiline_statement", "Select-Box und From-Feld im Formular sind leer", "UI terms without SQL structure", carrier="prose"),
        dp(
            "dlp.content.sql", "en", "dlp_sql_multiline_statement",
            "Could you run ", "SELECT email FROM users WHERE plan = 'pro';", " and send me the list?", carrier="prose",
        ),
        dp(
            "dlp.content.sql", "en", "dlp_sql_statement",
            "", "-- weekly cleanup\nDELETE FROM audit_log\nWHERE created_at < now() - interval '90 days';", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.sql", "en", "dlp_sql_statement",
            "Migration notes:\n", "CREATE INDEX idx_orders_user ON orders (user_id);", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.sql", "en", "dlp_sql_multiline_statement",
            "cursor.execute(\"", "UPDATE users SET role = 'admin' WHERE id = %s;", "\", (user_id,))\n", carrier="code",
        ),
        dn("dlp.content.sql", "en", "dlp_sql_statement", "Please update the table in the wiki.", "natural language is not SQL", carrier="prose"),
        dn("dlp.content.sql", "en", "dlp_sql_statement", "Delete from the list anything older than a year", "natural language without a statement", carrier="prose"),
        dn("dlp.content.sql", "en", "dlp_sql_statement", "SQL tutorial: joins and filters", "topic title without a statement"),
        dn("dlp.content.sql", "en", "dlp_sql_multiline_statement", "Select a file from the dialog", "natural language is not SQL", carrier="prose"),
    ],
    "dlp.content.database_dump": [
        dp("dlp.content.database_dump", "en", "dlp_database_dump_header", "", "-- PostgreSQL database dump"),
        dp("dlp.content.database_dump", "de", "dlp_database_dump_insert", "", "INSERT INTO kunden VALUES (1, 'Ada');"),
        dp("dlp.content.database_dump", "en", "dlp_database_dump_header", "", "PRAGMA foreign_keys = ON;"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "Datenbankexport wurde abgeschlossen.", "natural language is not a dump"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_insert", "INSERT the row into the table", "prose lacks SQL dump syntax"),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_header",
            "--\n", "-- MySQL database dump", "\n--\n-- Host: db.intern    Datenbank: shop\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_insert",
            "-- Auszug aus dem Export\n", "INSERT INTO bestellungen (id, kunde, summe) VALUES (17, 'Beispiel', 99.5);", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_header",
            "Hier der Anfang der Sicherung:\n", "CREATE TABLE mitarbeiter (\n  id INTEGER PRIMARY KEY,\n  gehalt INTEGER\n);", "\n",
            carrier="prose",
        ),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_insert",
            "Im Anhang steht zum Beispiel\n", "INSERT INTO patienten VALUES (4, 'Muster', '1980-02-01');", "\n", carrier="prose",
        ),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "$ pg_dump --schema-only shop > schema.sql", "dump command, not dump content", carrier="cli"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_insert", "Die Insert-Taste ist kaputt.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "Die Sicherung der Datenbank läuft jede Nacht.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "Tabellen werden mit CREATE TABLE angelegt.", "prose mentioning a keyword", carrier="prose"),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_header",
            "--\n", "-- MariaDB database dump", "\n--\n-- Host: localhost    Database: crm\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_insert",
            "-- excerpt from the export\n", "INSERT INTO users (id, email) VALUES (42, 'ada@example.org');", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_header",
            "Here is the schema from the backup:\n", "CREATE TABLE payroll (\n  id INTEGER,\n  salary INTEGER\n);", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_header",
            "sqlite> .dump\n", "PRAGMA foreign_keys=OFF;", "\nBEGIN TRANSACTION;\n", carrier="cli",
        ),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_header", "$ mysqldump --no-data crm > schema.sql", "dump command, not dump content", carrier="cli"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_insert", "Press Insert to add a new row.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_header", "The nightly database dump finished in 4 minutes.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_header", "Tables are created with CREATE TABLE by the ORM.", "prose mentioning a keyword", carrier="prose"),
    ],
    "dlp.content.system_log": [
        dp("dlp.content.system_log", "en", "dlp_structured_system_log", "", "2026-08-30T10:15:00Z ERROR database connection failed"),
        dp("dlp.content.system_log", "de", "dlp_structured_system_log", "", "2026-08-30 10:15:00 CRITICAL Speicherlimit erreicht"),
        dp("dlp.content.system_log", "en", "dlp_stacktrace_block", "", "Traceback (most recent call last):\n  File \"app.py\", line 4, in run"),
        dn("dlp.content.system_log", "de", "dlp_structured_system_log", "Der Fehler wurde gestern behoben.", "prose is not a structured log"),
        dn("dlp.content.system_log", "en", "dlp_structured_system_log", "2026-08-30 INFO service started", "non-sensitive INFO level is excluded"),
        dp(
            "dlp.content.system_log", "de", "dlp_structured_system_log",
            "Seit heute früh sehen wir das hier:\n", "2026-10-02 06:01:12 FEHLER Verbindung zur Kassen-DB abgebrochen", "\nWeiß jemand mehr?",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "de", "dlp_stacktrace_block",
            "Beim Export kommt:\n", "Exception in thread \"main\" java.lang.IllegalStateException: Kunde fehlt\n\tat de.beispiel.Export.run(Export.java:42)\n", "Danke!",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "de", "dlp_structured_system_log",
            "", "2026-10-02 06:01:12 ERROR Zahlungsdienst nicht erreichbar\n2026-10-02 06:01:13 ERROR Wiederholung fehlgeschlagen", "\n",
            carrier="log",
        ),
        dp(
            "dlp.content.system_log", "de", "dlp_stacktrace_block",
            "", "Traceback (most recent call last):\n  File \"/srv/abrechnung/job.py\", line 88, in main\n", "KeyError: 'kundennummer'\n",
            carrier="log",
        ),
        dn("dlp.content.system_log", "de", "dlp_structured_system_log", "2026-10-02 06:00:00 INFO Dienst gestartet", "non-sensitive INFO level is excluded", carrier="log"),
        dn("dlp.content.system_log", "de", "dlp_structured_system_log", "2026-10-02 06:00:00 WARN Festplatte zu 80 % voll", "WARN level is excluded", carrier="log"),
        dn("dlp.content.system_log", "de", "dlp_stacktrace_block", "Im Log steht ein Fehler, ich schaue morgen nach.", "prose about logs", carrier="prose"),
        dn("dlp.content.system_log", "de", "dlp_stacktrace_block", "Fehlerbehandlung ist im Handbuch beschrieben.", "prose with a log keyword", carrier="prose"),
        dp(
            "dlp.content.system_log", "en", "dlp_structured_system_log",
            "We keep seeing this since the deploy:\n", "2026-10-02T06:01:12Z FATAL payment worker crashed", "\nAny ideas?",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "en", "dlp_stacktrace_block",
            "The export fails with\n", "Exception in thread \"main\" java.lang.NullPointerException\n\tat com.example.Export.run(Export.java:17)\n", "Thanks!",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "en", "dlp_structured_system_log",
            "", "2026-10-02 06:01:12 ERROR billing queue unavailable\n2026-10-02 06:01:13 ERROR retry failed", "\n",
            carrier="log",
        ),
        dp(
            "dlp.content.system_log", "en", "dlp_stacktrace_block",
            "", "Traceback (most recent call last):\n  File \"/srv/billing/job.py\", line 12, in main\n", "ValueError: bad row\n",
            carrier="log",
        ),
        dn("dlp.content.system_log", "en", "dlp_structured_system_log", "2026-10-02 06:00:00 DEBUG cache warmed", "DEBUG level is excluded", carrier="log"),
        dn("dlp.content.system_log", "en", "dlp_structured_system_log", "2026-10-02 06:00:00 WARN disk 80% full", "WARN level is excluded", carrier="log"),
        dn("dlp.content.system_log", "en", "dlp_stacktrace_block", "There was an error in the log, I will check tomorrow.", "prose about logs", carrier="prose"),
        dn("dlp.content.system_log", "en", "dlp_stacktrace_block", "Error handling is described in the manual.", "prose with a log keyword", carrier="prose"),
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


def serialize(row: dict) -> str:
    """One JSONL line. The placeholder colon is written as the JSON escape ``\\u003a``.

    In the raw file a placeholder followed by more text (``<<secret:0>>\\nregion``)
    otherwise reads as ``secret: <value>`` to generic credential scanners.
    """
    line = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
    return line.replace("<<secret:", "<<secret\\u003a")


def write(name: str, rows: list[dict]) -> None:
    path = DATA_DIR / f"{name}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(serialize(row) + "\n")


if __name__ == "__main__":
    write("pii_l1", flatten("pii_l1", PII_CASES))
    write("dlp_l1", flatten("dlp_l1", DLP_CASES))
