import json
import re
import runpy
import unittest
from collections import Counter

from patronus_ark import benchmark
from patronus_ark.dlp_synth import recipes


PII_LABELS = {
    "APPLICANT_ID",
    "CREDITCARD",
    "CREDITCARD_CVV",
    "CREDITCARD_EXPIRY",
    "CUSTOMER_ID",
    "DOB",
    "DRIVER_LICENSE_NUMBER",
    "EMAIL",
    "EMPLOYEE_ID",
    "FINANCIAL_ACCOUNT_NUMBER",
    "HEALTH_INSURANCE_NUMBER",
    "IBAN",
    "IDENTITY_CARD_NUMBER",
    "IP_ADDRESS",
    "LICENSEPLATE",
    "MAC_ADDRESS",
    "NATIONALID",
    "PASSPORT_NUMBER",
    "PATIENT_ID",
    "PHONE",
    "PHYSICIAN_NUMBER_LANR",
    "SOCIALID",
    "SSN",
    "STEUERID",
    "STUDENT_ID",
    "SWIFT_CODE",
    "TAX_NUMBER_DE",
    "USERNAME",
}

DLP_LABELS = {
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
    "dlp.content.database_dump",
    "dlp.content.source_code",
    "dlp.content.sql",
    "dlp.content.system_log",
    "dlp.de.commercial_register_number",
    "dlp.de.facility_number_bsnr",
    "dlp.de.vat_id",
    "dlp.internal.business_metric",
    "dlp.organization_id",
    "dlp.project_id",
    "dlp.record.case_id",
    "dlp.record.claim_id",
    "dlp.record.contract_id",
    "dlp.record.invoice_id",
    "dlp.record.order_id",
}


# Gold convention T01 (research/l1-pii/README.md): well-formed values on reserved
# placeholder domains (RFC 2606/6761) and NANP placeholder numbers are PII positives.
PLACEHOLDER_EMAIL = re.compile(
    r"(?<![\w.+-])[\w.+-]+@(?:[\w-]+\.)*"
    r"(?:example\.(?:com|net|org)|[\w-]+\.(?:example|invalid|localhost|test))(?![\w-]|\.\w)"
)
PLACEHOLDER_PHONE = re.compile(
    r"(?<![\w+])(?:\+1[ .-]?)?\(?[2-9]\d\d\)?[ .-]?555[ .-]?01\d\d(?!\d)"
    r"|\+1[ .-]?\(?000\)?[ .-]?000[ .-]?0000(?!\d)"
)
PLACEHOLDER_LABELS = {"EMAIL", "PHONE"}
DEMO_GOLDENS = ("demo_pii_dlp", "demo_pii_dlp_blind_de", "demo_pii_dlp_blind_en_tech")


def placeholder_spans(text):
    return [
        (match.start(), match.end())
        for pattern in (PLACEHOLDER_EMAIL, PLACEHOLDER_PHONE)
        for match in pattern.finditer(text)
    ]


def load(name):
    path = benchmark.DATA_DIR / f"{name}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class L1BenchmarkDataTests(unittest.TestCase):
    def test_checked_in_goldens_match_the_generator(self):
        namespace = runpy.run_path(
            str(benchmark.DATA_DIR / "generate_l1_goldens.py")
        )
        for name, cases_name in (
            ("pii_l1", "PII_CASES"),
            ("dlp_l1", "DLP_CASES"),
        ):
            expected = namespace["flatten"](name, namespace[cases_name])
            self.assertEqual(load(name), expected, name)

    def test_every_native_pii_label_has_three_positives_and_two_hard_negatives(self):
        rows = load("pii_l1")
        self.assertEqual({row["target_label"] for row in rows}, PII_LABELS)
        counts = Counter((row["target_label"], row["case_type"]) for row in rows)
        for label in PII_LABELS:
            self.assertEqual(counts[(label, "positive")], 3, label)
            self.assertEqual(counts[(label, "hard_negative")], 2, label)

    def test_every_native_dlp_label_has_n_gated_cases_per_language(self):
        # Golden schema v2 (E13): known gaps are reported, not gated, so they do not count.
        rows = load("dlp_l1")
        self.assertEqual({row["target_label"] for row in rows}, DLP_LABELS)
        counts = Counter(
            (row["target_label"], row["language"], row["case_type"])
            for row in rows
            if not row["known_gap"]
        )
        for label in DLP_LABELS:
            for language in ("de", "en"):
                for case_type in ("positive", "hard_negative"):
                    self.assertGreaterEqual(
                        counts[(label, language, case_type)], 5, (label, language, case_type)
                    )

    def test_ids_schema_and_unicode_character_spans_are_exact(self):
        for name in ("pii_l1", "dlp_l1"):
            rows = load(name)
            self.assertEqual(len({row["id"] for row in rows}), len(rows))
            for row in rows:
                materialized = recipes.materialize_row(row)
                self.assertEqual(row["suite"], name, row["id"])
                self.assertIn(row["language"], {"de", "en"}, row["id"])
                self.assertEqual(row["span_unit"], "unicode_code_point", row["id"])
                self.assertIn(row["provenance"]["origin"], {"synthetic", "derived_existing_fixture"})
                if row["case_type"] == "positive":
                    # A split secret has one entity per fragment; everything else has one.
                    if "template" in row:
                        self.assertGreaterEqual(len(row["entities"]), 1, row["id"])
                    else:
                        self.assertEqual(len(row["entities"]), 1, row["id"])
                    for entity, materialized_entity in zip(row["entities"], materialized["entities"]):
                        self.assertEqual(entity["label"], row["target_label"], row["id"])
                        self.assertEqual(
                            materialized["text"][entity["start"] : entity["end"]],
                            materialized_entity["text"],
                            row["id"],
                        )
                else:
                    self.assertEqual(row["case_type"], "hard_negative", row["id"])
                    self.assertEqual(row["entities"], [], row["id"])
                    self.assertTrue(row["negative_reason"].strip(), row["id"])

    def test_language_distribution_is_broad(self):
        expected = {
            "pii_l1": {"de": 74, "en": 66},
            "dlp_l1": {"de": 265, "en": 272},
        }
        for name, distribution in expected.items():
            self.assertEqual(Counter(row["language"] for row in load(name)), distribution)

    def test_derived_cases_point_to_existing_dynamic_pii_values(self):
        dynamic_rows = {row["id"]: row for row in load("dynamic_pii")}
        derived = [
            row
            for name in ("pii_l1", "dlp_l1")
            for row in load(name)
            if row["provenance"]["origin"] == "derived_existing_fixture"
        ]
        self.assertGreaterEqual(len(derived), 8)
        for row in derived:
            source_id = row["provenance"]["source_fixture_id"]
            self.assertIn(source_id, dynamic_rows, row["id"])
            expected_value = row["entities"][0]["text"]
            self.assertIn(
                expected_value,
                {entity["text"] for entity in dynamic_rows[source_id]["entities"]},
                row["id"],
            )


class PlaceholderGoldConventionTests(unittest.TestCase):
    def test_patterns_cover_reserved_values_only(self):
        for text in (
            "customer@example.com",
            "ops@mail.example.org",
            "mira.linden@kundenbeispiel.invalid",
            "priya.nwosu@example.test",
            "info@muster.example",
            "dev@app.localhost",
            "+1 000-000-0000",
            "+1 202-555-0148",
            "+1-415-555-0196",
            "(212) 555-0100",
        ):
            self.assertEqual(placeholder_spans(f"Kontakt: {text}."), [(9, 9 + len(text))], text)
        for text in (
            "anna.keller@example.de",
            "ops+alerts@example.co.uk",
            "anna.beispiel@localhost",
            "user [at] example [dot] com",
            "name @ domain . test",
            "(415) 555-2671",
            "030 555 01872",
            "+00 0000000",
        ):
            self.assertEqual(placeholder_spans(f"Kontakt: {text}."), [], text)

    def test_demo_goldens_label_placeholders_as_pii(self):
        found = 0
        for name in DEMO_GOLDENS:
            for row in load(name):
                gold = {
                    (row["text"].find(entity["text"]), row["text"].find(entity["text"]) + len(entity["text"]))
                    for entity in row["entities"]
                    if entity["pipeline"] == "pii" and entity["label"] in PLACEHOLDER_LABELS
                }
                for span in placeholder_spans(row["text"]):
                    found += 1
                    self.assertNotEqual(row["case_type"], "hard_negative", row["id"])
                    self.assertIn(span, gold, (row["id"], row["text"][span[0] : span[1]]))
        self.assertGreaterEqual(found, 15)

    def test_native_pii_goldens_label_placeholders_as_pii(self):
        for row in load("pii_l1"):
            gold = {
                (entity["start"], entity["end"])
                for entity in row["entities"]
                if entity["label"] in PLACEHOLDER_LABELS
            }
            for span in placeholder_spans(row["text"]):
                self.assertNotEqual(row["case_type"], "hard_negative", row["id"])
                self.assertIn(span, gold, (row["id"], row["text"][span[0] : span[1]]))

    def test_contact_hard_negatives_do_not_rely_on_reserved_names(self):
        for name in ("pii_l1", *DEMO_GOLDENS):
            for row in load(name):
                if row["case_type"] != "hard_negative":
                    continue
                self.assertNotRegex(row["text"], r"@localhost\b", row["id"])
                if row.get("target_label") in PLACEHOLDER_LABELS:
                    self.assertNotRegex(row["negative_reason"], r"(?i)placeholder|reserved", row["id"])


if __name__ == "__main__":
    unittest.main()
