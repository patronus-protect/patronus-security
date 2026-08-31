import json
import runpy
import unittest
from collections import Counter

from patronus_ark import benchmark


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

    def test_every_native_label_has_three_positives_and_two_hard_negatives(self):
        for name, labels in (("pii_l1", PII_LABELS), ("dlp_l1", DLP_LABELS)):
            rows = load(name)
            self.assertEqual({row["target_label"] for row in rows}, labels)
            counts = Counter((row["target_label"], row["case_type"]) for row in rows)
            for label in labels:
                self.assertEqual(counts[(label, "positive")], 3, (name, label))
                self.assertEqual(counts[(label, "hard_negative")], 2, (name, label))

    def test_ids_schema_and_unicode_character_spans_are_exact(self):
        for name in ("pii_l1", "dlp_l1"):
            rows = load(name)
            self.assertEqual(len({row["id"] for row in rows}), len(rows))
            for row in rows:
                self.assertEqual(row["suite"], name, row["id"])
                self.assertIn(row["language"], {"de", "en"}, row["id"])
                self.assertEqual(row["span_unit"], "unicode_code_point", row["id"])
                self.assertIn(row["provenance"]["origin"], {"synthetic", "derived_existing_fixture"})
                if row["case_type"] == "positive":
                    self.assertEqual(len(row["entities"]), 1, row["id"])
                    entity = row["entities"][0]
                    self.assertEqual(entity["label"], row["target_label"], row["id"])
                    self.assertEqual(
                        row["text"][entity["start"] : entity["end"]],
                        entity["text"],
                        row["id"],
                    )
                else:
                    self.assertEqual(row["case_type"], "hard_negative", row["id"])
                    self.assertEqual(row["entities"], [], row["id"])
                    self.assertTrue(row["negative_reason"].strip(), row["id"])

    def test_language_distribution_is_broad(self):
        expected = {
            "pii_l1": {"de": 74, "en": 66},
            "dlp_l1": {"de": 57, "en": 58},
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


if __name__ == "__main__":
    unittest.main()
