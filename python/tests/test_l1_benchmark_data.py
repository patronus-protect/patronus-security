import json
import re
import runpy
import unittest
from collections import Counter

from patronus_ark import benchmark
from patronus_ark.dlp_synth import recipes


PII_LABELS = {
    "APPLICANT_ID",
    "AT_SOCIAL_SECURITY_NUMBER",
    "COMMERCIAL_REGISTER_DE",
    "AU_ABN",
    "AU_ACN",
    "AU_MEDICARE",
    "AU_TFN",
    "BE_NATIONAL_NUMBER",
    "CA_SIN",
    "CH_AHV_NUMBER",
    "CREDITCARD",
    "CREDITCARD_CVV",
    "CREDITCARD_EXPIRY",
    "CUSTOMER_ID",
    "DOB",
    "DK_CPR",
    "DRIVER_LICENSE_NUMBER",
    "EMAIL",
    "EMPLOYEE_ID",
    "ES_NIE",
    "ES_NIF",
    "FACILITY_NUMBER_BSNR",
    "FI_PERSONAL_IDENTITY_CODE",
    "FINANCIAL_ACCOUNT_NUMBER",
    "FR_NIR",
    "FR_SIREN",
    "FR_SIRET",
    "HEALTH_INSURANCE_NUMBER",
    "IBAN",
    "IDENTITY_CARD_NUMBER",
    "IP_ADDRESS",
    "IT_FISCAL_CODE",
    "LICENSEPLATE",
    "MAC_ADDRESS",
    "NATIONALID",
    "NHS_NUMBER",
    "NO_FODSELSNUMMER",
    "NL_BSN",
    "PASSPORT_NUMBER",
    "PATIENT_ID",
    "IE_PPSN",
    "IN_AADHAAR",
    "IN_GSTIN",
    "IN_PAN",
    "IN_VOTER",
    "MEDICAL_LICENSE",
    "US_NPI",
    "IMEI",
    "MEID",
    "ICCID",
    "IMSI",
    "VIN",
    "ISIN",
    "LEI",
    "DE_PZN",
    "KR_BRN",
    "KR_FRN",
    "KR_RRN",
    "PHONE",
    "PL_PESEL",
    "PL_REGON",
    "PHYSICIAN_NUMBER_LANR",
    "PT_NIF",
    "SE_ORGANISATIONSNUMMER",
    "SE_PERSONNUMMER",
    "SG_NRIC_FIN",
    "SG_UEN",
    "SOCIALID",
    "SSN",
    "STEUERID",
    "STUDENT_ID",
    "SWIFT_CODE",
    "TAX_NUMBER_DE",
    "TR_NATIONAL_ID",
    "USERNAME",
    "VAT_ID_AT",
    "VAT_ID_BE",
    "VAT_ID_BG",
    "VAT_ID_CH",
    "VAT_ID_CY",
    "VAT_ID_CZ",
    "VAT_ID_DE",
    "VAT_ID_DK",
    "VAT_ID_EE",
    "VAT_ID_EL",
    "VAT_ID_ES",
    "VAT_ID_FI",
    "VAT_ID_FR",
    "VAT_ID_GB",
    "VAT_ID_HR",
    "VAT_ID_HU",
    "VAT_ID_IE",
    "VAT_ID_IT",
    "VAT_ID_LT",
    "VAT_ID_LU",
    "VAT_ID_LV",
    "VAT_ID_MT",
    "VAT_ID_NL",
    "VAT_ID_NO",
    "VAT_ID_PL",
    "VAT_ID_PT",
    "VAT_ID_RO",
    "VAT_ID_SE",
    "VAT_ID_SI",
    "VAT_ID_SK",
    "ZA_ID_NUMBER",
}
# Languages of pii_l1: DE/EN, the FR/ES/IT/NL field names (T26) and the national languages of
# country IDs (B-LUHN, B-EU2, B-KR, A13), whose rows only target the IDs of their country.
NATIONAL_LANGUAGES = {"sv": "SE_", "tr": "TR_", "pt": "PT_", "ko": "KR_", "pl": "PL_"}
PII_LANGUAGES = {"de", "en", "fr", "es", "it", "nl", *NATIONAL_LANGUAGES}

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
# A local part may hold apostrophes between its characters (`o'neil`, B-EMAIL).
PLACEHOLDER_EMAIL = re.compile(
    r"(?<![\w.+'-])[\w.+-]+(?:'[\w.+-]+)*@(?:[\w-]+\.)*"
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

    def test_every_native_pii_label_has_n_gated_cases_per_language(self):
        # Golden schema v2 (E10): known gaps are reported, not gated, so they do not count.
        rows = load("pii_l1")
        self.assertEqual({row["target_label"] for row in rows}, PII_LABELS)
        counts = Counter(
            (row["target_label"], row["language"], row["case_type"])
            for row in rows
            if not row["known_gap"]
        )
        for label in PII_LABELS:
            for language in ("de", "en"):
                for case_type in ("positive", "hard_negative"):
                    self.assertGreaterEqual(
                        counts[(label, language, case_type)], 5, (label, language, case_type)
                    )

    def test_fr_es_it_nl_field_names_have_n_gated_cases_per_language(self):
        # T26: the anchor rules accept FR/ES/IT/NL field names; each language has at least
        # five gated positives and five hard negatives.
        counts = Counter(
            (row["language"], row["case_type"]) for row in load("pii_l1") if not row["known_gap"]
        )
        for language in ("fr", "es", "it", "nl"):
            for case_type in ("positive", "hard_negative"):
                self.assertGreaterEqual(counts[(language, case_type)], 5, (language, case_type))

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
                # pii_l1 also carries FR/ES/IT/NL field names of the anchor rules (T26) and
                # Swedish, Turkish, Portuguese, Korean and Polish rows of the country IDs (B-LUHN,
                # B-EU2, B-KR, A13).
                languages = PII_LANGUAGES if name == "pii_l1" else {"de", "en"}
                self.assertIn(row["language"], languages, row["id"])
                if row["language"] in NATIONAL_LANGUAGES:
                    self.assertTrue(
                        row["target_label"].startswith(NATIONAL_LANGUAGES[row["language"]]), row["id"]
                    )
                self.assertEqual(row["span_unit"], "unicode_code_point", row["id"])
                self.assertIn(row["provenance"]["origin"], {"synthetic", "derived_existing_fixture"})
                if row["case_type"] == "positive":
                    # A split secret has one entity per fragment; everything else has one
                    # target entity plus every other real entity in the text (T02).
                    targets = [e for e in row["entities"] if e["label"] == row["target_label"]]
                    if "template" in row:
                        self.assertEqual(targets, row["entities"], row["id"])
                        self.assertGreaterEqual(len(targets), 1, row["id"])
                    else:
                        self.assertEqual(len(targets), 1, row["id"])
                    starts = [entity["start"] for entity in row["entities"]]
                    self.assertEqual(starts, sorted(starts), row["id"])
                    for entity, materialized_entity in zip(row["entities"], materialized["entities"]):
                        self.assertEqual(
                            materialized["text"][entity["start"] : entity["end"]],
                            materialized_entity["text"],
                            row["id"],
                        )
                else:
                    # A hard negative may annotate other real entities in its text (T07: the
                    # valid IBAN around a card-shaped BBAN), never one of its target label.
                    self.assertEqual(row["case_type"], "hard_negative", row["id"])
                    self.assertTrue(row["negative_reason"].strip(), row["id"])
                    self.assertNotIn(row["target_label"], {e["label"] for e in row["entities"]}, row["id"])
                    if row["entities"]:
                        self.assertEqual(name, "pii_l1", row["id"])
                    starts = [entity["start"] for entity in row["entities"]]
                    self.assertEqual(starts, sorted(starts), row["id"])
                    for entity in row["entities"]:
                        self.assertEqual(row["text"][entity["start"] : entity["end"]], entity["text"], row["id"])

    def test_language_distribution_is_broad(self):
        # Shape, not exact totals: every new golden row used to change hard-coded counts here, so
        # concurrent PII and DLP changes conflicted in this test on every merge.
        for name in ("pii_l1", "dlp_l1"):
            counts = Counter(row["language"] for row in load(name))
            self.assertGreaterEqual(counts["de"], 100, name)
            self.assertGreaterEqual(counts["en"], 100, name)
            # Neither of the two main languages may fall far behind the other.
            self.assertLessEqual(max(counts["de"], counts["en"]) / min(counts["de"], counts["en"]), 1.25, name)
        pii = Counter(row["language"] for row in load("pii_l1"))
        for language in ("fr", "es", "it", "nl"):
            self.assertGreaterEqual(pii[language], 16, language)
        self.assertLessEqual(set(pii), PII_LANGUAGES)

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
            expected_value = next(
                entity["text"] for entity in row["entities"] if entity["label"] == row["target_label"]
            )
            self.assertIn(
                expected_value,
                {entity["text"] for entity in dynamic_rows[source_id]["entities"]},
                row["id"],
            )


class SecondaryEntityGoldTests(unittest.TestCase):
    """T02: a positive annotates every real entity in its text, not only the target."""

    def test_card_numbers_next_to_cvv_and_expiry_are_gold(self):
        card = re.compile(r"(?<!\d)\d{4}(?: ?\d{4,6}){2,3}(?!\d)|(?<!\d)\d{15,16}(?!\d)")
        annotated = 0
        for row in load("pii_l1"):
            if row["case_type"] != "positive" or row["target_label"] not in {
                "CREDITCARD_CVV",
                "CREDITCARD_EXPIRY",
            }:
                continue
            gold = {(e["start"], e["end"]) for e in row["entities"] if e["label"] == "CREDITCARD"}
            for match in card.finditer(row["text"]):
                self.assertIn(match.span(), gold, (row["id"], match.group()))
                annotated += 1
        self.assertGreaterEqual(annotated, 19)

    def test_known_secondary_entities_are_annotated(self):
        rows = {row["id"]: row for row in load("pii_l1")}
        for row_id, label, value in (
            ("pii_l1-email-pos-01", "PHONE", "+76-532-1520"),
            ("pii_l1-swift-code-pos-06", "IBAN", "DE89370400440532013000"),
        ):
            self.assertIn(
                (label, value),
                {(entity["label"], entity["text"]) for entity in rows[row_id]["entities"]},
                row_id,
            )

    def test_t07_hard_negatives_annotate_the_iban_that_carries_the_lookalike(self):
        # The card-shaped BBAN inside a valid IBAN and an account finding on an IBAN value are
        # secondary evidence in strict (T07); the IBAN itself is gold.
        annotated = Counter()
        for row in load("pii_l1"):
            if row["case_type"] != "hard_negative" or not row["entities"]:
                continue
            if row["target_label"] == "CREDITCARD_CVV":
                # T26: a non-card security code next to a real card annotates that card.
                self.assertEqual([e["label"] for e in row["entities"]], ["CREDITCARD"], row["id"])
                continue
            if [e["label"] for e in row["entities"]] == ["ZA_ID_NUMBER"]:
                # B-LUHN: thirteen digits that open with a birth date are a South African ID
                # number, no card.
                self.assertEqual(row["target_label"], "CREDITCARD", row["id"])
                annotated[("ZA_ID_NUMBER", row["language"])] += 1
                continue
            if [e["label"] for e in row["entities"]] == ["KR_RRN"]:
                # B-KR: thirteen digits `YYMMDD-GHHSSSC` next to a resident registration term
                # are a Korean RRN, no card.
                self.assertEqual(row["target_label"], "CREDITCARD", row["id"])
                annotated[("KR_RRN", row["language"])] += 1
                continue
            if [e["label"] for e in row["entities"]] == ["VAT_ID_PT"]:
                # B-EU2: nine digits after `PT ` are the body of a Portuguese VAT ID, no NIF.
                self.assertEqual(row["target_label"], "PT_NIF", row["id"])
                self.assertTrue(row["entities"][0]["text"].startswith("PT "), row["id"])
                annotated[("VAT_ID_PT", row["language"])] += 1
                continue
            if [e["label"] for e in row["entities"]] == ["PHONE"]:
                # B-PAN: the Luhn-valid digits after the `+` of a phone number are no card.
                self.assertEqual(row["target_label"], "CREDITCARD", row["id"])
                self.assertTrue(row["entities"][0]["text"].startswith("+"), row["id"])
                annotated[("PHONE", row["language"])] += 1
                continue
            if [e["label"] for e in row["entities"]] == ["IN_PAN"]:
                # B-IN: an Indian PAN after `Permanent Account Number` is no bank account.
                self.assertEqual(row["target_label"], "FINANCIAL_ACCOUNT_NUMBER", row["id"])
                continue
            if row["target_label"] in {"PASSPORT_NUMBER", "IDENTITY_CARD_NUMBER"}:
                # F08: the field name of another label wins over a bare document check digit.
                [entity] = row["entities"]
                self.assertIn(entity["label"], {"CUSTOMER_ID", "PASSPORT_NUMBER"}, row["id"])
                self.assertNotEqual(entity["label"], row["target_label"], row["id"])
                self.assertEqual(row["pii_mode"], "balanced", row["id"])
                annotated[(row["target_label"], row["language"])] += 1
                continue
            self.assertEqual([e["label"] for e in row["entities"]], ["IBAN"], row["id"])
            self.assertIn(row["target_label"], {"CREDITCARD", "FINANCIAL_ACCOUNT_NUMBER"}, row["id"])
            self.assertNotIn("pii_mode", row, row["id"])
            annotated[(row["target_label"], row["language"])] += 1
        self.assertEqual(
            annotated,
            {
                ("CREDITCARD", "de"): 3,
                ("CREDITCARD", "en"): 3,
                ("FINANCIAL_ACCOUNT_NUMBER", "de"): 3,
                ("FINANCIAL_ACCOUNT_NUMBER", "en"): 3,
                ("PHONE", "de"): 3,
                ("PHONE", "en"): 3,
                ("PASSPORT_NUMBER", "de"): 1,
                ("IDENTITY_CARD_NUMBER", "en"): 1,
                ("ZA_ID_NUMBER", "de"): 3,
                ("ZA_ID_NUMBER", "en"): 3,
                ("VAT_ID_PT", "en"): 1,
                ("KR_RRN", "de"): 2,
                ("KR_RRN", "en"): 2,
            },
        )

    def test_generator_rejects_hard_negatives_that_annotate_their_target(self):
        namespace = runpy.run_path(str(benchmark.DATA_DIR / "generate_l1_goldens.py"))
        n = namespace["n"]
        with self.assertRaises(ValueError):
            n("CREDITCARD", "en", "pii_credit_card", "Card 4111 1111 1111 1111", "x", also=(("CREDITCARD", "4111 1111 1111 1111"),))
        with self.assertRaises(ValueError):
            n("CREDITCARD", "en", "pii_credit_card", "IBAN DE89370400440532013000", "x", also=(("IBAN", "DE00000000000000000000"),))

    def test_generator_rejects_ambiguous_secondary_values(self):
        namespace = runpy.run_path(str(benchmark.DATA_DIR / "generate_l1_goldens.py"))
        p = namespace["p"]
        with self.assertRaises(ValueError):
            p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Card 4111 1111 1111 1111, CVV ", "123", also=(("CREDITCARD", "4012 8888 8888 1881"),))
        with self.assertRaises(ValueError):
            p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "4111 1111 1111 1111 or 4111 1111 1111 1111, CVV ", "123", also=(("CREDITCARD", "4111 1111 1111 1111"),))


class DynamicPiiChecksumGoldTests(unittest.TestCase):
    def test_only_checksum_invalid_card_and_health_insurance_numbers_are_marked(self):
        # The validity of each marked value is checked against the Rust validator (Luhn,
        # KVNR since B-DE1) in rust/examples/12_l1_pii_fixture_eval.rs; the L1 evaluation
        # skips marked spans.
        marked = [
            entity
            for row in load("dynamic_pii")
            for entity in row["entities"]
            if "checksum_valid" in entity
        ]
        self.assertEqual(
            sorted(entity["label"] for entity in marked),
            ["credit_card"] * 7 + ["health_insurance_number"],
        )
        for entity in marked:
            self.assertIs(entity["checksum_valid"], False)


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
