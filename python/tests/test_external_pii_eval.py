import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from patronus_ark import external_pii_eval


class ExternalPiiEvalTests(unittest.TestCase):
    def test_fixture_normalizes_to_stable_ark_ids(self):
        path = external_pii_eval.DATA_DIR / "fixtures" / "ai4privacy-openpii-nano.jsonl"
        rows = external_pii_eval.normalize_file(path, "ai4privacy-openpii-nano-1k")
        self.assertEqual(rows[0]["entities"], [
            {"entity_type": "pii.email", "start": 6, "end": 22},
            {"entity_type": "pii.phone", "start": 32, "end": 47},
        ])
        self.assertEqual(rows[1]["entities"], [{"entity_type": "pii.iban", "start": 6, "end": 28}])

    def test_tab_fixture_unions_annotators_and_applies_privacy_mask_scope(self):
        path = external_pii_eval.DATA_DIR / "fixtures" / "tab-standoff.json"
        rows = external_pii_eval.normalize_file(path, "tab")
        self.assertEqual(rows[0]["entities"], [
            {"entity_type": "entity.person_name", "start": 0, "end": 11},
            {"entity_type": "entity.organization", "start": 16, "end": 28},
            {"entity_type": "entity.date", "start": 42, "end": 52},
        ])

    def test_exact_metrics_are_separated_by_corpus_entity_and_language(self):
        rows = [
            {"corpus": "openpii", "language": "en", "entities": [{"entity_type": "pii.email", "start": 0, "end": 3}], "predicted_entities": [{"entity_type": "pii.email", "start": 0, "end": 3}]},
            {"corpus": "openpii", "language": "de", "entities": [{"entity_type": "pii.email", "start": 0, "end": 3}], "predicted_entities": [{"entity_type": "pii.email", "start": 1, "end": 3}]},
            {"corpus": "tab", "language": "en", "entities": [], "predicted_entities": [{"entity_type": "entity.person_name", "start": 0, "end": 4}]},
        ]
        report = external_pii_eval.exact_span_metrics(rows)
        self.assertEqual(report["overall"]["true_positives"], 1)
        self.assertEqual(report["overall"]["false_positives"], 2)
        self.assertEqual(report["overall"]["false_negatives"], 1)
        self.assertEqual(report["per_scope"]["native_pii"]["f1"], 0.5)
        self.assertEqual(
            report["per_scope"]["semantic_entity"]["false_positives"], 1
        )
        self.assertEqual(report["per_corpus"]["openpii"]["per_entity"]["pii.email"]["f1"], 0.5)
        self.assertEqual(report["per_corpus"]["openpii"]["per_language"]["de"]["overall"]["recall"], 0.0)
        self.assertEqual(
            report["per_corpus"]["openpii"]["per_language"]["de"]["per_scope"]["native_pii"]["recall"],
            0.0,
        )
        self.assertEqual(report["per_corpus"]["tab"]["per_entity"]["entity.person_name"]["false_positives"], 1)

    def test_invalid_offsets_are_rejected_and_unknown_labels_are_out_of_scope(self):
        corpus = external_pii_eval.load_manifest()["ai4privacy-openpii-nano-1k"]
        with self.assertRaisesRegex(ValueError, "outside text"):
            external_pii_eval.normalize_row({"text": "Ada", "entities": [{"label": "EMAIL_ADDRESS", "start": 0, "end": 4}]}, corpus)
        row = external_pii_eval.normalize_row({"text": "Ada", "entities": [{"label": "UNSUPPORTED", "start": 0, "end": 3}]}, corpus)
        self.assertEqual(row["entities"], [])

    def test_openpii_value_must_match_the_annotated_offsets(self):
        corpus = external_pii_eval.load_manifest()["ai4privacy-openpii-nano-1k"]
        with self.assertRaisesRegex(ValueError, "value/offset mismatch"):
            external_pii_eval.normalize_openpii_row(
                {
                    "uid": "broken",
                    "language": "en",
                    "source_text": "Ada",
                    "privacy_mask": [
                        {"label": "GIVENNAME", "start": 0, "end": 3, "value": "Eve"}
                    ],
                },
                corpus,
            )

    def test_gretel_row_parses_json_spans_and_normalizes_language(self):
        corpus = external_pii_eval.load_manifest()["gretel-synthetic-pii-finance"]
        row = external_pii_eval.normalize_gretel_row(
            {
                "language": "German",
                "expanded_type": "Bank transfer template",
                "generated_text": "IBAN: DE89370400440532013000",
                "pii_spans": '[{"label": "iban", "start": 6, "end": 28}]',
            },
            corpus,
            "German_test-00000-of-00001.parquet:0",
        )
        self.assertEqual(row["language"], "de")
        self.assertEqual(row["group_id"], "Bank transfer template")
        self.assertEqual(row["entities"], [{"entity_type": "pii.iban", "start": 6, "end": 28}])

    def test_gretel_row_rejects_invalid_offset_and_unknown_language(self):
        corpus = external_pii_eval.load_manifest()["gretel-synthetic-pii-finance"]
        with self.assertRaisesRegex(ValueError, "outside text"):
            external_pii_eval.normalize_gretel_row(
                {"language": "English", "generated_text": "Ada", "pii_spans": '[{"label": "email", "start": 0, "end": 4}]'},
                corpus,
                "test:0",
            )
        with self.assertRaisesRegex(ValueError, "unsupported Gretel language"):
            external_pii_eval.normalize_gretel_row(
                {"language": "Klingon", "generated_text": "Ada", "pii_spans": "[]"}, corpus, "test:0"
            )

    def test_manifest_label_map_is_case_insensitive(self):
        corpus = {
            "id": "custom",
            "default_language": "en",
            "label_map": {"UPSTREAM_PERSON": "entity.person_name"},
        }
        row = external_pii_eval.normalize_row(
            {
                "id": "custom-1",
                "text": "Ada",
                "entities": [{"label": "upstream_person", "start": 0, "end": 3}],
            },
            corpus,
        )
        self.assertEqual(
            row["entities"],
            [{"entity_type": "entity.person_name", "start": 0, "end": 3}],
        )

    def test_ark_evidence_spans_attach_by_id_and_use_ark_output_ids(self):
        gold = [{"id": "request-1", "corpus": "openpii", "language": "en", "entities": [{"entity_type": "pii.email", "start": 0, "end": 3}]}]
        rows = external_pii_eval.attach_ark_predictions(gold, [{"id": "request-1", "evidence_spans": [{"label": "EMAIL", "start_char": 0, "end_char": 3}]}])
        self.assertEqual(rows[0]["predicted_entities"], [{"entity_type": "pii.email", "start": 0, "end": 3}])

    def test_predictions_are_complete_unique_and_known(self):
        gold = [{"id": "request-1", "corpus": "openpii", "language": "en", "entities": []}]
        with self.assertRaisesRegex(ValueError, "missing"):
            external_pii_eval.attach_ark_predictions(gold, [])
        with self.assertRaisesRegex(ValueError, "unknown"):
            external_pii_eval.attach_ark_predictions(gold, [{"id": "other", "evidence_spans": []}])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            external_pii_eval.attach_ark_predictions(gold, [
                {"id": "request-1", "evidence_spans": []},
                {"id": "request-1", "evidence_spans": []},
            ])

    def test_predictions_outside_the_corpus_ontology_are_not_false_positives(self):
        gold = [{
            "id": "request-1",
            "corpus": "ai4privacy-openpii-nano-1k",
            "language": "en",
            "entities": [],
        }]
        rows = external_pii_eval.attach_ark_predictions(gold, [{
            "id": "request-1",
            "evidence_spans": [
                {"label": "IP_ADDRESS", "start_char": 0, "end_char": 7},
                {"label": "EMAIL", "start_char": 8, "end_char": 20},
            ],
        }])
        self.assertEqual(
            rows[0]["predicted_entities"],
            [{"entity_type": "pii.email", "start": 8, "end": 20}],
        )

    def test_dlp_spans_have_their_own_metric_scope(self):
        rows = [{
            "corpus": "gretel", "language": "en",
            "entities": [{"entity_type": "dlp.api_key", "start": 0, "end": 8}],
            "predicted_entities": [{"entity_type": "dlp.api_key", "start": 0, "end": 8}],
        }]
        report = external_pii_eval.exact_span_metrics(rows)
        self.assertEqual(report["per_scope"]["native_dlp"]["f1"], 1.0)

    def test_capped_selection_is_deterministic_group_atomic_and_text_free(self):
        rows = [
            {
                "id": "document-a", "group_id": "template-a", "corpus": "fixture", "language": "en", "text": "ignored",
                "entities": [
                    {"entity_type": "pii.email", "start": 0, "end": 1},
                    {"entity_type": "pii.email", "start": 2, "end": 3},
                ],
            },
            {
                "id": "document-b", "group_id": "template-b", "corpus": "fixture", "language": "en", "text": "ignored",
                "entities": [{"entity_type": "pii.email", "start": 0, "end": 1}],
            },
            {
                "id": "document-c", "group_id": "template-c", "corpus": "fixture", "language": "en", "text": "ignored",
                "entities": [{"entity_type": "pii.phone", "start": 0, "end": 1}],
            },
        ]
        first = external_pii_eval.capped_selection_manifest(rows, "fixture", "revision-1", "seed-1", cap=2)
        second = external_pii_eval.capped_selection_manifest(list(reversed(rows)), "fixture", "revision-1", "seed-1", cap=2)
        self.assertEqual(first, second)
        self.assertNotIn("ignored", json.dumps(first))
        email = next(item for item in first["selections"] if item["metric_id"] == "pii.email")
        self.assertLessEqual(email["selected_span_count"], 2)
        selected_by_group = {}
        for span in email["selected_spans"]:
            selected_by_group[span["group_id"]] = selected_by_group.get(span["group_id"], 0) + 1
        self.assertEqual(selected_by_group.get("template-a", 0), 2 if "template-a" in selected_by_group else 0)

    def test_ssn_runtime_label_uses_the_canonical_metric_id(self):
        self.assertEqual(
            external_pii_eval.ARK_OUTPUT_MAP["SSN"], "pii.us.social_security_number"
        )

    def test_cli_normalize_writes_jsonl(self):
        source = external_pii_eval.DATA_DIR / "fixtures" / "ai4privacy-openpii-nano.jsonl"
        with TemporaryDirectory() as directory:
            output = Path(directory) / "normalized.jsonl"
            external_pii_eval._write_jsonl(
                output,
                external_pii_eval.normalize_file(source, "ai4privacy-openpii-nano-1k"),
            )
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(
            [row["corpus"] for row in rows],
            ["ai4privacy-openpii-nano-1k", "ai4privacy-openpii-nano-1k"],
        )
