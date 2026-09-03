import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "evaluate_internal_pii_spans.py"
SPEC = importlib.util.spec_from_file_location("internal_pii_eval", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


FIXTURES = Path(__file__).parents[1] / "fixtures"


class InternalPiiSpanEvaluationTests(unittest.TestCase):
    def test_metrics_are_exact_and_partitioned_by_corpus_entity_and_language(self):
        report = MODULE.evaluate(
            MODULE.jsonl_rows(FIXTURES / "internal_pii_span_eval_controlled.jsonl"),
            MODULE.jsonl_rows(FIXTURES / "internal_pii_span_predictions_controlled.jsonl"),
        )
        self.assertEqual(report["metric"], "exact_label_and_unicode_code_point_span")
        self.assertEqual(report["slices"]["overall"], {
            "true_positives": 2, "false_positives": 1, "false_negatives": 0,
            "precision": 0.666667, "recall": 1.0, "f1": 0.8,
        })
        self.assertEqual(report["slices"]["entity/EMAIL"]["false_positives"], 1)
        self.assertEqual(report["slices"]["language/de"]["true_positives"], 1)
        self.assertEqual(report["slices"]["corpus/deidentified_hard_negative"]["false_positives"], 1)

    def test_document_labels_and_text_are_rejected_as_span_gold(self):
        row = {
            "id": "bad", "corpus": "private", "language": "de",
            "document_sha256": "a" * 64, "annotation_kind": "verified_no_pii",
            "entities": [], "expected_class": "medical",
        }
        with self.assertRaisesRegex(ValueError, "forbidden"):
            MODULE.validate_gold(row)

    def test_entity_buckets_do_not_mix_errors_from_other_labels(self):
        gold = [{
            "id": "mixed", "corpus": "private", "language": "de",
            "document_sha256": "a" * 64, "annotation_kind": "verified_span",
            "entities": [
                {"label": "EMAIL", "start": 0, "end": 4},
                {"label": "STUDENT_ID", "start": 5, "end": 9},
            ],
        }]
        predictions = [{"id": "mixed", "entities": [
            {"label": "EMAIL", "start": 0, "end": 4},
            {"label": "STUDENT_ID", "start": 6, "end": 9},
        ]}]
        slices = MODULE.evaluate(gold, predictions)["slices"]
        self.assertEqual(slices["entity/EMAIL"], {
            "true_positives": 1, "false_positives": 0, "false_negatives": 0,
            "precision": 1.0, "recall": 1.0, "f1": 1.0,
        })
        self.assertEqual(slices["entity/STUDENT_ID"]["false_positives"], 1)
        self.assertEqual(slices["entity/STUDENT_ID"]["false_negatives"], 1)

    def test_sampling_emits_hashes_and_never_document_text(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "private.jsonl"
            output = Path(directory) / "manifest.jsonl"
            source.write_text('{"id":"private-1","text":"do not export this"}\n', encoding="utf-8")
            result = MODULE.sample_manifest(source, output, "sensitive_current", 1, "test", "text")
            row = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["sampled"], 1)
        self.assertNotIn("text", row)
        self.assertEqual(row["review_role"], "requires_human_span_annotation")

    def test_sampling_rejects_duplicate_private_source_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "private.jsonl"
            output = Path(directory) / "manifest.jsonl"
            source.write_text(
                '{"id":"private-1","text":"first"}\n'
                '{"id":"private-1","text":"second"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                MODULE.sample_manifest(source, output, "sensitive_current", 2, "test", "text")


if __name__ == "__main__":
    unittest.main()
