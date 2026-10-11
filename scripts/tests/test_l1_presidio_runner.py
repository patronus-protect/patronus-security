from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "run_presidio.py"
SPEC = importlib.util.spec_from_file_location("run_presidio", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

sys.path.insert(0, str(ROOT / "python"))
from patronus_ark import external_pii_eval  # noqa: E402


def result(entity_type, start, end, score, recognizer="TestRecognizer"):
    return SimpleNamespace(
        entity_type=entity_type,
        start=start,
        end=end,
        score=score,
        recognition_metadata={"recognizer_name": recognizer},
    )


class FakeAnalyzer:
    """Records calls and returns canned Presidio-like results per text."""

    def __init__(self, results_by_text):
        self.results_by_text = results_by_text
        self.calls = []

    def analyze(self, *, text, language, score_threshold):
        self.calls.append((text, language, score_threshold))
        return list(self.results_by_text.get(text, []))


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def gold_rows():
    return [
        {
            "id": "en-1",
            "corpus": "ai4privacy-openpii-nano-1k",
            "language": "en",
            "text": "Mail ada@example.com or call 555",
            "entities": [{"entity_type": "pii.email", "start": 5, "end": 20}],
        },
        {
            "id": "de-1",
            "corpus": "ai4privacy-openpii-nano-1k",
            "language": "de",
            "text": "IBAN DE89370400440532013000",
            "entities": [{"entity_type": "pii.iban", "start": 5, "end": 27}],
        },
        {
            "id": "fr-1",
            "corpus": "ai4privacy-openpii-nano-1k",
            "language": "fr",
            "text": "Rien ici",
            "entities": [],
        },
    ]


def fake_results():
    return {
        "Mail ada@example.com or call 555": [
            result("PHONE_NUMBER", 29, 32, 0.4),
            result("EMAIL_ADDRESS", 5, 20, 1.0, "EmailRecognizer"),
        ],
        "IBAN DE89370400440532013000": [
            result("IBAN_CODE", 5, 27, 1.0, "IbanRecognizer"),
            result("DE_TAX_ID", 5, 16, 0.3),
        ],
    }


def test_both_profiles_are_checked_in_and_load():
    assert MODULE.PROFILES == ("default", "tuned")
    default = MODULE.load_profile("default")
    tuned = MODULE.load_profile("tuned")
    assert default["name"] == "default"
    assert default["presidio"] is None  # Presidio's own AnalyzerEngine() defaults
    assert default["languages"] == ["en"]
    assert tuned["name"] == "tuned"
    assert tuned["languages"] == ["en", "de"]
    models = {m["lang_code"]: m["model_name"] for m in tuned["presidio"]["nlp_configuration"]["models"]}
    assert models == {"en": "en_core_web_lg", "de": "de_core_news_lg"}
    names = {
        item if isinstance(item, str) else item["name"]
        for item in tuned["presidio"]["recognizer_registry"]["recognizers"]
    }
    assert {"DeTaxIdRecognizer", "DeIdCardRecognizer", "DePassportRecognizer"} <= names
    assert "context_enhancer" in tuned
    with pytest.raises(ValueError, match="unknown profile"):
        MODULE.load_profile("fast")


def test_requirements_pin_every_package_exactly():
    pins = MODULE.parse_requirements(MODULE.REQUIREMENTS_PATH)
    assert pins["presidio-analyzer"]
    assert pins["spacy"]
    assert pins["en-core-web-lg"] == "3.8.0"
    assert pins["de-core-news-lg"] == "3.8.0"
    for line in MODULE.REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            assert "==" in line or " @ " in line, line
            assert ">" not in line and "<" not in line and "~" not in line, line


def test_pin_check_reports_missing_and_different_versions():
    pins = {"presidio-analyzer": "2.2.364", "spacy": "3.8.16", "phonenumbers": "9.0.41"}
    installed = {"presidio-analyzer": "2.2.364", "spacy": "3.8.0"}.get
    assert MODULE.check_pins(pins, installed) == [
        "phonenumbers: pinned 9.0.41, installed none",
        "spacy: pinned 3.8.16, installed 3.8.0",
    ]
    assert MODULE.check_pins({"spacy": "3.8.16"}, {"spacy": "3.8.16"}.get) == []


def test_analysis_language_falls_back_for_unsupported_languages():
    tuned = MODULE.load_profile("tuned")
    assert MODULE.analysis_language("de", tuned) == "de"
    assert MODULE.analysis_language("fr", tuned) == "en"
    assert MODULE.analysis_language("de", MODULE.load_profile("default")) == "en"


def test_presidio_entities_map_to_benchmark_ids_or_stay_namespaced():
    assert MODULE.benchmark_label("EMAIL_ADDRESS") == "pii.email"
    assert MODULE.benchmark_label("IBAN_CODE") == "pii.iban"
    assert MODULE.benchmark_label("CREDIT_CARD") == "pii.credit_card.pan"
    assert MODULE.benchmark_label("US_SSN") == "pii.us.social_security_number"
    assert MODULE.benchmark_label("DE_PASSPORT") == "entity.passport_number"
    assert MODULE.benchmark_label("PERSON") == "entity.person_name"
    assert MODULE.benchmark_label("DE_TAX_ID") == "presidio.DE_TAX_ID"
    for label in MODULE.PRESIDIO_OUTPUT_MAP.values():
        assert external_pii_eval.ark_entity_id(label) == label
    # Unmapped entities must never be scored by accident.
    assert external_pii_eval.ark_entity_id("presidio.DE_TAX_ID") is None


def test_predict_rows_emits_sorted_code_point_spans_with_scores():
    profile = MODULE.load_profile("tuned")
    analyzer = FakeAnalyzer(fake_results())
    rows = list(MODULE.predict_rows(gold_rows(), analyzer, profile))
    assert [row["id"] for row in rows] == ["en-1", "de-1", "fr-1"]
    assert [call[1] for call in analyzer.calls] == ["en", "de", "en"]
    assert {call[2] for call in analyzer.calls} == {profile["score_threshold"]}
    assert rows[0] == {
        "id": "en-1",
        "language": "en",
        "analysis_language": "en",
        "evidence_spans": [
            {
                "label": "pii.email",
                "presidio_entity": "EMAIL_ADDRESS",
                "start_char": 5,
                "end_char": 20,
                "score": 1.0,
                "recognizer": "EmailRecognizer",
            },
            {
                "label": "pii.phone",
                "presidio_entity": "PHONE_NUMBER",
                "start_char": 29,
                "end_char": 32,
                "score": 0.4,
                "recognizer": "TestRecognizer",
            },
        ],
    }
    assert rows[2]["evidence_spans"] == []
    assert "text" not in rows[0]  # predictions never duplicate source text


def test_predict_rows_rejects_missing_or_duplicate_ids_and_bad_offsets():
    profile = MODULE.load_profile("default")
    with pytest.raises(ValueError, match="unique non-empty id"):
        list(MODULE.predict_rows([{"text": "x", "language": "en"}], FakeAnalyzer({}), profile))
    duplicate = [{"id": "a", "text": "x", "language": "en"}] * 2
    with pytest.raises(ValueError, match="unique non-empty id"):
        list(MODULE.predict_rows(duplicate, FakeAnalyzer({}), profile))
    with pytest.raises(ValueError, match="outside text"):
        list(
            MODULE.predict_rows(
                [{"id": "a", "text": "abc", "language": "en"}],
                FakeAnalyzer({"abc": [result("EMAIL_ADDRESS", 1, 9, 1.0)]}),
                profile,
            )
        )


def test_predictions_are_accepted_by_external_pii_eval(tmp_path):
    profile = MODULE.load_profile("tuned")
    predictions = list(MODULE.predict_rows(gold_rows(), FakeAnalyzer(fake_results()), profile))
    attached = external_pii_eval.attach_ark_predictions(gold_rows(), predictions)
    report = external_pii_eval.exact_span_metrics(attached)
    per_entity = report["per_corpus"]["ai4privacy-openpii-nano-1k"]["per_entity"]
    assert per_entity["pii.email"]["true_positives"] == 1
    assert per_entity["pii.iban"]["true_positives"] == 1
    assert "presidio.DE_TAX_ID" not in per_entity


def test_run_writes_byte_identical_predictions_and_metadata(tmp_path):
    source = tmp_path / "gold.jsonl"
    write_jsonl(source, gold_rows())
    outputs = []
    for attempt in ("a", "b"):
        out = tmp_path / f"{attempt}.jsonl"
        meta = tmp_path / f"{attempt}.meta.json"
        MODULE.run(
            input_path=source,
            output_path=out,
            meta_path=meta,
            profile_name="tuned",
            analyzer=FakeAnalyzer(fake_results()),
            versions={"presidio-analyzer": "2.2.364"},
        )
        outputs.append((out.read_bytes(), meta.read_bytes()))
    assert outputs[0] == outputs[1]
    metadata = json.loads(outputs[0][1])
    assert metadata["schema"] == "ark-l1-presidio-predictions-v1"
    assert metadata["profile"] == "tuned"
    assert metadata["rows"] == 3
    assert metadata["analysis_languages"] == {"de": {"de": 1}, "en": {"en": 1}, "fr": {"en": 1}}
    assert metadata["versions"] == {"presidio-analyzer": "2.2.364"}
    assert len(metadata["input_sha256"]) == 64
    assert len(metadata["profile_sha256"]) == 64
    assert metadata["output_sha256"] == MODULE.sha256_bytes(outputs[0][0])


def presidio_available():
    return importlib.util.find_spec("presidio_analyzer") is not None


@pytest.mark.skipif(not presidio_available(), reason="presidio_analyzer is not installed")
@pytest.mark.parametrize("profile_name", MODULE.PROFILES)
def test_real_presidio_profiles_are_reproducible(tmp_path, profile_name):
    assert MODULE.check_pins(MODULE.parse_requirements(MODULE.REQUIREMENTS_PATH)) == []
    rows = [
        {"id": "en", "language": "en", "text": "Contact ada@example.com, card 4111 1111 1111 1111."},
        {"id": "de", "language": "de", "text": "Bitte überweisen Sie auf IBAN DE89370400440532013000."},
    ]
    source = tmp_path / "gold.jsonl"
    write_jsonl(source, rows)
    digests = []
    for attempt in ("a", "b"):
        out = tmp_path / f"{attempt}.jsonl"
        MODULE.run(
            input_path=source,
            output_path=out,
            meta_path=tmp_path / f"{attempt}.meta.json",
            profile_name=profile_name,
        )
        digests.append(MODULE.sha256_bytes(out.read_bytes()))
        predicted = {
            row["id"]: {(s["label"], s["start_char"], s["end_char"]) for s in row["evidence_spans"]}
            for row in map(json.loads, out.read_text(encoding="utf-8").splitlines())
        }
        assert ("pii.email", 8, 23) in predicted["en"]
        assert ("pii.credit_card.pan", 30, 49) in predicted["en"]
        assert ("pii.iban", 30, 52) in predicted["de"]
    assert digests[0] == digests[1]
