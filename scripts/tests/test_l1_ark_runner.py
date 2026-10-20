from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "run_ark.py"
SPEC = importlib.util.spec_from_file_location("run_ark", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

PRESIDIO_SPEC = importlib.util.spec_from_file_location(
    "run_presidio", ROOT / "scripts" / "l1_presidio" / "run_presidio.py"
)
PRESIDIO = importlib.util.module_from_spec(PRESIDIO_SPEC)
assert PRESIDIO_SPEC.loader is not None
PRESIDIO_SPEC.loader.exec_module(PRESIDIO)

sys.path.insert(0, str(ROOT / "python"))
from patronus_ark import external_pii_eval  # noqa: E402


def span(label, text, start, end, score=1.0):
    """An evidence span as ``SecurityGateway.scan_category`` returns it."""
    value = text[start:end]
    prefix = len(text[:start].encode("utf-8"))
    return {
        "label": label,
        "text": value,
        "score": score,
        "start_byte": prefix,
        "end_byte": prefix + len(value.encode("utf-8")),
        "start_char": start,
        "end_char": end,
    }


class FakeGateway:
    """Records calls and returns canned scan results per text."""

    def __init__(self, spans_by_text):
        self.spans_by_text = spans_by_text
        self.calls = []

    def scan_category(self, category, text):
        self.calls.append((category, text))
        spans = self.spans_by_text.get(text, [])
        return [{"category": "pii", "class_name": "pii" if spans else "safe", "evidence_spans": list(spans)}]


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


EN_TEXT = "Mail ada@example.com or call +1 415 555 0100"
DE_TEXT = "Grüße — IBAN DE89370400440532013000, MAC 00:1a:2b:3c:4d:5e"


def gold_rows():
    return [
        {
            "id": "en-1",
            "corpus": "ai4privacy-openpii-nano-1k",
            "language": "en",
            "text": EN_TEXT,
            "entities": [{"entity_type": "pii.email", "start": 5, "end": 20}],
        },
        {
            "id": "de-1",
            "corpus": "ai4privacy-openpii-nano-1k",
            "language": "de",
            "text": DE_TEXT,
            "entities": [{"entity_type": "pii.iban", "start": 13, "end": 35}],
        },
        {
            "id": "fr-1",
            "corpus": "ai4privacy-openpii-nano-1k",
            "language": "fr",
            "text": "Rien ici",
            "entities": [],
        },
    ]


def fake_spans():
    return {
        EN_TEXT: [
            span("PHONE", EN_TEXT, 29, 44, 0.6),
            span("EMAIL", EN_TEXT, 5, 20),
        ],
        DE_TEXT: [
            span("MAC_ADDRESS", DE_TEXT, 41, 58),
            span("IBAN", DE_TEXT, 13, 35, 0.9),
            span("IBAN", DE_TEXT, 13, 35, 1.0),  # same span from a second rule
        ],
    }


def test_ark_labels_map_to_benchmark_ids_or_stay_namespaced():
    assert MODULE.benchmark_label("EMAIL") == "pii.email"
    assert MODULE.benchmark_label("IBAN") == "pii.iban"
    assert MODULE.benchmark_label("CREDITCARD") == "pii.credit_card.pan"
    assert MODULE.benchmark_label("PASSPORT_NUMBER") == "entity.passport_number"
    assert MODULE.benchmark_label("MAC_ADDRESS") == "ark.MAC_ADDRESS"
    assert MODULE.benchmark_label("STEUERID") == "ark.STEUERID"
    for ark_label, benchmark in external_pii_eval.ARK_OUTPUT_MAP.items():
        assert MODULE.benchmark_label(ark_label) == benchmark
    # Unmapped labels must never be scored by accident.
    assert external_pii_eval.ark_entity_id("ark.MAC_ADDRESS") is None


def test_predict_rows_emits_sorted_deduplicated_code_point_spans_with_scores():
    gateway = FakeGateway(fake_spans())
    rows = list(MODULE.predict_rows(gold_rows(), gateway))
    assert [row["id"] for row in rows] == ["en-1", "de-1", "fr-1"]
    assert [call[0] for call in gateway.calls] == ["pii", "pii", "pii"]
    assert rows[0] == {
        "id": "en-1",
        "language": "en",
        "evidence_spans": [
            {"label": "pii.email", "ark_label": "EMAIL", "start_char": 5, "end_char": 20, "score": 1.0},
            {"label": "pii.phone", "ark_label": "PHONE", "start_char": 29, "end_char": 44, "score": 0.6},
        ],
    }
    # Offsets are code points: "Grüße —" has more bytes than characters.
    assert rows[1]["evidence_spans"] == [
        {"label": "pii.iban", "ark_label": "IBAN", "start_char": 13, "end_char": 35, "score": 1.0},
        {"label": "ark.MAC_ADDRESS", "ark_label": "MAC_ADDRESS", "start_char": 41, "end_char": 58, "score": 1.0},
    ]
    assert rows[2]["evidence_spans"] == []
    assert "text" not in rows[0]  # predictions never duplicate source text
    assert all("text" not in item for row in rows for item in row["evidence_spans"])


def test_prediction_rows_share_the_presidio_runner_shape():
    ark = next(MODULE.predict_rows(gold_rows()[:1], FakeGateway(fake_spans())))
    presidio = {
        "id": "en-1",
        "language": "en",
        "analysis_language": "en",
        "evidence_spans": [
            PRESIDIO._evidence_span(
                type("R", (), {"entity_type": "EMAIL_ADDRESS", "start": 5, "end": 20, "score": 1.0})(),
                EN_TEXT,
                "en-1",
            )
        ],
    }
    common_row = {"id", "language", "evidence_spans"}
    assert common_row <= ark.keys() and common_row <= presidio.keys()
    common_span = {"label", "start_char", "end_char", "score"}
    assert common_span <= ark["evidence_spans"][0].keys()
    assert common_span <= presidio["evidence_spans"][0].keys()
    assert {k: ark["evidence_spans"][0][k] for k in common_span} == {
        k: presidio["evidence_spans"][0][k] for k in common_span
    }
    assert isinstance(ark["evidence_spans"][0]["score"], float)


def test_predict_rows_rejects_missing_or_duplicate_ids_and_bad_spans():
    with pytest.raises(ValueError, match="unique non-empty id"):
        list(MODULE.predict_rows([{"text": "x", "language": "en"}], FakeGateway({})))
    duplicate = [{"id": "a", "text": "x", "language": "en"}] * 2
    with pytest.raises(ValueError, match="unique non-empty id"):
        list(MODULE.predict_rows(duplicate, FakeGateway({})))
    with pytest.raises(ValueError, match="requires text"):
        list(MODULE.predict_rows([{"id": "a", "language": "en"}], FakeGateway({})))
    outside = {"label": "EMAIL", "text": "bc", "score": 1.0, "start_char": 1, "end_char": 9}
    with pytest.raises(ValueError, match="outside text"):
        list(MODULE.predict_rows([{"id": "a", "text": "abc", "language": "en"}], FakeGateway({"abc": [outside]})))
    shifted = {"label": "EMAIL", "text": "zz", "score": 1.0, "start_char": 1, "end_char": 3}
    with pytest.raises(ValueError, match="does not match"):
        list(MODULE.predict_rows([{"id": "a", "text": "abc", "language": "en"}], FakeGateway({"abc": [shifted]})))
    no_score = {"label": "EMAIL", "text": "bc", "start_char": 1, "end_char": 3}
    with pytest.raises(ValueError, match="score"):
        list(MODULE.predict_rows([{"id": "a", "text": "abc", "language": "en"}], FakeGateway({"abc": [no_score]})))


def test_predictions_are_accepted_by_external_pii_eval():
    predictions = list(MODULE.predict_rows(gold_rows(), FakeGateway(fake_spans())))
    attached = external_pii_eval.attach_ark_predictions(gold_rows(), predictions)
    report = external_pii_eval.exact_span_metrics(attached)
    per_entity = report["per_corpus"]["ai4privacy-openpii-nano-1k"]["per_entity"]
    assert per_entity["pii.email"]["true_positives"] == 1
    assert per_entity["pii.iban"]["true_positives"] == 1
    assert "ark.MAC_ADDRESS" not in per_entity


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
            gateway=FakeGateway(fake_spans()),
            build={"native_sha256": "0" * 64},
        )
        outputs.append((out.read_bytes(), meta.read_bytes()))
    assert outputs[0] == outputs[1]
    metadata = json.loads(outputs[0][1])
    assert metadata["schema"] == "ark-l1-predictions-v1"
    assert metadata["engine"] == {"categories": ["pii"], "max_level": "l1"}
    assert metadata["rows"] == 3
    assert metadata["spans"] == 4
    assert metadata["languages"] == {"de": 1, "en": 1, "fr": 1}
    assert metadata["build"] == {"native_sha256": "0" * 64}
    assert metadata["label_map"] == external_pii_eval.ARK_OUTPUT_MAP
    assert len(metadata["input_sha256"]) == 64
    assert metadata["output_sha256"] == MODULE.sha256_bytes(outputs[0][0])
    assert "time" not in json.dumps(metadata)


def native_available():
    try:
        return importlib.util.find_spec("patronus_ark._patronus_ark") is not None
    except ImportError:
        return False


@pytest.mark.skipif(not native_available(), reason="patronus_ark native binding is not built")
def test_real_ark_binding_is_reproducible_and_scored(tmp_path):
    rows = [
        {"id": "en", "language": "en", "text": "Contact: ada@example.com, IP 192.168.10.20."},
        {"id": "de", "language": "de", "text": "Grüße 😀 — IBAN DE89370400440532013000."},
        {"id": "neg", "language": "en", "text": "Nothing personal here."},
    ]
    source = tmp_path / "gold.jsonl"
    write_jsonl(source, rows)
    digests = []
    for attempt in ("a", "b"):
        out = tmp_path / f"{attempt}.jsonl"
        meta = MODULE.run(input_path=source, output_path=out, meta_path=tmp_path / f"{attempt}.meta.json")
        digests.append(meta["output_sha256"])
        predicted = {
            row["id"]: {(s["label"], s["start_char"], s["end_char"]) for s in row["evidence_spans"]}
            for row in map(json.loads, out.read_text(encoding="utf-8").splitlines())
        }
        assert ("pii.email", 9, 24) in predicted["en"]
        assert ("pii.ip_address", 29, 42) in predicted["en"]
        assert ("pii.iban", 15, 37) in predicted["de"]
        assert predicted["neg"] == set()
        for row in map(json.loads, out.read_text(encoding="utf-8").splitlines()):
            for item in row["evidence_spans"]:
                assert 0.0 < item["score"] <= 1.0
        assert len(meta["build"]["native_sha256"]) == 64
    assert digests[0] == digests[1]


@pytest.mark.skipif(not native_available(), reason="patronus_ark native binding is not built")
def test_cli_writes_predictions_and_default_sidecar(tmp_path):
    source = tmp_path / "gold.jsonl"
    write_jsonl(source, [{"id": "a", "language": "en", "text": "ada@example.com"}])
    out = tmp_path / "ark.jsonl"
    assert MODULE.main(["--input", str(source), "--output", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["evidence_spans"][0]["label"] == "pii.email"
    assert json.loads((tmp_path / "ark.meta.json").read_text(encoding="utf-8"))["rows"] == 1


def test_run_records_an_explicit_pii_mode_and_keeps_strict_metadata(tmp_path):
    source = tmp_path / "gold.jsonl"
    write_jsonl(source, gold_rows())
    metas = {}
    for mode in ("strict", "balanced"):
        meta = MODULE.run(
            input_path=source,
            output_path=tmp_path / f"{mode}.jsonl",
            meta_path=tmp_path / f"{mode}.meta.json",
            gateway=FakeGateway(fake_spans()),
            build={"native_sha256": "0" * 64},
            pii_mode=mode,
        )
        metas[mode] = meta
    # strict is the default: its metadata stays as before K02.
    assert metas["strict"]["engine"] == {"categories": ["pii"], "max_level": "l1"}
    assert metas["balanced"]["engine"] == {"categories": ["pii"], "max_level": "l1", "pii_mode": "balanced"}
    with pytest.raises(ValueError, match="pii_mode"):
        MODULE.run(
            input_path=source,
            output_path=tmp_path / "x.jsonl",
            meta_path=tmp_path / "x.meta.json",
            gateway=FakeGateway(fake_spans()),
            build={"native_sha256": "0" * 64},
            pii_mode="fast",
        )
    with pytest.raises(SystemExit):
        MODULE.main(["--input", str(source), "--output", str(tmp_path / "y.jsonl"), "--pii-mode", "fast"])


@pytest.mark.skipif(not native_available(), reason="patronus_ark native binding is not built")
def test_real_ark_binding_scores_spans_in_opt_in_modes(tmp_path):
    source = tmp_path / "gold.jsonl"
    write_jsonl(source, [{"id": "de", "language": "de", "text": "IBAN DE89370400440532013000, Kennzeichen: B-AB 1234"}])
    scores = {}
    for mode in ("strict", "balanced", "recall"):
        out = tmp_path / f"{mode}.jsonl"
        assert MODULE.main(["--input", str(source), "--output", str(out), "--pii-mode", mode]) == 0
        row = json.loads(out.read_text(encoding="utf-8"))
        scores[mode] = {item["ark_label"]: item["score"] for item in row["evidence_spans"]}
    assert scores["strict"] == {"IBAN": 1.0, "LICENSEPLATE": 1.0}
    assert scores["balanced"] == {"IBAN": 0.9, "LICENSEPLATE": 0.65}
    assert scores["recall"] == scores["balanced"]
