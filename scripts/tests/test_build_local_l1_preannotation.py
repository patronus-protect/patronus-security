import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "build_local_l1_preannotation.py"
SPEC = importlib.util.spec_from_file_location("build_local_l1_preannotation", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def document(text="Contact Alice at alice@example.com"):
    return MODULE.Document(
        corpus="fixture",
        split="test",
        source_id="private-row-7",
        text=text,
        document_class="hr",
        declared_language="en",
        source="fixture_source",
        provenance_kind="third_party_real",
        license_review="permissive_verified",
    )


def test_finding_inventory_excludes_source_and_matched_text():
    source = document()
    results = [
        {
            "category": "pii",
            "model": "native:pii",
            "class_name": "EMAIL",
            "evidence_spans": [
                {
                    "label": "EMAIL",
                    "text": "alice@example.com",
                    "start_char": 17,
                    "end_char": 34,
                }
            ],
            "layers": [],
        }
    ]

    records = MODULE.observations(source, results, b"x" * 32)

    assert len(records) == 1
    assert records[0]["candidate_kind"] == "ark_l1_finding"
    assert records[0]["gold_status"] == "not_gold_machine_candidate"
    serialized = json.dumps(records)
    assert source.text not in serialized
    assert "alice@example.com" not in serialized
    assert "private-row-7" not in serialized


def test_anchor_without_finding_is_only_a_hard_negative_candidate():
    source = document("Authorization header contains an intentionally omitted value")
    results = [
        {
            "category": "dlp",
            "model": "native:dlp",
            "evidence_spans": [],
            "layers": [
                {
                    "details": {
                        "l1_anchors": [
                            {
                                "category": "auth_header_cookie",
                                "strength": "strong",
                                "text": "Authorization",
                                "start_char": 0,
                                "end_char": 13,
                            }
                        ]
                    }
                }
            ],
        }
    ]

    records = MODULE.observations(source, results, b"y" * 32)

    assert records[0]["candidate_kind"] == "anchor_hard_negative_candidate"
    assert records[0]["review_status"] == "unreviewed"
    assert "Authorization" not in json.dumps(records)


def test_build_inventory_reports_discovered_before_review_cap():
    sources = [document(f"Email {index}: alice{index}@example.com") for index in range(3)]

    def fake_scanner(text):
        start = text.index("alice")
        return [
            {
                "category": "pii",
                "model": "native:pii",
                "evidence_spans": [
                    {
                        "label": "EMAIL",
                        "start_char": start,
                        "end_char": len(text),
                    }
                ],
                "layers": [],
            }
        ]

    inventory, summary = MODULE.build_inventory(sources, fake_scanner, b"z" * 32, 2)

    assert summary["candidates_discovered_raw"] == 3
    assert summary["candidates_discovered_unique"] == 3
    assert summary["candidates_in_inventory"] == 2
    assert len(inventory) == 2


def test_inventory_deduplicates_same_content_imported_by_two_corpora():
    first = document()
    second = MODULE.Document(
        **{**first.__dict__, "corpus": "v4_1_sensitive", "source_id": "copied-row"}
    )

    def fake_scanner(text):
        start = text.index("alice@example.com")
        return [
            {
                "category": "pii",
                "model": "native:pii",
                "evidence_spans": [
                    {"label": "EMAIL", "start_char": start, "end_char": len(text)}
                ],
                "layers": [],
            }
        ]

    inventory, summary = MODULE.build_inventory(
        [first, second], fake_scanner, b"d" * 32, maximum_per_label=0
    )

    assert summary["candidates_discovered_raw"] == 2
    assert summary["candidates_discovered_unique"] == 1
    assert len(inventory) == 1


def test_language_inference_keeps_declared_language_and_is_conservative():
    assert MODULE.infer_language("beliebig", "code") == "code"
    assert MODULE.infer_language("Das ist ein Text und der ist für die Akte.", "unknown") == "de"
    assert MODULE.infer_language("A file that is in the folder and is for the team.", None) == "en"
    assert MODULE.infer_language("invoice 2026-04", "unknown") == "unknown"
