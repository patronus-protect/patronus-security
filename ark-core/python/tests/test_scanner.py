import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from patronus_ark_core import CancelledError, ScanControl, Scanner


def test_original_unicode_spans_and_selective_checks():
    text = "😀 Kontakt: " + "alice" + "@example.org"
    scanner = Scanner({"categories": ["pii", "dlp"]})
    report = scanner.scan(text, dlp=False, injection=False)
    assert report["input_bytes"] == len(text.encode())
    assert report["wolf"] is None
    assert {r["category"] for r in report["native"]} == {"pii"}
    spans = [s for r in report["native"] for s in r["evidence_spans"]]
    assert any(s["text"] == "alice" + "@example.org" for s in spans)
    for span in spans:
        assert text[span["start_char"]:span["end_char"]] == span["text"]
        assert text.encode()[span["start_byte"]:span["end_byte"]].decode() == span["text"]


def test_limits_deadline_and_cancellation_never_return_partial_results():
    scanner = Scanner({"max_input_bytes": 8})
    with pytest.raises(RuntimeError, match="input exceeds"):
        scanner.scan("x" * 9)
    with pytest.raises(TimeoutError):
        scanner.scan("hello", control=ScanControl(timeout_ms=0))
    control = ScanControl()
    control.cancel()
    with pytest.raises(CancelledError):
        scanner.scan("hello", control=control)
    assert scanner.scan("hello")["input_bytes"] == 5


@pytest.mark.parametrize("config", [
    {"categories": []}, {"categories": ["unknown"]}, {"max_findings": 0},
    {"unsupported": True}, {"pii_mode": "unknown"},
])
def test_core_rejects_invalid_configuration(config):
    with pytest.raises(ValueError):
        Scanner(config)


def test_wolf_configuration_fails_at_construction_for_missing_assets(tmp_path):
    with pytest.raises(RuntimeError):
        Scanner({"wolf": {"bundle_dir": str(tmp_path), "threshold": 0.8}})


def test_independent_scanners_can_run_in_threads():
    scanners = [Scanner({"categories": ["dlp"]}) for _ in range(4)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        reports = list(pool.map(lambda scanner: scanner.scan("hello world"), scanners))
    assert all(report["input_bytes"] == 11 for report in reports)


@pytest.mark.skipif(not os.environ.get("PATRONUS_CORE_WOLF_BUNDLE"), reason="requires local Wolf assets")
def test_real_wolf_is_reused_and_obeys_per_call_selection():
    scanner = Scanner({"wolf": {
        "bundle_dir": os.environ["PATRONUS_CORE_WOLF_BUNDLE"],
        "threshold": 0.8, "precision": os.environ.get("PATRONUS_CORE_WOLF_PRECISION", "fp16"),
        "backend": "cpu",
    }})
    first = scanner.scan("Please summarize this document", pii=False, dlp=False)
    second = scanner.scan("Please summarize this document", pii=False, dlp=False)
    assert first["wolf"]["attack_probability"] == second["wolf"]["attack_probability"]
    assert first["wolf"]["windows"] > 0
    assert scanner.scan("hello", injection=False)["wolf"] is None
