from __future__ import annotations

import base64
import copy
import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "competitors.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_competitors", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
SCOREBOARD = MODULE.SCOREBOARD


def benchmark(**extra):
    entry = {"id": "b", "name": "B", "classes": ["jailbreak"], "languages": ["en"],
             "source": "https://huggingface.co/datasets/someone/bench", "licence": "MIT", "revision": "a" * 40,
             "files": [{"path": "test.json", "sha256": "b" * 64}], "commercial": True, "eval_only": True,
             "protocol": "f1_at_cut", "note": "n"}
    entry.update(extra)
    return entry


EMAP = {"datasets": [
    {"id": "held", "source": "github:owner/heldout-bench pure.json", "split": "holdout"},
    {"id": "dev_set", "source": "hf:x/dev", "split": "train_dev"},
    {"id": "report_set", "source": "hf:x/report", "split": "report"},
]}
PUBLISHED = {"schema": MODULE.SCHEMA, "numbers": [
    {"benchmark": "b", "system": "Other", "metric": "F1", "value": 0.5, "url": "https://arxiv.org/pdf/1", "table": "Table 1"}]}


# ── protocol adapters ────────────────────────────────────────────────────────


def test_f1_at_cut_counts_the_decision_and_zero_never_flags():
    cell = MODULE.f1_at_cut([0.9, 0.6, 0.2, 0.0], [0.7, 0.1, 0.0], 0.5)
    assert (cell["tp"], cell["fp"]) == (2, 1)
    assert cell["precision"] == pytest.approx(2 / 3) and cell["recall"] == pytest.approx(0.5)
    assert cell["f1"] == pytest.approx(2 * (2 / 3) * 0.5 / (2 / 3 + 0.5))
    assert MODULE.f1_at_cut([0.0], [0.0], 0.0)["tp"] == 0


def test_best_f1_picks_the_best_cut_on_the_set():
    cell = MODULE.best_f1([0.9, 0.8, 0.3], [0.85, 0.2])
    assert cell["cut"] == 0.3 and cell["f1"] == pytest.approx(2 * 0.75 * 1.0 / 1.75)
    assert MODULE.best_f1([0.0], [0.5])["f1"] == 0.0


def test_auroc_counts_ties_half():
    assert MODULE.auroc([0.9, 0.8], [0.1, 0.2]) == 1.0
    assert MODULE.auroc([0.5], [0.5]) == 0.5
    assert MODULE.auroc([0.1], [0.9, 0.0]) == 0.5
    assert MODULE.auroc([], [0.1]) is None


def test_evaluate_follows_the_protocol_and_always_adds_the_decisive_tpr():
    pos, neg = [0.9, 0.8, 0.1], [0.05] * 998 + [0.85, 0.95]
    out = MODULE.evaluate(benchmark(protocol="tpr_at_fpr", targets=[0.01, 0.001]), pos, neg, 0.5)
    assert out["tpr_at_fpr"]["0.01"]["tpr"] == 1.0
    assert out["tpr_at_fpr"]["0.001"]["tpr"] == pytest.approx(1 / 3)
    assert out["tpr_at_0.001"]["tpr"] == pytest.approx(1 / 3)
    assert MODULE.evaluate(benchmark(protocol="auprc"), pos, neg, 0.5)["auprc"] is not None
    assert "tpr_at_0.001" not in MODULE.evaluate(benchmark(), pos, [], 0.5)
    with pytest.raises(ValueError):
        MODULE.evaluate(benchmark(protocol="accuracy"), pos, neg, 0.5)


def test_obfuscations_are_the_generators_renderings():
    assert MODULE.obfuscate("hi", "base64") == base64.b64encode(b"hi").decode()
    assert MODULE.obfuscate("hi", "unicode_tags") == chr(0xE0068) + chr(0xE0069)
    assert MODULE.obfuscate("ab", "zero_width") == "a​b"
    assert MODULE.obfuscate("test", "leetspeak") == "7357"
    assert MODULE.obfuscate("pace", "homoglyph") != "pace"
    with pytest.raises(ValueError):
        MODULE.obfuscate("x", "rot13")


def test_tpr_drop_compares_at_the_same_cut():
    assert MODULE.tpr_drop([0.9, 0.8], [0.9, 0.1], 0.5) == pytest.approx(0.5)
    assert MODULE.tpr_drop([0.9], [], 0.5) is None


# ── registry ─────────────────────────────────────────────────────────────────


def test_a_clean_benchmark_passes():
    assert MODULE.check({"benchmarks": [benchmark()]}, EMAP, PUBLISHED) == []


@pytest.mark.parametrize("change, problem", [
    ({"eval_only": False}, "evaluation only"),
    ({"protocol": "accuracy"}, "protocol must be"),
    ({"protocol": "tpr_at_fpr"}, "needs targets"),
    ({"classes": ["spam"]}, "unknown classes"),
    ({"source": "https://github.com/Owner/heldout-bench"}, "holdout source"),
    ({"dataset": "held"}, "registered non-holdout set"),
    ({"dataset": "dev_set"}, "dev data"),
    ({"files": [{"path": "t", "sha256": "short"}]}, "pins its files"),
    ({"commercial": "maybe"}, "commercial must be"),
])
def test_check_names_each_problem(change, problem):
    problems = MODULE.check({"benchmarks": [benchmark(**change)]}, EMAP, PUBLISHED)
    assert any(problem in p for p in problems), problems


def test_a_registered_report_set_needs_no_own_files():
    entry = benchmark(dataset="report_set")
    del entry["files"]
    assert MODULE.check({"benchmarks": [entry]}, EMAP, PUBLISHED) == []


def test_a_published_number_needs_its_citation():
    for key in ("url", "table"):
        published = copy.deepcopy(PUBLISHED)
        published["numbers"][0][key] = ""
        assert MODULE.check({"benchmarks": [benchmark()]}, EMAP, published)
    published = copy.deepcopy(PUBLISHED)
    published["numbers"][0]["benchmark"] = "other"
    assert any("unknown benchmark" in p for p in MODULE.check({"benchmarks": [benchmark()]}, EMAP, published))


def test_gaps_ignore_dropped_benchmarks():
    gaps = MODULE.gaps({"benchmarks": [benchmark(), benchmark(classes=["tool_poisoning"], dropped="holdout")]})
    assert "jailbreak" not in gaps and "tool_poisoning" in gaps


def test_the_repository_registry_and_citations_check():
    registry, published = MODULE.load()
    assert MODULE.check(registry, MODULE.read(MODULE.ENTITY_MAP), published) == []
    assert all(entry["eval_only"] for entry in registry["benchmarks"])


# ── rendering ────────────────────────────────────────────────────────────────


def test_render_one_row_per_benchmark_and_system():
    results = {"machine": "test box", "benchmarks": {"b": {"systems": {"rules": {
        "protocol": "f1_at_cut", "f1": {"f1": 0.75}, "tpr_at_0.001": {"tpr": 0.5},
        "drops": {"base64": 0.25, "de": 0.1}}}}},
        "latency": {"ARK rules": {"1KiB": {"p50": 0.1, "p95": 0.2}, "throughput": 900}}}
    registry = {"benchmarks": [benchmark(), benchmark(id="p", name="P", pending="gated")]}
    text = SCOREBOARD.render_competitors(registry, PUBLISHED, results, ["toxic_language"])
    assert "| B | jailbreak | MIT | ARK rules only | F1 75.0 | 50.0 | – / – / 25.0 / – / – | 10.0 | this run |" in text
    assert f"| B | jailbreak | MIT | ARK L1 model | {SCOREBOARD.NOT_RUN} |" in text
    assert "| B | jailbreak | MIT | Other (published) | F1 0.5 | – | – | – | [Table 1](https://arxiv.org/pdf/1) |" in text
    assert "| P | jailbreak | MIT | ARK | pending: gated |" in text
    assert "Classes without any competitor benchmark: toxic_language." in text
    assert "test box" in text and "| ARK rules | 0.100 / 0.200 |" in text


def test_the_committed_report_is_current():
    registry, published = MODULE.load()
    committed = (ROOT / "research" / "l1-threat" / "scoreboard" / SCOREBOARD.COMPETITORS_FILE).read_text(encoding="utf-8")
    assert "Classes without any competitor benchmark: " + ", ".join(MODULE.gaps(registry)) in committed
    for number in published["numbers"]:
        assert number["url"] in committed
