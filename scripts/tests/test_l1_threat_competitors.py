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
             "protocol": "f1_at_cut", "note": "n", "positive": [{"field": "label", "equals": 1}]}
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
    flags = ([True, True, False], [False] * 999 + [True])
    out = MODULE.evaluate(benchmark(protocol="tpr_at_fpr", targets=[0.01, 0.001]), pos, neg, *flags)
    assert out["tpr_at_fpr"]["0.01"]["tpr"] == 1.0
    assert out["tpr_at_fpr"]["0.001"]["tpr"] == pytest.approx(1 / 3)
    assert out["tpr_at_0.001"]["tpr"] == pytest.approx(1 / 3)
    assert MODULE.evaluate(benchmark(protocol="auprc"), pos, neg, *flags)["auprc"] is not None
    decided = MODULE.evaluate(benchmark(), pos, neg, *flags)["f1"]
    assert (decided["tp"], decided["fp"]) == (2, 1)
    assert "tpr_at_0.001" not in MODULE.evaluate(benchmark(), pos, [], flags[0], [])
    with pytest.raises(ValueError):
        MODULE.evaluate(benchmark(protocol="accuracy"), pos, neg, *flags)


def test_obfuscations_are_the_generators_renderings():
    assert MODULE.obfuscate("hi", "base64") == base64.b64encode(b"hi").decode()
    assert MODULE.obfuscate("hi", "unicode_tags") == chr(0xE0068) + chr(0xE0069)
    assert MODULE.obfuscate("ab", "zero_width") == "a​b"
    assert MODULE.obfuscate("test", "leetspeak") == "7357"
    assert MODULE.obfuscate("pace", "homoglyph") != "pace"
    with pytest.raises(ValueError):
        MODULE.obfuscate("x", "rot13")


def test_tpr_drop_compares_at_the_same_decision():
    assert MODULE.tpr_drop([True, True], [True, False]) == pytest.approx(0.5)
    assert MODULE.tpr_drop([True], []) is None


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
    ({"positive": []}, "names its positive rows"),
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


# ── measurement ──────────────────────────────────────────────────────────────


def test_windows_are_exact_utf8_sizes_and_capped():
    out = MODULE.windows(["ä" * 700, "b" * 900, "c" * 2000], 1024, 2)
    assert len(out) == 2 and all(len(w.encode("utf-8")) <= 1024 for w in out)
    assert len(out[1].encode("utf-8")) == 1024
    assert MODULE.windows(["short"], 1024, 5) == []


def test_benchmark_rows_keep_the_split_and_mark_positives(tmp_path):
    data = b"text,label,train_test_split\nja,1.0,1\nnein,0.0,1\ntrain,1.0,0\n"
    digest = __import__("hashlib").sha256(data).hexdigest()
    entry = benchmark(id="rp", files=[{"path": "f.csv", "sha256": digest}], format="csv", text="text",
                      positive=[{"field": "label", "at_least": 0.5}], rows=[{"field": "train_test_split", "equals": "1"}])
    (tmp_path / "rp").mkdir()
    (tmp_path / "rp" / "f.csv").write_bytes(data)
    rows = MODULE.benchmark_rows(entry, {"datasets": []}, tmp_path, offline=True)
    assert [(r["text"], r["positive"]) for r in rows] == [("ja", True), ("nein", False)]


def test_a_reused_dataset_keeps_its_own_pins():
    registry = {"datasets": [{"id": "d", "source": "https://github.com/a/b", "revision": "c" * 40,
                              "files": [{"path": "x.jsonl", "sha256": "d" * 64}], "format": "jsonl", "text": "t"}]}
    entry = benchmark(dataset="d", positive=[{"field": "y", "equals": 1}])
    del entry["files"]
    full = MODULE.recipe(entry, registry)
    assert (full["source"], full["format"], full["text"]) == ("https://github.com/a/b", "jsonl", "t")
    assert full["labels"] == [{"field": "y", "equals": 1}]


def test_system_result_scores_the_benchmark_classes_and_the_obfuscation_drop():
    rows = [{"id": "p", "positive": True}, {"id": "n", "positive": False}]
    predictions = {"p": {"scores": {"jailbreak": 0.9}, "flagged": ["jailbreak"]},
                   "n": {"scores": {"jailbreak": 0.1, "toxic_language": 1.0}, "flagged": ["toxic_language"]}}
    for kind in MODULE.OBFUSCATION_KINDS:
        predictions[f"p~{kind}"] = {"scores": {}, "flagged": ["jailbreak"] if kind == "leetspeak" else []}
    out = MODULE.system_result(benchmark(), rows, predictions, curve=True)
    assert out["f1"]["f1"] == 1.0
    assert out["drops"]["leetspeak"] == 0.0 and out["drops"]["base64"] == 1.0
    assert [v["text"] for v in MODULE.variants([{"id": "p", "text": "hi", "positive": True}])][2] == "aGk="


class FakeReference:
    id = "prompt_guard_2_22m"
    classes = ["instruction_injection", "jailbreak"]

    def score(self, texts):
        return [{"scores": {cls: 0.9 if "attack" in t else 0.1 for cls in self.classes}} for t in texts]


def test_a_reference_classifier_decides_at_one_half_and_skips_foreign_classes():
    rows = [{"id": "p", "text": "attack", "positive": True}, {"id": "n", "text": "hello", "positive": False}]
    out = MODULE.reference_result(benchmark(), rows, FakeReference())
    assert out["f1"]["f1"] == 1.0 and set(out["drops"].values()) == {1.0}
    assert MODULE.reference_result(benchmark(classes=["toxic_language"]), rows, FakeReference()) is None
    assert set(MODULE.reference_latency(["x" * 2000], FakeReference())) == {"1KiB", "throughput"}


def test_runs_merge_per_benchmark_and_refuse_two_machines():
    a = {"machine": "m", "benchmarks": {"b": {"rows": 2, "systems": {"rules": {"x": 1}}}}, "latency": {"ARK": {}}}
    b = {"machine": "m", "benchmarks": {"b": {"rows": 2, "systems": {"protectai_v2": {"x": 2}}}}, "latency": {"P": {}}}
    merged = SCOREBOARD.merge_results([a, b])
    assert set(merged["benchmarks"]["b"]["systems"]) == {"rules", "protectai_v2"} and set(merged["latency"]) == {"ARK", "P"}
    with pytest.raises(ValueError):
        SCOREBOARD.merge_results([a, {**b, "machine": "other"}])
