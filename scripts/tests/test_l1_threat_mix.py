from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "scoreboard.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_scoreboard_mix", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
MIX = MODULE.MIX


def rows(source: str, count: int, classes=(), language="en"):
    return [{"id": f"{source}:{language}:{','.join(classes)}:{i}", "dataset": source, "benign": not classes,
             "classes": list(classes), "language": language, "text": "x"} for i in range(count)]


def test_every_source_reaches_every_part_and_no_row_is_in_two():
    sources = {"a": rows("a", 5), "b": rows("b", 23) + rows("b", 7, ["jailbreak"]), "c": rows("c", 101, language="de")}
    parts = MIX.assign_parts(sources)
    assert len(parts) == sum(len(r) for r in sources.values())
    counts = MIX.part_counts(sources, parts)
    for source, by_part in counts.items():
        assert all(by_part[part] > 0 for part in MIX.PARTS), source
    assert set(parts.values()) == set(MIX.PARTS)


def test_split_is_stratified_within_a_source():
    sources = {"s": rows("s", 500) + rows("s", 100, ["jailbreak"]) + rows("s", 50, ["jailbreak"], "de")}
    parts = MIX.assign_parts(sources)
    for stratum in (rows("s", 500), rows("s", 100, ["jailbreak"]), rows("s", 50, ["jailbreak"], "de")):
        share = Counter(parts[r["id"]] for r in stratum)
        assert share["train"] == pytest.approx(0.6 * len(stratum), abs=1)
        assert share["calibration"] == pytest.approx(0.2 * len(stratum), abs=1)
        assert share["measurement"] == pytest.approx(0.2 * len(stratum), abs=1)


def test_split_is_seeded_and_independent_of_row_order():
    sources = {"a": rows("a", 40), "b": rows("b", 40, ["exfiltration"])}
    parts = MIX.assign_parts(sources)
    assert MIX.assign_parts({k: list(reversed(v)) for k, v in reversed(sources.items())}) == parts
    assert MIX.assign_parts(sources, seed="another seed") != parts


def test_split_refuses_a_too_small_source_and_a_row_in_two_sources():
    with pytest.raises(ValueError, match="cannot fill"):
        MIX.assign_parts({"tiny": rows("tiny", 4)})
    with pytest.raises(ValueError, match="twice"):
        MIX.assign_parts({"a": rows("a", 5), "b": rows("a", 5)})


def test_frozen_parts_refuse_other_inputs(tmp_path):
    sources = {"a": rows("a", 10)}
    document = MIX.parts_document(sources, {"a": "1" * 64})
    path = tmp_path / MIX.PARTS_FILE
    assert MIX.freeze_parts(path, document)
    assert not MIX.freeze_parts(path, document)
    other = MIX.parts_document(sources, {"a": "2" * 64})
    with pytest.raises(ValueError, match="frozen"):
        MIX.freeze_parts(path, other)
    assert MIX.freeze_parts(path, other, force=True)
    assert json.loads(path.read_text())["sets"] == {"a": "2" * 64}


def test_trigger_negatives_are_benign_german_and_english_and_seeded():
    generated = MIX.trigger_negatives()
    assert Counter(r["language"] for r in generated) == {"de": MIX.TRIGGER_ROWS, "en": MIX.TRIGGER_ROWS}
    assert all(r["benign"] and not r["classes"] for r in generated)
    assert len({r["text"] for r in generated}) == len(generated)
    assert len({r["id"] for r in generated}) == len(generated)
    assert MIX.trigger_negatives() == generated
    assert {r["template_family"] for r in generated} == {"chat", "mail", "doc", "code", "log"}


def test_extra_sets_take_german_and_english_pii_and_dlp_texts():
    extra = MIX.extra_sets(ROOT)
    assert set(extra) == {MIX.TRIGGER_SET, *MIX.CORPUS_SETS}
    for set_id in MIX.CORPUS_SETS:
        assert extra[set_id] and {r["language"] for r in extra[set_id]} == {"de", "en"}
        assert all(r["benign"] and r["text"] and r["id"].startswith(f"{set_id}:") for r in extra[set_id])


def test_negatives_of_a_class_are_benign_rows_and_other_classes():
    assert MODULE.mix_label({"benign": False, "classes": ["jailbreak"]}, "jailbreak") is True
    assert MODULE.mix_label({"benign": False, "classes": ["exfiltration"]}, "jailbreak") is False
    assert MODULE.mix_label({"benign": True, "classes": []}, "jailbreak") is False
    assert MODULE.mix_label({"benign": False, "classes": [], "reported_classes": ["jailbreak"]}, "jailbreak") is None
    assert MODULE.mix_label({"benign": False, "classes": []}, "jailbreak") is None


def mix_rows(scores_by_part):
    """MixRows of one class: per part (positive scores, negative scores)."""
    out, scores = [], {}
    for part, (pos, neg) in scores_by_part.items():
        for label, values in (("p", pos), ("n", neg)):
            for i, value in enumerate(values):
                rid = f"{part}:{label}:{i}"
                row = {"id": rid, "dataset": "s", "benign": label == "n", "language": "en",
                       "classes": ["jailbreak"] if label == "p" else []}
                out.append(MODULE.MixRow(row, "s", part))
                scores[rid] = {"jailbreak": value}
    return out, scores


def test_cut_comes_only_from_the_calibration_part():
    calibration = ([0.9] * 10, [0.1 * (i % 10) for i in range(1000)])
    rows, scores = mix_rows({"calibration": calibration, "measurement": ([0.95] * 10, [0.2] * 1000),
                             "train": ([1.0], [0.99] * 500), "report": ([0.95], [0.5] * 10)})
    cell = MODULE.fair_cells(rows, scores, ["jailbreak"])["jailbreak"]["all"]["0.001"]
    # Measurement and train negatives score far higher than the calibration ones: they move nothing.
    noisy, noisy_scores = mix_rows({"calibration": calibration, "measurement": ([0.95] * 10, [0.95] * 1000),
                                    "train": ([1.0], [1.0] * 500), "report": ([0.95], [0.97] * 10)})
    moved = MODULE.fair_cells(noisy, noisy_scores, ["jailbreak"])["jailbreak"]["all"]["0.001"]
    assert cell["cut"] == moved["cut"] == MODULE.mix_cut(calibration[1], 0.001)
    assert cell["measurement"]["fpr"] == 0.0 and moved["measurement"]["fpr"] == 1.0
    assert cell["measurement"]["tpr"] == 1.0
    assert cell["report"] == {**cell["report"], "pos": 1, "neg": 10, "fp": 0}
    shifted, shifted_scores = mix_rows({"calibration": ([0.9] * 10, [0.96] * 1000),
                                        "measurement": ([0.95] * 10, [0.2] * 1000)})
    assert MODULE.fair_cells(shifted, shifted_scores, ["jailbreak"])["jailbreak"]["all"]["0.001"]["measurement"]["tpr"] == 0.0


def test_cut_falls_back_to_any_score_when_the_budget_is_unreachable():
    assert MODULE.mix_cut([0.0] * 100, 0.001) == pytest.approx(0.0) and MODULE.mix_cut([0.0] * 100, 0.001) > 0.0


def test_best_heuristic_is_picked_on_the_calibration_part():
    rows, scores = mix_rows({"calibration": ([0.9] * 10, [0.0] * 1000), "measurement": ([0.9] * 10, [0.0] * 1000)})
    good_on_calibration = MODULE.fair_cells(rows, scores, ["jailbreak"])
    flipped = {rid: {"jailbreak": 0.0 if rid.startswith("calibration:p") else s["jailbreak"]} for rid, s in scores.items()}
    good_on_measurement = MODULE.fair_cells(rows, flipped, ["jailbreak"])
    best = MODULE.best_of({"a": good_on_measurement, "b": good_on_calibration})
    assert best["jailbreak"]["all"]["system"] == "b"


def test_fair_report_renders_the_decisive_level_first():
    rows, scores = mix_rows({"calibration": ([0.9] * 10, [0.0] * 1000), "measurement": ([0.9] * 10, [0.0] * 1000),
                             "report": ([0.9] * 2, [0.0] * 5)})
    report = {"seed": MIX.SEED, "parts_hash": "abc", "report_sets": ["r"], "missing": {"cascade": "why"},
              "parts": {"train": 0, "calibration": 1010, "measurement": 1010, "report": 7, "rows": 2020, "sources": 1},
              "systems": {"rules": MODULE.fair_cells(rows, scores, ["jailbreak"])}}
    text = MODULE.render_fair(report, "T", [], ["rules", "cascade"])
    assert text.index("At 0.1% FPR (decisive)") < text.index("At 1% FPR")
    assert "| jailbreak | all | 10 | 1 | 1000 | 0 | 100.0 / 0.00 | 100.0 / 0.00 |" in text
    assert "Not measured: cascade (why)." in text
