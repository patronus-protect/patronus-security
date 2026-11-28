from __future__ import annotations

import importlib.util
import json
import os
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
             "classes": list(classes), "language": language, "text": f"{source} {language} {classes} {i}"}
            for i in range(count)]


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
        assert set(share) == {"calibration", "measurement"}
        assert share["calibration"] == pytest.approx(0.5 * len(stratum), abs=1)
        assert share["measurement"] == pytest.approx(0.5 * len(stratum), abs=1)


def test_split_is_seeded_and_independent_of_row_order():
    sources = {"a": rows("a", 40), "b": rows("b", 40, ["exfiltration"])}
    parts = MIX.assign_parts(sources)
    assert MIX.assign_parts({k: list(reversed(v)) for k, v in reversed(sources.items())}) == parts
    assert MIX.assign_parts(sources, seed="another seed") != parts


def test_split_names_a_too_small_source_and_refuses_a_row_in_two_sources():
    document = MIX.parts_document({"tiny": rows("tiny", 1), "full": rows("full", 5)}, {})
    assert document["short_sources"] == ["tiny"]
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


def test_dlp_texts_materialize_the_recipe_rows():
    goldens = [json.loads(line) for line in (ROOT / MIX.GOLDENS / MIX.CORPUS_SETS["dlp_texts"]).read_text().splitlines()
               if line.strip()]
    recipe_ids = {f"dlp_texts:{g['id']}" for g in goldens if "template" in g and g.get("language") in MIX.LANGUAGES}
    assert recipe_ids
    texts = {r["id"]: r["text"] for r in MIX.corpus_texts(ROOT, "dlp_texts")}
    assert recipe_ids <= set(texts)
    assert all(texts[rid] and "<<secret" not in texts[rid] for rid in recipe_ids)


def test_identical_texts_land_in_one_part_across_rows_and_sources():
    sources = {"a": [{**row, "text": f"text {i % 7}"} for i, row in enumerate(rows("a", 60))],
               "b": [{**row, "text": f"Text  {i % 7}"} for i, row in enumerate(rows("b", 30))] + rows("b", 10, language="de")}
    parts = MIX.assign_parts(sources)
    by_text = {}
    for row in [*sources["a"], *sources["b"]]:
        by_text.setdefault(MIX.text_key(row), set()).add(parts[row["id"]])
    assert all(len(found) == 1 for found in by_text.values())
    assert MIX.assign_parts({k: list(reversed(v)) for k, v in reversed(sources.items())}) == parts


def test_the_checked_in_extra_sets_share_no_text_between_parts():
    extra = MIX.extra_sets(ROOT)
    parts = MIX.assign_parts(extra)
    by_text = {}
    for set_rows in extra.values():
        for row in set_rows:
            by_text.setdefault(MIX.text_key(row), set()).add(parts[row["id"]])
    assert all(len(found) == 1 for found in by_text.values())


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
                             "report": ([0.95], [0.5] * 10)})
    cell = MODULE.fair_cells(rows, scores, ["jailbreak"])["jailbreak"]["all"]["0.001"]
    # Measurement and report negatives score far higher than the calibration ones: they move nothing.
    noisy, noisy_scores = mix_rows({"calibration": calibration, "measurement": ([0.95] * 10, [0.95] * 1000),
                                    "report": ([0.95], [0.97] * 10)})
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
    report = {"seed": MIX.SEED, "parts_hash": "abc", "report_sets": ["r"], "missing": {"cascade": "why"}, "short_sources": [],
              "excluded": {}, "trained": {"models": {}, "keys": 0},
              "parts": {"calibration": 1010, "measurement": 1010, "report": 7, "rows": 2020, "sources": 1},
              "systems": {"rules": MODULE.fair_cells(rows, scores, ["jailbreak"])}}
    text = MODULE.render_fair(report, "T", [])
    assert text.index("At 0.1% FPR (decisive)") < text.index("At 1% FPR")
    not_run = " | ".join([MODULE.NOT_RUN] * 6)
    assert f"| jailbreak | all | 10 | 1 | 1000 | 0 | 100.0 / 0.00 | {not_run} | 100.0 / 0.00 | {not_run} |" in text
    assert "train" not in text.split("Mix:")[1].split("\n")[0]
    assert "Not measured: cascade (why)." in text


def test_decision_score_puts_heuristic_detections_above_every_model_score():
    stage = {"l1": "escalate", "l1_score": 0.2, "decision": "clear", "decided_by": "l1_model", "score": 0.0}
    assert MODULE.decision_score(stage) == 0.5
    assert MODULE.decision_score({**stage, "score": -1e6}) == pytest.approx(0.0)
    assert 0.5 < MODULE.decision_score({**stage, "score": 3.0}) < 1.0
    assert MODULE.decision_score({**stage, "l1": "detected", "decided_by": "heuristic", "decision": "detected"}) == 1.0
    assert MODULE.decision_score({**stage, "l1": "clear", "decided_by": "heuristic"}) == 0.2
    assert MODULE.decision_score({**stage, "decided_by": "l3", "score": 0.7}) == 0.7


def fair_report_of(cell):
    return {"seed": MIX.SEED, "parts_hash": "abc", "report_sets": [], "missing": {}, "short_sources": [],
            "excluded": {}, "trained": {"models": {}, "keys": 0},
            "parts": {"calibration": 1010, "measurement": 1010, "report": 0, "rows": 2020, "sources": 1},
            "systems": {"rules": {"jailbreak": {"all": cell}}}}


def test_the_first_reachable_level_of_the_ladder_wins():
    # 0.3 % of the negatives share the top score: 0.1 % and 0.2 % are out of reach, 0.5 % is the first level within.
    negatives = [1.0] * 3 + [0.5] * 7 + [0.0] * 990
    level, cut, reachable = MODULE.ladder_cut(negatives, 1.0, 0.001)
    assert (level, reachable) == (0.005, True) and cut == MODULE.mix_cut(negatives, 0.005) and 0.5 < cut <= 1.0
    # A reachable level keeps its own cut; a lower ladder level wins over a higher one.
    assert MODULE.ladder_cut(negatives, 1.0, 0.01) == (0.01, MODULE.mix_cut(negatives, 0.01), True)
    assert MODULE.ladder_cut([1.0] * 3 + [0.5] * 997, 1.0, 0.001)[0] == 0.005
    assert MODULE.ladder_cut([1.0] * 2 + [0.5] * 998, 1.0, 0.001)[0] == 0.002
    # No level of the ladder is reachable.
    assert MODULE.ladder_cut([1.0] * 60 + [0.0] * 940, 1.0, 0.001) == (0.001, MODULE.mix_cut([1.0] * 60 + [0.0] * 940,
                                                                                              0.001), False)


def test_an_unreachable_level_falls_back_to_the_ladder_with_the_cut_from_calibration_only():
    calibration = ([1.0] * 10, [1.0] * 3 + [0.5] * 7 + [0.0] * 990)
    rows, scores = mix_rows({"calibration": calibration,
                             "measurement": ([1.0] * 6 + [0.5] * 4, [1.0] * 2 + [0.0] * 998)})
    cell = MODULE.fair_cells(rows, scores, ["jailbreak"])["jailbreak"]["all"]
    assert cell["0.001"]["level"] == "0.005" and cell["0.001"]["reachable"]
    assert cell["0.001"]["cut"] == MODULE.mix_cut(calibration[1], 0.005)
    assert cell["0.001"]["measurement"]["tpr"] == 0.6 and cell["0.001"]["measurement"]["fpr"] == 0.002
    assert cell["0.01"]["level"] == "0.01"
    # Measurement negatives at the top score move neither the level nor the cut.
    noisy, noisy_scores = mix_rows({"calibration": calibration, "measurement": ([1.0] * 10, [1.0] * 1000)})
    moved = MODULE.fair_cells(noisy, noisy_scores, ["jailbreak"])["jailbreak"]["all"]["0.001"]
    assert (moved["level"], moved["cut"]) == (cell["0.001"]["level"], cell["0.001"]["cut"])
    text = MODULE.render_fair(fair_report_of(cell), "T", [])
    decisive, one_percent = text.split("## At 1% FPR")
    # The fallback cell names its level and is set apart, so it is never read as a 0.1 % number.
    assert "| jailbreak | all | 10 | 1 | 1000 | 0 | *60.0 / 0.20 @0.5%* |" in decisive
    assert "| jailbreak | all | 10 | 1 | 1000 | 0 | 100.0 / 0.20 |" in one_percent
    assert MODULE.NO_BUDGET not in decisive.split("|---|")[1]


def test_held_out_scores_never_move_the_ladder_level():
    # 0.3 % of the calibration negatives share the calibration's top score: 0.5 % is the first reachable level.
    calibration = ([0.5] * 10, [0.5] * 3 + [0.0] * 997)
    rows, scores = mix_rows({"calibration": calibration, "measurement": ([0.5] * 10, [0.0] * 1000)})
    cell = MODULE.fair_cells(rows, scores, ["jailbreak"])["jailbreak"]["all"]["0.001"]
    assert (cell["level"], cell["measurement"]["tpr"]) == ("0.005", 1.0)
    # A report or measurement row above every calibration score moves neither the level nor the cut.
    for part in ("report", "measurement"):
        louder, louder_scores = mix_rows({"calibration": calibration, "measurement": ([0.5] * 10, [0.0] * 1000),
                                          part: ([0.5] * 10 + [0.9], [0.0] * 1000)})
        moved = MODULE.fair_cells(louder, louder_scores, ["jailbreak"])["jailbreak"]["all"]["0.001"]
        assert (moved["level"], moved["cut"], moved["measurement"]["tpr"]) == (cell["level"], cell["cut"], 1.0)


def test_a_cell_beyond_the_ladder_stays_not_reachable():
    # 6 % of the calibration negatives share the top score: no level up to 5 % holds.
    rows, scores = mix_rows({"calibration": ([1.0] * 10, [1.0] * 60 + [0.0] * 940),
                             "measurement": ([1.0] * 10, [0.0] * 1000)})
    cell = MODULE.fair_cells(rows, scores, ["jailbreak"])["jailbreak"]["all"]
    assert not cell["0.001"]["reachable"] and cell["0.001"]["measurement"]["tpr"] == 0.0
    budget = MODULE.NO_BUDGET
    assert f"| jailbreak | all | 10 | 1 | 1000 | 0 | {budget} |" in MODULE.render_fair(fair_report_of(cell), "T", [])


def test_best_heuristic_ranks_a_fallback_cut_as_nothing_at_the_level():
    plain, plain_scores = mix_rows({"calibration": ([0.9] * 2 + [0.0] * 8, [0.0] * 1000),
                                    "measurement": ([0.9] * 10, [0.0] * 1000)})
    fallback, fallback_scores = mix_rows({"calibration": ([1.0] * 10, [1.0] * 3 + [0.0] * 997),
                                          "measurement": ([1.0] * 10, [0.0] * 1000)})
    best = MODULE.best_of({"a": MODULE.fair_cells(fallback, fallback_scores, ["jailbreak"]),
                           "b": MODULE.fair_cells(plain, plain_scores, ["jailbreak"])})
    assert best["jailbreak"]["all"]["system"] == "b"


def test_training_rows_are_left_out_of_both_parts_and_counted_per_source():
    sources = {"a": rows("a", 40), "b": rows("b", 20, ["jailbreak"])}
    trained = {"jailbreak": frozenset(MIX.text_sha(r) for r in sources["b"][:5]),
               "other": frozenset(MIX.text_sha({"text": r["text"].upper()}) for r in sources["a"][:3])}
    document = MIX.parts_document(sources, {}, trained)
    left_out = {r["id"] for r in sources["b"][:5] + sources["a"][:3]}
    assert left_out.isdisjoint(document["parts"]) and len(document["parts"]) == 60 - len(left_out)
    assert document["excluded"] == {"a": 3, "b": 5}
    assert document["trained"]["models"] == {"jailbreak": 5, "other": 3} and document["trained"]["keys"] == 8
    assert document["counts"]["b"] == {"calibration": 8, "measurement": 7} or \
        document["counts"]["b"] == {"calibration": 7, "measurement": 8}
    # The exclusion is part of the frozen split: other training rows give another document.
    assert MIX.parts_document(sources, {}, {"jailbreak": trained["jailbreak"]}) != document


def freeze_dev(directory, by_set):
    """A frozen corpus directory of ``directory`` with ``by_set``: set id -> rows."""
    from test_l1_threat_scoreboard import freeze  # noqa: PLC0415

    freeze(directory, [r for set_rows in by_set.values() for r in set_rows])


def assert_no_training_row_is_measured(dev, mix_root):
    document = MODULE.build_mix(dev, mix_root)
    trained = MODULE.trained_keys(dev)
    keys = frozenset().union(*trained.values())
    sets, _ = MODULE.mix_sets(dev, mix_root)
    measured = [r for entry in sets for r in MODULE.BASELINES.read_rows(entry.path) if r["id"] in document["parts"]]
    assert measured and not [r["id"] for r in measured if MIX.text_sha(r) in keys]
    assert set(document["parts"].values()) <= {"calibration", "measurement"}
    assert sum(document["excluded"].values()) == sum(
        MIX.text_sha(r) in keys for entry in sets for r in MODULE.BASELINES.read_rows(entry.path))
    return document, trained


def test_no_training_row_of_a_shipped_model_is_in_calibration_or_measurement(tmp_path, monkeypatch):
    def tagged(source, count, classes=(), **extra):
        return [{**r, "dataset": source, "reported_classes": [], **extra} for r in rows(source, count, classes)]

    train_dev = {"dolly_15k": tagged("dolly_15k", 60), "spml": tagged("spml", 40, ["instruction_injection"]),
                 "nemotron_safety_v3": tagged("nemotron_safety_v3", 10, ["harmful_content"]),
                 "unseen_new_set": tagged("unseen_new_set", 30)}
    # A copy of a training text in a set no model trained on is excluded too (matched by text, not by id).
    for copy, original in zip(train_dev["unseen_new_set"], train_dev["dolly_15k"][:10]):
        copy["text"] = original["text"]
    freeze_dev(tmp_path / "dev" / "train_dev", train_dev)
    freeze_dev(tmp_path / "dev" / "generated", {"class_templates": [
        {**r, "generator": "class_templates", "template_family": f"family{i % 4}"}
        for i, r in enumerate(tagged("class_templates", 40, ["tool_poisoning"]))]})
    labelled = {r["id"]: "violent_crimes" for r in train_dev["nemotron_safety_v3"][:4]}
    monkeypatch.setattr(MODULE.HARMFUL_SUBCLASS, "load", lambda path=None: labelled)
    document, trained = assert_no_training_row_is_measured(tmp_path / "dev", tmp_path / "mix")
    assert trained["harmful_subclass"] == {MIX.text_sha(r) for r in train_dev["nemotron_safety_v3"][:4]}
    assert trained["instruction_injection"] and trained["tool_poisoning"]
    assert {"dolly_15k", "spml", "class_templates"} <= set(document["excluded"])
    copied = sum(MIX.text_sha(r) in trained["instruction_injection"] for r in train_dev["dolly_15k"][:10])
    assert copied and document["excluded"]["unseen_new_set"] == copied


def test_real_benign_train_rows_train_the_agent_models_and_the_evaluation_part_stays_measured(tmp_path, monkeypatch):
    real = [{**r, "reported_classes": []} for r in rows("real_cursorrules", 40)]
    quotes = [{**r, "reported_classes": []} for r in rows("real_agent_quotes", 4, ["tool_poisoning"])]
    dolly = [{**r, "reported_classes": []} for r in rows("dolly_15k", 60)]
    freeze_dev(tmp_path / "dev" / "train_dev", {"dolly_15k": dolly, "real_cursorrules": real, "real_agent_quotes": quotes})
    key = {r["id"]: MODULE.hashlib.sha256(r["text"].encode("utf-8")).hexdigest() for r in real + quotes}
    labels, split = tmp_path / "labels.jsonl", tmp_path / "split.jsonl"
    labels.write_text("".join(json.dumps({"dataset": r["dataset"], "sha256": key[r["id"]],
                                          "label": "benign" if r["benign"] else "tool_poisoning"}) + "\n"
                              for r in real), encoding="utf-8")
    parts = {r["id"]: ("train", "evaluation")[i % 2] for i, r in enumerate(real + quotes)}
    split.write_text("".join(json.dumps({"sha256": key[rid], "part": part}) + "\n" for rid, part in parts.items()),
                     encoding="utf-8")
    monkeypatch.setattr(MODULE.REAL_AGENT, "evaluation_keys", lambda path=split: frozenset(
        key[rid] for rid, part in parts.items() if part == "evaluation"))
    original = MODULE.REAL_AGENT.train_benign_rows
    monkeypatch.setattr(MODULE.REAL_AGENT, "train_benign_rows", lambda dev: original(dev, labels, split))
    document, trained = assert_no_training_row_is_measured(tmp_path / "dev", tmp_path / "mix")
    benign_train = {MIX.text_sha(r) for r in real if parts[r["id"]] == "train"}
    # The agent classes train on the benign train part (and only on it), the other classes never see a real row.
    assert len(benign_train) == 20
    for cls in MODULE.REAL_CLASSES:
        assert benign_train <= trained[cls]
        assert not {MIX.text_sha(r) for r in real + quotes if parts[r["id"]] == "evaluation"} & trained[cls]
    assert not benign_train & trained["instruction_injection"]
    # Every row of the evaluation part stays in the mix and is measured, never trained on.
    evaluation = [r["id"] for r in real + quotes if parts[r["id"]] == "evaluation"]
    assert set(evaluation) <= set(document["parts"]) and document["excluded"]["real_cursorrules"] == 20


@pytest.mark.skipif(not os.environ.get("ARK_L1_DEV_DATA"), reason="needs the dev split (ARK_L1_DEV_DATA)")
def test_no_training_row_of_a_shipped_model_is_measured_on_the_dev_split(tmp_path):
    assert_no_training_row_is_measured(Path(os.environ["ARK_L1_DEV_DATA"]), tmp_path / "mix")


def test_real_rows_are_reported_apart_with_every_positive_and_measured_negatives(monkeypatch):
    synthetic, scores = mix_rows({"calibration": ([0.9] * 10, [0.0] * 1000), "measurement": ([0.9] * 10, [0.0] * 1000)})
    real = []
    for part, label, value in (("calibration", "p", 0.9), ("measurement", "p", 0.0), ("calibration", "n", 0.0),
                               ("measurement", "n", 0.95), ("measurement", "n", 0.0), ("report", "p", 0.9)):
        rid = f"real:{part}:{label}:{len(real)}"
        row = {"id": rid, "text": rid, "dataset": "real_cursorrules", "benign": label == "n", "language": "en",
               "classes": ["tool_poisoning"] if label == "p" else []}
        real.append(MODULE.MixRow(row, "real_cursorrules", part))
        scores[rid] = {"tool_poisoning": value}
    # The real calibration negative is a row of the frozen train part; every other real row is in the evaluation part.
    evaluation = frozenset(MODULE.hashlib.sha256(r.row["text"].encode("utf-8")).hexdigest() for r in real
                           if r.row["id"] != "real:calibration:n:2")
    monkeypatch.setattr(MODULE.REAL_AGENT, "evaluation_keys", lambda: evaluation)
    tool = [MODULE.MixRow({**r.row, "classes": ["tool_poisoning"] if r.row["classes"] else []}, r.source, r.part) for r in synthetic]
    tool_scores = {rid: {"tool_poisoning": s.get("jailbreak", s.get("tool_poisoning"))} for rid, s in scores.items()}
    cells = MODULE.fair_cells(tool + real, tool_scores, ["tool_poisoning"])
    entry = cells["tool_poisoning"]["en"]["0.001"]
    # Both real positives (calibration and measurement, never the report sets), the two real evaluation negatives.
    assert entry["real"] == {"pos": 2, "tp": 1, "neg": 2, "fp": 1, "tpr": 0.5, "fpr": 0.5}
    report = {"seed": MIX.SEED, "parts_hash": "abc", "report_sets": [], "missing": {}, "short_sources": [],
              "excluded": {}, "trained": {"models": {}, "keys": 0},
              "parts": {"calibration": 1012, "measurement": 1013, "report": 1, "rows": 2025, "sources": 2},
              "systems": {"rules": cells}}
    text = MODULE.render_fair(report, "T", [])
    real_part = text.split("## Real-world rows of the agent classes")[1]
    assert "| tool_poisoning | en | 2 | 2 | 50.0 / 50.00 |" in real_part
    assert "L1 model" not in real_part.split("\n### At 1% FPR")[0].split("| class")[1].split("\n")[0]
    without = {**report, "systems": {"rules": MODULE.fair_cells(tool, tool_scores, ["tool_poisoning"])}}
    assert "Real-world rows" not in MODULE.render_fair(without, "T", [])
