from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "scoreboard.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_scoreboard", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CORPORA = MODULE.CORPORA


def freeze(directory: Path, rows, schema=None, role="dev") -> None:
    by_set: dict[str, list] = {}
    for item in rows:
        by_set.setdefault(item["dataset"], []).append(item)
    files, sets = {}, {}
    for set_id, members in sorted(by_set.items()):
        data = CORPORA.BENIGN_CODE._jsonl(members)
        files[f"{set_id}.jsonl"] = data
        sets[set_id] = {"file": f"{set_id}.jsonl", "sha256": hashlib.sha256(data).hexdigest(), "role": role}
    manifest = CORPORA.BENIGN_CODE._manifest_bytes(
        {"schema": schema or CORPORA.CORPORA_SCHEMA, "split": "train_dev", "sets": sets})
    files["manifest.json"] = manifest
    files[CORPORA.READY] = f"{hashlib.sha256(manifest).hexdigest()}  manifest.json\n".encode("utf-8")
    CORPORA.BENIGN_CODE._write(directory, files)


def row(set_id, index, classes=(), benign=False, language="en", **extra):
    return {"id": f"{set_id}:{index:07d}", "dataset": set_id, "text": f"text {set_id} {index}",
            "classes": list(classes), "reported_classes": [], "benign": benign, "language": language, **extra}


def pred(item, score=0.0, flagged=(), cls="exfiltration"):
    return {"id": item["id"], "scores": {cls: score} if score else {}, "flagged": list(flagged)}


# --- ARK results -------------------------------------------------------------------------------


def result(category, class_name, confidence=1.0, details=None, layer_type="native"):
    return {"category": category, "class_name": class_name, "confidence": confidence, "model": "native:x",
            "layers": [{"layer_type": layer_type, "details": details or {}}], "label_scores": []}


def test_ark_scores_take_the_verdict_and_the_scorer_values_below_it():
    scores, flagged = MODULE.ark_class_scores([
        result("exfiltration", "exfiltration", 0.91, {"score": 0.91}),
        result("exfiltration", "safe", 1.0),
        result("unsafe_action", "benign", 1.0, {"score": 0.04}),
        result("injection", "safe", 1.0, {"l1_candidates": [{"score": 0.3}, {"score": 0.7}]}),
        result("agent_config_tampering", "benign", 1.0, {"score": 0.0}),
        result("dlp", "secret", 1.0),
    ])
    assert scores == {"exfiltration": 0.91, "unsafe_action": 0.04, "instruction_injection": 0.7}
    assert flagged == ["exfiltration"]


def test_ark_scores_refuse_a_scanner_error():
    with pytest.raises(RuntimeError):
        MODULE.ark_class_scores([result("jailbreak", "benign", layer_type="scanner_error")])
    with pytest.raises(RuntimeError):
        MODULE.ark_class_scores([result("jailbreak", "error")])


def test_predict_rows_scan_every_row_once():
    rows = [row("a", 0), row("a", 1)]
    seen = []

    def scan(text):
        seen.append(text)
        return [result("jailbreak", "jailbreak", 0.8)] if text.endswith("1") else []

    out = MODULE.predict_rows(rows, scan)
    assert seen == [r["text"] for r in rows]
    assert out == [{"id": "a:0000000", "scores": {}, "flagged": []},
                   {"id": "a:0000001", "scores": {"jailbreak": 0.8}, "flagged": ["jailbreak"]}]


def test_category_keeps_the_injection_name():
    assert MODULE.category("instruction_injection") == "injection"
    assert MODULE.CATEGORIES["injection"] == "instruction_injection"
    assert set(MODULE.CATEGORIES.values()) == set(MODULE.CLASSES)


# --- metrics -----------------------------------------------------------------------------------


def test_vectorised_tpr_equals_matched_fpr():
    rng = np.random.default_rng(1)
    for _ in range(40):
        pos = list(np.round(rng.random(rng.integers(1, 30)), 1) * rng.integers(0, 2))
        neg = list(np.round(rng.random(rng.integers(1, 300)), 1))
        for target in (0.0, 0.001, 0.01, 0.05, 0.3, 1.0):
            expected = MODULE.BASELINES.matched_fpr(pos, neg, target)["tpr"]
            got = MODULE.tpr_at_fpr(np.asarray([pos]), np.asarray([neg]), target)[0]
            assert got == pytest.approx(expected), (pos, neg, target)


def test_max_fp_matches_the_matched_fpr_comparison():
    for negatives in range(1, 2001, 7):
        for target in (0.01, 0.001, 0.07):
            k = MODULE._max_fp(negatives, target)
            assert k / negatives <= target and (k + 1) / negatives > target


def test_average_precision_steps_over_tied_scores():
    assert MODULE.average_precision([0.9, 0.4], [0.8, 0.1]) == pytest.approx(0.833333, abs=1e-6)
    assert MODULE.average_precision([0.5], [0.5]) == 0.5
    assert MODULE.average_precision([0.5, 0.5], [0.5, 0.1]) == pytest.approx(2 / 3, abs=1e-6)
    assert MODULE.average_precision([], [0.1]) is None
    assert MODULE.average_precision([0.1], []) is None


def test_bootstrap_ci_is_seeded_and_brackets_the_estimate():
    pos = [0.9] * 30 + [0.2] * 70
    neg = [0.1] * 980 + [0.5] * 20
    first = MODULE.bootstrap_ci(pos, neg, 0.01)
    assert first == MODULE.bootstrap_ci(pos, neg, 0.01)
    assert first[0] <= 0.3 <= first[1] and first[1] - first[0] < 0.3
    assert MODULE.bootstrap_ci([], neg, 0.01) is None


PAIRS_ROWS = [
    (row("dev_a", 0, ["exfiltration"]), 0.9, ()),
    (row("dev_a", 1, ["exfiltration"], language="de"), 0.6, ()),
    (row("dev_a", 2, ["exfiltration"], language="de", translated=True), 0.95, ("exfiltration",)),
    (row("dev_a", 3, [], reported_classes=["exfiltration"]), 0.99, ()),
    (row("dev_b", 0, ["exfiltration"]), 0.2, ()),
    (row("dev_b", 1, benign=True, twin_of="dev_b:0000000"), 0.92, ("exfiltration",)),
    (row("dev_b", 2, benign=True, language="de"), 0.1, ()),
    (row("notinject", 0, benign=True), 0.3, ()),
    (row("dolly", 0, benign=True), 0.0, ()),
]


def pairs(items=PAIRS_ROWS, role="dev"):
    return [(item, pred(item, score, flagged), role) for item, score, flagged in items]


def test_score_pairs_cells_by_language_origin_and_hard_benign():
    report = MODULE.score_pairs(pairs())
    cells = report["gated"]["exfiltration"]
    assert set(cells["all"]) == {"all", "native", "translated"}
    top = cells["all"]["all"]
    # reported-only classes never count; four positives against four benign rows
    assert (top["positives"], top["negatives"]) == (4, 4)
    assert top["hard_benign"] == {"rows": 2, "fp": 1, "fpr": 0.5}
    assert cells["de"]["translated"]["positives"] == 1
    assert cells["de"]["all"]["negatives"] == 1
    assert report["hard_benign_flags"] == {"exfiltration": ["dev_b:0000001"]}
    assert "jailbreak" not in report["gated"] and report["report"] == {}


def test_adversarial_benign_jailbreak_lookalikes_are_hard_benign():
    # WildJailbreak's benign rows are adversarial_benign: jailbreak-shaped prompts without harmful intent.
    assert MODULE.is_hard_benign(row("wildjailbreak", 0, benign=True))
    assert not MODULE.is_hard_benign(row("wildjailbreak", 1, ["jailbreak"]))
    assert not MODULE.is_hard_benign(row("dolly_15k", 0, benign=True))


def test_vanilla_benign_wildguardmix_prompts_are_hard_benign():
    # WildGuardMix's vanilla unharmful prompts are harmless requests that sound risky (killing a process, a heist film).
    assert MODULE.is_hard_benign(row("wildguardmix", 0, benign=True))
    assert not MODULE.is_hard_benign(row("wildguardmix", 1, ["harmful_content"]))


def test_score_pairs_keep_report_only_sets_apart_and_never_flag_them():
    report = MODULE.score_pairs(pairs(role="report"))
    assert report["gated"] == {} and "exfiltration" in report["report"]
    assert report["hard_benign_flags"] == {}


def test_leave_one_dataset_out_names_the_set_whose_removal_hurts():
    items = [(row("a", i, ["jailbreak"]), 0.9, ()) for i in range(5)]
    items += [(row("b", i, ["jailbreak"]), 0.3, ()) for i in range(5)]
    items += [(row("n", i, benign=True), 0.1, ()) for i in range(200)]
    rows = [(item, pred(item, score, flagged, cls="jailbreak"), "dev") for item, score, flagged in items]
    lodo = MODULE.score_pairs(rows, bootstrap=False)["gated"]["jailbreak"]["leave_one_dataset_out"]
    assert lodo["tpr"] == {"a": 1.0, "b": 1.0, "n": None}
    assert lodo["worst_left_out"] is None  # no removal lowers the TPR of 1.0
    rows.append((row("c", 0, benign=True), {"id": "c:0000000", "scores": {"jailbreak": 0.95}}, "dev"))
    rows += [(row("c", i, benign=True), {"id": f"c:{i:07d}", "scores": {"jailbreak": 0.5}}, "dev") for i in range(1, 4)]
    lodo = MODULE.score_pairs(rows, bootstrap=False)["gated"]["jailbreak"]["leave_one_dataset_out"]
    # 1 % of 204 negatives allows two: the cut is the third-highest negative, 0.5, which only "a" passes
    assert MODULE.score_pairs(rows, bootstrap=False)["gated"]["jailbreak"]["all"]["all"]["0.01"]["tpr"] == 0.5
    assert lodo["tpr"]["c"] == 1.0 and lodo["min"] == 0.0 and lodo["worst_left_out"] == "a"


def test_compare_fails_a_drop_beyond_tolerance_and_new_hard_benign_fp():
    base = MODULE.score_pairs(pairs(), bootstrap=False)
    assert all(check["ok"] for check in MODULE.compare(base, base))
    worse = [(item, 0.0 if item["id"] == "dev_a:0000002" else score, flagged) for item, score, flagged in PAIRS_ROWS]
    worse.append((row("dev_b", 3, benign=True, twin_of="dev_b:0000000"), 0.0, ("exfiltration",)))
    head = MODULE.score_pairs(pairs(worse), bootstrap=False)
    failed = {check["name"]: check for check in MODULE.compare(base, head) if not check["ok"]}
    # only the translated German positive passes the cut above the 0.92 twin, at either FPR
    assert set(failed) == {"tpr@1%fpr exfiltration all", "tpr@1%fpr exfiltration de",
                           "tpr@0.1%fpr exfiltration all", "tpr@0.1%fpr exfiltration de",
                           "hard-benign new fp exfiltration"}
    assert failed["hard-benign new fp exfiltration"]["rows"] == ["dev_b:0000003"]
    assert failed["tpr@1%fpr exfiltration de"]["delta_pp"] == -50.0


def test_compare_tolerates_half_a_point():
    base = {"gated": {"jailbreak": {"all": {"all": {"positives": 1000, "0.01": {"tpr": 0.500}}}}},
            "hard_benign_flags": {}}
    head = {"gated": {"jailbreak": {"all": {"all": {"positives": 1000, "0.01": {"tpr": 0.495}}}}},
            "hard_benign_flags": {}}
    checks = {c["name"]: c for c in MODULE.compare(base, head)}
    assert checks["tpr@1%fpr jailbreak all"]["ok"]
    head["gated"]["jailbreak"]["all"]["all"]["0.01"]["tpr"] = 0.494
    assert not {c["name"]: c for c in MODULE.compare(base, head)}["tpr@1%fpr jailbreak all"]["ok"]
    # a class that only the head scores is new, not a regression
    assert MODULE.compare(head, base) and all(c["ok"] for c in MODULE.compare({"gated": {}, "hard_benign_flags": {}}, head))


def gate_report(tpr_1, tpr_01, ci=None):
    cell = {"positives": 1000, "negatives": 5000, "auprc": 0.8, "0.01": {"tpr": tpr_1}, "0.001": {"tpr": tpr_01}}
    if ci:
        cell["tpr_ci95"] = ci
    return {"gated": {"jailbreak": {"all": {"all": cell}}}, "hard_benign_flags": {}}


def test_compare_gates_tpr_at_one_per_mille_like_one_percent():
    base = gate_report(0.600, 0.300)
    checks = {c["name"]: c for c in MODULE.compare(base, gate_report(0.600, 0.295))}
    assert list(checks)[:2] == ["tpr@1%fpr jailbreak all", "tpr@0.1%fpr jailbreak all"]
    assert all(c["ok"] for c in checks.values())  # half a point is tolerated at 0.1 % too
    failed = [c for c in MODULE.compare(base, gate_report(0.610, 0.290)) if not c["ok"]]
    # a 0.1 % drop beyond tolerance fails even when TPR@1 % improves
    assert [(c["name"], c["base"], c["head"], c["delta_pp"], c["positives"]) for c in failed] == [
        ("tpr@0.1%fpr jailbreak all", 0.3, 0.29, -1.0, 1000)]
    assert MODULE.compare(base, gate_report(0.600, 0.290), tolerance_pp=1.0)[1]["ok"]
    lost = {"gated": {"jailbreak": {"all": {"all": {"positives": 1000, "0.01": {"tpr": 0.6}, "0.001": None}}}},
            "hard_benign_flags": {}}
    assert not {c["name"]: c for c in MODULE.compare(base, lost)}["tpr@0.1%fpr jailbreak all"]["ok"]


def test_cell_metrics_bootstrap_both_operating_points():
    pos = [0.9] * 30 + [0.6] * 30 + [0.2] * 40
    neg = [0.1] * 990 + [0.5] * 8 + [0.7] * 2
    cell = MODULE.cell_metrics(pos, neg, [])
    assert set(cell["tpr_ci95"]) == {"0.01", "0.001"}
    assert cell["tpr_ci95"]["0.01"] == MODULE.bootstrap_ci(pos, neg, 0.01)
    assert cell["tpr_ci95"]["0.001"] == MODULE.bootstrap_ci(pos, neg, 0.001)
    # 1 % allows ten false positives (cut 0.1), 0.1 % one (cut 0.7)
    assert (cell["0.01"]["tpr"], cell["0.001"]["tpr"]) == (1.0, 0.3)
    assert "tpr_ci95" not in MODULE.cell_metrics(pos, neg, [], bootstrap=False)


def test_summary_table_shows_both_tprs_base_to_head_with_the_head_ci():
    head = gate_report(0.61, 0.29, ci={"0.01": [0.58, 0.64], "0.001": [0.25, 0.33]})
    lines = MODULE.summary_lines(gate_report(0.6, 0.3), head)
    assert "| class | lang | pos | TPR@1% base -> head [95% CI] | TPR@0.1% base -> head [95% CI] | AUPRC head |" in lines
    assert "| jailbreak | all | 1000 | 60.0 -> 61.0 [58.0–64.0] | 30.0 -> 29.0 [25.0–33.0] | 0.800 |" in lines
    # a class new in the head shows no base value
    new = MODULE.summary_lines({"gated": {}, "hard_benign_flags": {}}, head)
    assert "| jailbreak | all | 1000 | – -> 61.0 [58.0–64.0] | – -> 29.0 [25.0–33.0] | 0.800 |" in new


def test_holdout_verdict_names_checks_without_numbers():
    checks = [{"name": "tpr@1%fpr jailbreak de", "base": 0.5, "head": 0.4, "delta_pp": -10.0, "positives": 50,
               "ok": False},
              {"name": "tpr@0.1%fpr jailbreak de", "base": 0.2, "head": 0.1, "delta_pp": -10.0, "positives": 50,
               "ok": False},
              {"name": "hard-benign new fp jailbreak", "base": 0, "head": 1, "new": 1, "rows": ["h:1"], "ok": False}]
    lines = MODULE.verdict_lines("holdout", checks, numbers=False)
    assert lines == ["holdout: regression (0/3 checks pass)", "  FAIL tpr@1%fpr jailbreak de",
                     "  FAIL tpr@0.1%fpr jailbreak de", "  FAIL hard-benign new fp jailbreak"]
    dev = "\n".join(MODULE.verdict_lines("dev", checks, numbers=True))
    assert "-10.0 pp" in dev and "h:1" in dev


# --- splits, CLI and gate ----------------------------------------------------------------------


SPLIT_ROWS = [
    row("attacks", 0, ["exfiltration"]), row("attacks", 1, ["exfiltration"], language="de"),
    row("benign", 0, benign=True), row("benign", 1, benign=True, language="de"),
]


@pytest.fixture
def split(tmp_path):
    root = tmp_path / "dev"
    freeze(root / "train_dev", SPLIT_ROWS)
    freeze(root / "report", [row("rep", 0, ["jailbreak"]), row("rep", 1, benign=True)], role="report")
    freeze(root / "generated", [row("gen", 0, ["tool_poisoning"]), row("gen", 1, benign=True, twin_of="gen:0000000")],
           schema=CORPORA.GENERATED_SCHEMA)
    (root / ".sources").mkdir()
    return root


def fake_predict(sets, out, package=None, jobs=1, flag=()):
    out.mkdir(parents=True, exist_ok=True)
    for entry in sets:
        rows = list(MODULE.BASELINES.read_rows(entry.path))
        preds = [{"id": r["id"], "scores": {c: 0.9 for c in r["classes"]},
                  "flagged": list(r["classes"]) + [c for c in flag if r["id"] == "gen:0000001"]} for r in rows]
        MODULE.prediction_path(out, entry).write_text("".join(json.dumps(p) + "\n" for p in preds))


def test_split_sets_find_every_frozen_directory_with_its_role(split, tmp_path):
    sets = MODULE.split_sets(split)
    assert {(s.set_id, s.role) for s in sets} == {("attacks", "dev"), ("benign", "dev"), ("rep", "report"),
                                                   ("gen", "dev")}
    assert [s.set_id for s in MODULE.split_sets(split / "train_dev")] == ["attacks", "benign"]
    with pytest.raises(ValueError):
        MODULE.split_sets(tmp_path / "dev" / ".sources")


def test_score_refuses_missing_predictions(split, tmp_path):
    sets = MODULE.split_sets(split)
    with pytest.raises(ValueError):
        MODULE.score_split(sets, {})
    fake_predict(sets, tmp_path / "pred")
    path = MODULE.prediction_path(tmp_path / "pred", sets[0])
    path.write_text(path.read_text().splitlines()[0] + "\n")
    with pytest.raises(ValueError):
        MODULE.score_split(sets, MODULE.ark_predictions(sets, tmp_path / "pred"))


def test_cli_score_and_report(split, tmp_path, capsys):
    sets = MODULE.split_sets(split)
    fake_predict(sets, tmp_path / "pred")
    out = tmp_path / "report.json"
    assert MODULE.main(["score", "--split", str(split), "--predictions", str(tmp_path / "pred"),
                        "--output", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["sets"] == {"dev": ["attacks", "benign", "gen"], "report": ["rep"]}
    assert report["gated"]["exfiltration"]["de"]["all"]["0.01"]["tpr"] == 1.0
    assert MODULE.main(["compare", "--base", str(out), "--head", str(out)]) == 0
    md = tmp_path / "baseline.md"
    assert MODULE.main(["report", "--split", str(split), "--predictions", str(tmp_path / "pred"),
                        "--out", str(md)]) == 0
    text = md.read_text()
    assert "## Gated sets (dev and decisive)" in text and "## Report-only sets" in text
    assert "| exfiltration | de | all | 1 | 1 |" in text and "No positives: instruction_injection" in text
    assert MODULE.main(["score", "--split", str(tmp_path / "nowhere"), "--predictions", str(tmp_path)]) == 2


def test_german_rows_of_a_translated_source_set_score_as_translated(tmp_path):
    # Corpus rows carry no `translated` field; the entity map marks the German part of rtp_lx translated.
    rows = [row("rtp_lx", 0, ["toxic_language"], language="de"), row("rtp_lx", 1, ["toxic_language"]),
            row("rtp_lx", 2, benign=True, language="de"), row("rtp_lx", 3, benign=True)]
    freeze(tmp_path / "train_dev", rows)
    sets = MODULE.split_sets(tmp_path)
    fake_predict(sets, tmp_path / "pred")
    cells = MODULE.score_split(sets, MODULE.ark_predictions(sets, tmp_path / "pred"), bootstrap=False)["gated"]
    cells = cells["toxic_language"]
    assert cells["de"]["translated"]["positives"] == 1 and "native" not in cells["de"]
    assert cells["en"]["native"]["positives"] == 1 and "translated" not in cells["en"]


def cache_baseline(cache, baseline_id, version, sets, score, classes=("exfiltration", "tool_poisoning")):
    for entry in sets:
        target = MODULE.BASELINES.cache_path(cache, baseline_id, version, entry.set_id, entry.sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        rows = list(MODULE.BASELINES.read_rows(entry.path))
        target.write_text("".join(json.dumps({"id": r["id"], "scores": {c: score for c in r["classes"]}}) + "\n"
                                  for r in rows))
        target.with_suffix(".json").write_text(json.dumps({"corpus_sha256": entry.sha256, "classes": classes}))


def test_report_adds_the_best_heuristic_and_reference_baseline(split, tmp_path):
    sets = MODULE.split_sets(split)
    fake_predict(sets, tmp_path / "pred")
    cache = tmp_path / "cache"
    cache_baseline(cache, "atr", "v1", sets, 1)
    cache_baseline(cache, "prompt_guard_2_22m", "v1", sets, 0.9)
    (cache / "pipelock").mkdir()  # nothing cached: left out
    cache_baseline(cache, "protectai_v2", "v1", sets[:1], 0.9)  # one set only: left out
    baselines, left_out = MODULE.baseline_reports(sets, cache)
    assert list(baselines) == ["atr", "prompt_guard_2_22m"]
    assert left_out["pipelock"] == "no cached predictions" and left_out["vigil"] == "no cached predictions"
    assert left_out["protectai_v2"].startswith("`v1` not cached for ")
    assert "atr" not in left_out and "prompt_guard_2_86m" in left_out
    text = MODULE.render_baseline(MODULE.score_split(sets, MODULE.ark_predictions(sets, tmp_path / "pred")),
                                  baselines, "t", left_out)
    assert "best heuristic TPR@1% / 0.1% | best reference TPR@1% / 0.1% |" in text
    assert "| 100.0 / 100.0 (atr) | 100.0 / 100.0 (prompt_guard_2_22m) |" in text
    assert "atr `v1`, prompt_guard_2_22m `v1`." in text
    assert "Not in the columns: pipelock (no cached predictions);" in text
    # A baseline that does not score a class is no candidate for its cells.
    jailbreak = next(line for line in text.splitlines() if line.startswith("| jailbreak | all | all |"))
    assert jailbreak.endswith("| – | – |")


def test_gate_passes_an_unchanged_head_and_keeps_holdout_numbers_in_the_cache(split, tmp_path, monkeypatch, capsys):
    holdout = tmp_path / "holdout"
    freeze(holdout / "holdout", SPLIT_ROWS, role="decisive")
    freeze(holdout / "generated", [row("hgen", 0, ["tool_poisoning"]), row("gen", 1, benign=True, twin_of="x")],
           schema=CORPORA.GENERATED_SCHEMA, role="decisive")
    builds = {"base": "b" * 40, "head": "h" * 40}
    monkeypatch.setattr(MODULE.DLP_SCOREBOARD, "resolve_commit", lambda tree, rev: builds["head" if rev == "HEAD" else "base"])
    monkeypatch.setattr(MODULE.DLP_SCOREBOARD, "ensure_build",
                        lambda tree, commit, cache: MODULE.DLP_SCOREBOARD.Build(commit, commit[:1] * 64, tmp_path / commit[:1], tmp_path))
    monkeypatch.setattr(MODULE.DLP_SCOREBOARD, "prune", lambda cache, keep: None)
    monkeypatch.setattr(MODULE, "predict_split", fake_predict)
    assert MODULE.gate(tmp_path, "base", split, holdout, tmp_path / "cache") == 0
    out = capsys.readouterr().out
    assert "dev: no regression" in out and "holdout: no regression" in out and out.endswith("PASS\n")
    assert "| exfiltration | de | 1 | 100.0 -> 100.0 [100.0–100.0] | 100.0 -> 100.0 [100.0–100.0] | 1.000 |" in out
    dev = json.loads(next((tmp_path / "cache" / "threat-scoreboard" / "reports").glob("*/dev.json")).read_text())
    assert {"tpr@1%fpr exfiltration de", "tpr@0.1%fpr exfiltration de"} <= {c["name"] for c in dev["checks"]}

    def flagging(sets, out, package=None, jobs=1):
        fake_predict(sets, out, flag=("tool_poisoning",) if package == tmp_path / "h" else ())

    monkeypatch.setattr(MODULE, "predict_split", flagging)
    assert MODULE.gate(tmp_path, "base", split, holdout, tmp_path / "cache2") == 1
    out = capsys.readouterr().out
    holdout_part = out.split("holdout:")[1]
    assert "FAIL hard-benign new fp tool_poisoning" in holdout_part and "gen:" not in holdout_part
    reports = list((tmp_path / "cache2" / "threat-scoreboard" / "reports").glob("*/holdout.json"))
    assert len(reports) == 1
