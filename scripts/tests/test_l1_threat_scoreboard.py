from __future__ import annotations

import hashlib
import importlib.util
import json
import math
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
    # Hard-benign FPR at the matched threshold of each TPR (0.95: no negative reaches it), not at L1's
    # decision, which flags the twin.
    assert top["0.01"]["threshold"] == 0.95
    assert top["hard_benign"] == {"rows": 2, "0.01": {"fp": 0, "fpr": 0.0}, "0.001": {"fp": 0, "fpr": 0.0}}
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


def test_obfuscation_invariance_counts_flagged_sources_and_kept_twins():
    def pair(row_id, flagged, **row):
        base = {"id": row_id, "benign": False, "classes": ["instruction_injection"]}
        return {**base, **row}, {"id": row_id, "scores": {}, "flagged": flagged}, "gated"

    pairs = [
        pair("src:1", ["instruction_injection"]),
        pair("src:2", ["instruction_injection"]),
        pair("src:3", []),
        pair("obf:1", ["instruction_injection"], obfuscation="base64", source_id="src:1"),
        pair("obf:2", [], obfuscation="base64", source_id="src:2"),
        pair("obf:3", ["instruction_injection"], obfuscation="hex", source_id="src:3"),
        pair("obf:4", ["jailbreak"], obfuscation="hex", source_id="src:1"),
        pair("obf:5", [], obfuscation="rot13", source_id="missing"),
        pair("twin:1", ["instruction_injection"], obfuscation="base64", source_id="src:1", benign=True, classes=[]),
    ]
    assert MODULE.obfuscation_invariance(pairs) == {
        "base64": {"source_flagged": 2, "kept": 1},
        "hex": {"source_flagged": 1, "kept": 0},
    }
    lines = MODULE.invariance_lines({"obfuscation_invariance": MODULE.obfuscation_invariance(pairs)})
    assert lines[2] == "| base64 | 2 | 1 |"
    assert MODULE.invariance_lines({}) == ["- no obfuscated row with a flagged source"]


def test_compare_fails_a_drop_beyond_tolerance_and_new_hard_benign_fp():
    # A handful of benign rows cannot hold the 0.1 % benign FPR budget; it has its own test below.
    def compare(base, head):
        return [check for check in MODULE.compare(base, head) if not check["name"].startswith("benign fpr")]

    base = MODULE.score_pairs(pairs(), bootstrap=False)
    assert all(check["ok"] for check in compare(base, base))
    worse = [(item, 0.0 if item["id"] == "dev_a:0000002" else score, flagged) for item, score, flagged in PAIRS_ROWS]
    worse.append((row("dev_b", 3, benign=True, twin_of="dev_b:0000000"), 0.0, ("exfiltration",)))
    head = MODULE.score_pairs(pairs(worse), bootstrap=False)
    failed = {check["name"]: check for check in compare(base, head) if not check["ok"]}
    # only the translated German positive passes the cut above the 0.92 twin, at either FPR
    assert set(failed) == {"tpr@1%fpr exfiltration all", "tpr@1%fpr exfiltration de",
                           "tpr@0.1%fpr exfiltration all", "tpr@0.1%fpr exfiltration de",
                           "hard-benign new fp exfiltration"}
    assert failed["hard-benign new fp exfiltration"]["rows"] == ["dev_b:0000003"]
    assert failed["tpr@1%fpr exfiltration de"]["delta_pp"] == -50.0


def budget_report(flags, hard_rows, tpr=0.5):
    cell = {"positives": 1000, "0.01": {"tpr": tpr}, "0.001": {"tpr": tpr}, "hard_benign": {"rows": hard_rows}}
    return {"gated": {"toxic_language": {"all": {"all": cell}}}, "hard_benign_flags": {"toxic_language": flags}}


def test_compare_lets_new_hard_benign_fp_pass_within_the_class_budget():
    # owner decision 2026-11-22: new hard-benign FPs pass while the head FPR of the class stays <= 0.1 %
    base = budget_report([], 2000)
    within = {c["name"]: c for c in MODULE.compare(base, budget_report(["h:1", "h:2"], 2000))}
    check = within["hard-benign new fp toxic_language"]
    assert check["ok"] and check["new"] == 2 and check["head_fpr"] == 0.001 and check["budget"] == 0.001
    assert MODULE.verdict_lines("holdout", list(within.values()), numbers=False)[1] == (
        "  PASS hard-benign new fp toxic_language: 2 new within budget "
        "(head hard-benign FPR 0.1%, budget 0.1%)")
    over = {c["name"]: c for c in MODULE.compare(base, budget_report(["h:1", "h:2", "h:3"], 2000))}
    assert not over["hard-benign new fp toxic_language"]["ok"]
    assert MODULE.verdict_lines("holdout", list(over.values()), numbers=False)[1] == (
        "  FAIL hard-benign new fp toxic_language (head hard-benign FPR 0.15%, budget 0.1%)")
    # within the budget, but a falling TPR of the class keeps the check red
    dropped = {c["name"]: c for c in MODULE.compare(base, budget_report(["h:1"], 2000, tpr=0.4))}
    assert not dropped["hard-benign new fp toxic_language"]["ok"]
    # no hard-benign rows in the gate cell: no FPR, no budget
    assert not {c["name"]: c for c in MODULE.compare(base, budget_report(["h:1"], 0))}[
        "hard-benign new fp toxic_language"]["ok"]


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


def test_cell_metrics_hard_benign_fpr_is_at_the_threshold_of_each_tpr():
    pos = [0.9] * 10
    neg = [0.1] * 990 + [0.5] * 10
    # 1 %: cut 0.5, where two of the three hard benigns count; 0.1 %: cut 0.9, where none does.
    cell = MODULE.cell_metrics(pos, neg, [0.5, 0.5, 0.1], bootstrap=False)
    assert (cell["0.01"]["threshold"], cell["0.001"]["threshold"]) == (0.5, 0.9)
    assert cell["hard_benign"] == {"rows": 3, "0.01": {"fp": 2, "fpr": 2 / 3}, "0.001": {"fp": 0, "fpr": 0.0}}
    assert MODULE.cell_metrics(pos, neg, [], bootstrap=False)["hard_benign"]["0.01"] == {"fp": 0, "fpr": None}


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
              {"name": "hard-benign new fp jailbreak", "base": 0, "head": 1, "new": 1, "rows": ["h:1"],
               "head_fpr": 0.002, "budget": 0.001, "ok": False}]
    lines = MODULE.verdict_lines("holdout", checks, numbers=False)
    assert lines == ["holdout: regression (0/3 checks pass)", "  FAIL tpr@1%fpr jailbreak de",
                     "  FAIL tpr@0.1%fpr jailbreak de",
                     "  FAIL hard-benign new fp jailbreak (head hard-benign FPR 0.2%, budget 0.1%)"]
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


def fake_predict(sets, out, binary=None, config=None, jobs=1, flag=()):
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
        MODULE.score_split(sets, MODULE.core_predictions(sets, tmp_path / "pred"))


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
    cells = MODULE.score_split(sets, MODULE.core_predictions(sets, tmp_path / "pred"), bootstrap=False)["gated"]
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
    text = MODULE.render_baseline(MODULE.score_split(sets, MODULE.core_predictions(sets, tmp_path / "pred")),
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
    monkeypatch.setattr(MODULE, "ensure_predictor",
                        lambda tree, commit, cache: MODULE.Predictor(commit, commit[:1] * 64, tmp_path / commit[:1]))
    monkeypatch.setattr(MODULE.DLP_SCOREBOARD, "prune", lambda cache, keep: None)
    monkeypatch.setattr(MODULE, "predict_split", fake_predict)
    assert MODULE.gate(tmp_path, "base", split, holdout, tmp_path / "cache") == 0
    out = capsys.readouterr().out
    assert "dev: no regression" in out and "holdout: no regression" in out and out.endswith("PASS\n")
    assert "| exfiltration | de | 1 | 100.0 -> 100.0 [100.0–100.0] | 100.0 -> 100.0 [100.0–100.0] | 1.000 |" in out
    dev = json.loads(next((tmp_path / "cache" / "threat-scoreboard" / "reports").glob("*/dev.json")).read_text())
    assert {"tpr@1%fpr exfiltration de", "tpr@0.1%fpr exfiltration de"} <= {c["name"] for c in dev["checks"]}

    seen = []

    def flagging(sets, out, binary, config, jobs=1):
        seen.append(config)
        fake_predict(sets, out, flag=("tool_poisoning",) if binary == tmp_path / "h" else ())

    monkeypatch.setattr(MODULE, "predict_split", flagging)
    assert MODULE.gate(tmp_path, "base", split, holdout, tmp_path / "cache2") == 1
    out = capsys.readouterr().out
    holdout_part = out.split("holdout:")[1]
    assert "FAIL hard-benign new fp tool_poisoning" in holdout_part and "gen:" not in holdout_part
    reports = list((tmp_path / "cache2" / "threat-scoreboard" / "reports").glob("*/holdout.json"))
    assert len(reports) == 1
    # The gate measures the L1 cascade.
    assert seen and all(config == MODULE.L1_CASCADE for config in seen)


# --- Core predictor plumbing ---------------------------------------------------------------------


def test_category_keeps_the_injection_name():
    assert MODULE.category("instruction_injection") == "injection"
    assert MODULE.category("jailbreak") == "jailbreak"


def test_config_defaults_to_l1_only_and_hashes_canonically(tmp_path):
    assert MODULE.load_config(None) == {"scanner": {"max_level": "l1", "cascade": {}}}
    path = tmp_path / "c.json"
    path.write_text('{"scanner": {"wolf": {"bundle_dir": "/m"}, "max_level": "l3", "cascade": {}}}')
    config = MODULE.load_config(path)
    assert MODULE.needs_wolf(config) and not MODULE.needs_wolf(MODULE.L1_CASCADE)
    assert MODULE.config_hash(config) == MODULE.config_hash(json.loads(json.dumps(config, sort_keys=True)))
    assert MODULE.config_hash(config) != MODULE.config_hash(MODULE.L1_CASCADE)
    path.write_text('{"scanner": []}')
    with pytest.raises(ValueError):
        MODULE.load_config(path)


FAKE_PREDICTOR = """\
import hashlib, json, sys
config = open(sys.argv[1], "rb").read()
for line in sys.stdin:
    row = json.loads(line)
    print(json.dumps({"id": row["id"], "scores": {}, "flagged": [], "config": hashlib.sha256(config).hexdigest()}))
"""


def test_predict_split_runs_the_predictor_per_set_with_the_bound_config(split, tmp_path):
    binary = tmp_path / "threat_cascade"
    binary.write_text(f"#!{sys.executable}\n{FAKE_PREDICTOR}")
    binary.chmod(0o755)
    sets = MODULE.split_sets(split)
    out = tmp_path / "pred"
    MODULE.predict_split(sets, out, binary, MODULE.L1_CASCADE, jobs=2)
    bound = (out / MODULE.CONFIG_FILE).read_bytes()
    for entry in sets:
        preds = list(MODULE.BASELINES.read_rows(MODULE.prediction_path(out, entry)))
        assert [p["id"] for p in preds] == [r["id"] for r in MODULE.BASELINES.read_rows(entry.path)]
        assert {p["config"] for p in preds} == {hashlib.sha256(bound).hexdigest()}
    # One directory holds the predictions of one config.
    with pytest.raises(ValueError):
        MODULE.predict_split(sets, out, binary, {"scanner": {}})
    failing = tmp_path / "failing"
    failing.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(3)\n")
    failing.chmod(0o755)
    with pytest.raises(RuntimeError, match="exit 3"):
        MODULE.predict_split(sets, tmp_path / "other", failing, MODULE.L1_CASCADE)


# --- cascade decisions --------------------------------------------------------------------------


QUIET = {"l1": "escalate", "l1_score": 0.0, "decision": "clear", "decided_by": "heuristic"}


def stage(l1, decision, decided_by, l1_score=0.5):
    return {"l1": l1, "l1_score": l1_score, "decision": decision, "decided_by": decided_by}


def cascade_pred(item, ms_l3=None, **stages):
    """A prediction with the cascade answers of ``stages`` (class -> answer); every other class stays quiet."""
    cascade = {cls: stages.get(cls, QUIET) for cls in MODULE.CLASSES}
    ms = {"scan": 1.0 + (ms_l3 or 0.0), "l1": 1.0, **({"l3": ms_l3} if ms_l3 is not None else {})}
    return {"id": item["id"], "scores": {cls: s["l1_score"] for cls, s in stages.items() if s["l1_score"]},
            "flagged": sorted(cls for cls, s in stages.items() if s["l1"] == "detected"), "cascade": cascade, "ms": ms}


INJ = "instruction_injection"
CASCADE_ROWS = [
    # L1 detects: final, decided by the heuristic, no L3.
    (row("dev_a", 0, [INJ]), {INJ: stage("detected", "detected", "heuristic", 0.99)}, None),
    # L1 escalates: L3 decides either way.
    (row("dev_a", 1, [INJ]), {INJ: stage("escalate", "detected", "l3")}, 20.0),
    (row("dev_a", 2, [INJ], language="de"), {INJ: stage("escalate", "clear", "l3")}, 30.0),
    # A jailbreak positive L1 escalates but no later layer answers: clear, still the heuristic's.
    (row("dev_a", 3, ["jailbreak"]), {"jailbreak": stage("escalate", "clear", "heuristic")}, None),
    (row("dolly", 0, benign=True), {INJ: stage("escalate", "clear", "l3")}, 10.0),
    (row("dev_b", 0, benign=True, twin_of="dev_a:0000001"), {INJ: stage("escalate", "detected", "l3")}, 40.0),
    # Below the clear threshold: L1 clears on its own.
    (row("notinject", 0, benign=True), {INJ: stage("clear", "clear", "heuristic", 0.01)}, None),
]


def cascade_pairs(items=CASCADE_ROWS, role="dev"):
    return [(item, cascade_pred(item, ms_l3, **stages), role) for item, stages, ms_l3 in items]


def test_cascade_counts_the_final_decision_and_the_deciding_stage():
    cell = MODULE.cascade_metrics(cascade_pairs())["gated"][INJ]["all"]
    assert (cell["positives"], cell["tp"], cell["negatives"], cell["fp"]) == (3, 2, 3, 1)
    assert cell["tpr"] == pytest.approx(2 / 3) and cell["fpr"] == pytest.approx(1 / 3)
    assert cell["decided_by"] == {"heuristic": 2, "l1_model": 0, "l3": 4}
    assert cell["escalated"] == 4 and cell["escalated_share"] == pytest.approx(4 / 6)
    # No later layer: the escalated jailbreak positive is clear and counts as the heuristic's.
    jailbreak = MODULE.cascade_metrics(cascade_pairs())["gated"]["jailbreak"]["all"]
    assert (jailbreak["positives"], jailbreak["tp"], jailbreak["decided_by"]["heuristic"]) == (1, 0, 4)
    assert MODULE.cascade_metrics(cascade_pairs())["gated"][INJ]["de"]["tp"] == 0


def test_cascade_hard_benign_fpr_is_at_the_same_decision_per_source():
    cell = MODULE.cascade_metrics(cascade_pairs())["gated"][INJ]["all"]
    # The twin L3 detects is a false positive of the same decision the TPR counts; notinject L1 cleared.
    assert cell["hard_benign"] == {"notinject": {"rows": 1, "fp": 0, "fpr": 0.0},
                                   "twins": {"rows": 1, "fp": 1, "fpr": 1.0}}
    assert "dolly" not in cell["hard_benign"]


def test_cascade_needs_cascade_answers():
    item = row("dev_a", 9, [INJ])
    with pytest.raises(ValueError, match="no cascade answer"):
        MODULE.cascade_metrics([(item, {"id": item["id"], "scores": {}, "flagged": []}, "dev")])


def test_a_class_without_a_decision_counts_as_clear_by_no_stage():
    positive = row("dev_a", 7, [INJ])
    benign = row("dolly", 8, benign=True)
    pairs = [(item, {**cascade_pred(item), "cascade": {}}, "dev") for item in (positive, benign)]
    cell = MODULE.cascade_metrics(pairs)["gated"][INJ]["all"]
    assert cell["tpr"] == 0.0 and cell["fpr"] == 0.0
    assert cell["decided_by"] == {stage: 0 for stage in MODULE.STAGES}
    assert MODULE._stage(pairs[0][1], INJ)["l1_score"] == 0.0


def test_stage_latency_counts_l3_only_where_it_ran():
    latency = MODULE.stage_latency(cascade_pairs())
    cell = latency["all"]
    assert cell["rows"] == 7 and cell["l1"] == {"p50": 1.0, "p95": 1.0}
    assert cell["l3"]["runs"] == 4 and cell["l3"]["share"] == pytest.approx(4 / 7)
    assert cell["l3"]["p50"] == 25.0 and cell["l3"]["mean_per_row"] == pytest.approx(100 / 7, abs=1e-3)
    assert latency["de"]["l3"]["runs"] == 1
    with pytest.raises(ValueError):
        MODULE.stage_latency([(row("a", 0), {"id": "a:0000000"}, "dev")])


# --- calibration --------------------------------------------------------------------------------


def calibration_pairs(n=4000):
    """Benign rows with injection scores spread over (0, 1], a few positives and a report-only benign row."""
    pairs = []
    for i in range(n):
        item = row("dolly" if i % 3 else "notinject", i, benign=True)
        score = round((i + 1) / n, 6)
        pairs.append((item, cascade_pred(item, **{INJ: stage("escalate", "clear", "heuristic", score)}), "dev"))
    for i in range(5):
        item = row("dev_a", i, [INJ])
        pairs.append((item, cascade_pred(item, **{INJ: stage("detected", "detected", "heuristic", 1.0)}), "dev"))
    item = row("rep", 0, benign=True)
    pairs.append((item, cascade_pred(item, **{INJ: stage("escalate", "clear", "heuristic", 1.0)}), "report"))
    return pairs


def test_calibrate_holds_one_per_mille_on_the_benign_pool():
    pairs = calibration_pairs()
    config = MODULE.calibrate(pairs, MODULE.L1_CASCADE)
    benign = [p["cascade"][INJ]["l1_score"] for r, p, role in pairs if r["benign"] and role != "report"]
    entry = config["calibration"]["classes"][INJ]
    cuts = config["scanner"]["cascade"]["modules"]["injection"]
    detect = cuts["detect_threshold"]
    flagged = sum(s >= detect for s in benign)
    assert flagged / len(benign) <= 0.001 and entry["detect_fpr"] == flagged / len(benign)
    # The lowest such threshold: one more benign score would be over budget.
    assert sum(s >= max(s for s in benign if s < detect) for s in benign) / len(benign) > 0.001
    clear = cuts["clear_threshold"]
    assert clear <= detect
    assert sum(s >= clear for s in benign) / len(benign) <= 0.01 and entry["escalate_fpr"] <= 0.01
    # The report-only benign row is not in the pool; the base config's deepest layer stays.
    assert config["calibration"]["benign_rows"] == 4000 and config["scanner"]["max_level"] == "l1"
    assert entry["benign_scored"] == 4000 and "detect" not in entry and "clear" not in entry
    # A class without benign scores gets no degenerate cut ("any score above 0"): it keeps the shipped
    # acceptance and escalates every undetected row, reported as not reachable.
    assert "jailbreak" not in config["scanner"]["cascade"]["modules"]
    assert config["calibration"]["classes"]["jailbreak"] == {
        "benign_scored": 0, "detect": MODULE.UNREACHABLE, "clear": MODULE.UNREACHABLE}
    assert MODULE.L1_CASCADE == {"scanner": {"max_level": "l1", "cascade": {}}}


def test_calibrate_keeps_the_shipped_cuts_when_the_benign_scores_cannot_fill_the_budget():
    # 2000 benign rows: the 0.1 % budget is 2 rows, the 1 % budget 20 rows. Three non-zero scores place the
    # detect cut but not the clear cut; two cannot place either, and a stale cut of the base is removed.
    def pairs(scored):
        out = []
        for i in range(2000):
            item = row("dolly", i, benign=True)
            score = 0.5 + i / 100 if i < scored else 0.0
            out.append((item, cascade_pred(item, **{INJ: stage("escalate", "clear", "heuristic", score)}), "dev"))
        return out

    three = MODULE.calibrate(pairs(3), MODULE.L1_CASCADE)
    cuts = three["scanner"]["cascade"]["modules"]["injection"]
    assert cuts == {"detect_threshold": math.nextafter(0.5, math.inf)}
    assert three["calibration"]["classes"][INJ] == {"benign_scored": 3, "detect_fpr": 2 / 2000,
                                                    "clear": MODULE.UNREACHABLE}
    stale = {"scanner": {"max_level": "l1", "cascade": {"modules": {"injection": {
        "detect_threshold": 0.7, "clear_threshold": 0.1}}}}}
    two = MODULE.calibrate(pairs(2), stale)
    assert "injection" not in two["scanner"]["cascade"]["modules"]
    assert two["calibration"]["classes"][INJ] == {"benign_scored": 2, "detect": MODULE.UNREACHABLE,
                                                  "clear": MODULE.UNREACHABLE}
    lines = MODULE.config_lines(two)
    assert lines[2].startswith(f"Detect {MODULE.UNREACHABLE}") and "instruction_injection" in lines[2]
    assert "Core's built-in acceptance" in lines[0]
    assert lines[3].startswith(f"Clear {MODULE.UNREACHABLE}")


def test_calibrate_leaves_out_excluded_rows_and_can_switch_clearing_off():
    pairs = calibration_pairs()
    top = {r["id"] for r, p, role in pairs if role == "dev" and r["benign"] and p["scores"].get(INJ, 0) > 0.99}
    excluded = MODULE.calibrate(pairs, MODULE.L1_CASCADE, exclude=frozenset(top))
    assert excluded["calibration"]["excluded_rows"] == len(top) == 40
    assert excluded["scanner"]["cascade"]["modules"]["injection"]["detect_threshold"] < 0.99
    off = MODULE.calibrate(pairs, MODULE.calibrate(pairs, MODULE.L1_CASCADE), clear_fpr=None)
    assert all("clear_threshold" not in cuts for cuts in off["scanner"]["cascade"]["modules"].values())
    assert "escalate_fpr" not in off["calibration"]["classes"][INJ]
    assert off["calibration"]["clear_fpr"] is None


def test_fpr_threshold_never_counts_a_zero_and_needs_negatives():
    # Too few non-zero scores to fill the budget: no cut rather than "any score above 0".
    assert MODULE.fpr_threshold([0.0] * 10, 0.001) is None
    assert MODULE.fpr_threshold([0.5, 0.0, 0.0, 0.0], 0.5) is None
    assert MODULE.fpr_threshold([0.5, 0.4, 0.3], 0.5) == math.nextafter(0.4, math.inf)
    with pytest.raises(ValueError):
        MODULE.fpr_threshold([], 0.001)


# --- cascade report CLI -------------------------------------------------------------------------


def fake_cascade(sets, out, config=MODULE.L1_CASCADE):
    """Positives: L1 escalates and L3 detects; benign rows: L1 clears, except the twin L3 detects."""
    MODULE.bind_config(out, config)
    for entry in sets:
        preds = []
        for r in MODULE.BASELINES.read_rows(entry.path):
            stages = {cls: stage("escalate", "detected", "l3", 0.4) for cls in r["classes"]}
            if r["id"] == "gen:0000001":
                stages = {"tool_poisoning": stage("escalate", "detected", "l3", 0.4)}
            preds.append(cascade_pred(r, 25.0 if stages else None, **stages))
        MODULE.prediction_path(out, entry).write_text("".join(json.dumps(p) + "\n" for p in preds))


def test_cli_cascade_report_shows_the_operating_point_stages_and_latency(split, tmp_path):
    config = tmp_path / "cascade.json"
    config.write_text(json.dumps({"scanner": {"cascade": {"modules": {"injection": {"clear_threshold": 0.2}}},
                                              "wolf": {"bundle_dir": "/private/models/wolf"}}}))
    sets = MODULE.split_sets(split)
    fake_cascade(sets, tmp_path / "pred", MODULE.load_config(config))
    md = tmp_path / "cascade.md"
    assert MODULE.main(["report", "--cascade", str(config), "--split", str(split), "--predictions",
                        str(tmp_path / "pred"), "--out", str(md)]) == 0
    text = md.read_text()
    assert f"Cascade config `{MODULE.config_hash(MODULE.load_config(config))[:12]}`" in text
    assert "clear thresholds injection 0.2" in text and "L3 Wolf default model at threshold its default" in text
    assert "/private/models" not in text  # no local paths in a public report
    assert ("| class | lang | pos | neg | TPR | FPR | hard-benign FPR | decided heuristic % | decided l1_model % | "
            "decided l3 % | escalated % |") in text
    # The twin L3 detects is the hard-benign FP of tool_poisoning at the same decision.
    assert "| tool_poisoning | all | 1 | 3 | 100.0 | 33.33 | 100.0 (1/1) | 50.0 | 0.0 | 50.0 | 100.0 |" in text
    assert "| tool_poisoning | twins | 1 | 1 | 100.0 |" in text
    assert "### L1 score curve (gated sets (dev and decisive))" in text and "## Latency per stage" in text
    assert "## Report-only sets" in text
    # Predictions of another config are refused.
    assert MODULE.main(["report", "--split", str(split), "--predictions", str(tmp_path / "pred"), "--out", str(md),
                        "--cascade", str(tmp_path / "missing.json")]) == 2
    other = tmp_path / "other.json"
    other.write_text('{"scanner": {}}')
    assert MODULE.main(["report", "--cascade", str(other), "--split", str(split), "--predictions",
                        str(tmp_path / "pred"), "--out", str(md)]) == 2


def test_cli_cascade_counts_only_leaves_rates_and_latency_out(split, tmp_path):
    sets = MODULE.split_sets(split)
    fake_cascade(sets, tmp_path / "pred")
    config = tmp_path / "l1.json"
    config.write_text(json.dumps(MODULE.L1_CASCADE))
    md = tmp_path / "counts.md"
    assert MODULE.main(["report", "--cascade", str(config), "--counts-only", "--split", str(split), "--predictions",
                        str(tmp_path / "pred"), "--out", str(md)]) == 0
    text = md.read_text()
    assert "| tool_poisoning | all | 1 / 1 | 1 / 3 | 1 / 1 | 2 | 0 | 2 | 4 |" in text
    assert "Latency" not in text and "TPR" not in text.split("### L1 score curve")[0]
    assert "deepest layer L1" in text
    # Counts only is a form of the cascade report.
    assert MODULE.main(["report", "--counts-only", "--split", str(split), "--predictions", str(tmp_path / "pred"),
                        "--out", str(md)]) == 2


def test_cli_calibrate_writes_a_config_the_report_names(split, tmp_path, capsys):
    sets = MODULE.split_sets(split)
    fake_cascade(sets, tmp_path / "pred")
    ids = tmp_path / "train-negatives.txt"
    ids.write_text("benign:0000000\n")
    out = tmp_path / "calibrated.json"
    assert MODULE.main(["calibrate", "--split", str(split), "--predictions", str(tmp_path / "pred"),
                        "--exclude-ids", str(ids), "--out", str(out)]) == 0
    config = json.loads(out.read_text())
    assert config["calibration"]["excluded_rows"] == 1 and config["calibration"]["target_fpr"] == 0.001
    # Every class is calibrated; only tool_poisoning has a benign score to place a cut on.
    assert set(config["calibration"]["classes"]) == set(MODULE.CLASSES)
    assert set(config["scanner"]["cascade"]["modules"]) == {"tool_poisoning"}
    assert MODULE.config_hash(config)[:12] in capsys.readouterr().out
    lines = MODULE.config_lines(config)
    assert "Calibrated by `scoreboard.py calibrate` on 2 benign rows at 0.1 % FPR (detect) and 1 % FPR (clear)" in lines[1]
    with pytest.raises(SystemExit):
        MODULE.main(["calibrate", "--split", str(split), "--predictions", str(tmp_path / "pred"), "--no-clear",
                     "--clear-fpr", "0.02", "--out", str(out)])


# --- refresh of main -----------------------------------------------------------------------------


def commit_files(tree, files, message):
    import subprocess
    for name, text in files.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text(text)
    env = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "-C", str(tree), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tree), *env, "commit", "-q", "-m", message], check=True)
    return subprocess.run(["git", "-C", str(tree), "rev-parse", "HEAD"], check=True, capture_output=True,
                          text=True).stdout.strip()


@pytest.fixture
def main_tree(tmp_path, monkeypatch):
    import subprocess
    tree = tmp_path / "main"
    tree.mkdir()
    subprocess.run(["git", "init", "-q", str(tree)], check=True)
    first = commit_files(tree, {"ark-core/src/lib.rs": "// v1\n", "README.md": "x\n"}, "first")
    built = []

    def predictor(tree_, commit, cache, wolf=False):
        built.append((commit, wolf))
        return MODULE.Predictor(commit, "k" * 64, tmp_path / "bin")

    monkeypatch.setattr(MODULE, "ensure_predictor", predictor)
    monkeypatch.setattr(MODULE, "predict_split", fake_predict)
    monkeypatch.setattr(MODULE.DLP_SCOREBOARD, "prune", lambda cache, keep: None)
    return tree, first, built


def test_refresh_renders_baseline_of_head_with_the_commit_and_both_tprs(split, tmp_path, main_tree, capsys):
    tree, first, built = main_tree
    cache = tmp_path / "bcache"
    sets = MODULE.split_sets(split)
    cache_baseline(cache, "atr", "v1", sets, 1)
    assert MODULE.main(["refresh", "--tree", str(tree), "--dev", str(split), "--cache", str(tmp_path / "cache"),
                        "--baseline-cache", str(cache)]) == 0
    text = (tree / MODULE.SCOREBOARD_DIR / "baseline.md").read_text()
    assert f"{MODULE.RENDERED_FROM} `{first[:12]}` on the dev split." in text
    assert "| TPR@1% | 95% CI | TPR@0.1% |" in text and "hard-benign FPR" in text
    assert "| 100.0 / 100.0 (atr) |" in text
    # Without a calibrated cascade config only baseline.md is rendered, with the L1 build.
    assert not (tree / MODULE.SCOREBOARD_DIR / "cascade.md").exists() and built == [(first, False)]
    assert "rewrote research/l1-threat/scoreboard/baseline.md" in capsys.readouterr().out


def test_refresh_skips_commits_without_detector_scorer_or_gold_change(split, tmp_path, main_tree, capsys):
    tree, first, built = main_tree
    args = ["refresh", "--tree", str(tree), "--dev", str(split), "--cache", str(tmp_path / "c")]
    assert MODULE.main(args) == 0 and len(built) == 1
    rendered = (tree / MODULE.SCOREBOARD_DIR / "baseline.md").read_text()
    first = commit_files(tree, {str(MODULE.SCOREBOARD_DIR / "baseline.md"): rendered}, "scoreboard")
    commit_files(tree, {"README.md": "docs only\n"}, "docs")
    args += ["--since", first]
    capsys.readouterr()
    assert MODULE.main(args) == 0
    assert "nothing to render" in capsys.readouterr().out and len(built) == 1
    for path in ("ark-core/src/lib.rs", "scripts/l1_threat/scoreboard.py", "research/l1-threat/scoreboard/gold-dev.json"):
        commit_files(tree, {path: f"// {path}\n"}, path)
        assert path in MODULE.changed_paths(tree, first, "HEAD")
    assert MODULE.main(args) == 0 and len(built) == 2
    # A new subclass label file changes the cascade report's subclass section.
    labels = str(MODULE.HARMFUL_SUBCLASS.LABELS_PATH.relative_to(MODULE.ROOT))
    assert any(labels.startswith(path) for path in MODULE.REFRESH_PATHS)


def test_refresh_rerenders_after_a_dev_refreeze_or_new_cached_baselines_without_code_change(split, tmp_path,
                                                                                            main_tree, capsys):
    tree, first, built = main_tree
    cache = tmp_path / "bcache"
    args = ["refresh", "--tree", str(tree), "--dev", str(split), "--cache", str(tmp_path / "c"),
            "--baseline-cache", str(cache)]
    assert MODULE.main(args) == 0
    path = tree / MODULE.SCOREBOARD_DIR / "baseline.md"
    recorded = MODULE.recorded_inputs(path)
    assert recorded == MODULE.inputs_fingerprint(MODULE.split_sets(split), cache)
    since = commit_files(tree, {str(MODULE.SCOREBOARD_DIR / "baseline.md"): path.read_text()}, "scoreboard")
    args += ["--since", since]
    assert MODULE.main(args) == 0 and len(built) == 1
    # The dev split is re-frozen with a new set; main's code is unchanged.
    freeze(split / "generated", [row("gen", 0, ["tool_poisoning"]), row("gen", 1, benign=True, twin_of="gen:0000000"),
                                 row("gen2", 0, ["memory_poisoning"])], schema=CORPORA.GENERATED_SCHEMA)
    capsys.readouterr()
    assert MODULE.main(args) == 0 and len(built) == 2
    assert "rewrote research/l1-threat/scoreboard/baseline.md" in capsys.readouterr().out
    assert '"gen2"' in path.read_text() and MODULE.recorded_inputs(path) != recorded
    # Baselines cached for the new split re-render the baseline column, again without a code change.
    recorded = MODULE.recorded_inputs(path)
    cache_baseline(cache, "atr", "v1", MODULE.split_sets(split), 1)
    assert MODULE.main(args) == 0 and len(built) == 3
    assert "| 100.0 / 100.0 (atr) |" in path.read_text() and MODULE.recorded_inputs(path) != recorded
    assert MODULE.main(args) == 0 and len(built) == 3


def test_refresh_rerenders_after_a_set_moves_between_dev_and_report_with_the_same_contents(split, tmp_path,
                                                                                          main_tree, capsys):
    tree, first, built = main_tree
    args = ["refresh", "--tree", str(tree), "--dev", str(split), "--cache", str(tmp_path / "c")]
    assert MODULE.main(args) == 0
    path = tree / MODULE.SCOREBOARD_DIR / "baseline.md"
    recorded = MODULE.recorded_inputs(path)
    since = commit_files(tree, {str(MODULE.SCOREBOARD_DIR / "baseline.md"): path.read_text()}, "scoreboard")
    args += ["--since", since]
    # The report set is re-frozen into dev scope: same JSONL bytes and hashes, only its role changes.
    freeze(split / "report", [row("rep", 0, ["jailbreak"]), row("rep", 1, benign=True)], role="dev")
    capsys.readouterr()
    assert MODULE.main(args) == 0 and len(built) == 2
    assert MODULE.recorded_inputs(path) != recorded


def test_refresh_keeps_a_report_whose_numbers_did_not_change(split, tmp_path, main_tree, capsys):
    tree, first, _ = main_tree
    args = ["refresh", "--tree", str(tree), "--dev", str(split), "--cache", str(tmp_path / "c")]
    assert MODULE.main(args) == 0
    path = tree / MODULE.SCOREBOARD_DIR / "baseline.md"
    commit_files(tree, {"ark-core/src/lib.rs": "// v2\n"}, "same numbers")
    assert MODULE.main(args) == 0
    assert f"`{first[:12]}`" in path.read_text() and "numbers unchanged" in capsys.readouterr().out
    assert MODULE.write_rendered(path, path.read_text().replace("100.0", " 99.0")) is True


def test_refresh_renders_cascade_md_from_the_calibrated_config_of_main(split, tmp_path, main_tree, monkeypatch):
    tree, _, built = main_tree
    config = {"scanner": {"cascade": {"modules": {"injection": {"clear_threshold": 0.2}}},
                          "wolf": {"bundle_dir": "/private/models/wolf"}}}
    head = commit_files(tree, {str(MODULE.CASCADE_CONFIG): json.dumps(config)}, "calibrated")
    seen = []

    def predict(sets, out, binary, config, jobs=1):
        seen.append(config)
        (fake_predict if config == MODULE.L1_CASCADE else fake_cascade)(sets, out, config)

    monkeypatch.setattr(MODULE, "predict_split", predict)
    assert MODULE.main(["refresh", "--tree", str(tree), "--dev", str(split), "--cache", str(tmp_path / "c")]) == 0
    text = (tree / MODULE.SCOREBOARD_DIR / "cascade.md").read_text()
    assert f"Cascade config `{MODULE.config_hash(config)[:12]}`" in text and f"`{head[:12]}`" in text
    assert "/private/models" not in text
    assert seen == [MODULE.L1_CASCADE, config] and built == [(head, False), (head, True)]


HC = "harmful_content"


def test_subclass_metrics_split_harmful_positives_by_label_and_mark_gaps_and_off():
    items = [(row("dev_h", i, [HC]), {HC: stage("detected", "detected", "heuristic") if i < 15 else QUIET})
             for i in range(25)]
    items += [(row("dev_h", 30 + i, [HC], language="de"), {HC: stage("escalate", "detected", "l1_model")})
              for i in range(3)]
    items += [(row("dev_h", 40, [HC]), {HC: QUIET}), (row("dolly", 0, benign=True), {HC: QUIET})]
    labels = {item["id"]: "nonviolent_crime" for item, _ in items[:25]}
    labels.update({item["id"]: "privacy" for item, _ in items[25:28]})
    pairs = [(item, cascade_pred(item, None, **stages), "dev") for item, stages in items]
    cells = MODULE.subclass_metrics(pairs, labels)
    crime = cells["nonviolent_crime"]["en"]
    assert (crime["positives"], crime["tp"], crime["tpr"]) == (25, 15, 0.6)
    assert not crime["gap"] and not crime["off"]
    # Three German privacy rows: a gap, and a model-only subclass the model detects.
    privacy = cells["privacy"]["de"]
    assert privacy["gap"] and privacy["tpr"] == 1.0 and not privacy["off"]
    # The rules alone: the heuristic detected the 15 crime rows, none of the privacy rows.
    assert (crime["rules_tp"], crime["rules_tpr"], privacy["rules_tp"]) == (15, 0.6, 0)
    assert cells["unlabelled"]["all"]["positives"] == 1 and set(cells) == {*MODULE.HARMFUL_SUBCLASS.SUBCLASSES, "unlabelled"}
    lines = MODULE.subclass_lines({"subclasses": cells}, counts_only=True)
    assert "| `nonviolent_crime` | 15/25, rules 15 | 0/0, rules 0 gap | 15/25, rules 15 |" in lines
    assert lines[-1].startswith("| `unlabelled` |")
    assert "gap" in next(line for line in lines if "`privacy`" in line)
    assert "| `nonviolent_crime` | 60.0 (25), rules 60.0 | – (0), rules – gap | 60.0 (25), rules 60.0 |" in MODULE.subclass_lines({"subclasses": cells}, False)


def test_subclass_metrics_name_zero_positive_subclasses_and_languages_as_gaps():
    items = [(row("dev_h", i, [HC]), {HC: QUIET}) for i in range(25)]
    pairs = [(item, cascade_pred(item, None, **stages), "dev") for item, stages in items]
    cells = MODULE.subclass_metrics(pairs, {item["id"]: "nonviolent_crime" for item, _ in items})
    assert set(MODULE.HARMFUL_SUBCLASS.SUBCLASSES) <= set(cells)
    # A subclass without positives and a language without positives stay in the table as unmeasured gaps.
    for cell in (cells["elections"]["all"], cells["nonviolent_crime"]["de"]):
        assert (cell["positives"], cell["tp"], cell["tpr"], cell["gap"], cell["off"]) == (0, 0, None, True, False)
    assert "| `elections` | – (0), rules – gap | – (0), rules – gap | – (0), rules – gap |" in MODULE.subclass_lines({"subclasses": cells}, False)
    assert "| `nonviolent_crime` | 0/25, rules 0 | 0/0, rules 0 gap | 0/25, rules 0 |" in MODULE.subclass_lines({"subclasses": cells}, True)


def test_subclass_metrics_mark_a_weak_model_only_subclass_off():
    items = [(row("dev_h", i, [HC]), {HC: stage("escalate", "detected", "l1_model") if i < 9 else QUIET})
             for i in range(20)]
    pairs = [(item, cascade_pred(item, None, **stages), "dev") for item, stages in items]
    cell = MODULE.subclass_metrics(pairs, {item["id"]: "elections" for item, _ in items})["elections"]["all"]
    assert cell["tpr"] == 0.45 and cell["off"] and not cell["gap"]
    # Report-only rows never count.
    assert MODULE.subclass_metrics([(i, p, "report") for i, p, _ in pairs], {}) == {}


def test_compare_holds_the_benign_fpr_budget_per_class_and_language():
    # owner decision 2026-11-23: L1's benign FPR at its detect cut stays <= 0.1 % per class and language
    def report(flagged_de):
        rows = [(row("dev_b", i, benign=True, language="de"), 0.9 if i < flagged_de else 0.0,
                 ("harmful_content",) if i < flagged_de else ()) for i in range(1000)]
        rows += [(row("dev_e", i, benign=True), 0.0, ()) for i in range(1000)]
        rows += [(row("dev_h", i, ["harmful_content"], language=lang), 0.95, ("harmful_content",))
                 for i, lang in enumerate(["de", "en"] * 5)]
        return MODULE.score_pairs([(item, pred(item, score, flagged, cls="harmful_content"), "dev")
                                   for item, score, flagged in rows], bootstrap=False)

    base = report(0)
    within = {c["name"]: c for c in MODULE.compare(base, report(1))}
    assert within["benign fpr harmful_content de"]["ok"] and within["benign fpr harmful_content de"]["head"] == 0.001
    over = {c["name"]: c for c in MODULE.compare(base, report(2))}
    # 2 of 1000 German benign rows: red in German although `all` (2 of 2000) holds
    assert not over["benign fpr harmful_content de"]["ok"]
    assert over["benign fpr harmful_content all"]["ok"] and over["benign fpr harmful_content en"]["ok"]
    assert "  FAIL benign fpr harmful_content de (head benign FPR 0.2%, budget 0.1%)" in MODULE.verdict_lines(
        "dev", list(over.values()), numbers=False)
    assert "  FAIL benign fpr harmful_content de: head benign FPR 0.2%, budget 0.1%" in MODULE.verdict_lines(
        "dev", list(over.values()), numbers=True)
