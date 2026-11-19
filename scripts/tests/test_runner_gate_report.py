from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "research" / "l1-pii" / "runner" / "ark-l1"
SCOREBOARD = ROOT / "scripts" / "l1_threat" / "scoreboard.py"


def load_scoreboard():
    spec = importlib.util.spec_from_file_location("l1_threat_scoreboard_gate_report", SCOREBOARD)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    monkeypatch.setenv("ARK_L1_PROGRAM", "threat")
    monkeypatch.setenv("ARK_L1_ROOT", str(tmp_path / "ark-l1"))
    loader = importlib.machinery.SourceFileLoader("ark_l1_runner_gate_report", str(RUNNER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setattr(sys, "argv", ["ark-l1"])
    loader.exec_module(module)
    return module


def test_gate_report_keeps_the_threat_summary_row_of_every_class_and_language(runner):
    board = load_scoreboard()
    cell = {"positives": 100, "negatives": 1000, "auprc": 0.9, "0.01": {"tpr": 0.6}, "0.001": {"tpr": 0.3},
            "tpr_ci95": {"0.01": [0.5, 0.7], "0.001": [0.2, 0.4]}}
    gated = {cls: {language: {"all": cell} for language in board.GATE_LANGUAGES} for cls in board.CLASSES}
    report = {"gated": gated, "hard_benign_flags": {}}
    checks = board.compare(report, report)
    # A green threat gate prints, like scoreboard.py `gate`: header, dev table, dev and holdout verdicts.
    stdout = "\n".join(["threat scoreboard: head h (build h) vs base b (build b)",
                        *board.summary_lines(report, report), *board.verdict_lines("dev", checks, numbers=True),
                        *board.verdict_lines("holdout", checks, numbers=False), "threat scoreboard: PASS"]) + "\n"
    kept = runner.scoreboard_summary(stdout)
    assert "dev TPR at matched FPR (origin all):" in kept
    for cls in board.CLASSES:
        for language in board.GATE_LANGUAGES:
            assert any(line.startswith(f"| {cls} | {language} | 100 |") for line in kept), (cls, language)
    assert kept[-3:] == [f"dev: no regression ({len(checks)}/{len(checks)} checks pass)",
                         f"holdout: no regression ({len(checks)}/{len(checks)} checks pass)",
                         "threat scoreboard: PASS"]


def test_gate_report_keeps_a_bounded_tail_of_a_long_scoreboard(runner):
    stdout = "\n".join(f"line {i}" for i in range(500))
    kept = runner.scoreboard_summary(stdout)
    assert len(kept) == runner.GATE_SCOREBOARD_LINES and kept[-1] == "line 499"
