from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "research" / "l1-pii" / "runner" / "ark-l1"


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    monkeypatch.setenv("ARK_L1_PROGRAM", "threat")
    monkeypatch.setenv("ARK_L1_ROOT", str(tmp_path / "ark-l1"))
    loader = importlib.machinery.SourceFileLoader("ark_l1_runner_threat", str(RUNNER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setattr(sys, "argv", ["ark-l1"])
    loader.exec_module(module)
    return module


def fake_sandbox(calls: list[list[str]], compare_codes: list[int]):
    def sandbox(cmd, cwd, rw, env, *, network=True, readable=(), max_sec=3600):
        calls.append(cmd)
        code = compare_codes.pop(0) if cmd[2] == "compare" else 0
        return subprocess.CompletedProcess(cmd, code, stdout=f"RESULT: {code}\n", stderr="")
    return sandbox


def trees(tmp_path):
    return {"base": tmp_path / "verify-base", "head": tmp_path / "verify-head"}


def test_threat_latency_ab_prepares_the_corpus_and_measures_head_with_the_base_harness(runner, tmp_path, monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(runner, "sandbox", fake_sandbox(calls, [0]))
    result = runner._threat_latency_ab(trees(tmp_path), tmp_path / "out")
    assert result == {"lines": ["attempt 1: RESULT: 0"], "regression": False}
    script = str(tmp_path / "verify-base" / "scripts/l1_threat/latency.py")
    assert [cmd[1:3] for cmd in calls] == [[script, "prepare"], [script, "run"], [script, "run"], [script, "compare"]]
    assert calls[0][calls[0].index("--out") + 1] == str(runner.THREAT_LATENCY_CORPUS)
    assert [cmd[cmd.index("--repo") + 1] for cmd in calls[1:3]] == [
        str(tmp_path / "verify-base"), str(tmp_path / "verify-head")]


def test_threat_latency_ab_reports_a_regression_only_when_every_attempt_regresses(runner, tmp_path, monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(runner, "sandbox", fake_sandbox(calls, [1, 0]))
    assert runner._threat_latency_ab(trees(tmp_path), tmp_path / "out")["regression"] is False
    attempts = runner.VERIFY_LATENCY_ATTEMPTS
    calls.clear()
    monkeypatch.setattr(runner, "sandbox", fake_sandbox(calls, [1] * attempts))
    result = runner._threat_latency_ab(trees(tmp_path), tmp_path / "out")
    assert result["regression"] is True
    assert len(result["lines"]) == attempts
    assert sum(cmd[2] == "compare" for cmd in calls) == attempts


def test_threat_latency_ab_raises_on_a_setup_error(runner, tmp_path, monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(runner, "sandbox", fake_sandbox(calls, [2]))
    with pytest.raises(RuntimeError, match="compare exit 2"):
        runner._threat_latency_ab(trees(tmp_path), tmp_path / "out")
