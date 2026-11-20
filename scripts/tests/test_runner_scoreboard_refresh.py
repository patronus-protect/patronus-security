from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "research" / "l1-pii" / "runner" / "ark-l1"
GIT_ID = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]


def load_runner(tmp_path, monkeypatch, program="threat", lane=None):
    monkeypatch.setenv("ARK_L1_PROGRAM", program)
    monkeypatch.setenv("ARK_L1_ROOT", str(tmp_path / "ark-l1"))
    if lane is None:
        monkeypatch.delenv("ARK_L1_LANE", raising=False)
    else:
        monkeypatch.setenv("ARK_L1_LANE", lane)
    loader = importlib.machinery.SourceFileLoader(f"ark_l1_runner_refresh_{program}_{lane}", str(RUNNER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setattr(sys, "argv", ["ark-l1"])
    loader.exec_module(module)
    return module


def sh(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    """The threat runner with a trusted clone whose origin (a bare repository) has main with a scoreboard."""
    module = load_runner(tmp_path, monkeypatch)
    origin = tmp_path / "origin.git"
    sh("git", "init", "-q", "--bare", "-b", "main", str(origin))
    seed = tmp_path / "seed"
    sh("git", "clone", "-q", str(origin), str(seed))
    (seed / module.SCOREBOARD_DIR).mkdir(parents=True)
    (seed / module.SCOREBOARD_DIR / "baseline.md").write_text("# old\n")
    sh("git", "-C", str(seed), "add", "-A")
    sh("git", "-C", str(seed), *GIT_ID, "commit", "-q", "-m", "main")
    sh("git", "-C", str(seed), "push", "-q", "origin", "HEAD:main")
    sh("git", "clone", "-q", str(origin), str(module.REPO))
    sh("git", "-C", str(module.REPO), "config", "user.name", "runner")
    sh("git", "-C", str(module.REPO), "config", "user.email", "runner@example.invalid")
    module.STATE.mkdir(parents=True, exist_ok=True)
    return module


def fake_sandbox(calls, text="# new\n"):
    def sandbox(cmd, cwd, rw, env, *, network=True, readable=(), max_sec=3600):
        calls.append({"cmd": cmd, "rw": rw, "network": network, "readable": readable})
        if text is not None:
            (cwd / "research/l1-threat/scoreboard/baseline.md").write_text(text)
        return subprocess.CompletedProcess(cmd, 0, stdout="threat scoreboard refresh of abc: rewrote baseline.md\n",
                                           stderr="")
    return sandbox


def fake_gh(runner, monkeypatch, gh_calls, existing="[]"):
    real = runner.run

    def run(cmd, cwd=None, check=True, env=None):
        if cmd[0] == "gh":
            gh_calls.append(cmd)
            return existing if cmd[2] == "list" else "https://github.com/o/r/pull/7"
        return real(cmd, cwd=cwd, check=check, env=env)

    monkeypatch.setattr(runner, "run", run)


def test_refresh_pushes_the_rerendered_scoreboard_as_one_follow_up_pr(runner, monkeypatch, capsys):
    calls, gh_calls = [], []
    monkeypatch.setattr(runner, "sandbox", fake_sandbox(calls))
    fake_gh(runner, monkeypatch, gh_calls)
    main = runner.git("rev-parse", "origin/main")
    assert runner.cmd_refresh() == 0
    out = capsys.readouterr().out
    assert "REFRESH_PR=https://github.com/o/r/pull/7" in out
    # main's scoreboard.py runs sandboxed on the dev split: no network, no holdout, no --since the first time.
    cmd = calls[0]["cmd"]
    assert cmd[1].endswith("scripts/l1_threat/scoreboard.py") and cmd[2] == "refresh" and "--since" not in cmd
    assert calls[0]["network"] is False and runner.HOLDOUT not in calls[0]["readable"]
    assert runner.HOLDOUT not in calls[0]["rw"] and cmd[cmd.index("--dev") + 1] == str(runner.DEV_DATA)
    # The branch holds one commit on main with the new report.
    pushed = sh("git", "-C", str(runner.REPO), "ls-remote", "origin", runner.SCOREBOARD_BRANCH).split()[0]
    assert runner.git("rev-parse", f"{pushed}^") == main
    assert runner.git("show", f"{pushed}:research/l1-threat/scoreboard/baseline.md") == "# new"
    create = next(c for c in gh_calls if c[2] == "create")
    assert create[create.index("--base") + 1] == "main" and create[create.index("--label") + 1] == "ark-threat"
    assert json.loads(runner.SCOREBOARD_STATE.read_text()) == {"rendered_from": main}
    assert not (runner.GATE_TREES / "refresh").exists()
    # main did not move: nothing runs.
    assert runner.cmd_refresh() == 0 and len(calls) == 1 and "up to date" in capsys.readouterr().out


def test_refresh_passes_since_and_opens_no_pr_when_no_report_changed(runner, monkeypatch, capsys):
    calls, gh_calls = [], []
    monkeypatch.setattr(runner, "sandbox", fake_sandbox(calls, text=None))
    fake_gh(runner, monkeypatch, gh_calls)
    runner.save(runner.SCOREBOARD_STATE, {"rendered_from": "0" * 40})
    assert runner.cmd_refresh() == 0
    cmd = calls[0]["cmd"]
    assert cmd[cmd.index("--since") + 1] == "0" * 40
    assert gh_calls == [] and "REFRESH=no report changed" in capsys.readouterr().out
    assert json.loads(runner.SCOREBOARD_STATE.read_text())["rendered_from"] == runner.git("rev-parse", "origin/main")


def test_refresh_failure_keeps_the_last_render_for_the_next_run(runner, monkeypatch, capsys):
    def failing(cmd, cwd, rw, env, *, network=True, readable=(), max_sec=3600):
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="threat scoreboard: error: boom\n")

    monkeypatch.setattr(runner, "sandbox", failing)
    assert runner.cmd_refresh() == 1
    assert "REFRESH_ERROR=exit 2" in capsys.readouterr().out and not runner.SCOREBOARD_STATE.exists()


def test_refresh_commit_updates_only_changed_reports(runner):
    main = runner.git("rev-parse", "origin/main")
    tree = runner.REPO
    assert runner.refresh_commit(tree, main) is None
    (tree / runner.SCOREBOARD_DIR / "cascade.md").write_text("# cascade\n")
    commit = runner.refresh_commit(tree, main)
    assert runner.git("diff", "--name-only", main, commit).split() == ["research/l1-threat/scoreboard/cascade.md"]
    assert "scoreboard of main" in runner.git("log", "-1", "--format=%s", commit)


@pytest.mark.parametrize("program,lane", [("dlp", None), ("threat", "b")])
def test_refresh_runs_only_for_threat_in_lane_a(tmp_path, monkeypatch, capsys, program, lane):
    module = load_runner(tmp_path, monkeypatch, program, lane)
    monkeypatch.setattr(module, "git", lambda *a, **k: pytest.fail("no git"))
    assert module.cmd_refresh() == 0 and "REFRESH=none" in capsys.readouterr().out
