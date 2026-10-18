from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "latency.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_latency", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

_HELPERS = importlib.util.spec_from_file_location("l1_dlp_scoreboard_tests", Path(__file__).with_name(
    "test_l1_dlp_scoreboard.py"))
HELPERS = importlib.util.module_from_spec(_HELPERS)
assert _HELPERS.loader is not None
_HELPERS.loader.exec_module(HELPERS)

# Placeholder carrier texts only; multi-byte characters check the exact byte sizes.
CARRIER_TEXTS = ["API_KEY=placeholder-ä-value\n", "passwort: «nicht-gesetzt»\n", "token = 'xxxxxxxxxxxx'\n"]
SMALL = {"doc_counts": {"short": 3, "4k": 4, "100k": 2}, "doc_bytes": {"4k": 512, "100k": 2048},
         "repo_bytes": 5000, "carrier_every": 256, "repo_carrier_every": 1000}
FAST = {"short": 1, "4k": 1, "100k": 2, "repo": 1}


def carriers() -> list[dict]:
    rows = []
    for index, text in enumerate(CARRIER_TEXTS):
        row = HELPERS.carrier(f"c-{index}", [])
        rows.append(dict(row, text=text, format="env" if index != 1 else "yaml"))
    return rows


def code() -> list[dict]:
    return [{"id": f"alpha:src/m{index}.py", "repo": "alpha", "path": f"src/m{index}.py", "kind": "code",
             "text": f"def f{index}():\n    return 'Grüße'\n" * 20} for index in range(3)]


@pytest.fixture
def dev(tmp_path):
    return HELPERS.write_split(tmp_path / "dev", "dev", carriers(), code(), HELPERS.text_docs())


# ── workloads ────────────────────────────────────────────────────────────────


def test_workloads_have_exact_sizes_and_embed_one_carrier_per_block(dev):
    workloads = MODULE.build_workloads(dev, **SMALL)
    assert [row["text"] for row in workloads["short"]] == [row["text"] for row in MODULE.load_sources(dev)[0]]
    for size, count in (("4k", 4), ("100k", 2)):
        rows = workloads[size]
        assert len(rows) == count
        assert all(len(row["text"].encode("utf-8")) == SMALL["doc_bytes"][size] for row in rows)
        # every block of carrier_every bytes starts with a carrier row
        for row in rows:
            data = row["text"].encode("utf-8")
            starts = [data[offset:offset + 64].decode("utf-8", "ignore")
                      for offset in range(0, len(data), SMALL["carrier_every"])]
            assert all(any(start.startswith(text) for text in CARRIER_TEXTS) for start in starts)
    repo = workloads["repo"]
    assert sum(len(row["text"].encode("utf-8")) for row in repo) == SMALL["repo_bytes"]
    carrier_files = [row for row in repo if "format" in row]
    assert len(carrier_files) == SMALL["repo_bytes"] // SMALL["repo_carrier_every"]
    assert all(row.get("path", "").startswith("src/") for row in repo if "format" not in row)
    ids = [row["id"] for rows in workloads.values() for row in rows]
    assert len(ids) == len(set(ids))


def test_workloads_are_deterministic_and_stats_carry_no_text(dev, tmp_path):
    first, second = MODULE.build_workloads(dev, **SMALL), MODULE.build_workloads(dev, **SMALL)
    assert first == second
    stats = MODULE.workload_stats(first)
    assert stats["4k"] == {"docs": 4, "bytes": 2048, "sha256": stats["4k"]["sha256"]}
    assert not any(text.strip() in json.dumps(stats) for text in CARRIER_TEXTS)
    path = tmp_path / "workloads.jsonl"
    MODULE.write_workloads(first, path)
    assert MODULE.read_workloads(path) == first


def test_default_workloads_match_the_task_sizes():
    assert MODULE.DOC_BYTES == {"4k": 4096, "100k": 102400}
    assert MODULE.REPO_BYTES == 10 * 1024 * 1024
    assert MODULE.SIZES == ("short", "4k", "100k", "repo")


def test_workloads_refuse_a_modified_split(dev):
    with (dev / "synthetic" / "carriers.jsonl").open("a") as handle:
        handle.write("\n")
    with pytest.raises(ValueError, match="does not match"):
        MODULE.build_workloads(dev, **SMALL)


# ── statistics and checks ────────────────────────────────────────────────────


def test_percentiles_use_the_nearest_rank():
    values = [float(value) for value in range(1, 101)]
    assert MODULE.percentile(values, 0.5) == 50.0
    assert MODULE.percentile(values, 0.95) == 95.0
    assert MODULE.percentile([3.0], 0.99) == 3.0
    summary = MODULE.summarize([1.0, 2.0, 3.0, 4.0], [0.004, 0.006], 2 * MODULE.MIB)
    assert summary["p50_ms"] == 2.0 and summary["max_ms"] == 4.0 and summary["rounds"] == 2
    assert summary["mib_per_s"] == pytest.approx(2 / 0.005, rel=1e-3)


def summary(p95: float) -> dict:
    return {"100k": {"p95_ms": p95}}


def checks(base: float, head: float) -> dict[str, bool]:
    return {check["check"]: check["ok"] for check in MODULE.latency_checks(summary(base), summary(head))}


def test_head_may_be_ten_percent_plus_slack_slower_at_100k_p95():
    assert checks(5.0, 5.0 * 1.1 + MODULE.SLACK_MS)["latency:100k_p95_ms"]
    assert not checks(5.0, 5.0 * 1.1 + MODULE.SLACK_MS + 0.01)["latency:100k_p95_ms"]
    assert checks(5.0, 2.0)["latency:100k_p95_ms"]


def test_the_budget_holds_once_the_base_is_within_it():
    assert not checks(9.0, 10.2)["latency:budget_100k_p95_ms"]
    assert checks(9.0, 9.9)["latency:budget_100k_p95_ms"]
    # Above the budget already (before H03): only the relative check applies.
    assert checks(18.0, 18.5)["latency:budget_100k_p95_ms"]


# ── ARK worker and gate ──────────────────────────────────────────────────────


def fake_package(path: Path, delay: float, fail: bool = False) -> Path:
    """A stand-in patronus_ark whose scan sleeps ``delay`` seconds (no native module)."""
    (path / "patronus_ark").mkdir(parents=True)
    (path / "patronus_ark" / "__init__.py").write_text(
        "import time\n"
        "class SecurityGateway:\n"
        "    def __init__(self, **kwargs):\n"
        "        assert kwargs['categories'] == ['dlp'] and kwargs['max_level'] == 'l1'\n"
        "        assert kwargs['execution_gates'] is None\n"
        "    def scan_category(self, category, text):\n"
        f"        time.sleep({delay})\n"
        f"        return [{{'class_name': {'error' if fail else 'dlp'!r}}}]\n"
    )
    return path


def build(tmp_path: Path, name: str, delay: float, fail: bool = False) -> SimpleNamespace:
    return SimpleNamespace(key=name, commit=name, package=fake_package(tmp_path / name, delay, fail))


def test_gate_check_passes_equal_builds_with_alternating_rounds(dev, tmp_path):
    result = MODULE.gate_check(build(tmp_path, "base", 0.0), build(tmp_path, "head", 0.0), dev, tmp_path / "work",
                               rounds=FAST, workload_options=SMALL)
    assert all(check["ok"] for check in result["checks"]) and result["attempts"] == 1
    assert result["head"]["100k"]["samples"] == 2 * 2 and result["head"]["repo"]["docs"] == len(
        MODULE.build_workloads(dev, **SMALL)["repo"])
    assert not list((tmp_path / "work").iterdir())  # the workload file with carrier text is gone
    assert MODULE.gate_lines(result)[0].startswith("dev latency: 100 KiB p95")


def test_gate_check_fails_a_slower_head_only_after_every_attempt(dev, tmp_path):
    result = MODULE.gate_check(build(tmp_path, "base", 0.0), build(tmp_path, "head", 0.005), dev, tmp_path / "work",
                               rounds=FAST, workload_options=SMALL)
    failed = [check["check"] for check in result["checks"] if not check["ok"]]
    assert failed == ["latency:100k_p95_ms"] and result["attempts"] == MODULE.GATE_ATTEMPTS
    assert 5.0 <= result["head"]["100k"]["p95_ms"]
    assert "2 attempts" in MODULE.gate_lines(result)[0]


def test_gate_check_passes_when_a_repeated_measurement_passes(dev, tmp_path, monkeypatch):
    measured = iter([{"base": summary(5.0), "head": summary(9.0)}, {"base": summary(5.0), "head": summary(5.1)}])

    class Worker:
        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(MODULE, "ArkWorker", Worker)
    monkeypatch.setattr(MODULE, "measure_ark", lambda workers, workloads, rounds: next(measured))
    result = MODULE.gate_check(SimpleNamespace(key="a", package=None), SimpleNamespace(key="b", package=None), dev,
                               tmp_path / "work", workload_options=SMALL)
    assert result["attempts"] == 2 and all(check["ok"] for check in result["checks"])
    assert result["head"]["100k"]["p95_ms"] == 5.1


def test_gate_check_skips_a_shared_build(dev, tmp_path):
    same = SimpleNamespace(key="k", package=tmp_path / "missing")
    result = MODULE.gate_check(same, same, dev, tmp_path / "work")
    assert result["checks"] == [] and "not measured" in MODULE.gate_lines(result)[0]


def test_scanner_errors_and_missing_modules_stop_the_worker(dev, tmp_path):
    with pytest.raises(RuntimeError, match="worker exited"):
        MODULE.gate_check(build(tmp_path, "base", 0.0), build(tmp_path, "head", 0.0, fail=True), dev,
                          tmp_path / "work", rounds=FAST, workload_options=SMALL)
    with pytest.raises(RuntimeError, match="worker exited"):
        MODULE.gate_check(SimpleNamespace(key="a", package=tmp_path / "empty"), build(tmp_path, "h2", 0.0), dev,
                          tmp_path / "work", rounds=FAST, workload_options=SMALL)


def test_workers_are_pinned_to_the_last_cpus():
    available = sorted(os.sched_getaffinity(0))
    assert MODULE.pinned_cpus(1) == available[-1:]
    assert MODULE.pinned_cpus(0) is None
    with pytest.raises(ValueError):
        MODULE.pinned_cpus(len(available) + 1)


# ── baselines and bench ──────────────────────────────────────────────────────


def fake_tools(tmp_path: Path, fail: str | None = None) -> tuple[Path, Path, Path]:
    """Executables named like the pinned tools; they log their arguments and write empty reports."""
    bin_dir, log = tmp_path / "bin", tmp_path / "calls.log"
    bin_dir.mkdir()
    outputs = {
        "gitleaks": 'while [ "$1" != "--report-path" ]; do shift; done; echo "[]" > "$2"',
        "trufflehog": "",
        "detect-secrets": """echo '{"files": 1, "errors": 0}'""",
    }
    for tool, output in outputs.items():
        path = bin_dir / ("python" if tool == "detect-secrets" else tool)
        path.write_text(f'#!/bin/sh\necho "{tool} $*" >> {log}\n' + ("exit 3\n" if tool == fail else "")
                        + output + "\n")
        path.chmod(0o755)
    return bin_dir, bin_dir / "python", log


def test_baselines_run_their_default_scan_once_per_round_and_per_invocation(dev, tmp_path):
    bin_dir, python, log = fake_tools(tmp_path)
    workloads = MODULE.build_workloads(dev, **SMALL)
    report = {tool: MODULE.measure_baseline(tool, workloads, FAST, 2, None, bin_dir, python)
              for tool in ("gitleaks", "trufflehog", "detect-secrets")}
    gitleaks = report["gitleaks"]
    assert gitleaks["startup_ms"] > 0 and gitleaks["100k"]["rounds"] == 2 and gitleaks["100k"]["docs"] == 2
    assert gitleaks["4k"]["invocation"]["samples"] == 2 and "invocation" not in gitleaks["repo"]
    assert report["detect-secrets"]["repo"]["errors"] == 0
    calls = log.read_text().splitlines()
    # 3 starts on an empty file + rounds per workload + 2 invocations for short/4k/100k
    expected = 3 + sum(FAST.values()) + 2 * 3
    for tool in ("gitleaks", "trufflehog", "detect-secrets"):
        assert sum(call.startswith(tool + " ") for call in calls) == expected
    assert all("--no-verification" in call for call in calls if call.startswith("trufflehog"))
    assert all(f" {MODULE.DETECT_SECRETS_WORKER} " in call for call in calls if call.startswith("detect-secrets"))
    assert not any(text.strip() in json.dumps(report) for text in CARRIER_TEXTS)


def test_a_failing_baseline_is_an_error(dev, tmp_path):
    bin_dir, python, _ = fake_tools(tmp_path, fail="trufflehog")
    with pytest.raises(RuntimeError, match="trufflehog exited 3"):
        MODULE.measure_baseline("trufflehog", MODULE.build_workloads(dev, **SMALL), FAST, 0, None, bin_dir, python)


def test_bench_reports_every_tool_without_text(dev, tmp_path, monkeypatch):
    bin_dir, python, _ = fake_tools(tmp_path)
    package = fake_package(tmp_path / "ark", 0.0)
    report = MODULE.bench(dev, ["ark", "gitleaks"], ["4k", "repo"], 2, None, package, bin_dir, python,
                          invocations=1, check_pins=False, workload_options=SMALL)
    assert set(report["workloads"]) == {"4k", "repo"} and set(report["tools"]) == {"ark", "gitleaks"}
    ark = report["tools"]["ark"]
    assert ark["4k"]["samples"] == 2 * 4 and ark["startup_ms"] > 0 and ark["repo"]["end_to_end_mib_per_s"] > 0
    lines = MODULE.table_lines(report)
    assert len(lines) == 2 + 4 and lines[2].startswith("| ark | 4 KiB | 4 |")
    assert not any(text.strip() in json.dumps(report) for text in CARRIER_TEXTS)


def test_bench_checks_the_baseline_pins(dev, tmp_path):
    bin_dir, python, _ = fake_tools(tmp_path)
    with pytest.raises(RuntimeError, match="differ from the pins"):
        MODULE.bench(dev, ["gitleaks"], ["4k"], 1, None, None, bin_dir, python, workload_options=SMALL)


def test_cli_rejects_unknown_tools_and_sizes(dev):
    for flag, value in (("--tools", "semgrep"), ("--sizes", "1g")):
        with pytest.raises(SystemExit):
            MODULE.main(["bench", "--dev", str(dev), flag, value])


def test_detect_secrets_worker_counts_files_and_errors(tmp_path):
    pytest.importorskip("detect_secrets")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "config.yaml").write_text("name: demo\n")
    result = subprocess.run([sys.executable, str(SCRIPT), MODULE.DETECT_SECRETS_WORKER, str(tmp_path)],
                            capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {"files": 1, "errors": 0}


def test_loads_without_native_module():
    code = ("import importlib.util, sys; spec = importlib.util.spec_from_file_location('l', sys.argv[1]); "
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); "
            "assert 'patronus_ark' not in sys.modules")
    subprocess.run([sys.executable, "-c", code, str(SCRIPT)], check=True)
