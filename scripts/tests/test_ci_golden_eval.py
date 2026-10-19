"""CI runs the L1 golden evaluation (13_l1_golden_eval) for both PII and DLP."""
from pathlib import Path
import shlex

import yaml


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = "13_l1_golden_eval"


def _golden_steps():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return [
        step
        for step in workflow["jobs"]["rust"]["steps"]
        if EXAMPLE in step.get("run", "")
    ]


def test_rust_job_runs_the_golden_eval_once():
    assert len(_golden_steps()) == 1, f"ci.yml rust job must run {EXAMPLE} exactly once"


def test_golden_eval_covers_both_suites_with_the_locked_lockfile():
    (step,) = _golden_steps()
    argv = shlex.split(step["run"])
    assert argv[:2] == ["cargo", "run"], step["run"]
    assert "--locked" in argv
    assert argv[argv.index("--example") + 1] == EXAMPLE
    suite = argv[argv.index("--") + 1:] if "--" in argv else []
    # No suite argument means `all`; `pii` or `dlp` alone would skip a fixture.
    assert suite in ([], ["all"]), f"golden eval must cover pii and dlp, got {suite}"


def test_golden_eval_runs_from_the_rust_package():
    (step,) = _golden_steps()
    # The example resolves fixtures relative to rust/.
    assert step.get("working-directory") == "rust"


def test_golden_eval_fixtures_exist():
    data = ROOT / "python" / "patronus_ark" / "benchmark_data"
    for name in ("pii_l1.jsonl", "dlp_l1.jsonl"):
        assert (data / name).is_file(), name
    assert (ROOT / "python" / "patronus_ark" / "dlp_synth" / "generators.json").is_file()
    assert (ROOT / "rust" / "examples" / f"{EXAMPLE}.rs").is_file()
