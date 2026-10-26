"""Golden CI preserves both suites while selecting only affected domains."""
from pathlib import Path
import shlex

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = "13_l1_golden_eval"
CONDITIONS = {
    "all": "needs.changes.outputs.pii == 'true' && needs.changes.outputs.dlp == 'true'",
    "pii": "needs.changes.outputs.pii == 'true' && needs.changes.outputs.dlp != 'true'",
    "dlp": "needs.changes.outputs.dlp == 'true' && needs.changes.outputs.pii != 'true'",
}


def _golden_steps():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return [step for step in workflow["jobs"]["rust"]["steps"] if EXAMPLE in step.get("run", "")]


def test_golden_eval_has_one_step_per_selection():
    suites = [shlex.split(step["run"])[-1] for step in _golden_steps()]
    assert sorted(suites) == ["all", "dlp", "pii"]


@pytest.mark.parametrize("suite", CONDITIONS)
def test_golden_eval_keeps_locked_execution_and_correct_condition(suite):
    (step,) = [step for step in _golden_steps() if shlex.split(step["run"])[-1] == suite]
    argv = shlex.split(step["run"])
    assert argv == ["cargo", "run", "--locked", "--example", EXAMPLE, "--", suite]
    assert step["working-directory"] == "rust"
    assert step["if"] == CONDITIONS[suite]


def test_golden_eval_fixtures_exist():
    data = ROOT / "python" / "patronus_ark" / "benchmark_data"
    for name in ("pii_l1.jsonl", "dlp_l1.jsonl"):
        assert (data / name).is_file(), name
    assert (ROOT / "python" / "patronus_ark" / "dlp_synth" / "generators.json").is_file()
    assert (ROOT / "rust" / "examples" / f"{EXAMPLE}.rs").is_file()
