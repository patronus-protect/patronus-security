"""The examples that need no model files run against the installed package."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import runpy

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def run(name: str) -> str:
    out = StringIO()
    with redirect_stdout(out):
        runpy.run_path(str(EXAMPLES / name), run_name="__main__")
    return out.getvalue()


@pytest.fixture(scope="module")
def threat_output() -> str:
    return run("02_threat_l1.py")


def test_pii_dlp_example_finds_and_redacts():
    out = run("01_pii_dlp.py")
    assert "Reach me at <EMAIL> or <PHONE>." in out
    assert "dlp  class=CREDENTIAL" in out
    assert "without pii_email: 3 spans" in out
    assert "tool output: 0 spans" in out


@pytest.mark.parametrize("line", [
    "injection:instruction_override",
    "unsafe_action:unsafe_action",
    "tool_poisoning:tool_poisoning",
    "injection(heuristic)",
    "(l1_model)",
])
def test_threat_l1_example_reports_rules_and_l1_models(threat_output, line):
    assert line in threat_output


def test_threat_l1_example_leaves_the_benign_input_clear(threat_output):
    benign = [row for row in threat_output.splitlines() if row.startswith("Please summarize")]
    assert len(benign) == 2 and all(not row[40:].strip() for row in benign)
