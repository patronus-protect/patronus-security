from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("_ark_generate_docs_rule_catalog", ROOT / "scripts" / "generate_docs.py")
GENERATE_DOCS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = GENERATE_DOCS
SPEC.loader.exec_module(GENERATE_DOCS)


def test_shell_policies_are_catalogued_as_rules():
    policies = GENERATE_DOCS.parse_shell_policies()
    # Same count as the Rust loader: 13 core plus 104 shipped DefenseClaw rules.
    assert len(policies) == 117
    core = [rule for rule in policies if rule["tier"] == "core"]
    assert len(core) == 13
    remote = next(rule for rule in core if rule["id"] == "core.remote_to_exec")
    assert (remote["scope"], remote["level"]) == ("command", "`block`")
    privileged = next(rule for rule in core if rule["id"] == "core.privileged_container")
    assert (privileged["scope"], privileged["level"]) == ("segment", "`ask`")
    pipe_curl = next(rule for rule in policies if rule["id"] == "CMD-PIPE-CURL")
    assert (pipe_curl["tier"], pipe_curl["level"]) == ("bundle-default", "release gate")

    page = GENERATE_DOCS.generate_l1_rule_catalog_doc()
    assert "## Shell command policies (117)" in page
    assert "| `CMD-PIPE-CURL` |" in page
