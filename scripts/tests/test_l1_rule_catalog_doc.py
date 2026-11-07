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
    assert "| `cat.CMD-PIPE-CURL` |" in page


def test_bare_pii_rules_inherit_their_base_and_are_catalogued_opt_in():
    rules = {
        rule["id"]: rule
        for rule in GENERATE_DOCS.parse_native_patterns(ROOT / "ark-core/src/detectors/pii/pii.rs", "PiiPattern")
    }
    bare = rules["pii_sin_ca_bare"]
    base = rules["pii_sin_ca"]
    assert (bare["entity_group"], bare["validator"], bare["strength"]) == (
        base["entity_group"], base["validator"], base["strength"],
    )
    assert (bare["base_score"], bare["requires_context"], base["requires_context"]) == (15, False, True)
    assert rules["pii_steuer_id_de_bare"]["validator"] == "steuer_id_bare"

    page = GENERATE_DOCS.generate_l1_rule_catalog_doc()
    assert "| `pii_sin_ca_bare` | `CA_SIN` | yes | checksum | 15 | none, opt-in (off by default) | 0.50–0.75 |" in page
