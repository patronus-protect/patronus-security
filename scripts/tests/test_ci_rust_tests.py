"""Check CI dependency routing and Cargo target coverage without compiling models."""
from fnmatch import fnmatchcase
import importlib.util
from pathlib import Path
import re
import tomllib

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ci_rust_tests", ROOT / "scripts/ci_rust_tests.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
WORKFLOW = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
FILTERS = yaml.safe_load((ROOT / ".github/ci-paths.yml").read_text())


def route(*paths):
    # The filter file uses literal paths, * and **; exclusions veto positive matches.
    def matches(path, pattern):
        return fnmatchcase(path, pattern) or (pattern.startswith("**/") and fnmatchcase(path, pattern[3:]))

    flags = {}
    for name, patterns in FILTERS.items():
        positive = [p for p in patterns if not p.startswith("!")]
        negative = [p[1:] for p in patterns if p.startswith("!")]
        flags[name] = any(
            any(matches(path, p) for p in positive) and not any(matches(path, p) for p in negative)
            for path in paths
        )
    outputs = {}
    for name, expression in WORKFLOW["jobs"]["changes"]["outputs"].items():
        inputs = re.findall(r"steps\.filter\.outputs\.(\w+) == 'true'", expression)
        assert inputs, expression
        outputs[name] = "true" if any(flags[key] for key in inputs) else "false"
    return outputs


def targets(commands):
    return {command[i + 1] for command in commands for i, value in enumerate(command) if value == "--test"}


@pytest.mark.parametrize("path,pii,dlp", [
    ("ark-core/src/detectors/pii/de.rs", True, False),
    ("ark-core/src/detectors/dlp/rules/credentials.rs", False, True),
    ("python/patronus_ark/benchmark_data/pii_l1.jsonl", True, False),
    ("python/patronus_ark/benchmark_data/dlp_l1.jsonl", False, True),
    ("rust/tests/pii_l1.rs", True, False),
    ("rust/tests/dlp_score_model.rs", False, True),
    ("rust/tests/fixtures/dlp_synth_vectors.json", False, True),
    ("ark-core/src/detectors/pii/context.rs", True, True),
    ("ark-core/src/detectors/pii/score.rs", True, True),
    ("ark-core/src/normalization.rs", True, True),
    ("ark-core/src/detectors/validators/mod.rs", True, True),
    ("rust/src/pipeline/security.rs", True, True),
    ("rust/examples/13_l1_golden_eval.rs", True, True),
    ("Cargo.lock", True, True),
    ("Cargo.toml", True, True),
    ("ark-api/src/main.rs", False, False),
    ("ark-coordinator/src/main.rs", False, False),
    ("ark-distributed-protocol/src/lib.rs", False, False),
    ("ark-core/src/wolf.rs", False, False),
    ("README.md", False, False),
    ("scripts/generate_docs.py", False, False),
])
def test_domain_dependencies(path, pii, dlp):
    flags = route(path)
    assert (flags["pii"] == "true") is pii
    assert (flags["dlp"] == "true") is dlp


def test_pii_fixture_selects_only_pii_targets_and_example_tests():
    flags = route("python/patronus_ark/benchmark_data/pii_l1.jsonl")
    commands = MODULE.plan("wrapper", flags)
    selected = targets(commands)
    assert selected == {p.stem for p in (ROOT / "rust/tests").glob("pii*.rs")}
    assert any(command[-2:] == ["--example", "12_l1_pii_fixture_eval"] for command in commands)
    assert not any("--lib" in command or "--bins" in command for command in commands)
    assert flags["throughput"] == flags["core_features"] == "false"


def test_dlp_fixture_selects_only_dlp_targets():
    flags = route("python/patronus_ark/benchmark_data/dlp_l1.jsonl")
    commands = MODULE.plan("wrapper", flags)
    assert targets(commands) == {p.stem for p in (ROOT / "rust/tests").glob("dlp*.rs")}
    assert len(commands) == 1


def test_shared_changes_preserve_all_previous_target_types():
    flags = route("Cargo.lock")
    commands = MODULE.plan("wrapper", flags)
    assert targets(commands) == {p.stem for p in (ROOT / "rust/tests").glob("*.rs")}
    for target in ("--lib", "--bins", "--examples", "--doc"):
        assert any(target in command for command in commands)
    examples = tomllib.loads((ROOT / "rust/Cargo.toml").read_text()).get("example", [])
    expected = {example["name"] for example in examples if example.get("test", False)}
    actual = {command[command.index("--example") + 1] for command in commands if "--example" in command}
    assert actual == expected
    assert all("--locked" in command for command in commands)


def test_core_pii_change_skips_unchanged_dlp_units_and_feature_matrix():
    flags = route("ark-core/src/detectors/pii/de.rs")
    (command,) = MODULE.plan("core", flags)
    assert command[-3:] == ["--", "--skip", "detectors::dlp::"]
    assert "detectors::pii::" not in command
    assert flags["core_features"] == "false"


def test_dlp_only_change_still_checks_test_util_feature():
    flags = route("ark-core/src/detectors/dlp/rules/credentials.rs")
    commands = MODULE.plan("core", flags)
    assert any(command[command.index("--features") + 1] == "test-util" for command in commands if "--features" in command)
    assert all("detectors::pii::" in command for command in commands)
    assert flags["core_features"] == "false"


def test_coordinator_change_does_not_build_other_crates_or_models():
    flags = route("ark-coordinator/src/main.rs")
    (command,) = MODULE.plan("clippy", flags)
    assert command[command.index("-p") + 1] == "ark-coordinator"
    assert command.count("-p") == 1
    for key in ("core", "core_features", "wrapper", "api", "protocol", "python", "throughput"):
        assert flags[key] == "false"


def test_api_change_keeps_api_and_entrypoint_validation_only():
    flags = route("ark-api/src/main.rs")
    assert flags["api"] == flags["python"] == "true"
    for key in ("core", "core_features", "wrapper", "coordinator", "protocol", "throughput"):
        assert flags[key] == "false"


def test_full_clippy_plan_covers_every_workspace_package():
    commands = MODULE.plan("clippy", route("Cargo.lock"))
    selected = {command[i + 1] for command in commands for i, value in enumerate(command) if value == "-p"}
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["members"]
    expected = {tomllib.loads((ROOT / member / "Cargo.toml").read_text())["package"]["name"] for member in workspace}
    assert selected == expected


@pytest.mark.parametrize("changes,expected", [
    ({"core": "true"}, {"patronus-ark-core", "patronus-ark-core-python"}),
    ({"bindings": "true"}, {"patronus-ark-python", "patronus-ark-core-python"}),
    ({"core": "true", "bindings": "true"}, {
        "patronus-ark-core", "patronus-ark-python", "patronus-ark-core-python",
    }),
])
def test_core_python_clippy_follows_core_or_bindings_without_duplicate_packages(changes, expected):
    (command,) = MODULE.plan("clippy", changes)
    selected = [command[i + 1] for i, value in enumerate(command) if value == "-p"]
    assert set(selected) == expected
    assert selected.count("patronus-ark-core-python") == 1


@pytest.mark.parametrize("path", [
    "ark-core/python/src/lib.rs",
    "ark-core/python/patronus_ark_core/types.py",
    "ark-core/python/patronus_ark_core/_patronus_ark_core.pyi",
    "ark-core/python/tests/test_concurrency.py",
])
def test_core_python_paths_select_binding_clippy(path):
    flags = route(path)
    assert flags["rust"] == flags["core"] == flags["bindings"] == "true"
    (command,) = MODULE.plan("clippy", flags)
    assert command.count("patronus-ark-core-python") == 1


def test_core_python_markdown_does_not_select_rust_or_bindings():
    flags = route("ark-core/python/README.md")
    assert flags["rust"] == flags["core"] == flags["bindings"] == "false"
    assert MODULE.plan("clippy", flags) == []


def test_workflow_uses_exclusion_aware_filters_and_conditional_jobs():
    jobs = WORKFLOW["jobs"]
    (filter_step,) = [step for step in jobs["changes"]["steps"] if step.get("id") == "filter"]
    assert filter_step["with"]["predicate-quantifier"] == "some-with-excludes"
    assert filter_step["with"]["filters"] == ".github/ci-paths.yml"
    assert filter_step["with"]["base"] == "${{ github.ref }}"
    assert jobs["changes"]["permissions"]["pull-requests"] == "read"
    for job in ("rust", "core-features", "python", "native-throughput"):
        assert jobs[job]["needs"] == "changes"
        assert "needs.changes.outputs." in jobs[job]["if"]
    # Required checks must report on every PR, so only pushes are path-filtered.
    assert not WORKFLOW["on"]["pull_request"]
    assert ".github/ci-paths.yml" in WORKFLOW["on"]["push"]["paths"]


def test_runner_uses_checked_subprocesses(monkeypatch):
    import json
    calls = []
    monkeypatch.setenv("CI_RUST_CHANGES", json.dumps(route("Cargo.lock")))
    monkeypatch.setattr("sys.argv", ["ci_rust_tests.py", "wrapper"])
    monkeypatch.setattr(MODULE.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    MODULE.main()
    assert calls
    assert all(options == {"cwd": ROOT, "check": True} for _, options in calls)


def test_core_matrix_uses_available_minor_series_for_cargo_helper_only():
    job = WORKFLOW["jobs"]["core-features"]
    (setup,) = [step for step in job["steps"] if step.get("uses", "").startswith("actions/setup-python@")]
    assert setup["with"]["python-version"] == "3.12"
    assert setup["with"]["check-latest"] == "true"
    assert not any("pip" in step.get("run", "") for step in job["steps"])
    assert any(step.get("run") == "python scripts/ci_rust_tests.py core-all-features" for step in job["steps"])


def test_ci_token_permissions_are_read_only_except_change_listing():
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert WORKFLOW["jobs"]["changes"]["permissions"] == {"contents": "read", "pull-requests": "read"}
    for job in WORKFLOW["jobs"].values():
        assert all(level == "read" for level in job.get("permissions", {}).values())


@pytest.mark.parametrize("path", [
    "python/patronus_ark/benchmark_data/pii_l1.jsonl",
    "python/patronus_ark/benchmark_data/dlp_l1.jsonl",
    "ark-core/src/detectors/dlp/rules/credentials.rs",
    "ark-core/src/detectors/pii/de.rs",
])
def test_shared_fixture_tests_follow_domain_changes(path):
    # synchronous_core counts the rows of both benchmark fixtures; a domain-only PR must run it.
    assert "synchronous_core" in targets(MODULE.plan("wrapper", route(path)))
