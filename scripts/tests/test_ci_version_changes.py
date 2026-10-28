"""Version bumps skip builds; source, features and dependency changes still select them."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("ci_version_changes", ROOT / "scripts/ci_version_changes.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PATH = "ark-core/Cargo.toml"
BEFORE = '[package]\nname = "patronus-ark-core"\nversion = "0.1.13"\n'
AFTER = BEFORE.replace("0.1.13", "0.1.14")
OLD = {PATH: tomllib.loads(BEFORE)}
NEW = {PATH: tomllib.loads(AFTER)}


@pytest.mark.parametrize("path,before,after", [
    (PATH, BEFORE, AFTER),
    ("ark-core/python/pyproject.toml", '[project]\nversion = "0.1.13"', '[project]\nversion = "0.1.14"'),
    ("rust/Cargo.toml", BEFORE + '[dependencies]\ncore = { path = "../ark-core", version = "0.1.13" }',
     AFTER + '[dependencies]\ncore = { path = "../ark-core", version = "0.1.14" }'),
    ("Cargo.lock", '[[package]]\nname = "patronus-ark-core"\nversion = "0.1.13"',
     '[[package]]\nname = "patronus-ark-core"\nversion = "0.1.14"'),
])
def test_release_versions_are_metadata(path, before, after):
    old = {**OLD, "rust/Cargo.toml": tomllib.loads(BEFORE)}
    new = {**NEW, "rust/Cargo.toml": tomllib.loads(AFTER)}
    assert MODULE.version_only(path, before, after, old, new)


@pytest.mark.parametrize("path,before,after", [
    (PATH, BEFORE + '[dependencies]\nregex = "1.0"', AFTER + '[dependencies]\nregex = "1.1"'),
    (PATH, BEFORE + '[features]\ndefault = []', AFTER + '[features]\ndefault = ["wolf"]'),
    (PATH, BEFORE + '[dependencies]\ncore = { path = "../unknown", version = "0.1.13" }',
     AFTER + '[dependencies]\ncore = { path = "../unknown", version = "0.1.14" }'),
    ("Cargo.lock", '[[package]]\nname = "regex"\nversion = "1.0"',
     '[[package]]\nname = "regex"\nversion = "1.1"'),
    ("Cargo.lock", '[[package]]\nname = "patronus-ark-core"\nversion = "0.1.13"\nsource = "registry"',
     '[[package]]\nname = "patronus-ark-core"\nversion = "0.1.14"\nsource = "registry"'),
    ("ark-core/python/pyproject.toml", '[project]\nversion = "0.1.13"\nrequires-python = ">=3.11"',
     '[project]\nversion = "0.1.14"\nrequires-python = ">=3.12"'),
    ("ark-core/src/lib.rs", "before", "after"),
])
def test_build_inputs_are_not_metadata(path, before, after):
    assert not MODULE.version_only(path, before, after, OLD, NEW)


@pytest.mark.parametrize("runtime_change,missing_base", [(False, False), (True, False), (False, True)])
def test_filter_outputs_exclude_only_proven_version_changes(tmp_path, monkeypatch, runtime_change, missing_base):
    (tmp_path / "ark-core").mkdir()
    (tmp_path / PATH).write_text(AFTER)
    output = tmp_path / "output"
    paths = [PATH, *(["ark-core/src/lib.rs"] if runtime_change else [])]
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "CARGO_MANIFESTS", (PATH,))
    def read_base(base, path):
        if missing_base:
            raise subprocess.CalledProcessError(1, "git show")
        return BEFORE
    monkeypatch.setattr(MODULE, "read_base", read_base)
    monkeypatch.setenv("CI_BASE", "base")
    monkeypatch.setenv("CI_PATH_SELECTIONS", json.dumps({"core_files": json.dumps(paths)}))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    MODULE.main()
    assert output.read_text() == f"core={str(runtime_change or missing_base).lower()}\n"
