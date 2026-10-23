"""Checks for the release version cross-check used by the image workflows."""

from pathlib import Path
import importlib.util

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_version", ROOT / "scripts" / "release_version.py")
RELEASE_VERSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_VERSION)


def write_sources(root: Path, versions: dict[str, str]) -> None:
    for path in RELEASE_VERSION.CARGO_MANIFESTS:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(f'[package]\nname = "x"\nversion = "{versions.get(path, "1.2.3")}"\n')
    pyproject = RELEASE_VERSION.PYPROJECT
    (root / pyproject).write_text(f'[project]\nname = "x"\nversion = "{versions.get(pyproject, "1.2.3")}"\n')


def test_repository_versions_agree():
    assert RELEASE_VERSION.release_version()


def test_agreeing_sources_yield_the_version(tmp_path):
    write_sources(tmp_path, {})
    assert RELEASE_VERSION.release_version(tmp_path) == "1.2.3"


@pytest.mark.parametrize("stale", ["ark-distributed-protocol/Cargo.toml", "python/pyproject.toml"])
def test_any_stale_source_is_rejected(tmp_path, stale):
    write_sources(tmp_path, {stale: "1.2.2"})
    with pytest.raises(ValueError, match=stale):
        RELEASE_VERSION.release_version(tmp_path)
