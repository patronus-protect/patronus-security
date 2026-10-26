"""Checks for the release version cross-check used by the image workflows."""

from pathlib import Path
import importlib.util

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_version", ROOT / "scripts" / "release_version.py")
RELEASE_VERSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_VERSION)


def write_sources(root: Path, versions: dict[str, str]) -> None:
    members = [str(Path(path).parent) for path in RELEASE_VERSION.CARGO_MANIFESTS]
    (root / "Cargo.toml").write_text(f"[workspace]\nmembers = {members!r}\n")
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


@pytest.mark.parametrize("stale", [*RELEASE_VERSION.CARGO_MANIFESTS, RELEASE_VERSION.PYPROJECT])
def test_any_stale_source_is_rejected(tmp_path, stale):
    write_sources(tmp_path, {stale: "1.2.2"})
    with pytest.raises(ValueError, match=stale):
        RELEASE_VERSION.release_version(tmp_path)


@pytest.mark.parametrize("omitted", RELEASE_VERSION.CARGO_MANIFESTS)
def test_every_workspace_package_must_be_checked(tmp_path, monkeypatch, omitted):
    write_sources(tmp_path, {})
    monkeypatch.setattr(
        RELEASE_VERSION,
        "CARGO_MANIFESTS",
        tuple(path for path in RELEASE_VERSION.CARGO_MANIFESTS if path != omitted),
    )
    with pytest.raises(ValueError, match=omitted):
        RELEASE_VERSION.release_version(tmp_path)


def test_new_workspace_member_cannot_silently_escape_version_check(tmp_path):
    write_sources(tmp_path, {})
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(manifest.read_text().replace("members = [", "members = ['new-crate', "))
    (tmp_path / "new-crate").mkdir()
    (tmp_path / "new-crate/Cargo.toml").write_text(
        '[package]\nname = "new-crate"\nversion = "1.2.3"\n'
    )
    with pytest.raises(ValueError, match="new-crate/Cargo.toml"):
        RELEASE_VERSION.release_version(tmp_path)


def test_stale_core_python_distribution_version_is_rejected(tmp_path):
    write_sources(tmp_path, {})
    (tmp_path / "ark-core/python/pyproject.toml").write_text(
        '[project]\nname = "patronus-ark-core"\nversion = "1.2.2"\n'
    )
    with pytest.raises(ValueError, match="ark-core/python/pyproject.toml"):
        RELEASE_VERSION.release_version(tmp_path)
