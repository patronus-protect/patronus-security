#!/usr/bin/env python3
"""Print the release version after checking that every version source agrees."""

from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CARGO_MANIFESTS = (
    "rust/Cargo.toml",
    "python/Cargo.toml",
    "ark-api/Cargo.toml",
    "ark-coordinator/Cargo.toml",
    "ark-distributed-protocol/Cargo.toml",
)
PYPROJECT = "python/pyproject.toml"


def versions(root: Path = ROOT) -> dict[str, str]:
    found = {}
    for path in CARGO_MANIFESTS:
        found[path] = tomllib.loads((root / path).read_text())["package"]["version"]
    found[PYPROJECT] = tomllib.loads((root / PYPROJECT).read_text())["project"]["version"]
    return found


def release_version(root: Path = ROOT) -> str:
    found = versions(root)
    if len(set(found.values())) != 1:
        raise ValueError(f"version sources disagree: {found}")
    return found[CARGO_MANIFESTS[0]]


if __name__ == "__main__":
    try:
        print(release_version())
    except ValueError as error:
        sys.exit(str(error))
