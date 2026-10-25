#!/usr/bin/env python3
"""Require publishing from a version tag at the matching release-branch head."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

from release_version import release_version

ROOT = Path(__file__).resolve().parents[1]


def validate_release_source(channel: str, ref: str, version: str, head: str, tag: str | None, branch: str | None) -> None:
    if channel == "build":
        return
    if channel not in {"testpypi", "production"}:
        raise ValueError(f"unknown release channel: {channel}")
    if ref != f"refs/tags/v{version}":
        raise ValueError(f"publishing requires tag v{version}, not {ref}")
    if not tag or not branch or head != tag or head != branch:
        raise ValueError(f"tag v{version} and release/{version} must both point at the checked-out release commit")


def revision(ref: str) -> str | None:
    result = subprocess.run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=ROOT, text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def main() -> None:
    channel = os.environ.get("RELEASE_CHANNEL", "build")
    version = release_version()
    validate_release_source(channel, os.environ.get("GITHUB_REF", ""), version,
                            revision("HEAD") or "", revision(f"refs/tags/v{version}"),
                            revision(f"refs/remotes/origin/release/{version}"))
    print(f"Release source validated: {channel}, version {version}")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from error
