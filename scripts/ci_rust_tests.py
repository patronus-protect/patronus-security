"""Select Cargo targets without running unchanged PII/DLP integration suites."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def enabled(changes: dict[str, str], name: str) -> bool:
    return changes.get(name) == "true"


def domain_skips(changes: dict[str, str]) -> list[str]:
    args = []
    for domain in ("pii", "dlp"):
        if not enabled(changes, domain):
            args.extend(["--skip", f"detectors::{domain}::"])
    return ["--", *args] if args else []


def plan(group: str, changes: dict[str, str], root: Path = ROOT) -> list[list[str]]:
    core = ["cargo", "test", "--locked", "-p", "patronus-ark-core"]
    wrapper = ["cargo", "test", "--locked", "-p", "patronus-ark"]
    if group == "core":
        commands = [[*core, "--no-default-features", *domain_skips(changes)]]
        if enabled(changes, "dlp") and not enabled(changes, "core_features"):
            commands.append([
                *core, "--no-default-features", "--features", "test-util", "--lib",
                *domain_skips(changes),
            ])
        return commands
    if group == "core-features":
        return [[*core, "--features", feature, *domain_skips(changes)] for feature in ("wolf", "download")]
    if group == "core-all-features":
        return [[*core, "--all-features", "--lib", *domain_skips(changes)]]
    if group == "clippy":
        packages = []
        for key, package in (
            ("core", "patronus-ark-core"),
            ("wrapper", "patronus-ark"),
            ("api", "ark-api"),
            ("coordinator", "ark-coordinator"),
            ("protocol", "ark-distributed-protocol"),
            ("bindings", "patronus-ark-python"),
        ):
            if enabled(changes, key):
                packages.extend(["-p", package])
        return [["cargo", "clippy", "--locked", *packages, "--all-targets", "--", "-D", "warnings"]] if packages else []
    if group != "wrapper":
        raise ValueError(f"unknown group: {group}")

    commands = []
    if enabled(changes, "wrapper_base"):
        # Preserve all non-domain targets, including binaries, examples and doctests.
        commands.extend([
            [*wrapper, "--lib", "--bins"],
            [*wrapper, "--examples", "--no-run"],
            [*wrapper, "--doc"],
        ])
    targets = []
    for path in sorted((root / "rust" / "tests").glob("*.rs")):
        domain = next((name for name in ("pii", "dlp") if path.stem.startswith(name)), None)
        if enabled(changes, domain or "wrapper_base"):
            targets.extend(["--test", path.stem])
    if targets:
        commands.append([*wrapper, *targets])
    manifest = tomllib.loads((root / "rust" / "Cargo.toml").read_text())
    for example in manifest.get("example", []):
        if example.get("test", False):
            domain = next((name for name in ("pii", "dlp") if name in example["name"]), None)
            if enabled(changes, domain or "wrapper_base"):
                commands.append([*wrapper, "--example", example["name"]])
    return commands


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=("core", "core-features", "core-all-features", "wrapper", "clippy"))
    args = parser.parse_args()
    changes = json.loads(os.environ["CI_RUST_CHANGES"])
    for command in plan(args.group, changes):
        print(shlex.join(command), flush=True)
        subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
