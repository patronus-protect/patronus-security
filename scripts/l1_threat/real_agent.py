#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hand labels of the real-world dev sets for the agent classes.

``research/l1-threat/labels/real_agent.jsonl`` holds one row per distinct text of the real sets registered
in ``datasets.yaml`` (real rules files, Copilot instructions and agent files, tool descriptions, memory
conversations): ``{"dataset", "sha256", "source", "family", "label", "reason"}`` — the set, the SHA-256 of
the row text, the file at its pinned revision, the carrier family (``FAMILIES``), ``benign`` or one class
of the agent classes, and a short snake_case reason code. It never holds row text. An agent labels every
row; a second, independent pass labels the fixed 10 % sample (``in_sample``: SHA-256 of the text key modulo
10 is 0) without seeing the first labels, and ``agree`` lists where the two differ.

    python3 scripts/l1_threat/real_agent.py check            # Exit 1 bei jedem Problem
    python3 scripts/l1_threat/real_agent.py counts           # rows per family and label
    python3 scripts/l1_threat/real_agent.py agree --check SECOND_PASS.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
LABELS_PATH = ROOT / "research/l1-threat/labels/real_agent.jsonl"
REGISTRY_PATH = ROOT / "scripts/l1_threat/datasets.yaml"
FAMILIES = ("agent_config", "tool_manifest", "memory_write")
LABELS = ("benign", "tool_poisoning", "agent_config_tampering", "memory_poisoning")
KEYS = {"dataset", "sha256", "source", "family", "label", "reason"}
REASON = re.compile(r"[a-z][a-z0-9_]*")
SHA256 = re.compile(r"[0-9a-f]{64}")
SAMPLE_MODULUS = 10
# Real benign rows each carrier family needs.
MIN_BENIGN_PER_FAMILY = 300


def load(path: Path = LABELS_PATH) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def in_sample(key: str) -> bool:
    """The fixed second-pass sample: one text key in ``SAMPLE_MODULUS``."""
    return int(hashlib.sha256(key.encode("ascii")).hexdigest(), 16) % SAMPLE_MODULUS == 0


def check(rows: list[dict[str, Any]], registry: dict[str, Any]) -> list[str]:
    sets = {entry["id"]: entry for entry in registry.get("datasets") or []}
    problems = []
    seen: Counter[tuple[str, str]] = Counter()
    for number, row in enumerate(rows, 1):
        where = f"label row {number}"
        if set(row) != KEYS:
            problems.append(f"{where}: keys must be {sorted(KEYS)}")
            continue
        seen[(row["dataset"], row["sha256"])] += 1
        entry = sets.get(row["dataset"])
        if entry is None or "source" not in entry:
            problems.append(f"{where}: {row['dataset']!r} is no recipe in datasets.yaml")
        elif not row["source"].startswith(f"{entry['source']}/blob/{entry['revision']}/"):
            problems.append(f"{where}: source must be a file of {entry['source']} at {entry['revision']}")
        if not SHA256.fullmatch(row["sha256"]):
            problems.append(f"{where}: sha256 must be 64 hex")
        if row["family"] not in FAMILIES or row["label"] not in LABELS or not REASON.fullmatch(row["reason"]):
            problems.append(f"{where}: family in {FAMILIES}, label in {LABELS}, reason a snake_case code")
    problems.extend(f"{dataset}: text {key[:12]} labelled {count} times" for (dataset, key), count in seen.items() if count > 1)
    benign = Counter(row["family"] for row in rows if row.get("label") == "benign")
    problems.extend(
        f"family {family}: {benign[family]} real benign rows (needs {MIN_BENIGN_PER_FAMILY})"
        for family in FAMILIES if benign[family] < MIN_BENIGN_PER_FAMILY
    )
    return problems


def agree(rows: list[dict[str, Any]], second: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare the second pass (``{"sha256", "label"}`` per sampled row) with the label file."""
    first = {row["sha256"]: row["label"] for row in rows if in_sample(row["sha256"])}
    given = {row["sha256"]: row["label"] for row in second}
    missing = sorted(set(first) - set(given))
    disagreements = [{"sha256": key, "first": first[key], "second": given[key]} for key in sorted(first) if key in given and given[key] != first[key]]
    return {"sample": len(first), "checked": len(set(first) & set(given)), "missing": missing, "disagreements": disagreements}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sub.add_parser("counts")
    agree_parser = sub.add_parser("agree")
    agree_parser.add_argument("--check", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = load()
    if args.command == "check":
        problems = check(rows, yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8")))
        print("\n".join(problems) or f"{LABELS_PATH.name}: ok ({len(rows)} rows)")
        return 1 if problems else 0
    if args.command == "counts":
        for (family, label), count in sorted(Counter((row["family"], row["label"]) for row in rows).items()):
            print(f"{family}\t{label}\t{count}")
        return 0
    result = agree(rows, load(args.check))
    print(json.dumps(result, indent=1))
    return 1 if result["missing"] else 0


if __name__ == "__main__":
    sys.exit(main())
