#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Multi-label gold of the threat rows: every class a row really carries (T34).

The label file ``research/l1-threat/labels/multi_label.jsonl`` holds one row per reviewed attack row of the
mix and the report sets: ``{"id", "labels", "reason"}`` — the row id, every class the row carries (its
``classes`` first, then each further class it carries; only allowed neighbours of ``research/l1-threat/README.md``,
Klassengrenzen) and a short snake_case reason code. It never holds row text. Reviewed are the rows on which rules
or a built-in L1 model report an allowed neighbour class; an agent labels every such row, a second, independent
pass labels the fixed 5 % sample (``harmful_subclass.in_sample``) without seeing the first labels, and ``agree``
lists where the two differ. The scoreboard reads a row's classes through ``apply``: a row counts as a positive of
each of its labels and is never a negative of one of them.

    # compare the second pass on the sample with the label file
    python3 scripts/l1_threat/multi_label.py agree --check SCRATCH/check.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harmful_subclass import REASON, in_sample, read_jsonl  # noqa: E402
from taxonomy import CLASSES  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
LABELS_PATH = ROOT / "research" / "l1-threat" / "labels" / "multi_label.jsonl"
KEYS = ("id", "labels", "reason")


def validate(rows: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    """Labels by row id; raises ``ValueError`` on a missing or extra key, an unknown or repeated class, a reason
    that is not a short snake_case code (text never goes into the file) or a duplicate id."""
    out: dict[str, list[str]] = {}
    for row in rows:
        if tuple(sorted(row)) != tuple(sorted(KEYS)):
            raise ValueError(f"label row needs exactly the keys {KEYS}: {sorted(row)}")
        labels = row["labels"]
        if not labels or len(set(labels)) != len(labels) or not set(labels) <= set(CLASSES):
            raise ValueError(f"{row['id']}: labels must be distinct taxonomy classes: {labels}")
        if not REASON.fullmatch(row["reason"]) or len(row["reason"]) > 48:
            raise ValueError(f"{row['id']}: reason must be a short snake_case code")
        if row["id"] in out:
            raise ValueError(f"duplicate label id {row['id']}")
        out[row["id"]] = list(labels)
    return out


def load(path: Path = LABELS_PATH) -> dict[str, list[str]]:
    """Labels per row id of the label file; empty when there is none."""
    return validate(read_jsonl(path)) if path.exists() else {}


def apply(row: dict[str, Any], labels: dict[str, list[str]]) -> dict[str, Any]:
    """``row`` with the classes of its label row; a label row must keep the row's own classes."""
    found = labels.get(row["id"])
    if found is None:
        return row
    if not set(row["classes"]) <= set(found):
        raise ValueError(f"{row['id']}: labels {found} drop a class of the row {row['classes']}")
    return {**row, "classes": found}


def agree(labels: dict[str, list[str]], second: dict[str, list[str]]) -> tuple[int, list[tuple[str, list, list]]]:
    """Rows both passes labelled and the (id, first, second) rows whose class sets differ."""
    both = sorted(set(labels) & set(second))
    return len(both), [(i, labels[i], second[i]) for i in both if set(labels[i]) != set(second[i])]


def _agree(args: argparse.Namespace) -> int:
    labels = load(args.labels)
    second = validate(read_jsonl(args.check))
    missing = sorted(i for i in labels if in_sample(i) and i not in second)
    rows, diffs = agree(labels, second)
    print(f"sample rows: {rows}; agree: {rows - len(diffs)}; differ: {len(diffs)}"
          + (f"; sample rows without a second label: {len(missing)}" if missing else ""))
    for row_id, first, other in diffs:
        print(f"- {row_id}: {','.join(first)} / {','.join(other)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--labels", type=Path, default=LABELS_PATH)
    commands = parser.add_subparsers(dest="command", required=True)
    a = commands.add_parser("agree", help="compare the second pass on the 5 %% sample with the label file")
    a.add_argument("--check", type=Path, required=True)
    args = parser.parse_args(argv)
    return {"agree": _agree}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
