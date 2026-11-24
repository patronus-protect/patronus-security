#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Subclass labels of the ``harmful_content`` positives of the dev split (AILuminate hazard taxonomy).

The label file ``research/l1-threat/labels/harmful_subclass.jsonl`` holds one row per dev positive of
``harmful_content`` (``train_dev``, ``generated``, ``translated``; never the holdout, never ``report``
sets): ``{"id", "subclass", "reason"}`` — the row id, one subclass of ``SUBCLASSES`` and a short
snake_case reason code. It never holds row text. An agent labels every row; a second, independent pass
labels the fixed 5 % sample (``in_sample``: sha256 of the row id modulo 20 is 0) without seeing the first
labels, and ``agree`` lists where the two differ.

    # rows to label (text only in the scratch directory, never committed)
    python3 scripts/l1_threat/harmful_subclass.py export --dev "$ARK_L1_DEV_DATA" --out SCRATCH [--batches 3]
    # merge the labelled batches into the label file (checked against the dev positives)
    python3 scripts/l1_threat/harmful_subclass.py merge --dev "$ARK_L1_DEV_DATA" SCRATCH/labels*.jsonl
    # compare the second pass on the sample with the label file
    python3 scripts/l1_threat/harmful_subclass.py agree --check SCRATCH/check.jsonl
    # positives per subclass and language; subclasses below MIN_POSITIVES per language are named gaps
    python3 scripts/l1_threat/harmful_subclass.py coverage --dev "$ARK_L1_DEV_DATA"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
LABELS_PATH = ROOT / "research" / "l1-threat" / "labels" / "harmful_subclass.jsonl"
CLASS = "harmful_content"
DEV_PARTS = ("train_dev", "generated", "translated")
LANGUAGES = ("de", "en")
# Subclasses the rules cover (request framing + hazard class); self_harm and child_safety are subclasses
# with the normal verdict.
PATTERN_SUBCLASSES = ("violent_crime", "cbrne", "cyber_harm", "nonviolent_crime", "sex_crime", "child_safety",
                      "self_harm")
# Subclasses without a clear word form: only the n-gram model detects them.
MODEL_ONLY_SUBCLASSES = ("specialized_advice", "ip", "defamation", "elections", "privacy")
# A harmful positive that fits none of the twelve hazards.
OTHER = "other"
SUBCLASSES = (*PATTERN_SUBCLASSES, *MODEL_ONLY_SUBCLASSES, OTHER)
# Below this many positives in a language a subclass is a named gap, not a measured one.
MIN_POSITIVES = 20
SAMPLE_MODULUS = 20
REASON = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+){0,5}")
KEYS = ("id", "subclass", "reason")


def in_sample(row_id: str) -> bool:
    """The fixed 5 % sample the second pass labels: sha256 of the row id modulo 20 is 0."""
    return int(hashlib.sha256(row_id.encode()).hexdigest(), 16) % SAMPLE_MODULUS == 0


def validate(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Label rows by id; raises ``ValueError`` on a missing or extra key, an unknown subclass, a reason that
    is not a short snake_case code (text never goes into the file) or a duplicate id."""
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        if tuple(sorted(row)) != tuple(sorted(KEYS)):
            raise ValueError(f"label row needs exactly the keys {KEYS}: {sorted(row)}")
        if row["subclass"] not in SUBCLASSES:
            raise ValueError(f"{row['id']}: unknown subclass {row['subclass']!r}")
        if not REASON.fullmatch(row["reason"]) or len(row["reason"]) > 48:
            raise ValueError(f"{row['id']}: reason must be a short snake_case code")
        if row["id"] in out:
            raise ValueError(f"duplicate label id {row['id']}")
        out[row["id"]] = {"subclass": row["subclass"], "reason": row["reason"]}
    return out


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load(path: Path = LABELS_PATH) -> dict[str, str]:
    """Subclass per row id of the label file; empty when there is none."""
    if not path.exists():
        return {}
    return {row_id: label["subclass"] for row_id, label in validate(read_jsonl(path)).items()}


def dev_positives(dev: Path) -> list[dict[str, Any]]:
    """The ``harmful_content`` positives of the dev parts, in file order."""
    rows = []
    for part in DEV_PARTS:
        for path in sorted((dev / part).glob("*.jsonl")):
            rows += [row for row in read_jsonl(path) if CLASS in row.get("classes", [])]
    return rows


def check(labels: dict[str, dict[str, str]], positives: list[dict[str, Any]]) -> list[str]:
    """Errors of a label set against the dev positives: unlabelled positives and labels of other rows."""
    ids = {row["id"] for row in positives}
    return [f"unlabelled positive {i}" for i in sorted(ids - set(labels))] + \
        [f"label of a row that is no dev positive: {i}" for i in sorted(set(labels) - ids)]


def agree(labels: dict[str, str], second: dict[str, str]) -> tuple[int, list[tuple[str, str, str]]]:
    """Rows both passes labelled and the (id, first, second) rows where they differ."""
    both = sorted(set(labels) & set(second))
    return len(both), [(i, labels[i], second[i]) for i in both if labels[i] != second[i]]


def coverage(labels: dict[str, str], positives: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Positives per subclass and language (``all``, ``de``, ``en``)."""
    counts: dict[str, Counter] = {sub: Counter() for sub in SUBCLASSES}
    for row in positives:
        sub = labels.get(row["id"])
        if sub is None:
            continue
        counts[sub]["all"] += 1
        counts[sub][row.get("language") or "unknown"] += 1
    return {sub: {lang: c[lang] for lang in ("all", *LANGUAGES)} for sub, c in counts.items()}


def gaps(table: dict[str, dict[str, int]]) -> list[tuple[str, str]]:
    """(subclass, language) cells below ``MIN_POSITIVES``, ``other`` excluded."""
    return [(sub, lang) for sub in SUBCLASSES if sub != OTHER for lang in LANGUAGES
            if table[sub][lang] < MIN_POSITIVES]


def write_labels(labels: dict[str, dict[str, str]], path: Path = LABELS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row_id in sorted(labels):
            handle.write(json.dumps({"id": row_id, **labels[row_id]}, sort_keys=True) + "\n")


def _export(args: argparse.Namespace) -> int:
    rows = dev_positives(args.dev)
    args.out.mkdir(parents=True, exist_ok=True)
    size = -(-len(rows) // args.batches)
    for n in range(args.batches):
        with (args.out / f"batch{n}.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows[n * size:(n + 1) * size]:
                upstream = [x.split("= ", 1)[1] for x in row.get("labels", []) if x.startswith("category =")]
                handle.write(json.dumps({"id": row["id"], "language": row.get("language"), "upstream": upstream,
                                         "text": row["text"]}, ensure_ascii=False) + "\n")
    sample = [row for row in rows if in_sample(row["id"])]
    print(f"{len(rows)} positives in {args.batches} batches, {len(sample)} in the 5 % sample")
    return 0


def _merge(args: argparse.Namespace) -> int:
    labels = validate(row for path in args.batches for row in read_jsonl(path))
    errors = check(labels, dev_positives(args.dev))
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    write_labels(labels, args.labels)
    print(f"{len(labels)} labels -> {args.labels}")
    return 0


def _agree(args: argparse.Namespace) -> int:
    labels = load(args.labels)
    second = {i: v["subclass"] for i, v in validate(read_jsonl(args.check)).items()}
    missing = sorted(i for i in labels if in_sample(i) and i not in second)
    rows, diffs = agree(labels, second)
    print(f"sample rows: {rows}; agree: {rows - len(diffs)}; differ: {len(diffs)}"
          + (f"; sample rows without a second label: {len(missing)}" if missing else ""))
    for row_id, first, other in diffs:
        print(f"- {row_id}: {first} / {other}")
    return 0


def _coverage(args: argparse.Namespace) -> int:
    table = coverage(load(args.labels), dev_positives(args.dev))
    print("| subclass | all | de | en |\n|---|---:|---:|---:|")
    for sub in SUBCLASSES:
        print(f"| `{sub}` | " + " | ".join(str(table[sub][lang]) for lang in ("all", *LANGUAGES)) + " |")
    print("\ngaps (< %d per language): " % MIN_POSITIVES
          + ", ".join(f"{sub}/{lang}" for sub, lang in gaps(table)))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--labels", type=Path, default=LABELS_PATH)
    commands = parser.add_subparsers(dest="command", required=True)
    e = commands.add_parser("export", help="write the dev positives to label in batches (scratch only)")
    e.add_argument("--dev", type=Path, required=True)
    e.add_argument("--out", type=Path, required=True)
    e.add_argument("--batches", type=int, default=3)
    m = commands.add_parser("merge", help="validate labelled batches and write the label file")
    m.add_argument("--dev", type=Path, required=True)
    m.add_argument("batches", type=Path, nargs="+")
    a = commands.add_parser("agree", help="compare the second pass on the 5 %% sample with the label file")
    a.add_argument("--check", type=Path, required=True)
    c = commands.add_parser("coverage", help="positives per subclass and language, gaps named")
    c.add_argument("--dev", type=Path, required=True)
    args = parser.parse_args(argv)
    return {"export": _export, "merge": _merge, "agree": _agree, "coverage": _coverage}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
