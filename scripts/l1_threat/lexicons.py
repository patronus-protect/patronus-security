#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the L1 context lexica and mine candidate terms for them.

The counter-context and support lexica of the L1 categories live in
``ark-core/src/detectors/anchor_lexicons/context.json``. Every term carries an origin:

- ``ark_existing``: taken over from an existing ARK lexicon or rule;
- ``oss:<source>@<commit>``: from a permissively licensed OSS rule set at a pinned commit;
- ``taxonomy``: named in ``research/l1-threat/taxonomy.yaml``;
- ``mined:<train-split-hash>``: proposed by ``mine`` on a train split and reviewed by hand;
- ``hand``: written by hand.

Term syntax (matched by ``ark-core/src/detectors/context_lexica.rs``): lowercase words; ``*`` at
the start or end of a part opens that side to a word continuation (German compounds, inflection,
gender forms such as ``Nutzer:innen``); parts joined by `` … `` must follow each other in one
clause (German separable verbs: ``leite … weiter``). Terms in ``cased`` match case-sensitively
(``Sie``, ``Ihnen`` as the polite address).

    python3 scripts/l1_threat/lexicons.py check
    python3 scripts/l1_threat/lexicons.py mine TRAIN.jsonl --label 0 [--top 50]

``mine`` ranks words and word pairs of the texts with ``--label`` against all other texts by
weighted log-odds with an informative Dirichlet prior (Monroe, Colaresi and Quinn 2008). It reads
only train splits: a path with a ``dev``, ``gold``, ``golden(s)`` or ``holdout`` part, or without a
``train`` part, is refused. Its output is a candidate list for review, never written into a lexicon.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTEXT_PATH = ROOT / "ark-core" / "src" / "detectors" / "anchor_lexicons" / "context.json"

KINDS = {"support", "counter"}
TERM_LISTS = ("en", "de", "shared", "cased")
ORIGIN = re.compile(r"^(?:ark_existing|taxonomy|hand|oss:[a-z0-9][a-z0-9_.-]*@[0-9a-f]{7,40}|mined:[0-9a-f]{12})$")
SEPARATOR = " … "
FORBIDDEN_SPLITS = {"dev", "gold", "golden", "goldens", "holdout"}
TOKEN = re.compile(r"\w+")


def load(path: Path = CONTEXT_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_origin(origin: str) -> bool:
    return bool(ORIGIN.match(origin))


def _term_problems(lexicon_id: str, term: str, cased: bool) -> list[str]:
    if not cased and term != term.lower():
        return [f"{lexicon_id}: term {term!r} is not lowercase (use cased)"]
    problems = []
    for part in term.split(SEPARATOR):
        core = part.removeprefix("*").removesuffix("*")
        if not core.strip() or core != core.strip() or "…" in core or core.startswith("*") or core.endswith("*"):
            problems.append(f"{lexicon_id}: term {term!r} has a malformed part")
        elif "*" in core:
            problems.append(f"{lexicon_id}: term {term!r} has a wildcard inside a part")
    return problems


def check(lexica: list[dict[str, Any]]) -> list[str]:
    """Return every problem of the context lexica: ids, kinds, term syntax and term origins."""
    problems = []
    ids = Counter(lexicon.get("id") for lexicon in lexica)
    problems += [f"{lexicon_id} is defined {'twice' if count == 2 else f'{count} times'}" for lexicon_id, count in ids.items() if count > 1]
    for lexicon in lexica:
        lexicon_id = lexicon.get("id")
        if lexicon.get("kind") not in KINDS:
            problems.append(f"{lexicon_id}: kind {lexicon.get('kind')!r} is not support or counter")
        origin = lexicon.get("origin") or {}
        seen: set[str] = set()
        for key in TERM_LISTS:
            for term in lexicon.get(key) or []:
                if term in seen:
                    problems.append(f"{lexicon_id}: term {term!r} listed twice")
                    continue
                seen.add(term)
                problems += _term_problems(lexicon_id, term, key == "cased")
                if term not in origin:
                    problems.append(f"{lexicon_id}: term {term!r} has no origin")
                elif not valid_origin(origin[term]):
                    problems.append(f"{lexicon_id}: term {term!r} has unknown origin {origin[term]!r}")
        problems += [f"{lexicon_id}: origin for unknown term {term!r}" for term in origin if term not in seen]
    return problems


def split_hash(path: Path) -> str:
    """First 12 hex digits of the SHA-256 of a split file: the ``mined:`` origin of its terms."""
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def _ngrams(text: str) -> set[str]:
    words = TOKEN.findall(text.lower())
    return set(words) | {f"{a} {b}" for a, b in zip(words, words[1:])}


def mine(
    path: Path,
    target_label: Any,
    *,
    text_field: str = "text",
    label_field: str = "label",
    top: int = 50,
    min_count: int = 5,
    prior: float = 0.01,
) -> list[dict[str, Any]]:
    """Terms of the ``target_label`` texts ranked by log-odds z-score against the other texts."""
    tokens = {token for part in path.resolve().parts for token in re.split(r"[^a-z0-9]+", part.lower()) if token}
    if tokens & FORBIDDEN_SPLITS or "train" not in tokens:
        raise ValueError(f"{path}: mining reads only a train split, never dev, gold, goldens or holdout")
    target: Counter[str] = Counter()
    other: Counter[str] = Counter()
    with path.open(encoding="utf-8") as rows:
        for line in rows:
            if line.strip():
                row = json.loads(line)
                (target if row[label_field] == target_label else other).update(_ngrams(row[text_field]))
    total = target + other
    n_target, n_other, n_total = sum(target.values()), sum(other.values()), sum(total.values())
    alpha0 = prior * n_total
    candidates = []
    for term, count in total.items():
        if target[term] < min_count:
            continue
        alpha = alpha0 * count / n_total
        y_t, y_o = target[term] + alpha, other[term] + alpha
        delta = math.log(y_t / (n_target + alpha0 - y_t)) - math.log(y_o / (n_other + alpha0 - y_o))
        z = delta / math.sqrt(1 / y_t + 1 / y_o)
        if z > 0:
            candidates.append({"term": term, "z": round(z, 4), "count": target[term]})
    candidates.sort(key=lambda candidate: (-candidate["z"], candidate["term"]))
    origin = f"mined:{split_hash(path)}"
    return [{**candidate, "origin": origin} for candidate in candidates[:top]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    mining = commands.add_parser("mine")
    mining.add_argument("train", type=Path)
    mining.add_argument("--label", required=True, help="label of the target texts (JSON value)")
    mining.add_argument("--text-field", default="text")
    mining.add_argument("--label-field", default="label")
    mining.add_argument("--top", type=int, default=50)
    mining.add_argument("--min-count", type=int, default=5)
    args = parser.parse_args(argv)
    if args.command == "check":
        problems = check(load())
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    try:
        label = json.loads(args.label)
    except json.JSONDecodeError:
        label = args.label
    result = mine(args.train, label, text_field=args.text_field, label_field=args.label_field, top=args.top, min_count=args.min_count)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
