#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Python reference of ``patronus.text_facts/1``: canonical JSON and the ``tf1`` analyzer.

The Rust port (``ark-core/src/detectors/text``) extracts the facts of a text; this reference
defines the bytes of their canonical form and the tokens the text models train on, so Python
training and Rust inference agree exactly. The parity goldens
(``ark-core/src/detectors/text/testdata/parity.jsonl``) hold per row the text, the findings and
data references passed in, the facts document the Rust extractor builds, and what this reference
makes of them:

    python3 scripts/l1_threat/text_facts.py parity           # rewrite canonical and tf1
    python3 scripts/l1_threat/text_facts.py parity --check   # exit code 1 when stale

- ``dumps``: every list but a ``span`` sorted by its ``json.dumps(sort_keys=True)`` form, sorted
  keys, compact separators, UTF-8 (the shell facts use the same form and keep ``segments`` in
  order).
- ``tf1``: ``T:<word>`` for every ``\\w+`` of the lowercased text, then the fact tokens
  ``F:<key>=<value>`` (each once, sorted). A multiset; the order does not matter.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PARITY_PATH = ROOT / "ark-core" / "src" / "detectors" / "text" / "testdata" / "parity.jsonl"
VERSION = "1.0"
WORD = re.compile(r"\w+")


def canonical(value: Any) -> Any:
    """Every list sorted by its ``json.dumps(sort_keys=True)`` form, recursively; a ``span``
    keeps its ``[start, end]`` order."""
    if isinstance(value, dict):
        return {key: item if key == "span" else canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        items = [canonical(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def dumps(facts: dict) -> str:
    """The canonical JSON of a facts document."""
    if facts.get("v") != VERSION:
        raise ValueError(f"facts must be patronus.text_facts/1 v {VERSION}")
    return json.dumps(canonical(facts), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fact_tokens(facts: dict) -> set[str]:
    """Deterministic flattening of the facts of one text into model tokens."""
    out = {f"F:LANG={facts['language']}"}
    out |= {f"F:CAR={c}" for c in facts["carrier"]}
    out |= {f"F:ADR={a}" for a in facts["addressee"]}
    out |= {f"F:SINK={s['kind']}" for s in facts["sinks"]}
    out |= {f"F:DATA={d['source']}:{d['label']}" for d in facts["data"]}
    for finding in facts["findings"]:
        category = finding["category"]
        out.add(f"F:CAT={category}")
        out.add(f"F:FAM={category}:{finding['family']}")
        out.add(f"F:PAT={finding['pattern']}")
        out |= {f"F:MOD={category}:{m}" for m in finding["modifiers"]}
    out |= {f"F:OBF={o}" for o in facts["obfuscated"]}
    out |= {f"F:DEC={d}" for d in facts["decoded"]}
    out |= {f"F:SUP={s}" for s in facts["support"]}
    out |= {f"F:CTR={c}" for c in facts["counter"]}
    if facts["addressee"] and facts["sinks"]:
        out.add("F:ADR_SINK")
    return out


def tf1(text: str, facts: dict) -> list[str]:
    """The ``tf1`` tokens of ``text`` and its facts."""
    return [f"T:{word}" for word in WORD.findall(text.lower())] + sorted(fact_tokens(facts))


def parity_rows(rows: list[dict]) -> list[dict]:
    """The rows with ``canonical`` and ``tf1`` (sorted) recomputed from text and facts."""
    return [
        {**row, "canonical": dumps(row["facts"]), "tf1": sorted(tf1(row["text"], row["facts"]))}
        for row in rows
    ]


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def render(rows: list[dict]) -> str:
    return "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    parity = sub.add_parser("parity", help="recompute canonical and tf1 of the parity goldens")
    parity.add_argument("--check", action="store_true", help="only check, exit 1 when stale")
    parity.add_argument("--path", type=Path, default=PARITY_PATH)
    args = parser.parse_args(argv)
    current = args.path.read_text(encoding="utf-8")
    expected = render(parity_rows(read_rows(args.path)))
    if args.check:
        if current != expected:
            print(f"{args.path} is stale: run text_facts.py parity", file=sys.stderr)
            return 1
        return 0
    args.path.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
