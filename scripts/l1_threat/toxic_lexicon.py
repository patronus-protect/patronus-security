#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build, check and count the hashed toxic_language lexicon.

The repository holds no plaintext insult, slur or violence word list. The toxic_language rules
(``ark.threat.tx_*``) look up the words of a match in
``ark-core/src/detectors/threat/toxic_lexicon.json``: per family a sorted list of 64-bit
FNV-1a hashes over ``SALT`` + the normalised term (NFKC, lowercase, ä/ö/ü/ß spelled out,
leetspeak digits and ``@``/``$`` folded to letters, ``*`` dropped, whitespace collapsed). The Rust
side (``toxic_lexicon.rs``) normalises and hashes the same way; the parity case in
``scripts/tests/test_l1_toxic_lexicon.py`` and the Rust unit test pin one hash.

Sources and their licences are listed in ``research/l1-threat/toxic_lexicon_sources.yaml``. The
plaintext stays outside the repository:

1. candidate terms come from the train split of a listed dataset by frequency and contrast
   (``lexicons.py mine TRAIN.jsonl --label <toxic>``) or from a listed permissive word list;
2. a reviewer keeps the terms that belong to a family and writes ``family<TAB>term<TAB>source``
   lines into a file outside the repository;
3. ``build`` refuses a source that is not listed or whose licence is not allowed and writes the
   hashed lexicon.

    python3 scripts/l1_threat/toxic_lexicon.py build TERMS.tsv [TERMS.tsv ...]
    python3 scripts/l1_threat/toxic_lexicon.py check
    python3 scripts/l1_threat/toxic_lexicon.py count TEXTS.jsonl [--field text]

``count`` reports per family how many texts contain a hashed term, counts only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LEXICON_PATH = ROOT / "ark-core" / "src" / "detectors" / "threat" / "toxic_lexicon.json"
SOURCES_PATH = ROOT / "research" / "l1-threat" / "toxic_lexicon_sources.yaml"
SCHEMA_VERSION = 1
SALT = "ark-toxic-v1\0"
FAMILIES = ("insult", "dehumanise", "violence_verb")
ALLOWED_LICENCES = ("MIT", "Apache-2.0", "BSD-3-Clause", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0")
FOLD = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "0": "o", "1": "i", "3": "e", "4": "a",
                      "5": "s", "7": "t", "@": "a", "$": "s", "*": None})
HEX = re.compile(r"^[0-9a-f]{16}$")
WORD = re.compile(r"[\w@$*'-]+")
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


def normalize(term: str) -> str:
    """The lookup form of a term, the same as ``toxic_lexicon::normalize`` in Rust."""
    return " ".join(unicodedata.normalize("NFKC", term).lower().translate(FOLD).split())


def term_hash(term: str) -> str:
    value = FNV_OFFSET
    for byte in (SALT + normalize(term)).encode("utf-8"):
        value = ((value ^ byte) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def load_sources(path: Path = SOURCES_PATH) -> dict[str, dict[str, Any]]:
    return {source["id"]: source for source in yaml.safe_load(path.read_text(encoding="utf-8"))["sources"]}


def source_problems(sources: dict[str, dict[str, Any]]) -> list[str]:
    problems = []
    for source_id, source in sources.items():
        for key in ("licence", "url", "revision", "kind"):
            if not source.get(key):
                problems.append(f"source {source_id}: missing {key}")
        if source.get("use", True) and source.get("licence") not in ALLOWED_LICENCES:
            problems.append(f"source {source_id}: licence {source.get('licence')!r} is not allowed")
    return problems


def read_terms(paths: Iterable[Path]) -> list[tuple[str, str, str]]:
    terms = []
    for path in paths:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not all(part.strip() for part in parts):
                raise ValueError(f"{path}:{number}: expected family<TAB>term<TAB>source")
            terms.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
    return terms


def build(terms: list[tuple[str, str, str]], sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    problems = source_problems(sources)
    hashes: dict[str, set[str]] = {family: set() for family in FAMILIES}
    used: Counter[str] = Counter()
    for family, term, source_id in terms:
        if family not in FAMILIES:
            problems.append(f"unknown family {family!r}")
        elif source_id not in sources or not sources[source_id].get("use", True):
            problems.append(f"source {source_id!r} is not listed for use in {SOURCES_PATH.name}")
        elif normalize(term):
            hashes[family].add(term_hash(term))
            used[source_id] += 1
    if problems:
        raise ValueError("; ".join(sorted(set(problems))))
    return {
        "schema_version": SCHEMA_VERSION,
        "hash": "fnv1a64",
        "salt": SALT.rstrip("\0"),
        "families": {family: sorted(values) for family, values in hashes.items()},
        "sources": [{"id": source_id, "licence": sources[source_id]["licence"],
                     "revision": sources[source_id]["revision"], "terms": count}
                    for source_id, count in sorted(used.items())],
    }


def check(lexicon: dict[str, Any], sources: dict[str, dict[str, Any]]) -> list[str]:
    problems = source_problems(sources)
    if lexicon.get("schema_version") != SCHEMA_VERSION or lexicon.get("hash") != "fnv1a64" \
            or lexicon.get("salt") != SALT.rstrip("\0"):
        problems.append("lexicon: schema, hash or salt differs from the builder")
    if set(lexicon.get("families", {})) != set(FAMILIES):
        problems.append(f"lexicon: families must be {', '.join(FAMILIES)}")
    for family, values in lexicon.get("families", {}).items():
        if not values:
            problems.append(f"lexicon: family {family} is empty")
        if values != sorted(set(values)) or not all(HEX.match(value) for value in values):
            problems.append(f"lexicon: family {family} is not a sorted list of 16-hex hashes")
    for entry in lexicon.get("sources", []):
        source = sources.get(entry.get("id"))
        if source is None or source.get("licence") != entry.get("licence") or not source.get("use", True):
            problems.append(f"lexicon: source {entry.get('id')} is not listed with its licence")
    return problems


def families_of(text: str, lexicon: dict[str, Any]) -> set[str]:
    words = [normalize(word) for word in WORD.findall(text)]
    keys = {term_hash(word) for word in words} | {term_hash(f"{a} {b}") for a, b in zip(words, words[1:])}
    return {family for family, values in lexicon["families"].items() if keys & set(values)}


def count(path: Path, lexicon: dict[str, Any], field: str = "text") -> dict[str, int]:
    counts: Counter[str] = Counter()
    rows = 0
    with path.open(encoding="utf-8") as lines:
        for line in lines:
            if line.strip():
                rows += 1
                counts.update(families_of(json.loads(line)[field], lexicon))
    return {"rows": rows, **{family: counts[family] for family in FAMILIES}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build")
    build_parser.add_argument("terms", nargs="+", type=Path)
    build_parser.add_argument("--out", type=Path, default=LEXICON_PATH)
    commands.add_parser("check")
    count_parser = commands.add_parser("count")
    count_parser.add_argument("texts", type=Path)
    count_parser.add_argument("--field", default="text")
    args = parser.parse_args(argv)
    try:
        sources = load_sources()
        if args.command == "build":
            lexicon = build(read_terms(args.terms), sources)
            args.out.write_text(json.dumps(lexicon, indent=1) + "\n", encoding="utf-8")
            print(f"{args.out}: " + ", ".join(f"{f} {len(v)}" for f, v in lexicon["families"].items()))
            return 0
        lexicon = json.loads(LEXICON_PATH.read_text(encoding="utf-8"))
        if args.command == "check":
            problems = check(lexicon, sources)
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1 if problems else 0
        print(json.dumps(count(args.texts, lexicon, args.field), indent=1))
        return 0
    except (ValueError, OSError, KeyError) as exc:
        print(f"toxic lexicon: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
