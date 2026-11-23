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

1. candidate terms come from the train half of a listed dataset by frequency and contrast
   (``mine``) or from a listed permissive word list;
2. a reviewer keeps the terms that belong to a family and writes ``family<TAB>term<TAB>source``
   lines into a file outside the repository;
3. ``build`` refuses a source that is not listed or whose licence is not allowed and writes the
   hashed lexicon with the source of every hash (``origins``); ``--keep`` carries the hashes of
   the committed lexicon over with their origins (a schema-1 lexicon names one source for all).

``mine`` reads scored rows (``id``, ``text``, ``classes``, ``benign``, ``dataset``), keeps only the
train half (``train_half``: a hash split by row id; the other half evaluates the lexicon) and ranks
the normalised words and word pairs of the ``--class`` positives against the benign rows by
weighted log-odds (``lexicons.rank``). Each candidate names the dataset it occurs in most often
among the positives; the list is printed for review and never written into the repository.

    python3 scripts/l1_threat/toxic_lexicon.py mine ROWS.jsonl [...] --class toxic_language [--top 300]
    python3 scripts/l1_threat/toxic_lexicon.py build TERMS.tsv [TERMS.tsv ...] [--keep]
    python3 scripts/l1_threat/toxic_lexicon.py check
    python3 scripts/l1_threat/toxic_lexicon.py count TEXTS.jsonl [--field text]

``count`` reports per family how many texts contain a hashed term, counts only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lexicons import rank  # noqa: E402

ROOT = HERE.parents[1]
LEXICON_PATH = ROOT / "ark-core" / "src" / "detectors" / "threat" / "toxic_lexicon.json"
SOURCES_PATH = ROOT / "research" / "l1-threat" / "toxic_lexicon_sources.yaml"
SCHEMA_VERSION = 2
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


def train_half(row_id: str) -> bool:
    """Whether a row belongs to the mining half: the first SHA-256 byte of its id is even."""
    return hashlib.sha256(row_id.encode("utf-8")).digest()[0] % 2 == 0


def terms_of(text: str) -> set[str]:
    """The normalised words and word pairs of a text: the keys the lookup hashes."""
    words = [normalize(word) for word in WORD.findall(text)]
    return set(words) | {f"{a} {b}" for a, b in zip(words, words[1:])}


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


def kept_hashes(lexicon: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(family, hash, source)`` of every hash of a built lexicon."""
    origins = lexicon.get("origins", {})
    single = [entry["id"] for entry in lexicon.get("sources", [])]
    kept = []
    for family, values in lexicon["families"].items():
        for value in values:
            source = origins.get(value) or (single[0] if len(single) == 1 else None)
            if source is None:
                raise ValueError(f"lexicon: hash {value} has no origin")
            kept.append((family, value, source))
    return kept


def build(terms: list[tuple[str, str, str]], sources: dict[str, dict[str, Any]],
          kept: Iterable[tuple[str, str, str]] = ()) -> dict[str, Any]:
    problems = source_problems(sources)
    hashes: dict[str, set[str]] = {family: set() for family in FAMILIES}
    origins: dict[str, str] = {}
    entries = [(family, term_hash(term), source_id) for family, term, source_id in terms if normalize(term)]
    for family, value, source_id in [*kept, *entries]:
        if family not in FAMILIES:
            problems.append(f"unknown family {family!r}")
        elif source_id not in sources or not sources[source_id].get("use", True):
            problems.append(f"source {source_id!r} is not listed for use in {SOURCES_PATH.name}")
        else:
            hashes[family].add(value)
            origins.setdefault(value, source_id)
    if problems:
        raise ValueError("; ".join(sorted(set(problems))))
    used = Counter(origins.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "hash": "fnv1a64",
        "salt": SALT.rstrip("\0"),
        "families": {family: sorted(values) for family, values in hashes.items()},
        "origins": dict(sorted(origins.items())),
        "sources": [{"id": source_id, "licence": sources[source_id]["licence"],
                     "revision": sources[source_id]["revision"], "terms": count}
                    for source_id, count in sorted(used.items())],
    }


def mine(paths: Iterable[Path], class_name: str, *, top: int = 300, min_count: int = 3) -> list[dict[str, Any]]:
    """Candidate terms of the train-half ``class_name`` positives against the train-half benign rows."""
    target: Counter[str] = Counter()
    other: Counter[str] = Counter()
    datasets: dict[str, Counter[str]] = {}
    for path in paths:
        with path.open(encoding="utf-8") as lines:
            for line in lines:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not train_half(row["id"]):
                    continue
                keys = terms_of(row["text"])
                if row["benign"]:
                    other.update(keys)
                elif class_name in row["classes"]:
                    target.update(keys)
                    for key in keys:
                        datasets.setdefault(key, Counter())[row["dataset"]] += 1
    return [{**candidate, "source": datasets[candidate["term"]].most_common(1)[0][0]}
            for candidate in rank(target, other, top=top, min_count=min_count)]


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
    hashed = {value for values in lexicon.get("families", {}).values() for value in values}
    if set(lexicon.get("origins", {})) != hashed:
        problems.append("lexicon: origins must name the source of every hash")
    listed = {entry.get("id") for entry in lexicon.get("sources", [])}
    if not set(lexicon.get("origins", {}).values()) <= listed:
        problems.append("lexicon: an origin is not among the listed sources")
    for entry in lexicon.get("sources", []):
        source = sources.get(entry.get("id"))
        if source is None or source.get("licence") != entry.get("licence") or not source.get("use", True):
            problems.append(f"lexicon: source {entry.get('id')} is not listed with its licence")
    return problems


def families_of(text: str, lexicon: dict[str, Any]) -> set[str]:
    keys = {term_hash(term) for term in terms_of(text)}
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
    build_parser.add_argument("--keep", action="store_true", help="keep the hashes of the committed lexicon")
    mine_parser = commands.add_parser("mine")
    mine_parser.add_argument("rows", nargs="+", type=Path)
    mine_parser.add_argument("--class", dest="class_name", required=True)
    mine_parser.add_argument("--top", type=int, default=300)
    mine_parser.add_argument("--min-count", type=int, default=3)
    commands.add_parser("check")
    count_parser = commands.add_parser("count")
    count_parser.add_argument("texts", type=Path)
    count_parser.add_argument("--field", default="text")
    args = parser.parse_args(argv)
    try:
        sources = load_sources()
        if args.command == "build":
            kept = kept_hashes(json.loads(LEXICON_PATH.read_text(encoding="utf-8"))) if args.keep else ()
            lexicon = build(read_terms(args.terms), sources, kept)
            args.out.write_text(json.dumps(lexicon, indent=1) + "\n", encoding="utf-8")
            print(f"{args.out}: " + ", ".join(f"{f} {len(v)}" for f, v in lexicon["families"].items()))
            return 0
        if args.command == "mine":
            print(json.dumps(mine(args.rows, args.class_name, top=args.top, min_count=args.min_count),
                             ensure_ascii=False, indent=1))
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
