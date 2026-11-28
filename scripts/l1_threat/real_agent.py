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

The positives are poisoned tool descriptions, rules files, config writes and memory writes quoted verbatim in
public advisories, write-ups and proof-of-concept repositories. ``research/l1-threat/labels/real_agent_quotes.jsonl``
names each one by its page (``page_url``), the document fetched (``raw_url``, a GitHub file pinned to a commit
where there is one), licence, commercial flag, label, reason and the span ``[start, end)`` in that document
(``extract``: ``raw`` text or ``html_text``, the page with tags stripped and entities unescaped) with the
SHA-256 of the quote; never the quote itself. ``fetch`` downloads the documents at evaluation time, cuts the
spans, keeps only quotes whose SHA-256 still matches (a changed page drops its row, counted under
``dropped``) and freezes them as a native dev directory that ``gold.py`` reads like ``prepare_corpora.py``
output.

    python3 scripts/l1_threat/real_agent.py check            # Exit 1 bei jedem Problem
    python3 scripts/l1_threat/real_agent.py counts           # rows per family and label
    python3 scripts/l1_threat/real_agent.py agree --check SECOND_PASS.jsonl
    python3 scripts/l1_threat/real_agent.py fetch --out DEV/real   # quoted positives, frozen
"""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import yaml

ROOT = Path(__file__).resolve().parents[2]
LABELS_PATH = ROOT / "research/l1-threat/labels/real_agent.jsonl"
REGISTRY_PATH = ROOT / "scripts/l1_threat/datasets.yaml"
QUOTES_PATH = ROOT / "research/l1-threat/labels/real_agent_quotes.jsonl"
QUOTES_SET = "real_agent_quotes"
QUOTE_KEYS = {"id", "class", "reason", "page_url", "raw_url", "repo", "revision", "licence", "commercial", "extract", "start", "end", "sha256"}
EXTRACTS = ("raw", "html_text")
TAG = re.compile(r"<[^>]*>")
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


def document_text(raw: bytes, extract: str) -> str:
    """The text a quote span points into: the UTF-8 document, or for ``html_text`` the page without tags."""
    text = raw.decode("utf-8", errors="replace")
    return html.unescape(TAG.sub("", text)) if extract == "html_text" else text


def check_quotes(quotes: list[dict[str, Any]]) -> list[str]:
    problems = []
    for number, quote in enumerate(quotes, 1):
        where = f"quote {number}"
        if set(quote) != QUOTE_KEYS:
            problems.append(f"{where}: keys must be {sorted(QUOTE_KEYS)}")
            continue
        if quote["class"] not in LABELS[1:] or not REASON.fullmatch(quote["reason"]) or quote["extract"] not in EXTRACTS:
            problems.append(f"{where}: class in {LABELS[1:]}, reason a snake_case code, extract in {EXTRACTS}")
        if not (isinstance(quote["start"], int) and isinstance(quote["end"], int) and 0 <= quote["start"] < quote["end"]):
            problems.append(f"{where}: span must be 0 <= start < end")
        if not SHA256.fullmatch(quote["sha256"]) or quote["commercial"] not in (True, False, "unknown"):
            problems.append(f"{where}: sha256 must be 64 hex, commercial true, false or unknown")
        pinned = quote["raw_url"].startswith("https://raw.githubusercontent.com/")
        if pinned and f"/{quote['revision']}/" not in quote["raw_url"]:
            problems.append(f"{where}: a GitHub document is pinned to its revision")
    ids = Counter(quote.get("id") for quote in quotes)
    problems.extend(f"quote id {key} used {count} times" for key, count in ids.items() if count > 1)
    return problems


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ark-l1-threat-eval"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def fetch(quotes: list[dict[str, Any]], out: Path, download: Callable[[str], bytes] = _download) -> dict[str, Any]:
    """Freeze the quoted positives under ``out`` (rows, manifest, ready marker); returns the manifest entry."""
    corpora = _corpora()
    documents: dict[tuple[str, str], str] = {}
    rows, dropped = [], Counter()
    for quote in quotes:
        key = (quote["raw_url"], quote["extract"])
        if key not in documents:
            try:
                documents[key] = document_text(download(quote["raw_url"]), quote["extract"])
            except OSError:
                documents[key] = ""
        text = documents[key][quote["start"]:quote["end"]]
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != quote["sha256"]:
            dropped["changed" if documents[key] else "unreachable"] += 1
            continue
        rows.append({
            "id": f"{QUOTES_SET}:{quote['id']}", "dataset": QUOTES_SET, "text": text, "language": "en", "benign": False,
            "classes": [quote["class"]], "reported_classes": [], "families": {}, "labels": [quote["reason"]],
            "contamination": {}, "source": quote["page_url"], "licence": quote["licence"],
        })
    out.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows).encode("utf-8")
    (out / f"{QUOTES_SET}.jsonl").write_bytes(body)
    entry = {
        "file": f"{QUOTES_SET}.jsonl", "sha256": corpora.PRESIDIO._sha256(body), "rows": len(rows), "role": "dev",
        "family": "neutral", "licence": "per row (quotation)", "source": "per row (page_url)", "commercial": "unknown",
        "classes": dict(Counter(row["classes"][0] for row in rows)), "benign": 0, "languages": {"en": len(rows)},
        "dropped": dict(dropped), "quotes": len(quotes),
    }
    manifest = json.dumps({"schema": corpora.CORPORA_SCHEMA, "split": "train_dev", "sets": {QUOTES_SET: entry}}, indent=1, sort_keys=True).encode("utf-8")
    (out / "manifest.json").write_bytes(manifest)
    (out / corpora.READY).write_text(f"{corpora.PRESIDIO._sha256(manifest)}  manifest.json\n", encoding="utf-8")
    return entry


def _corpora():
    spec = importlib.util.spec_from_file_location("l1_threat_prepare_corpora", ROOT / "scripts/l1_threat/prepare_corpora.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sub.add_parser("counts")
    agree_parser = sub.add_parser("agree")
    agree_parser.add_argument("--check", type=Path, required=True)
    fetch_parser = sub.add_parser("fetch")
    fetch_parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    rows, quotes = load(), load(QUOTES_PATH)
    if args.command == "check":
        problems = check(rows, yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))) + check_quotes(quotes)
        print("\n".join(problems) or f"{LABELS_PATH.name}: ok ({len(rows)} rows), {QUOTES_PATH.name}: ok ({len(quotes)} quotes)")
        return 1 if problems else 0
    if args.command == "counts":
        for (family, label), count in sorted(Counter((row["family"], row["label"]) for row in rows).items()):
            print(f"{family}\t{label}\t{count}")
        for label, count in sorted(Counter(quote["class"] for quote in quotes).items()):
            print(f"quoted\t{label}\t{count}")
        return 0
    if args.command == "fetch":
        print(json.dumps(fetch(quotes, args.out), indent=1, sort_keys=True))
        return 0
    # The sample spans both files: quotes are keyed by the SHA-256 of the quote, labelled by their class.
    result = agree(rows + [{"sha256": quote["sha256"], "label": quote["class"]} for quote in quotes], load(args.check))
    print(json.dumps(result, indent=1))
    return 1 if result["missing"] else 0


if __name__ == "__main__":
    sys.exit(main())
