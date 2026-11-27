#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""How the built-in L1 models react to obfuscation alone: each model's flag rate, at its own detect cut, on benign and
hard-negative text and its TPR on its positives, clean and with zero-width characters, Unicode tags, base64,
leetspeak or homoglyphs applied (``generators.OBFUSCATIONS``, as the competitor benchmarks apply them).

Rows: the dev sets (no report set), without any row a built-in model was trained on (``scoreboard.trained_keys``);
benign rows up to ``--benign`` per language and every hard benign, positives up to ``--positives`` per class and
language, each sample the lowest ``MIX.text_sha`` keys. The models answer on the text alone (no rule findings), through
``ark-core/examples/l1_models.rs``.

    python3 scripts/l1_threat/model_obfuscation.py run [--dev DIR] [--out research/l1-threat/scoreboard/model-obfuscation.md]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "research" / "l1-threat" / "scoreboard" / "model-obfuscation.md"
DEV_DIRS = ("train_dev", "generated", "translated")
KINDS = ("zero_width", "unicode_tags", "base64", "leetspeak", "homoglyph")
LANGUAGES = ("de", "en")

SCOREBOARD = sys.modules.get("_ark_l1_threat_scoreboard")
if SCOREBOARD is None:
    _spec = importlib.util.spec_from_file_location("_ark_l1_threat_scoreboard", HERE / "scoreboard.py")
    assert _spec is not None and _spec.loader is not None
    SCOREBOARD = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = SCOREBOARD
    _spec.loader.exec_module(SCOREBOARD)
OBFUSCATIONS = SCOREBOARD.GENERATORS.OBFUSCATIONS


def sample(rows: list[dict[str, Any]], benign: int, positives: int) -> list[dict[str, Any]]:
    """Every hard benign, the ``benign`` lowest-key other benign rows per language and the ``positives`` lowest-key
    positives per class and language, each row once with its ``group`` (``benign``, ``hard``, ``pos:<class>``)."""
    by_key = sorted(rows, key=SCOREBOARD.MIX.text_sha)
    out: dict[str, dict[str, Any]] = {}
    taken: dict[tuple[str, str], int] = defaultdict(int)
    for row in by_key:
        lang = row["language"]
        if lang not in LANGUAGES:
            continue
        if row["benign"]:
            group = "hard" if SCOREBOARD.is_hard_benign(row) else "benign"
            if group == "benign" and taken[(group, lang)] >= benign:
                continue
            taken[(group, lang)] += 1
            out.setdefault(row["id"], {**row, "group": group})
            continue
        for cls in row["classes"]:
            if cls in SCOREBOARD.CLASSES and taken[(cls, lang)] < positives and row["id"] not in out:
                taken[(cls, lang)] += 1
                out[row["id"]] = {**row, "group": f"pos:{cls}"}
    return list(out.values())


def variants(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Each row clean (``<id>``) and under every obfuscation (``<id>~<kind>``)."""
    return [{"id": row["id"], "text": row["text"]} for row in rows] + [
        {"id": f"{row['id']}~{kind}", "text": OBFUSCATIONS[kind](row["text"])} for row in rows for kind in KINDS]


def predict(texts: list[dict[str, str]], binary: Path | None = None) -> dict[str, list[str]]:
    """Row id -> the built-in models whose answer is Detected; ``binary``: a built ``l1_models`` example instead of
    building it with cargo."""
    command = [str(binary)] if binary else ["cargo", "run", "--release", "-q", "-p", "patronus-ark-core", "--example",
                                            "l1_models"]
    stdin = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in texts)
    done = subprocess.run(command, input=stdin, capture_output=True, text=True, check=True, cwd=ROOT)
    return {item["id"]: item["flagged"] for item in map(json.loads, done.stdout.splitlines())}


def rates(rows: list[dict[str, Any]], flags: dict[str, list[str]]) -> dict[str, Any]:
    """Per model and language: benign and hard-benign flag rate, TPR on the model's positives, clean and per kind."""
    out: dict[str, Any] = {}
    for model in SCOREBOARD.CLASSES:
        for lang in LANGUAGES:
            for group, members in (("benign", [r for r in rows if r["group"] == "benign"]),
                                   ("hard", [r for r in rows if r["group"] == "hard"]),
                                   ("positive", [r for r in rows if r["group"] == f"pos:{model}"])):
                members = [r for r in members if r["language"] == lang]
                cell = {"rows": len(members)}
                for kind in ("clean", *KINDS):
                    suffix = "" if kind == "clean" else f"~{kind}"
                    hits = sum(model in flags[f"{r['id']}{suffix}"] for r in members)
                    cell[kind] = 100.0 * hits / len(members) if members else None
                out[f"{model}|{lang}|{group}"] = cell
    return out


def render(result: dict[str, Any], note: str) -> str:
    def pct(value: float | None, digits: int) -> str:
        return "–" if value is None else f"{value:.{digits}f}"

    lines = ["# Built-in L1 models under obfuscation", "",
             "Generated by `scripts/l1_threat/model_obfuscation.py run`; do not edit by hand.", "", note, "",
             "Each built-in L1 model at its own detect cut (0.1 % FPR, per language), answering on the text alone. "
             "Flag rate in percent of benign rows, hard benign rows and TPR on the model's positives, clean and with "
             "each obfuscation applied to the whole text (zw: zero-width characters, tags: Unicode tags, b64: base64, "
             "leet: leetspeak, homoglyph). Rows: dev sets without the rows any built-in model was trained on.", "",
             "| model | lang | group | rows | clean | zw | tags | b64 | leet | homoglyph |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for key, cell in result.items():
        model, lang, group = key.split("|")
        digits = 1 if group == "positive" else 2
        lines.append(f"| {model} | {lang} | {group} | {cell['rows']} | "
                     + " | ".join(pct(cell[k], digits) for k in ("clean", *KINDS)) + " |")
    return "\n".join(lines) + "\n"


def run(dev: Path, benign: int, positives: int, binary: Path | None = None) -> dict[str, Any]:
    keys = set().union(*SCOREBOARD.trained_keys(dev).values())
    rows = [row for name in DEV_DIRS for entry in SCOREBOARD.split_sets(dev / name)
            for row in SCOREBOARD.BASELINES.read_rows(entry.path) if SCOREBOARD.MIX.text_sha(row) not in keys]
    picked = sample(rows, benign, positives)
    return rates(picked, predict(variants(picked), binary))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["run"])
    parser.add_argument("--dev", type=Path, default=Path(os.environ.get("ARK_L1_DEV_DATA", "")))
    parser.add_argument("--benign", type=int, default=3000)
    parser.add_argument("--positives", type=int, default=200)
    parser.add_argument("--binary", type=Path, help="a built l1_models example (default: cargo run)")
    parser.add_argument("--note", default="")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    result = run(args.dev, args.benign, args.positives, args.binary)
    if args.json:
        args.json.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    args.out.write_text(render(result, args.note), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
