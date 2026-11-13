#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Validate the L1 threat gold: label spot-check, counts, provenance, cross-split leakage, go/no-go.

The gold of one split is the pool of its frozen directories (``prepare_corpora.py`` corpora and
``generators.py`` sets). Validation has four parts, each a command that writes counts only (never a
row text), so the holdout parts can run where the holdout is readable and leave just their numbers:

    python3 scripts/l1_threat/gold.py sample DIR [DIR ...] --out SHEET.jsonl [--per-set 50]
    python3 scripts/l1_threat/gold.py summary DIR [DIR ...] --split dev|holdout --review SHEET.jsonl --out SUMMARY.json
    python3 scripts/l1_threat/gold.py leakage --dev DIR [DIR ...] --holdout DIR [DIR ...] --out LEAKAGE.json
    python3 scripts/l1_threat/gold.py render --dev SUMMARY.json [--holdout SUMMARY.json] [--leakage LEAKAGE.json] [--notes NOTES.md] --out gold.md

``sample`` draws a fixed hash sample of at least ``--per-set`` rows from every set, stratified by label
(benign or class combination), into a review sheet; the reviewer sets ``verdict`` of each row to ``ok``
(label right), ``wrong`` (label wrong) or ``unclear``. ``summary`` checks the sheet against the pool
and writes rows per class and language, provenance per class (native / translated / synthetic) and the
error rate per set. ``leakage`` counts holdout rows that duplicate a dev row (exact and MinHash, the
dedup settings of the corpora). ``render`` writes the report with a go/no-go per class. Only the dev
summary lists the flagged rows (id, label, verdict, note); a holdout summary holds counts alone.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent


def _load_file(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CORPORA = _load_file("_ark_l1_threat_prepare_corpora", HERE / "prepare_corpora.py")

SUMMARY_SCHEMA = "ark-l1-threat-gold-summary-v1"
LEAKAGE_SCHEMA = "ark-l1-threat-gold-leakage-v1"
SAMPLE_SEED = "ark-l1-threat-m06-v1"
VERDICTS = ("ok", "wrong", "unclear")
SPLITS = ("dev", "holdout")
PROVENANCE = ("native", "translated", "synthetic")
# Validation thresholds: rows reviewed per set, label error rate a set may have, scored rows a class
# needs in each split. ``unclear`` counts as an error: a label nobody can confirm does not measure.
MIN_REVIEWED = 50
MAX_ERROR_RATE = 0.05
MIN_CLASS_ROWS = 50


def read_pool(directories: list[Path]) -> list[tuple[str, dict[str, Any], list[dict[str, Any]]]]:
    """``(set key, manifest entry, rows)`` per set of the frozen directories (ValueError on a broken one)."""
    pool = []
    for directory in directories:
        problems = CORPORA.verify(directory, schemas=(CORPORA.CORPORA_SCHEMA, CORPORA.GENERATED_SCHEMA))
        if problems:
            raise ValueError("\n".join(problems))
        manifest = json.loads((directory / "manifest.json").read_bytes())
        generated = manifest["schema"] == CORPORA.GENERATED_SCHEMA
        for name, entry in sorted(manifest["sets"].items()):
            rows = [json.loads(line) for line in (directory / entry["file"]).read_text(encoding="utf-8").split("\n") if line]
            key = f"{directory.name}/{name}"
            pool.append((key, {**entry, "generated": generated}, rows))
    keys = [key for key, _, _ in pool]
    if len(keys) != len(set(keys)):
        raise ValueError("two directories with the same name hold the same set")
    return pool


def label(row: dict[str, Any]) -> str:
    """Stratum of a row: ``benign``, its classes joined by ``+``, or ``other`` (reported only)."""
    if row["benign"]:
        return "benign"
    return "+".join(sorted(row["classes"])) or "other"


def provenance(row: dict[str, Any], entry: dict[str, Any], translated_sets: set[str]) -> str:
    if entry["generated"]:
        return "synthetic"
    if row.get("translated") or (row["language"] == "de" and row["dataset"] in translated_sets):
        return "translated"
    return "native"


def _rank(key: str, row_id: str) -> str:
    return hashlib.sha256(f"{SAMPLE_SEED}/{key}/{row_id}".encode("utf-8")).hexdigest()


def sample(pool: list[tuple[str, dict[str, Any], list[dict[str, Any]]]], per_set: int) -> list[dict[str, Any]]:
    """At least ``per_set`` rows per set (all if fewer), round-robin over its strata in hash order."""
    sheet = []
    for key, _, rows in pool:
        strata: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in sorted(rows, key=lambda r: _rank(key, r["id"])):
            strata[label(row)].append(row)
        queues = [strata[name] for name in sorted(strata)]
        picked: list[dict[str, Any]] = []
        depth = 0
        while len(picked) < min(per_set, len(rows)):
            picked.extend(queue[depth] for queue in queues if depth < len(queue))
            depth += 1
        sheet.extend(
            {"set": key, "id": row["id"], "label": label(row), "language": row["language"], "text": row["text"], "verdict": None, "note": ""}
            for row in picked
        )
    return sheet


def check_sheet(sheet: list[dict[str, Any]], pool: list[tuple[str, dict[str, Any], list[dict[str, Any]]]], per_set: int) -> list[str]:
    """Problems of a reviewed sheet against the pool it was drawn from."""
    rows = {(key, row["id"]): label(row) for key, _, rs in pool for row in rs}
    problems = []
    seen: set[tuple[str, str]] = set()
    reviewed: Counter[str] = Counter()
    for item in sheet:
        ref = (item.get("set"), item.get("id"))
        if ref not in rows:
            problems.append(f"{ref}: not in the pool")
            continue
        if ref in seen:
            problems.append(f"{ref}: reviewed twice")
        seen.add(ref)
        if item.get("label") != rows[ref]:
            problems.append(f"{ref}: label {item.get('label')!r} differs from the corpus ({rows[ref]!r})")
        if item.get("verdict") not in VERDICTS:
            problems.append(f"{ref}: verdict must be one of {', '.join(VERDICTS)}")
        reviewed[ref[0]] += 1
    for key, _, rs in pool:
        if reviewed[key] < min(per_set, len(rs)):
            problems.append(f"{key}: {reviewed[key]} rows reviewed, needs {min(per_set, len(rs))}")
    return problems


def summary(pool: list[tuple[str, dict[str, Any], list[dict[str, Any]]]], sheet: list[dict[str, Any]], split: str,
            translated_sets: set[str]) -> dict[str, Any]:
    """Counts of one split (no row text): rows per class and language, provenance, error rate per set."""
    classes: dict[str, Counter[str]] = defaultdict(Counter)
    origin: dict[str, Counter[str]] = defaultdict(Counter)
    class_sets: dict[str, Counter[str]] = defaultdict(Counter)
    sets: dict[str, Any] = {}
    verdicts: dict[str, Counter[str]] = defaultdict(Counter)
    benign_verdicts: dict[str, Counter[str]] = defaultdict(Counter)
    for item in sheet:
        verdicts[item["set"]][item["verdict"]] += 1
        if item["label"] == "benign":
            benign_verdicts[item["set"]][item["verdict"]] += 1
    for key, entry, rows in pool:
        scored = entry["role"] != "report"
        for row in rows:
            names = ["benign"] if row["benign"] else row["classes"]
            for name in names:
                if scored:
                    classes[name][row["language"]] += 1
                    origin[name][provenance(row, entry, translated_sets)] += 1
                class_sets[name][key] += 1
        counted = verdicts[key]
        reviewed = sum(counted.values())
        errors = counted["wrong"] + counted["unclear"]
        benign = benign_verdicts[key]
        sets[key] = {
            "dataset": entry.get("dataset", key.split("/", 1)[1]),
            "role": entry["role"],
            "rows": len(rows),
            "reviewed": reviewed,
            "wrong": counted["wrong"],
            "unclear": counted["unclear"],
            "error_rate": round(errors / reviewed, 4) if reviewed else None,
            "benign_reviewed": sum(benign.values()),
            "benign_errors": benign["wrong"] + benign["unclear"],
        }
    # Row ids only on dev: the holdout summary leaves the owner's session with counts alone.
    flagged = [{key: item[key] for key in ("set", "id", "label", "verdict", "note")} for item in sheet if item["verdict"] != "ok"]
    return {
        "schema": SUMMARY_SCHEMA,
        "split": split,
        **({"flagged": flagged} if split == "dev" else {}),
        "sets": sets,
        "classes": {name: dict(sorted(by_lang.items())) for name, by_lang in sorted(classes.items())},
        "provenance": {name: dict(sorted(counts.items())) for name, counts in sorted(origin.items())},
        "class_sets": {name: dict(sorted(counts.items())) for name, counts in sorted(class_sets.items())},
    }


def leakage(dev: list[tuple[str, dict[str, Any], list[dict[str, Any]]]], holdout: list[tuple[str, dict[str, Any], list[dict[str, Any]]]],
            dedup: dict[str, Any]) -> dict[str, Any]:
    """Holdout rows per set that duplicate a dev row, exactly or by MinHash (counts only)."""
    index = CORPORA.Deduper(dedup)
    for _, _, rows in dev:
        for row in rows:
            kind, _, signature = index.match(row["text"])
            if kind is None:
                index.add(row["text"], signature)
    sets = {}
    for key, _, rows in holdout:
        found = Counter(index.match(row["text"])[0] for row in rows)
        sets[key] = {"rows": len(rows), "exact": found["exact"], "minhash": found["minhash"]}
    return {
        "schema": LEAKAGE_SCHEMA,
        "dedup": dedup,
        "dev_rows": sum(len(rows) for _, _, rows in dev),
        "sets": sets,
        "leaked": sum(entry["exact"] + entry["minhash"] for entry in sets.values()),
    }


def _failing(summary_: dict[str, Any]) -> dict[str, str]:
    """Sets of a split that fail the spot-check, with the reason."""
    failing = {}
    for key, entry in summary_["sets"].items():
        if entry["reviewed"] < min(MIN_REVIEWED, entry["rows"]):
            failing[key] = f"{entry['reviewed']} rows reviewed"
        elif entry["error_rate"] is not None and entry["error_rate"] > MAX_ERROR_RATE:
            failing[key] = f"error rate {entry['error_rate']:.1%}"
    return failing


def _benign_error(summary_: dict[str, Any]) -> tuple[int, int]:
    """(errors, reviewed) over the benign rows of the scored sets: one pool sets every class's FPR."""
    scored = [entry for entry in summary_["sets"].values() if entry["role"] != "report"]
    return sum(entry["benign_errors"] for entry in scored), sum(entry["benign_reviewed"] for entry in scored)


def decide(classes: list[str], dev: dict[str, Any], holdout: dict[str, Any] | None, leak: dict[str, Any] | None) -> dict[str, tuple[str, str]]:
    """``{class: (go | no-go | pending, reason)}``. A class measures when both splits hold enough scored
    rows of it (report-only sets excluded), every scored set behind its rows passes the spot-check, the benign pool of each split
    passes it too, and no holdout row leaks from dev."""
    splits = {"dev": dev, **({"holdout": holdout} if holdout else {})}
    failing = {split: _failing(data) for split, data in splits.items()}
    benign_fail = []
    for split, data in splits.items():
        errors, reviewed = _benign_error(data)
        if reviewed and errors / reviewed > MAX_ERROR_RATE:
            benign_fail.append(f"{split} benign pool: error rate {errors / reviewed:.1%}")
    decisions = {}
    for name in classes:
        reasons = list(benign_fail)
        for split, data in splits.items():
            rows = sum(data["classes"].get(name, {}).values())
            if rows < MIN_CLASS_ROWS:
                reasons.append(f"{split}: {rows} scored rows (needs {MIN_CLASS_ROWS})")
            reasons.extend(f"{split} {key}: {failing[split][key]}" for key in data["class_sets"].get(name, {})
                           if key in failing[split] and data["sets"][key]["role"] != "report")
        if leak and leak["leaked"]:
            reasons.append(f"{leak['leaked']} holdout rows leak from dev")
        if reasons:
            decisions[name] = ("no-go", "; ".join(reasons))
        elif holdout is None:
            decisions[name] = ("pending", "owner holdout review missing")
        elif leak is None:
            decisions[name] = ("pending", "leakage check missing")
        else:
            decisions[name] = ("go", "")
    return decisions


def _rate(entry: dict[str, Any]) -> str:
    return "-" if entry["error_rate"] is None else f"{entry['error_rate']:.1%}"


def render(classes: list[str], dev: dict[str, Any], holdout: dict[str, Any] | None, leak: dict[str, Any] | None,
           notes: str = "") -> str:
    splits = {"dev": dev, **({"holdout": holdout} if holdout else {})}
    lines = ["# L1-Threat gold validation", ""]
    lines += [
        f"Spot-check: at least {MIN_REVIEWED} rows per set (all rows of a smaller set), verdict ok / wrong / unclear; "
        f"a set passes at an error rate (wrong + unclear) of at most {MAX_ERROR_RATE:.0%}. A class measures (go) with at "
        f"least {MIN_CLASS_ROWS} scored rows (outside report-only sets) in dev and in holdout, every set behind those rows passing, the reviewed "
        "benign rows of each split (one pool for every class's false-positive rate) at most at the same error rate, and "
        "no holdout row duplicating a dev row. Report-only sets are listed but neither count nor block.",
        "",
        "## Go / no-go per class",
        "",
        "| Class | Decision | Reason |",
        "|---|---|---|",
    ]
    for name, (decision, reason) in decide(classes, dev, holdout, leak).items():
        lines.append(f"| {name} | {decision} | {reason or '-'} |")
    lines += ["", "## Rows per class and language", ""]
    header = "| Class | " + " | ".join(f"{split} {lang}" for split in SPLITS for lang in ("de", "en")) + " | " + \
        " | ".join(f"{split} {p}" for split in SPLITS for p in PROVENANCE) + " |"
    lines += [header, "|---|" + "---:|" * (2 * len(SPLITS) + len(SPLITS) * len(PROVENANCE))]
    for name in [*classes, "benign"]:
        cells = []
        for split in SPLITS:
            data = splits.get(split)
            cells += [str(data["classes"].get(name, {}).get(lang, 0)) if data else "?" for lang in ("de", "en")]
        for split in SPLITS:
            data = splits.get(split)
            cells += [str(data["provenance"].get(name, {}).get(p, 0)) if data else "?" for p in PROVENANCE]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    for split in SPLITS:
        data = splits.get(split)
        lines += ["", f"## Spot-check {split}", ""]
        if data is None:
            lines.append("Pending: the owner's aggregate review report is not present.")
            continue
        lines += ["| Set | Role | Rows | Reviewed | Wrong | Unclear | Error rate | Benign errors |",
                  "|---|---|---:|---:|---:|---:|---:|---:|"]
        for key, entry in sorted(data["sets"].items()):
            lines.append(f"| {key} | {entry['role']} | {entry['rows']} | {entry['reviewed']} | {entry['wrong']} | {entry['unclear']} "
                         f"| {_rate(entry)} | {entry['benign_errors']} / {entry['benign_reviewed']} |")
        errors, reviewed = _benign_error(data)
        lines += ["", f"Benign pool ({split}, scored sets): {errors} of {reviewed} reviewed benign rows wrong or unclear."]
    lines += ["", "## Leakage dev → holdout", ""]
    if leak is None:
        lines.append("Pending: runs in the independent gate, where both splits are readable.")
    else:
        lines.append(f"{leak['leaked']} of {sum(e['rows'] for e in leak['sets'].values())} holdout rows duplicate one of "
                     f"{leak['dev_rows']} dev rows (exact or MinHash).")
    if dev.get("flagged"):
        lines += ["", "## Flagged dev rows", "", "| Set | Row | Label | Verdict | Note |", "|---|---|---|---|---|"]
        lines += [f"| {item['set']} | {item['id']} | {item['label']} | {item['verdict']} | {item['note']} |" for item in dev["flagged"]]
    if notes.strip():
        lines += ["", notes.strip()]
    return "\n".join(lines) + "\n"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _load_summary(path: Path | None, split: str) -> dict[str, Any] | None:
    if path is None:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SUMMARY_SCHEMA or data.get("split") != split:
        raise ValueError(f"{path}: not a {split} summary ({SUMMARY_SCHEMA})")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    smp = sub.add_parser("sample")
    smp.add_argument("directories", type=Path, nargs="+")
    smp.add_argument("--out", type=Path, required=True)
    smp.add_argument("--per-set", type=int, default=MIN_REVIEWED)
    summ = sub.add_parser("summary")
    summ.add_argument("directories", type=Path, nargs="+")
    summ.add_argument("--split", choices=SPLITS, required=True)
    summ.add_argument("--review", type=Path, required=True)
    summ.add_argument("--out", type=Path, required=True)
    leak = sub.add_parser("leakage")
    leak.add_argument("--dev", type=Path, nargs="+", required=True)
    leak.add_argument("--holdout", type=Path, nargs="+", required=True)
    leak.add_argument("--out", type=Path, required=True)
    rend = sub.add_parser("render")
    rend.add_argument("--dev", type=Path, required=True)
    rend.add_argument("--holdout", type=Path)
    rend.add_argument("--leakage", type=Path)
    rend.add_argument("--notes", type=Path, help="hand-written findings (Markdown) appended to the report")
    rend.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "sample":
        sheet = sample(read_pool(args.directories), max(args.per_set, MIN_REVIEWED))
        args.out.write_bytes(CORPORA.BENIGN_CODE._jsonl(sheet))
        print(f"{args.out}: {len(sheet)} rows to review")
        return 0
    if args.command == "summary":
        pool, sheet = read_pool(args.directories), _read_jsonl(args.review)
        problems = check_sheet(sheet, pool, MIN_REVIEWED)
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 1
        emap = CORPORA.entity_map.load()
        translated = {d["id"] for d in emap["datasets"] if d.get("translated")}
        _write_json(args.out, summary(pool, sheet, args.split, translated))
        print(f"{args.out}: written")
        return 0
    if args.command == "leakage":
        dev, holdout = read_pool(args.dev), read_pool(args.holdout)
        result = leakage(dev, holdout, CORPORA.load()["dedup"])
        _write_json(args.out, result)
        print(f"{args.out}: {result['leaked']} holdout rows leak from dev")
        return 1 if result["leaked"] else 0
    dev = _load_summary(args.dev, "dev")
    assert dev is not None
    leak_data = json.loads(args.leakage.read_text(encoding="utf-8")) if args.leakage else None
    notes = args.notes.read_text(encoding="utf-8") if args.notes else ""
    args.out.write_text(render(list(CORPORA.taxonomy.CLASSES), dev, _load_summary(args.holdout, "holdout"), leak_data, notes), encoding="utf-8")
    print(f"{args.out}: written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
