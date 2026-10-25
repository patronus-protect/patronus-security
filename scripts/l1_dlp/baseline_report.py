#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""DLP baseline report (E14): ARK vs. gitleaks, TruffleHog and detect-secrets on one split.

Scores the predictions of every tool with ``scoreboard.score_split`` and prints the measured
tables of ``research/dlp/scoreboard/baseline.md`` as Markdown: untyped and per-group P/R/F1,
hard-negative FP per variant, FP/MB on benign code and docs, recall per shared provider entity
(M1 view), and the ARK error buckets (hard-negative FP per rule and variant, missed and
boundary gold spans per rule, extra spans on positive rows, benign-code FP per rule).

Predictions are read from ``PRED/<tool>.<component>.jsonl`` with ``tool`` in
``ark, gitleaks, trufflehog, detect-secrets`` and ``component`` in ``synthetic, benign_code,
benign_docs`` (``run_ark.py`` / ``run_baselines.py`` output). ARK's opt-in run goes to
``PRED/ark.extended.<component>.jsonl`` (component also ``external``). Missing tools are
skipped; a tool or profile with only part of its component files is an error. The default
tables score every tool on its default run only; ARK's extended run feeds the opt-in table. Reports and tables carry offsets, counts and rule IDs only, never text.

    python3 scripts/l1_dlp/baseline_report.py --dev DIR --predictions PRED [--output-dir OUT]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOOLS = ("ark", "gitleaks", "trufflehog", "detect-secrets")
COMPONENTS = ("synthetic", "benign_code", "benign_docs")
EXTENDED_COMPONENTS = ("synthetic", "benign_docs", "external")
TOP = 15  # rows per error-bucket table


def _load_scoreboard() -> ModuleType:
    name = "_ark_l1_dlp_scoreboard"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / "scoreboard.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


SCOREBOARD = _load_scoreboard()


def _read(directory: Path, prefix: str, components: Iterable[str]) -> list[dict[str, Any]] | None:
    """Rows of every ``<prefix>.<component>.jsonl``; ``None`` if none exists.

    A partial set is an error: a missing component would silently score as "no findings".
    """
    paths = [directory / f"{prefix}.{component}.jsonl" for component in components]
    present = [path for path in paths if path.is_file()]
    if not present:
        return None
    missing = [path.name for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"{directory}: incomplete component set for {prefix}, missing {', '.join(missing)}")
    rows: list[dict[str, Any]] = []
    for path in present:
        rows.extend(SCOREBOARD._read_jsonl(path))
    return rows


def load_predictions(directory: Path) -> dict[str, dict[str, list[dict[str, Any]] | None]]:
    """``{tool: {"default": rows, "extended": rows | None}}`` for every tool with a default run."""
    tools = {}
    for tool in TOOLS:
        default = _read(directory, tool, COMPONENTS)
        extended = _read(directory, f"{tool}.extended", EXTENDED_COMPONENTS)
        if default is None:
            if extended is not None:
                raise ValueError(f"{directory}: {tool}.extended.* without a default run of {tool}")
            continue
        tools[tool] = {"default": default, "extended": extended}
    return tools


# ── error buckets ────────────────────────────────────────────────────────────


def error_buckets(
    carriers: list[dict[str, Any]], predictions: Iterable[dict[str, Any]], taxonomy: Any
) -> dict[str, Any]:
    """Where a tool's value spans go wrong on the carrier rows, counted by rule.

    - ``hard_negative_fp``: spans on hard-negative rows per predicted rule and variant;
    - ``missed``: gold spans no prediction touches, per gold rule (entity id of a baseline
      entity) and per carrier format;
    - ``boundary``: gold spans a prediction overlaps but none matches exactly, per gold rule;
    - ``extra_on_positives``: spans on positive rows that touch no gold span, per predicted rule.
    Content-class spans are ignored like in the scoreboard; gold spans of opt-in groups are
    skipped, because ``predictions`` is the default run where those rules are off.
    """
    by_id = {row["id"]: row for row in carriers}
    spans: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for row in predictions:
        if row.get("id") not in by_id:
            continue
        for span in row.get("evidence_spans") or []:
            if any(taxonomy.is_content(group) for group in SCOREBOARD._span_groups(span)):
                continue
            spans[row["id"]].append((int(span["start_char"]), int(span["end_char"]), str(span.get("rule_id") or span.get("label"))))
    hard_negative: Counter[tuple[str, str]] = Counter()
    missed: Counter[str] = Counter()
    missed_format: Counter[str] = Counter()
    boundary: Counter[str] = Counter()
    extra: Counter[str] = Counter()
    for row in carriers:
        found = spans.get(row["id"], [])
        if row.get("case_type") == "hard_negative":
            for _, _, rule in set(found):
                hard_negative[(rule, str(row.get("variant", "")))] += 1
            continue
        # Gold of a baseline entity (no ARK rule, GOLD-D2) is counted under its entity id.
        gold = [(int(e["start"]), int(e["end"]), str(e.get("rule_id") or e["entity"])) for e in row.get("entities") or []
                if not taxonomy.is_opt_in(str(e["label"]))]  # opt-in groups are off in this run
        for start, end, rule in gold:
            if any((s, e) == (start, end) for s, e, _ in found):
                continue
            if any(s < end and start < e for s, e, _ in found):
                boundary[rule] += 1
            else:
                missed[rule] += 1
                missed_format[str(row.get("format", ""))] += 1
        for s, e, rule in set(found):
            if not any(s < end and start < e for start, end, _ in gold):
                extra[rule] += 1
    return {
        "hard_negative_fp": [
            {"rule_id": rule, "variant": variant, "fp": count}
            for (rule, variant), count in sorted(hard_negative.items(), key=lambda item: (-item[1], item[0]))
        ],
        "missed": dict(sorted(missed.items(), key=lambda item: (-item[1], item[0]))),
        "missed_by_format": dict(sorted(missed_format.items(), key=lambda item: (-item[1], item[0]))),
        "boundary": dict(sorted(boundary.items(), key=lambda item: (-item[1], item[0]))),
        "extra_on_positives": dict(sorted(extra.items(), key=lambda item: (-item[1], item[0]))),
    }


# ── Markdown ─────────────────────────────────────────────────────────────────


def _pct(value: float) -> str:
    return f"{value * 100:.1f}"


def _table(header: list[str], rows: list[list[Any]], right_from: int = 1) -> list[str]:
    align = ["---" if i < right_from else "---:" for i in range(len(header))]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join(align) + " |"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return lines


def overall_table(reports: dict[str, dict[str, Any]]) -> list[str]:
    rows = []
    for tool, report in reports.items():
        syn = report["synthetic"]
        exact, overlap = syn["overall"]["exact"], syn["overall"]["overlap"]
        hn = syn["hard_negatives"]
        rows.append([
            tool, syn["overall"]["gold"], syn["overall"]["predicted"], _pct(exact["precision"]), _pct(exact["recall"]),
            _pct(exact["f1"]), _pct(overlap["f1"]), f"{hn['fp']} / {hn['rows_with_fp']}",
            report["benign_code"]["fp"], report["benign_code"]["fp_per_mb"],
            report["benign_docs"]["default"]["fp"], report["benign_docs"]["default"]["fp_per_mb"],
        ])
    return _table(["Tool", "Gold", "Pred", "P", "R", "F1 exact", "F1 overlap", "HN-FP (Spans / Zeilen)",
                   "Code-FP", "Code-FP/MB", "Doku-FP", "Doku-FP/MB"], rows)


def group_table(reports: dict[str, dict[str, Any]], keep) -> list[str]:
    first = next(iter(reports.values()))
    groups = [g for g, m in first["synthetic"]["groups"].items() if m["gold"] and keep(g)]
    rows = []
    for group in groups:
        row: list[Any] = [group, first["synthetic"]["groups"][group]["gold"]]
        for report in reports.values():
            metrics = report["synthetic"]["groups"].get(group)
            row.append("–" if metrics is None else f"{_pct(metrics['exact']['f1'])} / {_pct(metrics['overlap']['f1'])}")
        rows.append(row)
    return _table(["Gruppe", "Gold", *[f"{tool} F1 exact / overlap" for tool in reports]], rows, right_from=1)


def hard_negative_table(reports: dict[str, dict[str, Any]]) -> list[str]:
    variants = sorted({v for r in reports.values() for v in r["synthetic"]["hard_negatives"]["by_variant"]})
    rows = []
    for variant in variants:
        first = next(iter(reports.values()))["synthetic"]["hard_negatives"]["by_variant"].get(variant, {})
        row: list[Any] = [variant, first.get("rows", 0)]
        for report in reports.values():
            stats = report["synthetic"]["hard_negatives"]["by_variant"].get(variant, {"fp": 0, "rows_with_fp": 0})
            row.append(f"{stats['fp']} / {stats['rows_with_fp']}")
        rows.append(row)
    return _table(["Variante", "Zeilen", *[f"{tool} FP / Zeilen" for tool in reports]], rows)


def provider_table(reports: dict[str, dict[str, Any]], scopes: dict[str, str], keep) -> list[str]:
    """Exact recall per entity with gold; overlap recall in parentheses (baselines often widen spans)."""
    first = next(iter(reports.values()))
    rows = []
    for entity, metrics in first["synthetic"]["providers"].items():
        if not metrics["gold"] or not keep(entity):
            continue
        row: list[Any] = [entity, scopes.get(entity, "?"), metrics["gold"]]
        for report in reports.values():
            m = report["synthetic"]["providers"].get(entity)
            row.append("–" if m is None or not m["predicted"] and not m["exact"]["recall"]
                       else f"{_pct(m['exact']['recall'])} ({_pct(m['overlap']['recall'])})")
        rows.append(row)
    return _table(["Entität", "Scope", "Gold", *[f"{tool} R exact (overlap)" for tool in reports]], rows, right_from=2)


def bucket_lines(buckets: dict[str, Any], code: dict[str, Any]) -> list[str]:
    lines = ["**Hard-Negative-FP je Regel und Variante**", ""]
    lines += _table(["Regel", "Variante", "FP"], [[b["rule_id"], b["variant"], b["fp"]] for b in buckets["hard_negative_fp"][:TOP]], 2)
    for key, title in (("missed", "Verfehlte Gold-Spans je Regel (kein Overlap)"),
                       ("missed_by_format", "Verfehlte Gold-Spans je Carrier-Format"),
                       ("boundary", "Grenzfehler je Regel (Overlap, aber nicht exakt)"),
                       ("extra_on_positives", "Zusätzliche Spans auf Positiv-Zeilen je Regel")):
        lines += ["", f"**{title}**", ""]
        lines += _table(["Regel" if key != "missed_by_format" else "Format", "Anzahl"],
                        [[name, count] for name, count in list(buckets[key].items())[:TOP]])
    by_rule = sorted(code["by_rule"].items(), key=lambda item: (-item[1]["fp"], item[0]))
    lines += ["", "**Benign-Code-FP je Regel**", ""]
    lines += _table(["Regel", "FP", "FP/MB"], [[rule, m["fp"], m["fp_per_mb"]] for rule, m in by_rule[:TOP]])
    return lines


def render(reports: dict[str, dict[str, Any]], buckets: dict[str, Any] | None, entities: dict[str, dict[str, str]],
           taxonomy: Any, extended: dict[str, Any] | None = None) -> str:
    """Markdown tables; secret groups for every tool (default runs), opt-in groups of ARK's extended run separately."""
    scopes = {entity: meta["scope"] for entity, meta in entities.items()}

    def secret(group: str) -> bool:
        return not taxonomy.is_opt_in(group)

    def secret_entity(entity: str) -> bool:
        return secret(entities.get(entity, {}).get("group", ""))

    lines = ["### Gesamt (Default-Profil, ungetypt)", "", *overall_table(reports),
             "", "### F1 je Secret-Gruppe", "", *group_table(reports, secret),
             "", "### Hard Negatives je Variante", "", *hard_negative_table(reports),
             "", "### Recall je Secret-Entität", "", *provider_table(reports, scopes, secret_entity)]
    if extended is not None:
        lines += ["", "### Opt-in-Gruppen (nur ARK, Profil extended)", "",
                  *group_table({"ark": extended}, taxonomy.is_opt_in)]
    if buckets is not None and "ark" in reports:
        lines += ["", "### Fehler-Buckets ARK", "", *bucket_lines(buckets, reports["ark"]["benign_code"])]
    return "\n".join(lines) + "\n"


def load_entities(entity_map: Path) -> dict[str, dict[str, str]]:
    """Scope and group per entity id of entity_map.yaml."""
    import yaml

    data = yaml.safe_load(entity_map.read_text(encoding="utf-8"))
    return {str(e["id"]): {"scope": str(e.get("scope", "")), "group": str(e.get("group", ""))}
            for e in data.get("entities") or []}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dev", type=Path, required=True, help="frozen dev split (prepare_corpora.py)")
    parser.add_argument("--predictions", type=Path, required=True, help="directory with <tool>.<component>.jsonl")
    parser.add_argument("--entity-map", type=Path, default=ROOT / SCOREBOARD.ENTITY_MAP)
    parser.add_argument("--output-dir", type=Path, help="write <tool>.json default reports, ark.extended.json and ark.buckets.json here")
    args = parser.parse_args(argv)
    try:
        split = SCOREBOARD.load_split(args.dev)
        taxonomy = SCOREBOARD.load_taxonomy(args.entity_map)
        predictions = load_predictions(args.predictions)
        if not predictions:
            raise ValueError(f"{args.predictions}: no predictions of {', '.join(TOOLS)}")
        # Default tables: every tool on its default run only, so ARK is not credited with opt-in spans.
        reports = {tool: SCOREBOARD.score_split(split, runs["default"], taxonomy)
                   for tool, runs in predictions.items()}
        # Opt-in table: ARK's default plus extended run.
        extended = None
        if "ark" in predictions and predictions["ark"]["extended"] is not None:
            extended = SCOREBOARD.score_split(split, predictions["ark"]["default"], taxonomy,
                                              predictions["ark"]["extended"])
        buckets = None
        if "ark" in predictions:
            buckets = error_buckets(split.carriers, predictions["ark"]["default"], taxonomy)
        if args.output_dir:
            for tool, report in reports.items():
                SCOREBOARD._write_json(args.output_dir / f"{tool}.json", report)
            if extended is not None:
                SCOREBOARD._write_json(args.output_dir / "ark.extended.json", extended)
            if buckets is not None:
                SCOREBOARD._write_json(args.output_dir / "ark.buckets.json", buckets)
        sys.stdout.write(render(reports, buckets, load_entities(args.entity_map), taxonomy, extended))
        return 0
    except (ValueError, OSError) as exc:
        print(f"baseline_report: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
