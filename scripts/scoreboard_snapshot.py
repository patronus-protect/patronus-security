#!/usr/bin/env python3
"""Build the per-entity part of a research/scoreboard/ milestone snapshot from measurement reports.

The milestone snapshot (schema ``ark-l1-scoreboard-snapshot-v1``) feeds
docs/reference/l1-capabilities.md. Milestones, latency and notes are written by hand; this script
fills the measured per-entity and per-group results from the aggregated reports of one measurement:

- ``--pii-report``: the JSON of ``scripts/l1_presidio/scoreboard.py report --json`` (ARK per mode,
  Presidio per profile, buckets ``family_entity/<family>/<id>`` with gold and exact counts);
- ``--dlp-reports``: the ``--output-dir`` of ``scripts/l1_dlp/baseline_report.py`` (``ark.json``,
  ``gitleaks.json``, ``trufflehog.json``, ``detect-secrets.json`` for the default runs and
  ``ark.extended.json`` for ARK's opt-in profile);
- ``--dlp-entity-map``: ``research/dlp/entity_map.yaml`` as of the measured commit
  (``git show <commit>:research/dlp/entity_map.yaml``), so ids added later stay "not measured".

Only counts and rates are read; reports never carry text. Ids of the measurement without gold get
``"gold": 0``; ids that were not part of the measurement are left out.

    python3 scripts/scoreboard_snapshot.py from-reports --snapshot research/scoreboard/2026-10-24.json \\
      --pii-report pii/report.json --dlp-reports dlp/REPORTS --dlp-entity-map entity_map@3e7c342.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml


SCHEMA = "ark-l1-scoreboard-snapshot-v1"
SCHEMA_VERSION = "1.1"
PII_FAMILIES = ("neutral", "presidio_favored", "ark_authored")
DLP_TOOLS = ("ark", "gitleaks", "trufflehog", "detect-secrets")
OPT_IN_FAMILIES = ("business_identifier", "content_class", "document_class")


def _pct(value: float) -> float:
    return round(value * 100, 1)


def _exact_f1(counts: dict[str, int]) -> float:
    precision = counts["exact"] / counts["predicted"] if counts["predicted"] else 0.0
    recall = counts["exact"] / counts["gold"] if counts["gold"] else 0.0
    return _pct(2 * precision * recall / (precision + recall)) if precision + recall else 0.0


def pii_entities(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, float]]]:
    """Gold and exact F1 per engine for every measured id and family, plus overall F1 per family."""
    engines = report["engines"]
    entities: dict[str, Any] = {}
    for entity_id in sorted(report["scopes"]):
        entry: dict[str, Any] = {}
        for family in PII_FAMILIES:
            key = f"family_entity/{family}/{entity_id}"
            counts = {name: engine["buckets"].get(key) for name, engine in engines.items()}
            gold = max((c["gold"] for c in counts.values() if c), default=0)
            if not gold:
                entry[family] = {"gold": 0}
                continue
            entry[family] = {
                "gold": gold,
                "f1": {name: _exact_f1(c) if c else 0.0 for name, c in counts.items()},
            }
        entities[entity_id] = entry
    overall = {
        family: {name: _exact_f1(engine["buckets"][f"family/{family}"]) for name, engine in engines.items()
                 if f"family/{family}" in engine["buckets"]}
        for family in PII_FAMILIES
    }
    return entities, overall


def _metrics(m: dict[str, Any]) -> dict[str, float]:
    exact = m["exact"] if "exact" in m and isinstance(m["exact"], dict) else m
    return {"f1": _pct(exact["f1"]), "precision": _pct(exact["precision"]), "recall": _pct(exact["recall"])}


def _covers(m: dict[str, Any] | None) -> bool:
    """A tool counts for an entity when it typed a span to it (baseline_report.provider_table rule)."""
    return m is not None and bool(m["predicted"] or m["exact"]["recall"])


def dlp_results(reports: dict[str, dict[str, Any]], extended: dict[str, Any] | None,
                entity_map: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Per-entity and per-group results: default profile for every tool, ARK's opt-in profile for
    default-off families."""
    taxonomy = entity_map["taxonomy"]

    def family(group: str | None) -> str:
        return (taxonomy.get(group or "") or {}).get("family", "")

    ark = reports["ark"]["synthetic"]
    opt_in_classes = set((extended or reports["ark"]).get("opt_in_classes") or [])
    ext_groups = (extended or {}).get("synthetic", {}).get("groups", {})
    ext_documents = ((extended or {}).get("external") or {}).get("documents", {})

    groups: dict[str, Any] = {}
    for group, meta in taxonomy.items():
        if family(group) in OPT_IN_FAMILIES:
            if meta.get("planned"):
                continue
            entry: dict[str, Any] = {"gold": 0, "profile": "extended"}
            if ext_groups.get(group, {}).get("gold"):
                entry.update(gold=ext_groups[group]["gold"], extended={"ark": _metrics(ext_groups[group])})
            groups[group] = entry
        elif group in ark["groups"]:
            gold = ark["groups"][group]["gold"]
            entry = {"gold": gold}
            if gold:
                entry["default"] = {tool: _metrics(report["synthetic"]["groups"][group])
                                    for tool, report in reports.items() if group in report["synthetic"]["groups"]}
            groups[group] = entry
        else:
            groups[group] = {"gold": 0}

    entities: dict[str, Any] = {}
    for item in entity_map["entities"]:
        entity_id, group = item["id"], item.get("group")
        if item.get("scope") == "out_of_scope" or (taxonomy.get(group or "") or {}).get("planned"):
            continue
        if family(group) in OPT_IN_FAMILIES:
            if entity_id not in opt_in_classes:
                continue
            entry = {"gold": 0, "profile": "extended"}
            if ext_groups.get(group, {}).get("gold"):
                entry.update(gold=ext_groups[group]["gold"], extended={"ark": _metrics(ext_groups[group])})
            elif ext_documents.get(entity_id, {}).get("gold"):
                document = ext_documents[entity_id]
                entry.update(gold=document["gold"], level="document", extended={"ark": _metrics(document)})
                groups[group] = dict(entry)
            entities[entity_id] = entry
            continue
        provider = ark["providers"].get(entity_id)
        if not provider or not provider["gold"]:
            entities[entity_id] = {"gold": 0}
            continue
        entities[entity_id] = {
            "gold": provider["gold"],
            "default": {tool: _metrics(report["synthetic"]["providers"][entity_id])
                        for tool, report in reports.items()
                        if tool == "ark" or _covers(report["synthetic"]["providers"].get(entity_id))},
        }
    return entities, groups


def from_reports(snapshot: dict[str, Any], pii_report: dict[str, Any] | None,
                 dlp_reports: dict[str, dict[str, Any]] | None, dlp_extended: dict[str, Any] | None,
                 dlp_entity_map: dict[str, Any] | None) -> dict[str, Any]:
    if snapshot.get("schema") != SCHEMA:
        raise ValueError(f"snapshot schema must be {SCHEMA}")
    out = json.loads(json.dumps(snapshot))
    out["schema_version"] = SCHEMA_VERSION
    if pii_report is not None:
        entities, overall = pii_entities(pii_report)
        pii = out["pii"]
        pii["families"] = list(PII_FAMILIES)
        pii["engines"] = list(pii_report["engines"])
        pii["entities"] = entities
        mode = f"ark-{pii.get('decision_mode', 'balanced')}"
        pii["overall_f1"] = {family: overall[family][mode] for family in ("neutral", "presidio_favored")
                             if mode in overall.get(family, {})}
    if dlp_reports is not None:
        if "ark" not in dlp_reports or dlp_entity_map is None:
            raise ValueError("DLP needs ark.json and the entity map")
        entities, groups = dlp_results(dlp_reports, dlp_extended, dlp_entity_map)
        dlp = out["dlp"]
        dlp.pop("group_f1", None)
        dlp["tools"] = [tool for tool in DLP_TOOLS if tool in dlp_reports]
        dlp["opt_in_profile"] = "extended"
        overall = dlp_reports["ark"]["synthetic"]["overall"]["exact"]
        dlp["overall"] = {"f1": _pct(overall["f1"]), "precision": _pct(overall["precision"]),
                          "recall": _pct(overall["recall"])}
        dlp["groups"] = groups
        dlp["entities"] = entities
    return out


def load_dlp_reports(directory: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
    reports = {tool: json.loads((directory / f"{tool}.json").read_text(encoding="utf-8"))
               for tool in DLP_TOOLS if (directory / f"{tool}.json").is_file()}
    extended_path = directory / "ark.extended.json"
    extended = json.loads(extended_path.read_text(encoding="utf-8")) if extended_path.is_file() else None
    return reports, extended


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    convert = commands.add_parser("from-reports", help="fill per-entity results of a snapshot from report files")
    convert.add_argument("--snapshot", type=Path, required=True, help="snapshot with milestones (read)")
    convert.add_argument("--pii-report", type=Path, help="scoreboard.py report --json output")
    convert.add_argument("--dlp-reports", type=Path, help="baseline_report.py --output-dir")
    convert.add_argument("--dlp-entity-map", type=Path, help="research/dlp/entity_map.yaml of the measured commit")
    convert.add_argument("--output", type=Path, help="write here (default: overwrite --snapshot)")
    args = parser.parse_args(argv)
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
        pii_report = json.loads(args.pii_report.read_text(encoding="utf-8")) if args.pii_report else None
        dlp_reports = dlp_extended = dlp_entity_map = None
        if args.dlp_reports:
            dlp_reports, dlp_extended = load_dlp_reports(args.dlp_reports)
            if not args.dlp_entity_map:
                raise ValueError("--dlp-reports needs --dlp-entity-map")
            dlp_entity_map = yaml.safe_load(args.dlp_entity_map.read_text(encoding="utf-8"))
        result = from_reports(snapshot, pii_report, dlp_reports, dlp_extended, dlp_entity_map)
    except (OSError, ValueError, KeyError) as exc:
        print(f"scoreboard_snapshot: error: {exc}", file=sys.stderr)
        return 2
    (args.output or args.snapshot).write_text(dump(result), encoding="utf-8")
    return 0


def dump(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    sys.exit(main())
