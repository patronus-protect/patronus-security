#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""DLP milestones M1–M3 (H-FINAL, criteria in research/dlp/README.md).

- M1 provider parity: on every shared provider entity with gold (scope ``shared``, not a
  generic credential, mapped to a gitleaks rule or TruffleHog detector), exact recall of ARK
  >= max(gitleaks, TruffleHog), and ARK FP/MB on benign code <= gitleaks.
- M2 generic secrets: exact F1 of the ``CREDENTIAL`` group (passwords, tokens, connection
  strings in config, CLI and DE/EN prose) >= the best baseline + 20 pp.
- M3 breadth, counted from ``entity_map.yaml`` and the ``RuleMeta`` of every DLP rule
  (``scripts/generate_docs.py`` parses the registry): share of gitleaks default rules whose
  entity has an ARK rule (>= 90 %), secret formats = rules of the secret families (>= 150),
  offline structure checks = secret rules with validator strength ``checksum`` or
  ``structure`` (>= 30), content/document classes with an ARK rule and no gitleaks,
  TruffleHog or detect-secrets counterpart (>= 20).

M1 and M2 read scoreboard reports (``scoreboard.score_split``); ``scoreboard.py gate`` prints
one ``milestone_line`` per split. M4 (latency) comes from ``latency.py``.

    python3 scripts/l1_dlp/milestones.py count            # M3 table + verdict line
    python3 scripts/l1_dlp/milestones.py count --json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENTITY_MAP = ROOT / "research" / "dlp" / "entity_map.yaml"
SECRET_FAMILIES = ("provider_secret", "generic_credential", "key_material")
CONTENT_FAMILIES = ("content_class", "document_class")
SECRET_SCANNERS = ("gitleaks", "trufflehog", "detect_secrets")
M1_TOOLS = ("gitleaks", "trufflehog")
M2_GROUP = "CREDENTIAL"
M2_MARGIN = 0.20
OFFLINE_STRENGTHS = ("checksum", "structure")
M3_TARGETS = {"gitleaks": 0.90, "secret_formats": 150, "offline_checks": 30, "content_classes": 20}


def dlp_patterns() -> list[dict[str, Any]]:
    """DLP rules with their RuleMeta, parsed from the registry by ``scripts/generate_docs.py``."""
    spec = importlib.util.spec_from_file_location("_ark_generate_docs", ROOT / "scripts" / "generate_docs.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module.parse_dlp_patterns()


def _family(entity_map: dict[str, Any], group: str) -> str:
    return str(((entity_map.get("taxonomy") or {}).get(group) or {}).get("family", ""))


def m1_entities(entity_map: dict[str, Any]) -> list[str]:
    return [
        str(entity["id"]) for entity in entity_map.get("entities") or []
        if entity.get("scope") == "shared" and entity.get("ark")
        and _family(entity_map, str(entity.get("group", ""))) in SECRET_FAMILIES
        and _family(entity_map, str(entity.get("group", ""))) != "generic_credential"
        and any(entity.get(tool) for tool in M1_TOOLS)
    ]


def _recall(report: dict[str, Any] | None, entity: str) -> float:
    metrics = ((report or {}).get("synthetic", {}).get("providers") or {}).get(entity)
    return float(metrics["exact"]["recall"]) if metrics else 0.0


def m1(head: dict[str, Any], baselines: dict[str, dict[str, Any]], entities: list[str]) -> dict[str, Any]:
    providers = head["synthetic"]["providers"]
    scored = [entity for entity in entities if (providers.get(entity) or {}).get("gold")]
    failed = [entity for entity in scored
              if _recall(head, entity) < max(_recall(baselines.get(tool), entity) for tool in M1_TOOLS)]
    fp = {"ark": head["benign_code"]["fp_per_mb"], "gitleaks": baselines["gitleaks"]["benign_code"]["fp_per_mb"]}
    return {"met": not failed and fp["ark"] <= fp["gitleaks"], "entities": len(scored),
            "held": len(scored) - len(failed), "failed": failed, "fp_per_mb": fp}


def _credential_f1(report: dict[str, Any]) -> float:
    group = report["synthetic"]["groups"].get(M2_GROUP)
    return float(group["exact"]["f1"]) if group else 0.0


def m2(head: dict[str, Any], baselines: dict[str, dict[str, Any]]) -> dict[str, Any]:
    best = max(baselines, key=lambda tool: _credential_f1(baselines[tool]))
    ark, baseline = _credential_f1(head), _credential_f1(baselines[best])
    return {"met": ark >= baseline + M2_MARGIN - 1e-9, "ark_f1": ark, "best": best, "baseline_f1": baseline}


def _verdict(met: bool) -> str:
    return "MET" if met else "MISSED"


def milestone_line(split: str, head: dict[str, Any], baselines: dict[str, dict[str, Any]],
                   entities: list[str]) -> str:
    """One aggregate line per split: counts and rates only, no entity or row ids."""
    one, two = m1(head, baselines, entities), m2(head, baselines)
    return (f"milestones {split} (default profile, exact spans): M1 {_verdict(one['met'])} "
            f"({one['held']}/{one['entities']} shared entities with recall >= max({', '.join(M1_TOOLS)}); "
            f"FP/MB benign code {one['fp_per_mb']['ark']} <= gitleaks {one['fp_per_mb']['gitleaks']}) | "
            f"M2 {_verdict(two['met'])} ({M2_GROUP} F1 {two['ark_f1'] * 100:.1f} >= {two['best']} "
            f"{two['baseline_f1'] * 100:.1f} + {M2_MARGIN * 100:.0f})")


def m3_counts(entity_map: dict[str, Any], patterns: list[dict[str, Any]]) -> dict[str, Any]:
    entities = entity_map.get("entities") or []
    mapped_rules = {str(rule) for entity in entities for rule in entity.get("ark") or []}
    unmapped = sorted(str(p["id"]) for p in patterns if p["id"] not in mapped_rules)
    if unmapped:
        raise ValueError(f"DLP rules without an entity in entity_map.yaml: {', '.join(unmapped)}")
    inventory = list((entity_map.get("baselines") or {}).get("gitleaks", {}).get("inventory") or [])
    covered = {str(rule) for entity in entities if entity.get("ark") for rule in entity.get("gitleaks") or []}
    mapped = len(covered & set(inventory))
    secret = [p for p in patterns if _family(entity_map, str(p["entity_group"])) in SECRET_FAMILIES]
    secret_ids = {p["id"] for p in secret}
    offline = [p for p in secret if p["validator_strength"] in OFFLINE_STRENGTHS]
    classes = sorted(
        str(entity["id"]) for entity in entities
        if entity.get("ark") and _family(entity_map, str(entity.get("group", ""))) in CONTENT_FAMILIES
        and not any(entity.get(tool) for tool in SECRET_SCANNERS)
    )
    counts = {
        "gitleaks": {"inventory": len(inventory), "mapped": mapped,
                     "share": round(mapped / len(inventory), 4) if inventory else 0.0},
        "secret_formats": {"rules": len(secret),
                           "entities": sum(any(r in secret_ids for r in e.get("ark") or []) for e in entities)},
        "offline_checks": {"rules": len(offline),
                           "by_strength": {s: sum(p["validator_strength"] == s for p in offline)
                                           for s in OFFLINE_STRENGTHS}},
        "content_classes": classes,
    }
    counts["met"] = {
        "gitleaks": counts["gitleaks"]["share"] >= M3_TARGETS["gitleaks"],
        "secret_formats": len(secret) >= M3_TARGETS["secret_formats"],
        "offline_checks": len(offline) >= M3_TARGETS["offline_checks"],
        "content_classes": len(classes) >= M3_TARGETS["content_classes"],
    }
    return counts


def m3_lines(counts: dict[str, Any]) -> list[str]:
    met = counts["met"]
    g, f, o = counts["gitleaks"], counts["secret_formats"], counts["offline_checks"]
    strengths = ", ".join(f"{name} {count}" for name, count in o["by_strength"].items())
    rows = [
        ("gitleaks default rules mapped", f"{g['mapped']}/{g['inventory']} ({g['share'] * 100:.1f} %)",
         f">= {M3_TARGETS['gitleaks'] * 100:.0f} %", met["gitleaks"]),
        ("secret formats (rules / entities)", f"{f['rules']} / {f['entities']}",
         f">= {M3_TARGETS['secret_formats']}", met["secret_formats"]),
        ("offline structure checks", f"{o['rules']} ({strengths})", f">= {M3_TARGETS['offline_checks']}",
         met["offline_checks"]),
        ("content/document classes without a secret-scanner counterpart", str(len(counts["content_classes"])),
         f">= {M3_TARGETS['content_classes']}", met["content_classes"]),
    ]
    lines = ["| M3 count | ARK | target | verdict |", "|---|---:|---:|---|"]
    lines += [f"| {name} | {value} | {target} | {_verdict(ok)} |" for name, value, target, ok in rows]
    lines.append(f"M3 {_verdict(all(met.values()))} ({sum(met.values())}/{len(met)} counts reach their target)")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    count = commands.add_parser("count", help="M3 counts from entity_map.yaml and RuleMeta")
    count.add_argument("--entity-map", type=Path, default=ENTITY_MAP)
    count.add_argument("--json", action="store_true", help="print the counts as JSON")
    args = parser.parse_args(argv)
    try:
        counts = m3_counts(yaml.safe_load(args.entity_map.read_text(encoding="utf-8")), dlp_patterns())
    except (ValueError, OSError) as exc:
        print(f"milestones: error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(counts, indent=2, sort_keys=True) if args.json else "\n".join(m3_lines(counts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
