#!/usr/bin/env python3
"""Generate Ark's pinned 63-rule Prompt Armor candidate catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


REVISION = "95e532e275280488b3abacb519f8b14ae17a9dcb"
SOURCE = "https://github.com/prompt-armor/prompt-armor"

CANONICAL_GROUPS = {
    "ark.injection.override.discard_prior": "PI-001 PI-002 PI-003 PI-004 PI-005 PI-011 ML-DE-001 ML-ES-001 ML-FR-001 ML-PT-001",
    "ark.injection.override.obfuscated_discard": "PI-012",
    "ark.injection.override.replacement_directive": "PI-006 PI-007 PI-008 PI-009 ML-DE-002 ML-DE-006 ML-ES-002 ML-FR-002 ML-PT-002",
    "ark.injection.boundary.fake_system": "PI-010 IB-001 IB-002 IB-003 IB-004",
    "ark.injection.obfuscation.steganographic": "PI-013",
    "ark.injection.obfuscation.decode_request": "PI-014 EA-001 EA-002 EA-003",
    "ark.injection.jailbreak.game_framing": "PI-015",
    "ark.injection.jailbreak.named_mode": "JB-001 JB-002",
    "ark.injection.jailbreak.remove_constraints": "JB-003 JB-004 JB-005 JB-006 JB-007 JB-008 ML-DE-005 ML-ES-004 ML-FR-004 ML-PT-003",
    "ark.injection.jailbreak.dual_response": "JB-009",
    "ark.injection.identity.reassign": "ID-001 ID-002 ID-003 ID-004 ML-DE-003 ML-ES-003 ML-FR-003",
    "ark.injection.leak.system_instructions": "SL-001 SL-002 SL-003 SL-004 ML-DE-004",
    "ark.injection.exfil.external_sink": "DE-001 DE-002 DE-003",
    "ark.injection.authority.claim": "SE-001 SE-002 SE-003 SE-004",
}

FAMILIES = {
    "ark.injection.override.discard_prior": "instruction_override",
    "ark.injection.override.obfuscated_discard": "instruction_override",
    "ark.injection.override.replacement_directive": "instruction_override",
    "ark.injection.boundary.fake_system": "instruction_boundary",
    "ark.injection.obfuscation.steganographic": "encoded_instruction",
    "ark.injection.obfuscation.decode_request": "encoded_instruction",
    "ark.injection.jailbreak.game_framing": "jailbreak_framing",
    "ark.injection.jailbreak.named_mode": "jailbreak_framing",
    "ark.injection.jailbreak.remove_constraints": "jailbreak_framing",
    "ark.injection.jailbreak.dual_response": "jailbreak_framing",
    "ark.injection.identity.reassign": "jailbreak_framing",
    "ark.injection.leak.system_instructions": "instruction_leak",
    "ark.injection.exfil.external_sink": "cross_tool_instruction",
    "ark.injection.authority.claim": "authority_escalation",
}

# These are the collision-free Prompt Armor roots already audited in Ark. The
# strict PI-009 and ID-003 subsets plus the four source-derived P0 roots live
# in their own catalog, bringing the complete preserved audited-root count to 17.
AUDITED_UPSTREAM_IDS = {
    "PI-004", "PI-008", "PI-011", "SL-002", "SL-003",
    "SL-004", "IB-004", "DE-003", "ML-ES-001", "ML-FR-001", "ML-PT-001",
}


def canonical_mapping() -> dict[str, str]:
    mapping = {
        upstream_id: canonical_id
        for canonical_id, ids in CANONICAL_GROUPS.items()
        for upstream_id in ids.split()
    }
    if len(mapping) != 63:
        raise ValueError(f"canonical inventory must contain 63 IDs, got {len(mapping)}")
    return mapping


def build_catalog(source_yaml: Path) -> dict:
    document = yaml.safe_load(source_yaml.read_text(encoding="utf-8"))
    rules = document["rules"]
    mapping = canonical_mapping()
    upstream_ids = [rule["id"] for rule in rules]
    if len(upstream_ids) != 63 or set(upstream_ids) != set(mapping):
        raise ValueError("pinned Prompt Armor inventory differs from frozen 63-rule mapping")

    generated = []
    for rule in rules:
        upstream_id = rule["id"]
        canonical_id = mapping[upstream_id]
        item = {
            "id": f"prompt-armor.{upstream_id.lower()}",
            "canonical_id": canonical_id,
            "upstream_id": upstream_id,
            "family": FAMILIES[canonical_id],
            "severity": "high" if float(rule["weight"]) >= 0.75 else "medium",
            "upstream_weight": float(rule["weight"]),
            "candidate_only": upstream_id not in AUDITED_UPSTREAM_IDS,
            "description": rule["description"],
            "pattern": rule["pattern"],
        }
        if upstream_id == "ID-004":
            item["pattern"] = r"(?:your|the)\s+name\s+is\s+(?:now\s+)?[A-Za-z][A-Za-z0-9_-]{1,31}"
            item["excluded_match_terms"] = ["claude", "gpt", "assistant"]
        if upstream_id in AUDITED_UPSTREAM_IDS:
            item["evidence_tier"] = "audited_high_precision"
        generated.append(item)

    return {
        "schema_version": 1,
        "catalog_id": "prompt-armor-complete-95e532e",
        "source": SOURCE,
        "source_revision": REVISION,
        "license": "Apache-2.0",
        "rules": generated,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_yaml", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(build_catalog(args.source_yaml), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
