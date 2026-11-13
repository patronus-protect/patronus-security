#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Load and check the L1 threat taxonomy (research/l1-threat/taxonomy.yaml).

The taxonomy lists the attack families of each of the eleven L1 threat classes: word-class shape,
anchor lexica, required and negative context, DE/EN example shapes, carriers, the existing
``ark.injection.*`` / ``ark.threat.*`` rules the family takes over, baseline coverage, gap,
priority and the backlog task that builds it. Shell-syntax rules that leave the threat detector
for shell risk are listed under ``handoffs``. ``check`` verifies the file against the repository:

    python3 scripts/l1_threat/taxonomy.py check      # exit code 1 on any problem
    python3 scripts/l1_threat/taxonomy.py summary    # families and mapped rules per class

Problems reported by ``check``:
- an existing rule (injection catalogs, native injection registry, native structural rules,
  threat ``rules.json``) that no family or handoff maps, or that two places map;
- a mapped rule id that does not exist;
- a ``must`` family without a task, or a task id that is not in ``backlog.yaml``;
- a key that ``backlog.yaml`` repeats within one mapping (YAML keeps the last one silently, so a
  merge that leaves ``status: done`` above ``status: todo`` would reopen the task);
- a lexicon id that is neither in ``ark-core/src/detectors/anchor_lexicons/*.json`` nor declared
  as planned in the taxonomy (and a planned id that already exists or is declared twice);
- schema errors (classes, family and lexicon keys, priorities, carriers, baselines, example shapes).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TAXONOMY_PATH = ROOT / "research" / "l1-threat" / "taxonomy.yaml"
BACKLOG_PATH = ROOT / "research" / "l1-threat" / "backlog.yaml"
INJECTION_DIR = ROOT / "ark-core" / "src" / "detectors" / "injection"
LEXICON_DIR = ROOT / "ark-core" / "src" / "detectors" / "anchor_lexicons"
# The threat detector moves from rust/ into ark-core; whichever copy exists is read.
THREAT_RULE_PATHS = (
    ROOT / "ark-core" / "src" / "detectors" / "threat" / "rules.json",
    ROOT / "rust" / "src" / "detectors" / "threat" / "rules.json",
)

SCHEMA = "ark-l1-threat-taxonomy-v1"
CLASSES = (
    "instruction_injection",
    "jailbreak",
    "prompt_extraction",
    "tool_poisoning",
    "agent_config_tampering",
    "memory_poisoning",
    "exfiltration",
    "unsafe_action",
    "resource_exhaustion",
    "harmful_content",
    "toxic_language",
)
PRIORITIES = ("must", "should", "could")
CARRIERS = (
    "chat",
    "email",
    "web",
    "document",
    "tool_description",
    "tool_output",
    "agent_config",
    "code",
    "config",
    "log",
    "rag_chunk",
    "memory",
)
BASELINES = (
    "pipelock",
    "cisco_yara",
    "atr",
    "prompt_guard",
    "llamafirewall",
    "nemo",
    "vigil",
    "protectai_v2",
    "prompt_guard_2",
)
COVERAGE = ("full", "partial", "none")
LEXICON_KINDS = ("support", "counter")
LEXICON_KEYS = {"id", "kind", "task", "title"}
FAMILY_KEYS = {
    "id",
    "pattern",
    "title",
    "priority",
    "shape",
    "anchors",
    "required_context",
    "negative_context",
    "examples",
    "carriers",
    "existing_rules",
    "baseline_coverage",
    "gap",
    "scored_only",
}
OPTIONAL_FAMILY_KEYS = {"task"}
CONTEXT_KEYS = ("anchors", "required_context", "negative_context")
RULE_ID_PATTERN = re.compile(r"^ark\.(?:injection|threat)\.[a-z0-9_.]+$")
NATIVE_RULE_LITERAL = re.compile(r'rule_id:\s*"(ark\.(?:injection|threat)\.[a-z0-9_.]+)"')


def load(path: Path = TAXONOMY_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    return data


def existing_rule_ids(root: Path = ROOT) -> set[str]:
    """Every rule id the injection and threat detectors can report or the rules map can toggle."""
    injection_dir = root / INJECTION_DIR.relative_to(ROOT)
    ids: set[str] = set()
    for path in sorted((injection_dir / "rules").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for rule in payload.get("rules", []):
            ids.add(rule.get("canonical_id") or rule["id"])
    for path in sorted(injection_dir.glob("*.rs")):
        # Rule ids under #[cfg(test)] are test fixtures, not detector rules.
        source = path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
        ids.update(NATIVE_RULE_LITERAL.findall(source))
    for path in THREAT_RULE_PATHS:
        path = root / path.relative_to(ROOT)
        if path.is_file():
            ids.update(rule["id"] for rule in json.loads(path.read_text(encoding="utf-8"))["rules"])
            break
    return ids


def existing_lexicon_ids(root: Path = ROOT) -> set[str]:
    ids: set[str] = set()
    for path in sorted((root / LEXICON_DIR.relative_to(ROOT)).glob("*.json")):
        ids.update(entry["id"] for entry in json.loads(path.read_text(encoding="utf-8")))
    return ids


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        duplicates = sorted({str(key) for key, count in Counter(keys).items() if count > 1})
        if duplicates:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key(s) {', '.join(duplicates)}", node.start_mark
            )
        return super().construct_mapping(node, deep=deep)


def backlog_task_ids(path: Path = BACKLOG_PATH) -> set[str]:
    backlog = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    return {task["id"] for section in ("tasks", "recurring") for task in backlog.get(section) or []}


def _families(taxonomy: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for class_name, entry in (taxonomy.get("classes") or {}).items():
        for family in (entry or {}).get("families") or []:
            yield class_name, family


def _planned_lexicons(taxonomy: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for lexicon in taxonomy.get("lexicons") or []:
        yield "core", lexicon
    for class_name, entry in (taxonomy.get("classes") or {}).items():
        for lexicon in (entry or {}).get("lexicons") or []:
            yield class_name, lexicon


def _check_family(where: str, family: dict[str, Any], tasks: set[str]) -> list[str]:
    problems = []
    keys = set(family)
    problems += [f"{where}: missing key {key}" for key in sorted(FAMILY_KEYS - keys)]
    problems += [f"{where}: unknown key {key}" for key in sorted(keys - FAMILY_KEYS - OPTIONAL_FAMILY_KEYS)]
    priority = family.get("priority")
    if priority not in PRIORITIES:
        problems.append(f"{where}: priority {priority!r} is not one of {', '.join(PRIORITIES)}")
    task = family.get("task")
    if task is None:
        if priority == "must":
            problems.append(f"{where}: must-family without task")
    elif task not in tasks:
        problems.append(f"{where}: task {task} is not in backlog.yaml")
    carriers = family.get("carriers") or []
    if not carriers:
        problems.append(f"{where}: no carriers")
    problems += [f"{where}: unknown carrier {carrier}" for carrier in carriers if carrier not in CARRIERS]
    examples = family.get("examples") or {}
    for language in ("de", "en"):
        shapes = examples.get(language) if isinstance(examples, dict) else None
        if not shapes or not all(isinstance(shape, str) and shape.strip() for shape in shapes):
            problems.append(f"{where}: no {language} example shape")
    coverage = family.get("baseline_coverage") or {}
    if not isinstance(coverage, dict):
        problems.append(f"{where}: baseline_coverage is not a mapping")
        coverage = {}
    for baseline, value in coverage.items():
        if baseline not in BASELINES:
            problems.append(f"{where}: unknown baseline {baseline}")
        if value not in COVERAGE:
            problems.append(f"{where}: coverage {value!r} of {baseline} is not one of {', '.join(COVERAGE)}")
    if not isinstance(family.get("scored_only", False), bool):
        problems.append(f"{where}: scored_only is not a boolean")
    return problems


def check(
    taxonomy: dict[str, Any],
    *,
    rules: set[str],
    lexicons: set[str],
    tasks: set[str],
) -> list[str]:
    """Return every problem of ``taxonomy`` against the given rule, lexicon and task ids."""
    problems = []
    if taxonomy.get("schema") != SCHEMA:
        problems.append(f"schema is {taxonomy.get('schema')!r}, expected {SCHEMA}")
    classes = set(taxonomy.get("classes") or {})
    problems += [f"class {name} is missing" for name in CLASSES if name not in classes]
    problems += [f"unknown class {name}" for name in sorted(classes - set(CLASSES))]

    planned: Counter[str] = Counter()
    for owner, lexicon in _planned_lexicons(taxonomy):
        lexicon_id = lexicon.get("id")
        planned[lexicon_id] += 1
        if set(lexicon) != LEXICON_KEYS:
            problems.append(f"lexicon {lexicon_id} ({owner}): keys {', '.join(sorted(lexicon))}, expected {', '.join(sorted(LEXICON_KEYS))}")
        if lexicon_id in lexicons:
            problems.append(f"lexicon {lexicon_id} ({owner}) is declared as planned but already exists")
        if lexicon.get("kind") not in LEXICON_KINDS:
            problems.append(f"lexicon {lexicon_id} ({owner}): kind {lexicon.get('kind')!r} is not support or counter")
        if lexicon.get("task") not in tasks:
            problems.append(f"lexicon {lexicon_id} ({owner}): task {lexicon.get('task')} is not in backlog.yaml")
    problems += [f"lexicon {lexicon_id} is declared {count} times" for lexicon_id, count in sorted(planned.items()) if count > 1]
    known_lexicons = lexicons | set(planned)

    mapped: Counter[str] = Counter()
    family_ids: Counter[tuple[str, str]] = Counter()
    for class_name, family in _families(taxonomy):
        where = f"{class_name}.{family.get('id')}"
        family_ids[(class_name, family.get("id"))] += 1
        problems += _check_family(where, family, tasks)
        for key in CONTEXT_KEYS:
            problems += [
                f"{where}: unknown lexicon id {lexicon_id} in {key}"
                for lexicon_id in family.get(key) or []
                if lexicon_id not in known_lexicons
            ]
        mapped.update(family.get("existing_rules") or [])
    problems += [f"family {name}.{family} is defined {count} times" for (name, family), count in sorted(family_ids.items()) if count > 1]
    for name in sorted(classes & set(CLASSES)):
        if not (taxonomy["classes"][name] or {}).get("families"):
            problems.append(f"class {name} has no families")

    for handoff in taxonomy.get("handoffs") or []:
        if handoff.get("task") not in tasks:
            problems.append(f"handoff to {handoff.get('target')}: task {handoff.get('task')} is not in backlog.yaml")
        mapped.update(handoff.get("rules") or [])

    problems += [f"rule {rule} is not mapped" for rule in sorted(rules - set(mapped))]
    problems += [f"rule {rule} is mapped {mapped[rule]} times" for rule in sorted(mapped) if mapped[rule] > 1]
    problems += [f"mapped rule {rule} does not exist" for rule in sorted(set(mapped) - rules)]
    problems += [f"mapped rule {rule} is not an ark.injection.*/ark.threat.* id" for rule in sorted(mapped) if not RULE_ID_PATTERN.match(rule)]
    return problems


def summary(taxonomy: dict[str, Any]) -> str:
    lines = ["class                     must should could rules"]
    for name in CLASSES:
        families = (taxonomy["classes"].get(name) or {}).get("families") or []
        counts = Counter(family["priority"] for family in families)
        rules = sum(len(family.get("existing_rules") or []) for family in families)
        lines.append(f"{name:<25} {counts['must']:>4} {counts['should']:>6} {counts['could']:>5} {rules:>5}")
    handed = sum(len(handoff.get("rules") or []) for handoff in taxonomy.get("handoffs") or [])
    lines.append(f"handoffs: {handed} rules")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "summary"))
    parser.add_argument("--taxonomy", type=Path, default=TAXONOMY_PATH)
    args = parser.parse_args(argv)
    try:
        taxonomy = load(args.taxonomy)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"taxonomy invalid: {error}", file=sys.stderr)
        return 1
    problems = check(
        taxonomy,
        rules=existing_rule_ids(),
        lexicons=existing_lexicon_ids(),
        tasks=backlog_task_ids(),
    )
    if args.command == "summary" and not problems:
        print(summary(taxonomy), end="")
        return 0
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    families = sum(1 for _ in _families(taxonomy))
    print(f"taxonomy ok: {len(CLASSES)} classes, {families} families, {len(existing_rule_ids())} rules mapped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
