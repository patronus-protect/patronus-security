#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Count checksum-validated entities of ARK and Presidio for milestone M3 (L1-PII task T03).

Counting rule (research/l1-pii/README.md, decided 2026-10-14): one unit per benchmark id and
country whose validator computes a real check digit or checksum. Format-only validation
(length, alphabet, ranges, dates, lookup tables) does not count. National number systems count
per country; international ones (IBAN, PAN, crypto addresses) count once. Presidio is pinned to
the ``presidio_version`` of the entity map (2.2.364). M3 holds when ARK has at least
``M3_FACTOR`` times as many units as Presidio.

Both sides come from ``research/l1-pii/entity_map.yaml`` (section ``checksums``): ARK by validator
function of the ``PII_PATTERNS`` registry in ``ark-core/src/detectors/pii/pii.rs``, Presidio by entity
of every pattern recognizer with ``validate_result``. ``--presidio`` compares the Presidio side with
the installed registry and version.

    python3 scripts/l1_presidio/count_validated.py count            # Markdown table + M3 line
    python3 scripts/l1_presidio/count_validated.py count --json
    python3 scripts/l1_presidio/count_validated.py check            # classification complete?
    ~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/count_validated.py check --presidio

``check`` exits with 1 on any problem; ``count`` refuses to count an inconsistent map (exit 1).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, NamedTuple

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import entity_map as ENTITY_MAP_MODULE  # noqa: E402

M3_FACTOR = 2
RULE_KEYS = {"algorithm", "country"}
COUNTRY_PATTERN = re.compile(r"^[a-z]{2}$")


class Rule(NamedTuple):
    algorithm: str
    country: str | None


class ChecksumRules(NamedTuple):
    ark: dict[str, Rule | None]  # validator function -> check digit algorithm, None = format only
    presidio: dict[str, Rule | None]  # Presidio entity -> check digit algorithm, None = format only


class ArkRule(NamedTuple):
    name: str
    label: str
    validator: str | None
    strength: str | None = None  # score-model strength of the rule (K02), None = not declared


class Unit(NamedTuple):
    entity_id: str
    country: str | None  # None: international, counted once


class Counts(NamedTuple):
    presidio_version: str
    ark: dict[Unit, tuple[str, ...]]  # unit -> "rule: validator"
    presidio: dict[Unit, tuple[str, ...]]  # unit -> "ENTITY (algorithm)"

    @property
    def target(self) -> int:
        return M3_FACTOR * len(self.presidio)

    @property
    def m3_met(self) -> bool:
        return len(self.ark) >= self.target

    @property
    def shared(self) -> set[Unit]:
        return set(self.ark) & set(self.presidio)


def _rule(raw: Any, where: str) -> Rule | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) - RULE_KEYS or "algorithm" not in raw:
        raise ValueError(f"{where} must be null or a mapping with algorithm and optional country")
    algorithm, country = raw["algorithm"], raw.get("country")
    if not isinstance(algorithm, str) or not algorithm.strip():
        raise ValueError(f"{where}.algorithm must be a non-empty string")
    if country is not None and (not isinstance(country, str) or not COUNTRY_PATTERN.match(country)):
        raise ValueError(f"{where}.country must be a lower-case two-letter code, got {country!r}")
    return Rule(algorithm, country)


def rules_from_dict(payload: Any) -> ChecksumRules:
    section = payload.get("checksums") if isinstance(payload, dict) else None
    if not isinstance(section, dict) or set(section) != {"ark", "presidio"}:
        raise ValueError("entity map requires a checksums section with exactly ark and presidio")
    sides = {}
    for side in ("ark", "presidio"):
        if not isinstance(section[side], dict):
            raise ValueError(f"checksums.{side} must be a mapping")
        sides[side] = {str(key): _rule(value, f"checksums.{side}.{key}") for key, value in section[side].items()}
    return ChecksumRules(**sides)


def load_rules(path: Path = ENTITY_MAP_MODULE.ENTITY_MAP_PATH) -> ChecksumRules:
    return rules_from_dict(yaml.safe_load(path.read_text(encoding="utf-8")))


def ark_rules_from_source(path: Path = ENTITY_MAP_MODULE.PII_SOURCE_PATH) -> list[ArkRule]:
    """Rule name, label and validator function of every ``PII_PATTERNS`` entry."""
    generate_docs = ENTITY_MAP_MODULE._load_file("_ark_generate_docs", ROOT / "scripts" / "generate_docs.py")
    return [
        ArkRule(pattern["id"], pattern["entity_group"], pattern["validator"], pattern["strength"])
        for pattern in generate_docs.parse_native_patterns(path, "PiiPattern")
    ]


def presidio_version() -> str:
    from importlib.metadata import version

    return version("presidio_analyzer")


def presidio_validated_entities() -> set[str]:
    """Entities of the installed Presidio's pattern recognizers that implement ``validate_result``."""
    import inspect

    from presidio_analyzer import PatternRecognizer, predefined_recognizers

    entities = set()
    for _, cls in inspect.getmembers(predefined_recognizers, inspect.isclass):
        if not issubclass(cls, PatternRecognizer) or cls is PatternRecognizer:
            continue
        own = [base for base in cls.__mro__ if base is not PatternRecognizer and "validate_result" in vars(base)]
        parameter = inspect.signature(cls.__init__).parameters.get("supported_entity")
        if own and parameter is not None and isinstance(parameter.default, str):
            entities.add(parameter.default)
    return entities


def id_country(entity_id: str) -> str | None:
    """Country of a national benchmark id (``pii.<country>.<name>``), None otherwise."""
    parts = entity_id.split(".")
    return parts[1] if len(parts) == 3 and COUNTRY_PATTERN.match(parts[1]) else None


def _unit(entity_id: str, rule: Rule) -> tuple[Unit, str | None]:
    """Counting unit and, if the declared country contradicts the id, a problem."""
    country = id_country(entity_id)
    if rule.country is not None and country is not None and rule.country != country:
        return Unit(entity_id, country), f"country {rule.country} contradicts {entity_id}"
    return Unit(entity_id, country or rule.country), None


def _strength_problem(ark_rule: ArkRule, rules: ChecksumRules) -> str | None:
    """The score model's validator strength must follow the checksum classification."""
    if ark_rule.strength is None:
        return None
    if ark_rule.validator is None:
        expected = "none"
    elif ark_rule.validator not in rules.ark:
        return None  # reported as unclassified
    else:
        expected = "format" if rules.ark[ark_rule.validator] is None else "checksum"
    if ark_rule.strength == expected:
        return None
    return (
        f"ARK rule {ark_rule.name} declares strength {ark_rule.strength}, "
        f"but validator {ark_rule.validator} is classified as {expected}"
    )


def _evaluate(
    entity_map: ENTITY_MAP_MODULE.EntityMap, rules: ChecksumRules, ark_rules: Iterable[ArkRule]
) -> tuple[Counts, list[str]]:
    problems: list[str] = []
    ark: dict[Unit, list[str]] = {}
    used = set()
    for ark_rule in ark_rules:
        problem = _strength_problem(ark_rule, rules)
        if problem:
            problems.append(problem)
        if ark_rule.validator is None:
            continue
        used.add(ark_rule.validator)
        if ark_rule.validator not in rules.ark:
            problems.append(f"ARK validator {ark_rule.validator} ({ark_rule.name}) is not classified in checksums.ark")
            continue
        rule = rules.ark[ark_rule.validator]
        if rule is None:
            continue
        entity_id = entity_map.ark_label(ark_rule.label)
        if entity_id is None:
            problems.append(f"ARK label {ark_rule.label} ({ark_rule.name}) is not in the entity map")
            continue
        unit, problem = _unit(entity_id, rule)
        if problem:
            problems.append(f"checksums.ark.{ark_rule.validator} ({ark_rule.name}): {problem}")
        ark.setdefault(unit, []).append(f"{ark_rule.name}: {ark_rule.validator}")
    problems += [
        f"checksums.ark.{validator} is not used by any rule of the PII registry"
        for validator in sorted(set(rules.ark) - used)
    ]

    presidio: dict[Unit, list[str]] = {}
    for entity, rule in sorted(rules.presidio.items()):
        entity_id = entity_map.presidio_entity(entity)
        if entity_id is None:
            problems.append(f"checksums.presidio.{entity} is not a Presidio entity of the entity map")
            continue
        if rule is None:
            continue
        unit, problem = _unit(entity_id, rule)
        if problem:
            problems.append(f"checksums.presidio.{entity}: {problem}")
        presidio.setdefault(unit, []).append(f"{entity} ({rule.algorithm})")

    counts = Counts(
        entity_map.presidio_version,
        {unit: tuple(sorted(sources)) for unit, sources in ark.items()},
        {unit: tuple(sorted(sources)) for unit, sources in presidio.items()},
    )
    return counts, problems


def count(
    entity_map: ENTITY_MAP_MODULE.EntityMap, rules: ChecksumRules, *, ark_rules: Iterable[ArkRule] | None = None
) -> Counts:
    return _evaluate(entity_map, rules, ark_rules_from_source() if ark_rules is None else ark_rules)[0]


def check(
    entity_map: ENTITY_MAP_MODULE.EntityMap,
    rules: ChecksumRules,
    *,
    ark_rules: Iterable[ArkRule] | None = None,
    presidio_validated: set[str] | None = None,
    presidio_version: str | None = None,
) -> list[str]:
    """Describe every gap in the classification (empty list: complete and consistent)."""
    problems = _evaluate(entity_map, rules, ark_rules_from_source() if ark_rules is None else ark_rules)[1]
    if presidio_version is not None and presidio_version != entity_map.presidio_version:
        problems.append(
            f"installed Presidio {presidio_version} differs from the pinned {entity_map.presidio_version}"
        )
    if presidio_validated is not None:
        classified = set(rules.presidio)
        problems += [
            f"Presidio entity {name} has validate_result but is not classified in checksums.presidio"
            for name in sorted(presidio_validated - classified)
        ]
        problems += [
            f"checksums.presidio.{name}: the installed recognizer has no validate_result"
            for name in sorted(classified - presidio_validated)
        ]
    return problems


def _units(units: dict[Unit, tuple[str, ...]]) -> list[dict[str, Any]]:
    return [
        {"entity_id": unit.entity_id, "country": unit.country, "sources": list(sources)}
        for unit, sources in sorted(units.items(), key=lambda item: (item[0].entity_id, item[0].country or ""))
    ]


def as_json(counts: Counts) -> dict[str, Any]:
    return {
        "presidio_version": counts.presidio_version,
        "ark": {"count": len(counts.ark), "units": _units(counts.ark)},
        "presidio": {"count": len(counts.presidio), "units": _units(counts.presidio)},
        "shared": len(counts.shared),
        "m3": {"factor": M3_FACTOR, "target": counts.target, "met": counts.m3_met},
    }


def markdown(counts: Counts) -> str:
    """One row per unit of either side, then the counts and the M3 verdict."""
    lines = ["| Benchmark-ID | Land | ARK | Presidio |", "|---|---|---|---|"]
    for unit in sorted(set(counts.ark) | set(counts.presidio), key=lambda u: (u.entity_id, u.country or "")):
        lines.append(
            f"| `{unit.entity_id}` | {unit.country or 'international'} | "
            f"{', '.join(counts.ark.get(unit, ())) or '–'} | {', '.join(counts.presidio.get(unit, ())) or '–'} |"
        )
    verdict = "erreicht" if counts.m3_met else "offen"
    return "\n".join(lines) + (
        f"\n\nPrüfziffervalidierte Entitäten (Presidio {counts.presidio_version}): "
        f"ARK {len(counts.ark)}, Presidio {len(counts.presidio)}, gemeinsam {len(counts.shared)}.\n"
        f"M3 (≥ {M3_FACTOR}× Presidio = {counts.target}): {verdict}.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("count", "check"))
    parser.add_argument("--map", type=Path, default=ENTITY_MAP_MODULE.ENTITY_MAP_PATH, help="entity map YAML")
    parser.add_argument("--presidio", action="store_true", help="also compare with the installed Presidio registry")
    parser.add_argument("--json", action="store_true", help="count: JSON instead of Markdown")
    args = parser.parse_args(argv)
    try:
        entity_map = ENTITY_MAP_MODULE.load(args.map)
        rules = load_rules(args.map)
    except ValueError as error:
        print(f"entity map invalid: {error}", file=sys.stderr)
        return 1
    registry = {}
    if args.presidio:
        registry = {"presidio_validated": presidio_validated_entities(), "presidio_version": presidio_version()}
    problems = check(entity_map, rules, **registry)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    counts = count(entity_map, rules)
    if args.command == "check":
        print(f"checksum classification ok: ARK {len(counts.ark)}, Presidio {len(counts.presidio)}")
    elif args.json:
        print(json.dumps(as_json(counts), indent=2, ensure_ascii=False))
    else:
        print(markdown(counts), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
