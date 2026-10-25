#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Load and check the ARK <-> Presidio <-> corpus entity map (research/l1-pii/entity_map.yaml).

Every map entry is one benchmark id of ``patronus_ark.external_pii_eval`` with a scope
(``shared``, ``ark_only``, ``presidio_only``, ``semantic``), the Ark labels
(``entity_group`` in ``ark-core/src/detectors/pii/pii.rs``), the Presidio entities of the
pinned ``presidio_analyzer`` and the upstream labels per corpus of the external PII
manifest. ``check`` verifies the map against those sources:

    python3 scripts/l1_presidio/entity_map.py check             # registry, manifest, runtime maps
    ~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/entity_map.py check --presidio
    python3 scripts/l1_presidio/entity_map.py table             # Markdown overview

``--presidio`` additionally compares the mapped Presidio entities with the predefined
recognizers of the installed Presidio. Exit code 1 on any problem.

``source_families`` tags every gold source (each corpus of the manifest and the Ark-authored
gold sets) with the family it belongs to: ``ark_authored``, ``neutral`` or
``presidio_favored``. Milestones are decided on neutral and presidio_favored data only
(research/l1-pii/README.md, fairness rule).
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, NamedTuple

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENTITY_MAP_PATH = ROOT / "research" / "l1-pii" / "entity_map.yaml"
PII_SOURCE_PATH = ROOT / "ark-core" / "src" / "detectors" / "pii" / "pii.rs"
SCHEMA = "ark-l1-entity-map-v1"
SCOPES = ("shared", "ark_only", "presidio_only", "semantic")
ENTITY_KEYS = {"id", "scope", "ark", "presidio", "corpora"}
ID_PATTERN = re.compile(r"^(?:pii|entity)\.[a-z0-9_]+(?:\.[a-z0-9_]+)*$")
FAMILIES = ("ark_authored", "neutral", "presidio_favored")
# Families that decide a milestone; ark_authored results are reported only.
MILESTONE_FAMILIES = ("neutral", "presidio_favored")
# Gold sets outside the external PII manifest; all of them are written by the Ark project.
ARK_GOLD_SOURCES = {
    "pii_l1": ROOT / "python" / "patronus_ark" / "benchmark_data" / "pii_l1.jsonl",
    "l1_bilingual_rules": ROOT / "rust" / "tests" / "fixtures" / "l1_bilingual_rules.json",
    "ark-synthetic-de-eu": HERE / "synth_goldset.py",
}


class Entity(NamedTuple):
    id: str
    scope: str
    ark: tuple[str, ...]
    presidio: tuple[str, ...]
    corpora: dict[str, tuple[str, ...]]


def _names(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{where} must be a list of non-empty strings")
    return tuple(value)


def _entity(raw: Any) -> Entity:
    if not isinstance(raw, dict):
        raise ValueError(f"entity must be a mapping: {raw!r}")
    unknown = sorted(set(raw) - ENTITY_KEYS)
    missing = sorted(ENTITY_KEYS - set(raw))
    if unknown or missing:
        raise ValueError(f"entity {raw.get('id')!r}: unknown keys {unknown}, missing keys {missing}")
    entity_id = raw["id"]
    if not isinstance(entity_id, str) or not ID_PATTERN.match(entity_id):
        raise ValueError(f"invalid id {entity_id!r}; expected pii.* or entity.* in lower snake case")
    scope = raw["scope"]
    if scope not in SCOPES:
        raise ValueError(f"{entity_id}: unknown scope {scope!r}; expected one of {', '.join(SCOPES)}")
    ark = _names(raw["ark"], f"{entity_id}.ark")
    presidio = _names(raw["presidio"], f"{entity_id}.presidio")
    if not isinstance(raw["corpora"], dict):
        raise ValueError(f"{entity_id}.corpora must be a mapping")
    corpora = {
        str(corpus): _names(labels, f"{entity_id}.corpora.{corpus}") for corpus, labels in raw["corpora"].items()
    }
    expected = {
        "shared": (True, True),
        "ark_only": (True, False),
        "presidio_only": (False, True),
        "semantic": (False, None),
    }[scope]
    if expected[0] != bool(ark) or (expected[1] is not None and expected[1] != bool(presidio)):
        raise ValueError(
            f"{entity_id}: scope {scope} requires ark {'set' if expected[0] else 'empty'}"
            + ("" if expected[1] is None else f" and presidio {'set' if expected[1] else 'empty'}")
        )
    if scope == "semantic" and not entity_id.startswith("entity."):
        raise ValueError(f"{entity_id}: semantic entities use an entity.* id")
    return Entity(entity_id, scope, ark, presidio, corpora)


class EntityMap:
    """Validated entity map with lookups from each vocabulary to the benchmark id."""

    def __init__(self, presidio_version: str, entities: Iterable[Entity], families: dict[str, str] | None = None):
        self.presidio_version = presidio_version
        self.families: dict[str, str] = dict(families or {})  # gold source -> family
        self.entities: dict[str, Entity] = {}
        self._ark: dict[str, str] = {}
        self._presidio: dict[str, str] = {}
        self._corpora: dict[str, dict[str, str]] = {}
        for entity in entities:
            if entity.id in self.entities:
                raise ValueError(f"duplicate id {entity.id}")
            self.entities[entity.id] = entity
            for vocabulary, names in (("ARK label", entity.ark), ("Presidio entity", entity.presidio)):
                target = self._ark if vocabulary == "ARK label" else self._presidio
                for name in names:
                    if name in target:
                        raise ValueError(f"duplicate {vocabulary} {name!r} in {target[name]} and {entity.id}")
                    target[name] = entity.id
            for corpus, labels in entity.corpora.items():
                target = self._corpora.setdefault(corpus, {})
                for label in labels:
                    key = label.strip().lower()
                    if key in target:
                        raise ValueError(f"duplicate {corpus} label {label!r} in {target[key]} and {entity.id}")
                    target[key] = entity.id

    @classmethod
    def from_dict(cls, payload: Any) -> "EntityMap":
        if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
            raise ValueError(f"entity map requires schema {SCHEMA!r}")
        version = payload.get("presidio_version")
        if not isinstance(version, str) or not version:
            raise ValueError("entity map requires presidio_version")
        entities = payload.get("entities")
        if not isinstance(entities, list) or not entities:
            raise ValueError("entity map requires a non-empty entities list")
        return cls(version, (_entity(raw) for raw in entities), _families(payload.get("source_families", {})))

    def ark_label(self, label: str) -> str | None:
        return self._ark.get(label)

    def presidio_entity(self, entity_type: str) -> str | None:
        return self._presidio.get(entity_type)

    def corpus_label(self, corpus: str, label: str) -> str | None:
        return self._corpora.get(corpus, {}).get(label.strip().lower())

    def scope(self, entity_id: str) -> str | None:
        entity = self.entities.get(entity_id)
        return entity.scope if entity else None

    def ids(self, scope: str) -> set[str]:
        return {entity.id for entity in self.entities.values() if entity.scope == scope}

    def ark_labels(self) -> set[str]:
        return set(self._ark)

    def presidio_entities(self) -> set[str]:
        return set(self._presidio)

    def corpora(self) -> set[str]:
        return set(self._corpora)

    def corpus_labels(self, corpus: str) -> dict[str, str]:
        """Lower-cased upstream label -> benchmark id for one corpus."""
        return dict(self._corpora.get(corpus, {}))

    def family(self, source: str) -> str | None:
        """Source family of a gold source (corpus id or Ark gold set name)."""
        return self.families.get(source)


def _families(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ValueError("source_families must map a family to a list of gold sources")
    families: dict[str, str] = {}
    for family, sources in raw.items():
        if family not in FAMILIES:
            raise ValueError(f"unknown source family {family!r}; expected one of {', '.join(FAMILIES)}")
        for source in _names(sources, f"source_families.{family}"):
            if source in families:
                raise ValueError(f"gold source {source} is tagged {families[source]} and {family}")
            families[source] = family
    return families


def _load_file(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault(name, module)  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


def load(path: Path = ENTITY_MAP_PATH) -> EntityMap:
    return EntityMap.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")))


def ark_labels_from_source(path: Path = PII_SOURCE_PATH) -> set[str]:
    """Every ``entity_group`` of the static PII_PATTERNS registry."""
    generate_docs = _load_file("_ark_generate_docs", ROOT / "scripts" / "generate_docs.py")
    return {pattern["entity_group"] for pattern in generate_docs.parse_native_patterns(path, "PiiPattern")}


def presidio_registry_entities() -> set[str]:
    """Entities of the installed Presidio's predefined pattern and spaCy recognizers.

    Remote and model-backed recognizers (Azure, GLiNER, Transformers, ...) declare no
    default entity and are not part of either Presidio profile.
    """
    import inspect

    from presidio_analyzer import EntityRecognizer, predefined_recognizers

    entities = set(predefined_recognizers.SpacyRecognizer.ENTITIES)
    for _, cls in inspect.getmembers(predefined_recognizers, inspect.isclass):
        if not issubclass(cls, EntityRecognizer):
            continue
        parameter = inspect.signature(cls.__init__).parameters.get("supported_entity")
        if parameter is not None and isinstance(parameter.default, str):
            entities.add(parameter.default)
    return entities


def _runtime_maps() -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, Any]]:
    # Loaded by path: the package __init__ needs the native module, this file does not,
    # so the check also runs in the Presidio venv.
    external_pii_eval = _load_file(
        "_ark_external_pii_eval", ROOT / "python" / "patronus_ark" / "external_pii_eval.py"
    )
    run_presidio = _load_file("_ark_run_presidio", HERE / "run_presidio.py")
    return (
        external_pii_eval.ARK_OUTPUT_MAP,
        run_presidio.PRESIDIO_OUTPUT_MAP,
        external_pii_eval.ENTITY_MAP,
        external_pii_eval.load_manifest(),
    )


def check(
    entity_map: EntityMap,
    *,
    ark_labels: set[str] | None = None,
    ark_output_map: dict[str, str] | None = None,
    presidio_output_map: dict[str, str] | None = None,
    benchmark_aliases: dict[str, str] | None = None,
    manifest: dict[str, Any] | None = None,
    presidio_entities: set[str] | None = None,
) -> list[str]:
    """Describe every disagreement between the map and its sources (empty list: consistent)."""
    if None in (ark_output_map, presidio_output_map, benchmark_aliases, manifest):
        defaults = _runtime_maps()
        ark_output_map = defaults[0] if ark_output_map is None else ark_output_map
        presidio_output_map = defaults[1] if presidio_output_map is None else presidio_output_map
        benchmark_aliases = defaults[2] if benchmark_aliases is None else benchmark_aliases
        manifest = defaults[3] if manifest is None else manifest
    if ark_labels is None:
        ark_labels = ark_labels_from_source()

    problems = []
    mapped = entity_map.ark_labels()
    problems += [f"ARK label {label} is not mapped" for label in sorted(ark_labels - mapped)]
    problems += [f"ARK label {label} is mapped but not in the registry" for label in sorted(mapped - ark_labels)]

    for name, runtime, lookup in (
        ("ARK_OUTPUT_MAP", ark_output_map, entity_map.ark_label),
        ("PRESIDIO_OUTPUT_MAP", presidio_output_map, entity_map.presidio_entity),
    ):
        for label, benchmark in sorted(runtime.items()):
            if lookup(label) != benchmark:
                problems.append(f"{name}[{label}] = {benchmark}, entity map says {lookup(label)}")
    for alias, benchmark in sorted(benchmark_aliases.items()):
        if benchmark not in entity_map.entities:
            problems.append(f"external_pii_eval.ENTITY_MAP[{alias}] = {benchmark} is not in the entity map")

    for corpus in sorted(entity_map.corpora() - set(manifest)):
        problems.append(f"corpus {corpus} is not in the external PII manifest")
    for corpus_id, corpus in sorted(manifest.items()):
        expected = {label.strip().lower(): benchmark for label, benchmark in corpus.get("label_map", {}).items()}
        actual = entity_map.corpus_labels(corpus_id)
        if not actual and corpus_id not in entity_map.corpora():
            problems.append(f"corpus {corpus_id} of the manifest is missing in the entity map")
            continue
        for label in sorted(expected.keys() | actual.keys()):
            if expected.get(label) != actual.get(label):
                problems.append(
                    f"{corpus_id} label {label}: manifest {expected.get(label)}, entity map {actual.get(label)}"
                )

    sources = set(manifest) | set(ARK_GOLD_SOURCES)
    problems += [f"Ark gold source {name} not found at {path}" for name, path in ARK_GOLD_SOURCES.items() if not path.is_file()]
    problems += [f"gold source {source} has no source family" for source in sorted(sources - entity_map.families.keys())]
    problems += [f"source family entry {source} is not a known gold source" for source in sorted(entity_map.families.keys() - sources)]

    if presidio_entities is not None:
        known = entity_map.presidio_entities()
        problems += [f"Presidio entity {name} is not mapped" for name in sorted(presidio_entities - known)]
        problems += [
            f"Presidio entity {name} is mapped but not in the installed registry"
            for name in sorted(known - presidio_entities)
        ]
    return problems


def table(entity_map: EntityMap) -> str:
    """Markdown overview, one row per benchmark id, grouped by scope."""
    lines = ["| Benchmark-ID | Scope | ARK | Presidio | Korpora |", "|---|---|---|---|---|"]
    for scope in SCOPES:
        for entity in sorted(entity_map.entities.values(), key=lambda item: item.id):
            if entity.scope != scope:
                continue
            corpora = "; ".join(f"{corpus}: {', '.join(labels)}" for corpus, labels in sorted(entity.corpora.items()))
            lines.append(
                f"| `{entity.id}` | {scope} | {', '.join(entity.ark) or '–'} | "
                f"{', '.join(entity.presidio) or '–'} | {corpora or '–'} |"
            )
    counts = ", ".join(f"{scope} {len(entity_map.ids(scope))}" for scope in SCOPES)
    families = "\n".join(
        f"- {family}: " + ", ".join(sorted(s for s, f in entity_map.families.items() if f == family))
        for family in FAMILIES
    )
    return "\n".join(lines) + f"\n\n{len(entity_map.entities)} IDs: {counts}.\n\nQuellfamilien:\n{families}\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("check", "table"))
    parser.add_argument("--map", type=Path, default=ENTITY_MAP_PATH, help="entity map YAML")
    parser.add_argument("--presidio", action="store_true", help="also compare with the installed Presidio registry")
    args = parser.parse_args(argv)
    try:
        entity_map = load(args.map)
    except ValueError as error:
        print(f"entity map invalid: {error}", file=sys.stderr)
        return 1
    if args.command == "table":
        print(table(entity_map), end="")
        return 0
    problems = check(entity_map, presidio_entities=presidio_registry_entities() if args.presidio else None)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"entity map ok: {len(entity_map.entities)} ids, {len(entity_map.ark_labels())} ARK labels")
    return 0


if __name__ == "__main__":
    sys.exit(main())
