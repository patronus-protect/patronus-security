#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Load and check the L1 threat baseline and dataset map (research/l1-threat/entity_map.yaml).

The map names, for every baseline of the threat scoreboard, how its output labels count for the
eleven L1 threat classes (heuristic baselines through the per-rule mapping of ``oss_rules.yaml``,
reference models through their output labels), and for every dataset its licence, languages,
split, source family and how each upstream label maps to a class, to benign or out of scope.

    python3 scripts/l1_threat/entity_map.py check    # exit code 1 on any problem
    python3 scripts/l1_threat/entity_map.py table    # Markdown overview incl. who decides

Problems reported by ``check``:
- schema errors (keys, kinds, splits, families, languages, label outcomes);
- a baseline id that is not one of the taxonomy baselines, or a taxonomy baseline without entry;
- a heuristic baseline whose ``rules`` source is not in ``oss_rules.yaml``, or an inventory rule of
  that source with neither class nor handoff nor out-of-scope mapping;
- an unknown class, or a family that is not a family of its class in ``taxonomy.yaml``;
- an NC or GPL licence outside ``report_only``; an ``ark_blind`` set outside the holdout or an
  ``ark_authored`` set inside it;
- a ``trained_on`` id that is not registered, or a ``baseline_trained`` set no baseline names;
- a class and language (de, en) that neither neutral nor ark_blind holdout data decides and that
  ``gaps`` does not list, a gap that is decided after all, a language without a benign pool.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import oss_inventory  # noqa: E402
import taxonomy  # noqa: E402

MAP_PATH = taxonomy.ROOT / "research" / "l1-threat" / "entity_map.yaml"
SCHEMA = "ark-l1-threat-entity-map-v1"
DECISION_LANGUAGES = ("de", "en")
KINDS = ("heuristic", "reference")
SPLITS = ("holdout", "train_dev", "report")
FAMILIES = ("neutral", "ark_blind", "ark_authored", "baseline_trained", "report_only")
DECIDING_FAMILIES = ("neutral", "ark_blind")
HANDOFFS = ("shell_command",)
OUTCOMES = ("classes", "benign", "out_of_scope", "handoff")
LABEL_KEYS = {"label", "family", "decides", "reason"} | set(OUTCOMES)
BASELINE_KEYS = {"id", "kind"}
OPTIONAL_BASELINE_KEYS = {"rules", "model", "labels", "note", "trained_on", "training_data"}
DATASET_KEYS = {"id", "name", "source", "licence", "languages", "split", "family", "labels"}
OPTIONAL_DATASET_KEYS = {"note", "translated"}
GAP_KEYS = {"class", "language", "reason"}
RESTRICTED_LICENCE = re.compile(r"\bNC\b|-NC-|GPL")


def load(path: Path = MAP_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    return data


def _class_families(tax: dict[str, Any]) -> dict[str, set[str]]:
    return {
        name: {family["id"] for family in (entry or {}).get("families") or []}
        for name, entry in (tax.get("classes") or {}).items()
    }


def _check_label(where: str, label: dict[str, Any], families: dict[str, set[str]]) -> list[str]:
    if not isinstance(label, dict):
        return [f"{where}: label entry is not a mapping"]
    where = f"{where} [{label.get('label')}]"
    problems = []
    keys = set(label)
    problems += [f"{where}: unknown key {key}" for key in sorted(keys - LABEL_KEYS)]
    if not str(label.get("label") or "").strip():
        problems.append(f"{where}: empty label")
    outcomes = [key for key in OUTCOMES if key in label]
    if len(outcomes) != 1:
        problems.append(f"{where}: needs exactly one of {', '.join(OUTCOMES)}, has {', '.join(outcomes) or 'none'}")
        return problems
    outcome = outcomes[0]
    if outcome == "benign" and label["benign"] is not True:
        problems.append(f"{where}: benign must be true")
    if outcome == "out_of_scope" and not str(label["out_of_scope"] or "").strip():
        problems.append(f"{where}: out_of_scope needs a reason")
    if outcome == "handoff" and label["handoff"] not in HANDOFFS:
        problems.append(f"{where}: handoff {label['handoff']!r} is not one of {', '.join(HANDOFFS)}")
    if outcome != "classes":
        problems += [f"{where}: {key} only applies to class labels" for key in ("family", "decides", "reason") if key in label]
        return problems
    classes = label["classes"]
    if not isinstance(classes, list) or not classes:
        return problems + [f"{where}: classes is not a non-empty list"]
    problems += [f"{where}: unknown class {name}" for name in classes if name not in taxonomy.CLASSES]
    problems += [f"{where}: class {name} listed twice" for name, count in Counter(classes).items() if count > 1]
    family = label.get("family")
    if family is not None:
        if len(classes) != 1:
            problems.append(f"{where}: family needs exactly one class")
        elif family not in families.get(classes[0], set()):
            problems.append(f"{where}: {family} is not a family of {classes[0]} in taxonomy.yaml")
    if "decides" in label:
        if label["decides"] is not False:
            problems.append(f"{where}: decides may only be false")
        if not str(label.get("reason") or "").strip():
            problems.append(f"{where}: decides: false needs a reason")
    elif "reason" in label:
        problems.append(f"{where}: reason without decides: false")
    return problems


def _check_baseline(baseline: dict[str, Any], inventory: dict[str, Any], families: dict[str, set[str]]) -> list[str]:
    where = f"baseline {baseline.get('id')}"
    keys = set(baseline)
    problems = [f"{where}: missing key {key}" for key in sorted(BASELINE_KEYS - keys)]
    problems += [f"{where}: unknown key {key}" for key in sorted(keys - BASELINE_KEYS - OPTIONAL_BASELINE_KEYS)]
    if baseline.get("id") not in taxonomy.BASELINES:
        problems.append(f"{where}: not a taxonomy baseline ({', '.join(taxonomy.BASELINES)})")
    kind = baseline.get("kind")
    labels = baseline.get("labels") or []
    for label in labels:
        problems += _check_label(where, label, families)
    if kind == "heuristic":
        source = baseline.get("rules")
        sources = {entry["id"] for entry in inventory.get("sources") or []}
        if source not in sources:
            problems.append(f"{where}: rules source {source!r} is not in oss_rules.yaml")
        for rule in inventory.get("rules") or []:
            if rule.get("source") == source and not rule.get("class") and rule.get("mapping") not in ("out_of_scope", "handoff"):
                problems.append(f"{where}: inventory rule {rule.get('id')} has no class, handoff or out_of_scope")
        problems += [f"{where}: {key} only applies to reference baselines" for key in ("model", "trained_on", "training_data") if key in baseline]
    elif kind == "reference":
        if not baseline.get("model"):
            problems.append(f"{where}: reference baseline without model")
        if "rules" in baseline:
            problems.append(f"{where}: rules only applies to heuristic baselines")
        if not any("classes" in label for label in labels) or not any(label.get("benign") for label in labels):
            problems.append(f"{where}: needs at least one class label and one benign label")
        if not isinstance(baseline.get("trained_on"), list):
            problems.append(f"{where}: trained_on is not a list")
    else:
        problems.append(f"{where}: kind {kind!r} is not one of {', '.join(KINDS)}")
    return problems


def _check_dataset(dataset: dict[str, Any], families: dict[str, set[str]]) -> list[str]:
    where = f"dataset {dataset.get('id')}"
    keys = set(dataset)
    problems = [f"{where}: missing key {key}" for key in sorted(DATASET_KEYS - keys)]
    problems += [f"{where}: unknown key {key}" for key in sorted(keys - DATASET_KEYS - OPTIONAL_DATASET_KEYS)]
    split, family, licence = dataset.get("split"), dataset.get("family"), str(dataset.get("licence") or "")
    if split not in SPLITS:
        problems.append(f"{where}: split {split!r} is not one of {', '.join(SPLITS)}")
    if family not in FAMILIES:
        problems.append(f"{where}: family {family!r} is not one of {', '.join(FAMILIES)}")
    if not licence.strip():
        problems.append(f"{where}: empty licence")
    elif RESTRICTED_LICENCE.search(licence) and family != "report_only":
        problems.append(f"{where}: licence {licence} needs family report_only")
    if family == "ark_blind" and split != "holdout":
        problems.append(f"{where}: ark_blind data belongs to the holdout")
    if family == "ark_authored" and split == "holdout":
        problems.append(f"{where}: ark_authored data cannot be holdout")
    languages = dataset.get("languages") or []
    if not languages:
        problems.append(f"{where}: no languages")
    problems += [f"{where}: unknown language {language}" for language in languages if language not in oss_inventory.LANGUAGES]
    if "translated" in dataset and dataset["translated"] is not True:
        problems.append(f"{where}: translated may only be true")
    labels = dataset.get("labels") or []
    if not labels:
        problems.append(f"{where}: no labels")
    for label in labels:
        problems += _check_label(where, label, families)
    return problems


def _deciding_labels(entity_map: dict[str, Any]) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    for dataset in entity_map.get("datasets") or []:
        if dataset.get("split") != "holdout" or dataset.get("family") not in DECIDING_FAMILIES:
            continue
        for label in dataset.get("labels") or []:
            if isinstance(label, dict) and isinstance(label.get("classes"), list) and label.get("decides", True):
                yield dataset, label


def decisions(entity_map: dict[str, Any]) -> dict[tuple[str, str], tuple[str, list[str]]]:
    """Return (family, dataset ids) deciding each (class, language); neutral wins over ark_blind."""
    found: dict[tuple[str, str], dict[str, list[str]]] = {}
    for dataset, label in _deciding_labels(entity_map):
        for language in dataset.get("languages") or []:
            if language not in DECISION_LANGUAGES:
                continue
            for name in label["classes"]:
                ids = found.setdefault((name, language), {}).setdefault(dataset["family"], [])
                if dataset["id"] not in ids:
                    ids.append(dataset["id"])
    result = {}
    for key, by_family in found.items():
        family = next(family for family in DECIDING_FAMILIES if family in by_family)
        result[key] = (family, by_family[family])
    return result


def benign_pool(entity_map: dict[str, Any]) -> dict[str, list[str]]:
    """Neutral holdout datasets with benign rows, per decision language."""
    pool: dict[str, list[str]] = {language: [] for language in DECISION_LANGUAGES}
    for dataset in entity_map.get("datasets") or []:
        if dataset.get("split") != "holdout" or dataset.get("family") != "neutral":
            continue
        if any(isinstance(label, dict) and label.get("benign") is True for label in dataset.get("labels") or []):
            for language in dataset.get("languages") or []:
                if language in pool:
                    pool[language].append(dataset["id"])
    return pool


def check(entity_map: dict[str, Any], *, inventory: dict[str, Any], tax: dict[str, Any]) -> list[str]:
    """Return every problem of ``entity_map`` against the OSS inventory and the taxonomy."""
    problems = []
    if entity_map.get("schema") != SCHEMA:
        problems.append(f"schema is {entity_map.get('schema')!r}, expected {SCHEMA}")
    families = _class_families(tax)

    baselines = entity_map.get("baselines") or []
    baseline_ids = Counter(baseline.get("id") for baseline in baselines)
    problems += [f"baseline {name} is defined {count} times" for name, count in sorted(baseline_ids.items()) if count > 1]
    problems += [f"taxonomy baseline {name} has no entry" for name in taxonomy.BASELINES if name not in baseline_ids]
    for baseline in baselines:
        problems += _check_baseline(baseline, inventory, families)

    datasets = entity_map.get("datasets") or []
    dataset_ids = Counter(dataset.get("id") for dataset in datasets)
    problems += [f"dataset {name} is defined {count} times" for name, count in sorted(dataset_ids.items()) if count > 1]
    for dataset in datasets:
        problems += _check_dataset(dataset, families)

    trained = Counter()
    for baseline in baselines:
        for dataset_id in baseline.get("trained_on") or []:
            trained[dataset_id] += 1
            if dataset_id not in dataset_ids:
                problems.append(f"baseline {baseline.get('id')}: trained_on {dataset_id} is not a registered dataset")
    problems += [
        f"dataset {dataset.get('id')}: baseline_trained but no baseline names it in trained_on"
        for dataset in datasets
        if dataset.get("family") == "baseline_trained" and dataset.get("id") not in trained
    ]

    decided = decisions(entity_map)
    gaps: Counter[tuple[str, str]] = Counter()
    for gap in entity_map.get("gaps") or []:
        key = (gap.get("class"), gap.get("language"))
        gaps[key] += 1
        if set(gap) != GAP_KEYS:
            problems.append(f"gap {key[0]}/{key[1]}: keys {', '.join(sorted(gap))}, expected {', '.join(sorted(GAP_KEYS))}")
        if key[0] not in taxonomy.CLASSES or key[1] not in DECISION_LANGUAGES:
            problems.append(f"gap {key[0]}/{key[1]}: unknown class or language")
        elif key in decided:
            family, ids = decided[key]
            problems.append(f"gap {key[0]}/{key[1]} is decided by {family} ({', '.join(ids)})")
    problems += [f"gap {name}/{language} is listed {count} times" for (name, language), count in sorted(gaps.items()) if count > 1]
    for name in taxonomy.CLASSES:
        for language in DECISION_LANGUAGES:
            if (name, language) not in decided and (name, language) not in gaps:
                problems.append(f"{name}/{language}: no neutral or ark_blind holdout data and no gap entry")
    problems += [f"language {language}: no neutral benign pool" for language, ids in benign_pool(entity_map).items() if not ids]
    return problems


def table(entity_map: dict[str, Any]) -> str:
    decided = decisions(entity_map)
    lines = ["| class | " + " | ".join(DECISION_LANGUAGES) + " |", "|---|" + "---|" * len(DECISION_LANGUAGES)]
    for name in taxonomy.CLASSES:
        cells = []
        for language in DECISION_LANGUAGES:
            family, ids = decided.get((name, language), ("gap", []))
            cells.append(f"{family}: {', '.join(ids)}" if ids else family)
        lines.append(f"| `{name}` | " + " | ".join(cells) + " |")
    pool = benign_pool(entity_map)
    lines += ["", "Benign pool: " + "; ".join(f"{language}: {', '.join(ids)}" for language, ids in pool.items())]
    by_family = Counter((dataset.get("family"), dataset.get("split")) for dataset in entity_map.get("datasets") or [])
    lines += ["", "| family | " + " | ".join(SPLITS) + " |", "|---|" + "---|" * len(SPLITS)]
    for family in FAMILIES:
        lines.append(f"| {family} | " + " | ".join(str(by_family[(family, split)]) for split in SPLITS) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "table"))
    parser.add_argument("--map", type=Path, default=MAP_PATH)
    args = parser.parse_args(argv)
    try:
        entity_map = load(args.map)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"entity map invalid: {error}", file=sys.stderr)
        return 1
    problems = check(entity_map, inventory=oss_inventory.load(), tax=taxonomy.load())
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    if args.command == "table":
        print(table(entity_map), end="")
        return 0
    datasets = entity_map.get("datasets") or []
    print(f"entity map ok: {len(entity_map.get('baselines') or [])} baselines, {len(datasets)} datasets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
