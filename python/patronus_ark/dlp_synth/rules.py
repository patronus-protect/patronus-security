# SPDX-License-Identifier: GPL-3.0-only
"""Rule → generator map for synthetic DLP values (``rules.json``).

Every ``dlp_*`` rule in ``DLP_PATTERNS`` is either a value rule with generators and
probe carriers, or a content rule without a secret value. ``samples`` materializes a
probe so a test can check that the rule reports exactly the generated value.
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Iterator, NamedTuple

from . import recipes


RULES_PATH = Path(__file__).resolve().parent / "rules.json"


class Sample(NamedTuple):
    rule_id: str
    generator: str
    seed: int
    probe: int
    text: str
    span: tuple[int, int]


@lru_cache(maxsize=1)
def _rules() -> dict:
    spec = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    if spec.get("version") != 1:
        raise recipes.RecipeError("unsupported rules spec")
    known = set(recipes.load_generators())
    for rule_id, entry in spec["rules"].items():
        if set(entry) - {"generators", "shape_only", "probes"} or not entry.get("generators"):
            raise recipes.RecipeError(f"{rule_id}: invalid rule entry")
        for name in entry["generators"] + entry.get("shape_only", []):
            if name not in known:
                raise recipes.RecipeError(f"{rule_id}: unknown generator {name!r}")
        for probe in entry["probes"]:
            recipes.materialize(probe, [{"gen": entry["generators"][0], "seed": 0}])
    if set(spec["rules"]) & set(spec["content_rules"]):
        raise recipes.RecipeError("a rule cannot be both a value and a content rule")
    return spec


def load_rule_map() -> dict:
    """``{rule_id: {"generators": [...], "shape_only": [...], "probes": [...]}}``."""
    return copy.deepcopy(_rules()["rules"])


def content_rules() -> dict:
    """``{rule_id: reason}`` for rules that have no generated secret value."""
    return dict(_rules()["content_rules"])


def generators_for(rule_id: str) -> list[str]:
    try:
        return list(_rules()["rules"][rule_id]["generators"])
    except KeyError:
        raise recipes.RecipeError(f"no generators for rule {rule_id!r}") from None


def samples(rule_id: str, seeds: range | list[int]) -> Iterator[Sample]:
    """Yield every (generator, probe, seed) carrier of ``rule_id``."""
    entry = _rules()["rules"].get(rule_id)
    if entry is None:
        raise recipes.RecipeError(f"no generators for rule {rule_id!r}")
    for generator in entry["generators"]:
        for probe_index, probe in enumerate(entry["probes"]):
            for seed in seeds:
                text, spans = recipes.materialize(probe, [{"gen": generator, "seed": seed}])
                yield Sample(rule_id, generator, seed, probe_index, text, spans[0])
