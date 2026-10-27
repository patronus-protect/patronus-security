#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Materialize all benchmark rows for Core's repository-only tokenizer tests."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def texts(dataset_dir: Path) -> list[str]:
    if not dataset_dir.is_dir():
        raise FileNotFoundError(dataset_dir)
    paths = sorted(dataset_dir.glob("*.jsonl"))
    if not paths:
        raise ValueError("benchmark directory contains no JSONL fixtures")
    spec = importlib.util.spec_from_file_location(
        "golden_recipes", ROOT / "python/patronus_ark/dlp_synth/recipes.py"
    )
    assert spec is not None and spec.loader is not None
    recipes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipes)
    return [
        recipes.materialize_row(json.loads(line))["text"]
        for path in paths
        for line in path.read_text().splitlines()
        if line.strip()
    ]


if __name__ == "__main__":
    print(json.dumps(texts(ROOT / "python/patronus_ark/benchmark_data")))
