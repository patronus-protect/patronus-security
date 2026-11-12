#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fetch, map, deduplicate and freeze the L1 threat evaluation corpora.

The registry ``scripts/l1_threat/datasets.yaml`` says how each dataset of
``research/l1-threat/entity_map.yaml`` is fetched (pinned revision, files with SHA-256, format,
text field, label rules); the entity map says what its labels mean and which split it belongs to.
Splitting is by source only: a dataset is ``train_dev``, ``holdout`` or ``report``, never two.

    python3 scripts/l1_threat/prepare_corpora.py check                       # exit 1 on any problem
    python3 scripts/l1_threat/prepare_corpora.py list                        # role and state per set
    python3 scripts/l1_threat/prepare_corpora.py prepare --split train_dev --out DIR --sources CACHE
    python3 scripts/l1_threat/prepare_corpora.py prepare --split holdout --out DIR --sources CACHE \\
        --overlay HOLDOUT_RECIPES.yaml                                        # holdout setup only
    python3 scripts/l1_threat/prepare_corpora.py verify DIR                   # exit 1 unless intact

``prepare`` writes one ``<id>.jsonl`` per ready set of the split, a ``manifest.json`` with the SHA-256
of every source file and output file, and ``.ready`` last. A frozen directory is rewritten only with
``--force``. Deduplication (texts after NFKC, case folding and whitespace collapsing):
- exact and MinHash within each set (first occurrence kept);
- across splits: preparing the holdout drops every row that duplicates a row of a train_dev or
  report set, so nothing the runner can train on reaches the holdout;
- against baseline training lists: ``trained_on`` of a baseline in the entity map names registered
  sets; a row of such a set, or a duplicate of one of its rows, is marked in the row's
  ``contamination`` column for that baseline (kept, reported apart).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _load_file(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Shared helpers: pinned downloads and the dependency-free Parquet reader (presidio corpora),
# JSONL/manifest bytes and atomic directory writes (DLP corpora).
PRESIDIO = _load_file("_ark_l1_presidio_prepare_corpora", HERE.parent / "l1_presidio" / "prepare_corpora.py")
BENIGN_CODE = _load_file("_ark_l1_dlp_benign_code", HERE.parent / "l1_dlp" / "benign_code.py")
# Loaded under its own name: other script directories have an entity_map module too.
entity_map = _load_file("_ark_l1_threat_entity_map", HERE / "entity_map.py")

REGISTRY_PATH = HERE / "datasets.yaml"
SCHEMA = "ark-l1-threat-datasets-v1"
CORPORA_SCHEMA = "ark-l1-threat-corpora-v1"
READY = ".ready"
FORMATS = ("jsonl", "json", "csv", "parquet")
SPLITS = entity_map.SPLITS
INTERNAL_FAMILIES = ("ark_blind", "ark_authored")
SOURCE_PREFIXES = ("https://huggingface.co/datasets/", "https://github.com/")
ENTRY_KEYS = {"id", "commercial"}
RECIPE_KEYS = {"source", "revision", "files", "format", "text", "labels"}
OPTIONAL_KEYS = {"training", "internal", "pending", "language", "language_field", "limit"}
RULE_OPS = ("equals", "at_least", "below")
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
# Mersenne prime 2^31 - 1: a * h + b stays below 2^63 for a, b, h < P (int64 without overflow).
PRIME = (1 << 31) - 1


def load(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    return data


def apply_overlay(registry: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Registry with the recipes of ``overlay`` (holdout setup) replacing the pending entries."""
    recipes = {entry["id"]: entry for entry in overlay.get("datasets") or []}
    merged = []
    for entry in registry.get("datasets") or []:
        recipe = recipes.pop(entry.get("id"), None)
        if recipe is None:
            merged.append(entry)
        elif "pending" not in entry:
            raise ValueError(f"overlay replaces {entry['id']!r}, which is not pending")
        else:
            merged.append({**{k: v for k, v in entry.items() if k != "pending"}, **recipe})
    if recipes:
        raise ValueError(f"overlay names unregistered sets: {', '.join(sorted(recipes))}")
    return {**registry, "datasets": merged}


def is_ready(entry: dict[str, Any]) -> bool:
    return "internal" not in entry and "pending" not in entry


def role(dataset: dict[str, Any], entry: dict[str, Any]) -> str:
    """decisive / dev / report, derived from the entity-map split and family and the licence flag."""
    if entry.get("commercial") is False:
        return "report"
    if dataset["split"] == "holdout" and dataset["family"] in entity_map.DECIDING_FAMILIES:
        return "decisive"
    return "dev" if dataset["split"] == "train_dev" else "report"


# ── check ────────────────────────────────────────────────────────────────────


def _check_rule(where: str, rule: Any, labels: set[str]) -> list[str]:
    if not isinstance(rule, dict):
        return [f"{where}: label rule is not a mapping"]
    problems = []
    unknown = set(rule) - {"field", "label", *RULE_OPS}
    if unknown:
        problems.append(f"{where}: unknown rule keys {sorted(unknown)}")
    if rule.get("label") not in labels:
        problems.append(f"{where}: label {rule.get('label')!r} is not a label of the set in entity_map.yaml")
    ops = [op for op in RULE_OPS if op in rule]
    if "field" in rule:
        if not isinstance(rule["field"], str) or not ops:
            problems.append(f"{where}: a rule with field needs a string field and one of {RULE_OPS}")
        if "equals" in rule and len(ops) > 1:
            problems.append(f"{where}: equals cannot be combined with at_least/below")
        for op in ("at_least", "below"):
            if op in rule and (isinstance(rule[op], bool) or not isinstance(rule[op], (int, float))):
                problems.append(f"{where}: {op} must be a number")
    elif ops:
        problems.append(f"{where}: {ops} without field")
    return problems


def _check_recipe(where: str, entry: dict[str, Any], labels: set[str]) -> list[str]:
    problems = []
    missing = RECIPE_KEYS - set(entry)
    if missing:
        return [f"{where}: recipe misses {sorted(missing)} (or mark it pending)"]
    if not str(entry["source"]).startswith(SOURCE_PREFIXES):
        problems.append(f"{where}: source must start with one of {SOURCE_PREFIXES}")
    if not SHA1.fullmatch(str(entry["revision"])):
        problems.append(f"{where}: revision must be a pinned 40-hex commit")
    files = entry["files"]
    if not isinstance(files, list) or not files:
        problems.append(f"{where}: files must be a non-empty list")
        files = []
    for item in files:
        path = str((item or {}).get("path", ""))
        if not path or Path(path).is_absolute() or ".." in Path(path).parts:
            problems.append(f"{where}: unsafe or empty file path {path!r}")
        if not SHA256.fullmatch(str((item or {}).get("sha256", ""))):
            problems.append(f"{where}: file {path!r} needs a SHA-256")
    if entry["format"] not in FORMATS:
        problems.append(f"{where}: format must be one of {FORMATS}")
    if ("language" in entry) == ("language_field" in entry):
        problems.append(f"{where}: exactly one of language / language_field")
    if "limit" in entry and (not isinstance(entry["limit"], int) or isinstance(entry["limit"], bool) or entry["limit"] < 1):
        problems.append(f"{where}: limit must be a positive integer")
    rules = entry["labels"]
    if not isinstance(rules, list) or not rules:
        return problems + [f"{where}: labels must be a non-empty list"]
    for index, rule in enumerate(rules):
        problems.extend(_check_rule(f"{where} labels[{index}]", rule, labels))
    return problems


def check(registry: dict[str, Any], emap: dict[str, Any]) -> list[str]:
    problems = []
    if registry.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA}")
    dedup = registry.get("dedup") or {}
    try:
        if dedup["permutations"] % dedup["bands"] or not 0 < dedup["threshold"] <= 1 or dedup["shingle_chars"] < 1:
            problems.append("dedup: permutations must be a multiple of bands, 0 < threshold <= 1, shingle_chars >= 1")
        str(dedup["seed"])
    except (KeyError, TypeError):
        problems.append("dedup needs shingle_chars, permutations, bands, threshold and seed")
    datasets = {dataset["id"]: dataset for dataset in emap.get("datasets") or []}
    seen: Counter[str] = Counter()
    for entry in registry.get("datasets") or []:
        if not isinstance(entry, dict):
            problems.append("dataset entry is not a mapping")
            continue
        dataset_id = entry.get("id")
        where = f"dataset {dataset_id}"
        seen[dataset_id] += 1
        dataset = datasets.get(dataset_id)
        if dataset is None:
            problems.append(f"{where}: not a dataset of entity_map.yaml")
            continue
        unknown = set(entry) - ENTRY_KEYS - RECIPE_KEYS - OPTIONAL_KEYS
        if unknown or ENTRY_KEYS - set(entry):
            problems.append(f"{where}: unknown keys {sorted(unknown)} or missing {sorted(ENTRY_KEYS - set(entry))}")
        commercial = entry.get("commercial")
        if commercial not in (True, False, "unknown"):
            problems.append(f"{where}: commercial must be true, false or unknown")
        if commercial is False and dataset["family"] != "report_only":
            problems.append(f"{where}: commercial false needs family report_only in entity_map.yaml")
        if "training" in entry and entry["training"] is not False:
            problems.append(f"{where}: training may only be false")
        if entry.get("training") is False and dataset["split"] == "train_dev":
            problems.append(f"{where}: an evaluation-only set (training: false) cannot be train_dev")
        kinds = [key for key in ("internal", "pending") if key in entry] + (["recipe"] if RECIPE_KEYS & set(entry) else [])
        if len(kinds) != 1:
            problems.append(f"{where}: exactly one of internal, pending or a recipe (found {kinds or 'none'})")
            continue
        internal = dataset["family"] in INTERNAL_FAMILIES
        if internal != (kinds[0] == "internal"):
            problems.append(f"{where}: internal exactly for families {INTERNAL_FAMILIES}")
        if kinds[0] == "recipe":
            problems.extend(_check_recipe(where, entry, {label["label"] for label in dataset["labels"]}))
    for dataset_id in datasets:
        if seen[dataset_id] != 1:
            problems.append(f"dataset {dataset_id}: {seen[dataset_id]} registry entries (expected 1)")
    return problems


# ── reading and mapping ──────────────────────────────────────────────────────


def _field(record: dict[str, Any], path: str) -> Any:
    if path in record:
        return record[path]
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _text_value(value: Any) -> str:
    return json.dumps(value) if isinstance(value, bool) else str(value)


def rule_matches(rule: dict[str, Any], record: dict[str, Any]) -> bool:
    if "field" not in rule:
        return True
    value = _field(record, rule["field"])
    if value is None:
        return False
    if "equals" in rule:
        wanted = rule["equals"] if isinstance(rule["equals"], list) else [rule["equals"]]
        return _text_value(value) in {_text_value(item) for item in wanted}
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return number >= rule.get("at_least", float("-inf")) and number < rule.get("below", float("inf"))


def read_records(entry: dict[str, Any], root: Path) -> Iterable[dict[str, Any]]:
    columns = sorted(
        {entry["text"].split(".")[0], *(rule["field"].split(".")[0] for rule in entry["labels"] if "field" in rule)}
        | ({entry["language_field"]} if "language_field" in entry else set())
    )
    for item in entry["files"]:
        path = root / item["path"]
        if entry["format"] == "jsonl":
            with path.open(encoding="utf-8") as handle:
                yield from (json.loads(line) for line in handle if line.strip())
        elif entry["format"] == "json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError(f"{path}: format json expects a list of records")
            yield from data
        elif entry["format"] == "csv":
            csv.field_size_limit(sys.maxsize)
            with path.open(encoding="utf-8", newline="") as handle:
                yield from csv.DictReader(handle)
        else:
            yield from PRESIDIO.read_parquet_columns(path, columns)


def map_labels(entry: dict[str, Any], dataset: dict[str, Any], record: dict[str, Any]) -> dict[str, Any] | None:
    """Outcome of one record: classes, reported-only classes, families, benign; None if out of scope."""
    meanings = {label["label"]: label for label in dataset["labels"]}
    hits = [meanings[rule["label"]] for rule in entry["labels"] if rule_matches(rule, record)]
    if not hits:
        raise ValueError(f"{entry['id']}: unmapped upstream label in record {json.dumps(record, default=str)[:200]}")
    classes: set[str] = set()
    reported: set[str] = set()
    families: dict[str, str] = {}
    benign = False
    for hit in hits:
        if hit.get("benign"):
            benign = True
        for name in hit.get("classes") or []:
            (classes if hit.get("decides", True) else reported).add(name)
            if hit.get("family"):
                families[name] = hit["family"]
    if benign and (classes or reported):
        raise ValueError(f"{entry['id']}: record maps to benign and to a class ({[hit['label'] for hit in hits]})")
    if not benign and not classes and not reported:
        return None
    return {
        "labels": sorted(hit["label"] for hit in hits),
        "classes": sorted(classes),
        "reported_classes": sorted(reported - classes),
        "families": dict(sorted(families.items())),
        "benign": benign,
    }


# ── deduplication ────────────────────────────────────────────────────────────


def normalise(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


class Deduper:
    """Exact and MinHash/LSH near-duplicate index over normalised texts."""

    def __init__(self, params: dict[str, Any]) -> None:
        import numpy as np

        self._np = np
        self.shingle = int(params["shingle_chars"])
        self.bands = int(params["bands"])
        self.rows = int(params["permutations"]) // self.bands
        self.threshold = float(params["threshold"])
        self._key = hashlib.sha256(str(params["seed"]).encode("utf-8")).digest()[:32]
        seeds = [
            int.from_bytes(hashlib.sha256(self._key + index.to_bytes(4, "big")).digest()[:8], "big")
            for index in range(int(params["permutations"]) * 2)
        ]
        self._a = np.array([1 + seed % (PRIME - 1) for seed in seeds[0::2]], dtype=np.int64)
        self._b = np.array([seed % PRIME for seed in seeds[1::2]], dtype=np.int64)
        self._exact: dict[str, int] = {}
        self._buckets: list[dict[bytes, list[int]]] = [{} for _ in range(self.bands)]
        self._signatures: list[Any] = []

    def signature(self, norm: str) -> Any:
        np = self._np
        grams = {norm} if len(norm) <= self.shingle else {norm[i : i + self.shingle] for i in range(len(norm) - self.shingle + 1)}
        hashes = np.array(
            [int.from_bytes(hashlib.blake2b(gram.encode("utf-8"), digest_size=8, key=self._key).digest(), "big") % PRIME for gram in grams],
            dtype=np.int64,
        )
        return ((self._a[:, None] * hashes[None, :] + self._b[:, None]) % PRIME).min(axis=1)

    def _bands(self, signature: Any) -> list[bytes]:
        return [signature[band * self.rows : (band + 1) * self.rows].tobytes() for band in range(self.bands)]

    def match(self, text: str) -> tuple[str | None, int | None, Any]:
        """('exact' | 'minhash' | None, index of the matched entry, signature of ``text``)."""
        norm = normalise(text)
        digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        if digest in self._exact:
            return "exact", self._exact[digest], None
        signature = self.signature(norm)
        seen: set[int] = set()
        for band, key in enumerate(self._bands(signature)):
            for index in self._buckets[band].get(key, ()):
                if index in seen:
                    continue
                seen.add(index)
                if float((self._signatures[index] == signature).mean()) >= self.threshold:
                    return "minhash", index, signature
        return None, None, signature

    def add(self, text: str, signature: Any = None) -> int:
        norm = normalise(text)
        index = len(self._signatures)
        self._exact.setdefault(hashlib.sha256(norm.encode("utf-8")).hexdigest(), index)
        signature = self.signature(norm) if signature is None else signature
        self._signatures.append(signature)
        for band, key in enumerate(self._bands(signature)):
            self._buckets[band].setdefault(key, []).append(index)
        return index


# ── fetch and build ──────────────────────────────────────────────────────────


def fetch(entry: dict[str, Any], sources: Path, offline: bool, download: Callable[[str], bytes] = PRESIDIO.download) -> Path:
    """Make every pinned file of a set present under ``sources/<id>`` and verified; return that root."""
    root = sources / entry["id"]
    for item in entry["files"]:
        target = root / item["path"]
        if target.is_file() and PRESIDIO._sha256(target.read_bytes()) == item["sha256"]:
            continue
        if offline:
            raise ValueError(f"{entry['id']}: {target} is missing or does not match the pinned SHA-256")
        url = PRESIDIO._upstream_url(entry["source"].rstrip("/"), entry["revision"], item["path"])
        data = download(url)
        if PRESIDIO._sha256(data) != item["sha256"]:
            raise ValueError(f"{url}: SHA-256 {PRESIDIO._sha256(data)}, pinned {item['sha256']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.with_name(target.name + ".part").write_bytes(data)
        target.with_name(target.name + ".part").replace(target)
    return root


def load_set(entry: dict[str, Any], dataset: dict[str, Any], root: Path, dedup: dict[str, Any]) -> tuple[list[dict[str, Any]], Counter[str]]:
    """Mapped rows of one set, deduplicated within the set (exact and MinHash), with drop counts."""
    index = Deduper(dedup)
    rows: list[dict[str, Any]] = []
    dropped: Counter[str] = Counter()
    for number, record in enumerate(read_records(entry, root)):
        text = _field(record, entry["text"])
        if not isinstance(text, str) or not text.strip():
            dropped["empty"] += 1
            continue
        outcome = map_labels(entry, dataset, record)
        if outcome is None:
            dropped["out_of_scope"] += 1
            continue
        kind, matched, signature = index.match(text)
        if kind is not None:
            dropped[kind] += 1
            if rows[matched]["benign"] != outcome["benign"] or rows[matched]["classes"] != outcome["classes"]:
                dropped["label_conflicts"] += 1
            continue
        index.add(text, signature)
        language = entry["language"] if "language" in entry else str(_field(record, entry["language_field"]))
        rows.append({"id": f"{entry['id']}:{number:07d}", "dataset": entry["id"], "text": text, "language": language, **outcome})
    if "limit" in entry and len(rows) > entry["limit"]:
        dropped["limit"] = len(rows) - entry["limit"]
        keep = set(sorted(range(len(rows)), key=lambda i: hashlib.sha256(normalise(rows[i]["text"]).encode("utf-8")).hexdigest())[: entry["limit"]])
        rows = [row for i, row in enumerate(rows) if i in keep]
    return rows, dropped


def _index(rows: Iterable[dict[str, Any]], dedup: dict[str, Any]) -> Deduper:
    index = Deduper(dedup)
    for row in rows:
        index.add(row["text"])
    return index


def build(
    split: str,
    registry: dict[str, Any],
    emap: dict[str, Any],
    sources: Path,
    offline: bool = False,
    download: Callable[[str], bytes] = PRESIDIO.download,
) -> dict[str, bytes]:
    """``{file name: content}`` of one prepared split (JSONL per set, manifest, .ready)."""
    problems = check(registry, emap)
    if problems:
        raise ValueError("registry check failed:\n" + "\n".join(problems))
    datasets = {dataset["id"]: dataset for dataset in emap["datasets"]}
    entries = {entry["id"]: entry for entry in registry["datasets"]}
    dedup = registry["dedup"]
    trained_on = {baseline["id"]: list(baseline.get("trained_on") or []) for baseline in emap["baselines"]}
    loaded: dict[str, tuple[list[dict[str, Any]], Counter[str]]] = {}

    def rows_of(dataset_id: str) -> list[dict[str, Any]]:
        if dataset_id not in loaded:
            entry = entries[dataset_id]
            loaded[dataset_id] = load_set(entry, datasets[dataset_id], fetch(entry, sources, offline, download), dedup)
        return loaded[dataset_id][0]

    members = [i for i, entry in entries.items() if datasets[i]["split"] == split and is_ready(entry)]
    skipped = {
        i: entry.get("internal") or entry.get("pending")
        for i, entry in entries.items()
        if datasets[i]["split"] == split and not is_ready(entry)
    }
    # Cross-split: the holdout drops what a train_dev or report set already holds.
    other = None
    if split == "holdout":
        other = _index((row for i, e in entries.items() if datasets[i]["split"] != "holdout" and is_ready(e) for row in rows_of(i)), dedup)
    # Holdout rows are only ever read while preparing the holdout itself.
    visible = [i for i, entry in entries.items() if is_ready(entry) and (split == "holdout" or datasets[i]["split"] != "holdout")]
    references = {
        baseline: _index((row for i in ids if i in visible for row in rows_of(i)), dedup)
        for baseline, ids in sorted(trained_on.items())
        if ids
    }
    files: dict[str, bytes] = {}
    sets: dict[str, Any] = {}
    for dataset_id in sorted(members):
        rows, dropped = list(rows_of(dataset_id)), Counter(loaded[dataset_id][1])
        if other is not None:
            kept = [row for row in rows if other.match(row["text"])[0] is None]
            dropped["cross_split"] = len(rows) - len(kept)
            rows = kept
        contamination: Counter[str] = Counter()
        for row in rows:
            row["contamination"] = {
                baseline: dataset_id in trained_on[baseline]
                or (baseline in references and references[baseline].match(row["text"])[0] is not None)
                for baseline in sorted(trained_on)
            }
            contamination.update(baseline for baseline, hit in row["contamination"].items() if hit)
        data = BENIGN_CODE._jsonl(rows)
        files[f"{dataset_id}.jsonl"] = data
        entry = entries[dataset_id]
        sets[dataset_id] = {
            "role": role(datasets[dataset_id], entry),
            "family": datasets[dataset_id]["family"],
            "licence": datasets[dataset_id]["licence"],
            "commercial": entry["commercial"],
            "training": entry.get("training", True),
            "source": entry["source"],
            "revision": entry["revision"],
            "source_files": {item["path"]: item["sha256"] for item in entry["files"]},
            "file": f"{dataset_id}.jsonl",
            "sha256": PRESIDIO._sha256(data),
            "rows": len(rows),
            "dropped": dict(sorted((key, value) for key, value in dropped.items() if value)),
            "classes": dict(sorted(Counter(name for row in rows for name in row["classes"]).items())),
            "benign": sum(row["benign"] for row in rows),
            "languages": dict(sorted(Counter(row["language"] for row in rows).items())),
            "contamination": {baseline: contamination[baseline] for baseline in sorted(trained_on)},
        }
    manifest = BENIGN_CODE._manifest_bytes(
        {
            "schema": CORPORA_SCHEMA,
            "split": split,
            "split_rule": "by source: every dataset belongs to exactly one split (entity_map.yaml)",
            "dedup": dedup,
            "trained_on": trained_on,
            "sets": sets,
            "skipped": dict(sorted(skipped.items())),
        }
    )
    return {**files, "manifest.json": manifest, READY: f"{PRESIDIO._sha256(manifest)}  manifest.json\n".encode("utf-8")}


def verify(directory: Path) -> list[str]:
    """Problems of a prepared directory (empty list: frozen and intact)."""
    ready, manifest_path = directory / READY, directory / "manifest.json"
    if not ready.is_file() or not manifest_path.is_file():
        return [f"{directory}: no {READY} or manifest.json"]
    manifest_bytes = manifest_path.read_bytes()
    problems = []
    if ready.read_text(encoding="utf-8") != f"{PRESIDIO._sha256(manifest_bytes)}  manifest.json\n":
        problems.append(f"{directory}: {READY} does not match manifest.json")
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != CORPORA_SCHEMA:
        problems.append(f"{directory}: manifest schema is not {CORPORA_SCHEMA}")
    expected = {entry["file"]: entry["sha256"] for entry in manifest.get("sets", {}).values()}
    for name, digest in sorted(expected.items()):
        path = directory / name
        if not path.is_file() or PRESIDIO._sha256(path.read_bytes()) != digest:
            problems.append(f"{path} is missing or does not match its SHA-256 in manifest.json")
    for path in sorted(directory.glob("*.jsonl")):
        if path.name not in expected:
            problems.append(f"{path} is not in manifest.json")
    return problems


def prepare(split: str, out: Path, registry: dict[str, Any], emap: dict[str, Any], sources: Path, offline: bool, force: bool, download: Callable[[str], bytes] = PRESIDIO.download) -> int:
    files = build(split, registry, emap, sources, offline, download)
    if (out / READY).exists():
        current = (out / "manifest.json").read_bytes() if (out / "manifest.json").is_file() else b""
        if not verify(out) and current == files["manifest.json"]:
            print(f"{split}: {out} unchanged (frozen)")
            return 0
        if not force:
            print(f"{split}: {out} is frozen and differs from this run (or was modified); nothing written. Use --force.", file=sys.stderr)
            return 1
    BENIGN_CODE._write(out, files)
    print(f"{split}: {len(files) - 2} sets written to {out}")
    return 0


def listing(registry: dict[str, Any], emap: dict[str, Any]) -> str:
    datasets = {dataset["id"]: dataset for dataset in emap["datasets"]}
    lines = ["| Dataset | Split | Family | Role | Commercial | State |", "|---|---|---|---|---|---|"]
    for entry in registry["datasets"]:
        dataset = datasets[entry["id"]]
        state = "internal" if "internal" in entry else ("pending" if "pending" in entry else f"ready @{entry['revision'][:12]}")
        lines.append(f"| {entry['id']} | {dataset['split']} | {dataset['family']} | {role(dataset, entry)} | {_text_value(entry["commercial"])} | {state} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--entity-map", type=Path, default=entity_map.MAP_PATH)
    parser.add_argument("--overlay", type=Path, help="recipes for pending sets (holdout setup only)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sub.add_parser("list")
    prep = sub.add_parser("prepare")
    prep.add_argument("--split", choices=SPLITS, required=True)
    prep.add_argument("--out", type=Path, required=True)
    prep.add_argument("--sources", type=Path, required=True, help="download cache, one directory per set")
    prep.add_argument("--offline", action="store_true")
    prep.add_argument("--force", action="store_true")
    ver = sub.add_parser("verify")
    ver.add_argument("directory", type=Path)
    args = parser.parse_args(argv)

    if args.command == "verify":
        problems = verify(args.directory)
        print("\n".join(problems) or f"{args.directory}: frozen and intact")
        return 1 if problems else 0
    registry, emap = load(args.registry), entity_map.load(args.entity_map)
    if args.overlay:
        registry = apply_overlay(registry, load(args.overlay))
    if args.command == "check":
        problems = check(registry, emap)
        print("\n".join(problems) or f"{args.registry}: ok ({sum(map(is_ready, registry['datasets']))} ready)")
        return 1 if problems else 0
    if args.command == "list":
        print(listing(registry, emap))
        return 0
    return prepare(args.split, args.out, registry, emap, args.sources, args.offline, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
