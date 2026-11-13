#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fetch, map, deduplicate and freeze the L1 threat evaluation corpora.

The registry ``scripts/l1_threat/datasets.yaml`` says how each dataset of
``research/l1-threat/entity_map.yaml`` is fetched (pinned revision, files with SHA-256, format,
text field, label rules); the entity map says what its labels mean and which split it belongs to.
Splitting is by source only: a dataset is ``train_dev``, ``holdout`` or ``report``, never two.

    python3 scripts/l1_threat/prepare_corpora.py check                       # exit 1 on any problem
    python3 scripts/l1_threat/prepare_corpora.py list                        # role and state per set
    python3 scripts/l1_threat/prepare_corpora.py --dev-out DEV --holdout-out HOLDOUT [--offline] [--force]
    python3 scripts/l1_threat/prepare_corpora.py verify DIR                   # exit 1 unless intact
    python3 scripts/l1_threat/prepare_corpora.py coverage DIR [DIR ...]       # exit 1 unless the pool is complete

Preparing writes ``DEV/train_dev/``, ``DEV/report/`` and ``HOLDOUT/holdout/``: one ``<id>.jsonl`` per
ready set of the split, a ``manifest.json`` with the SHA-256 of every source file and output file, and
``.ready`` last. Downloads are cached in ``--sources`` (default ``HOLDOUT/.sources``, never inside DEV).
Holdout recipes come from ``--overlay`` (default ``HOLDOUT/datasets.overlay.yaml`` when present); a
split without any ready set is not written. A frozen directory is rewritten only with ``--force``, when it
was frozen under a lower registry ``generation`` (raising it is the reviewed way to re-freeze every
split), or when it is intact but in an older corpus format and was built from the same inputs (sets,
revisions, source files, dedup settings, training lists).
Row caps: after deduplication every set keeps at most ``sampling.max_rows`` rows (or its lower
``cap``), sampled per stratum (benign, classes, language) in proportion to the stratum size and,
within a stratum, by a hash of the sampling seed, the set and the text; caps, seed and the row count
before the cap are in the manifest. ``coverage`` checks a pool of frozen directories (prepared and
generated) for gold rows of every taxonomy class, a benign pool of at least ``MIN_BENIGN_ROWS`` rows
from at least ``MIN_BENIGN_SOURCES`` sets, and contamination checked for every baseline.
Deduplication (texts after NFKC, case folding and whitespace collapsing):
- exact and MinHash within each set (first occurrence kept);
- across splits: preparing the holdout drops every row that duplicates a row of a train_dev or
  report set, so nothing the runner can train on reaches the holdout;
- against baseline training lists: ``trained_on`` of a baseline in the entity map names registered
  sets; a row of such a set, or a duplicate of one of its rows, is marked in the row's
  ``contamination`` column for that baseline (kept, reported apart). Preparing every split in one
  call compares train_dev and report rows against holdout training sources too (only the flag
  reaches the dev output, never a holdout row). A training source the split cannot read (pending,
  internal, or a holdout set when one split is prepared alone) is listed under ``unchecked`` in the
  manifest, and an unmatched row is ``null`` (unknown) for that baseline, never ``false``.
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
taxonomy = _load_file("_ark_l1_threat_taxonomy", HERE / "taxonomy.py")

REGISTRY_PATH = HERE / "datasets.yaml"
SCHEMA = "ark-l1-threat-datasets-v1"
# v2: unknown contamination (an unchecked training source) is null, manifest lists "unchecked".
# v3: seeded, stratified row caps per set (manifest "sampling", per set "cap" and "rows_before_cap").
CORPORA_SCHEMA = "ark-l1-threat-corpora-v3"
# Schema of the generated sets (generators.py), which ``coverage`` pools with the prepared ones.
GENERATED_SCHEMA = "ark-l1-threat-generated-v1"
READY = ".ready"
OVERLAY_FILE = "datasets.overlay.yaml"
# Output directory of each split: (DEV or HOLDOUT, subdirectory).
LAYOUT = {"train_dev": ("dev", "train_dev"), "report": ("dev", "report"), "holdout": ("holdout", "holdout")}
FORMATS = ("jsonl", "json", "csv", "parquet")
SPLITS = entity_map.SPLITS
INTERNAL_FAMILIES = ("ark_blind", "ark_authored")
SOURCE_PREFIXES = ("https://huggingface.co/datasets/", "https://github.com/")
ENTRY_KEYS = {"id", "commercial"}
RECIPE_KEYS = {"source", "revision", "files", "format", "text", "labels"}
OPTIONAL_KEYS = {"training", "internal", "pending", "language", "language_field", "cap"}
RULE_OPS = ("equals", "at_least", "below")
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
# Mersenne prime 2^31 - 1: a * h + b stays below 2^63 for a, b, h < P (int64 without overflow).
PRIME = (1 << 31) - 1
# Benign pool a split needs so that 0.1 % FPR still resolves (``coverage``).
MIN_BENIGN_ROWS = 30_000
MIN_BENIGN_SOURCES = 3


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
    rules = entry["labels"]
    if not isinstance(rules, list) or not rules:
        return problems + [f"{where}: labels must be a non-empty list"]
    for index, rule in enumerate(rules):
        problems.extend(_check_rule(f"{where} labels[{index}]", rule, labels))
    return problems


def _positive(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


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
    if not _positive(registry.get("generation")):
        problems.append("generation must be a positive integer")
    sampling = registry.get("sampling") or {}
    if not _positive(sampling.get("max_rows")) or not str(sampling.get("seed") or "").strip():
        problems.append("sampling needs a positive integer max_rows and a seed")
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
        if "cap" in entry and not (_positive(entry["cap"]) and entry["cap"] <= (sampling.get("max_rows") or 0)):
            problems.append(f"{where}: cap must be a positive integer up to sampling.max_rows")
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


def cap_rows(rows: list[dict[str, Any]], cap: int, seed: str, dataset_id: str) -> list[dict[str, Any]]:
    """At most ``cap`` rows, stratified by (benign, classes, language); input order kept.

    Every stratum keeps one row while the cap allows; the rest of the cap is shared in proportion to
    the stratum sizes (largest remainder). Within a stratum the rows with the lowest seeded text hash
    are kept."""
    if len(rows) <= cap:
        return rows
    strata: dict[tuple[Any, ...], list[int]] = {}
    for i, row in enumerate(rows):
        key = (row["benign"], tuple(row["classes"]), tuple(row["reported_classes"]), row["language"])
        strata.setdefault(key, []).append(i)
    keys = sorted(strata, key=lambda key: (-len(strata[key]), json.dumps(key)))
    floor = 1 if cap >= len(keys) else 0
    rest, total = cap - floor * len(keys), len(rows) - floor * len(keys)
    shares = {key: floor + (len(strata[key]) - floor) * rest // total for key in keys}
    for key in sorted(keys, key=lambda key: -((len(strata[key]) - floor) * rest % total)):
        if sum(shares.values()) == cap:
            break
        shares[key] += 1

    def rank(i: int) -> str:
        return hashlib.sha256(f"{seed}/{dataset_id}/{normalise(rows[i]['text'])}".encode("utf-8")).hexdigest()

    keep = {i for key in keys for i in sorted(strata[key], key=rank)[: shares[key]]}
    return [row for i, row in enumerate(rows) if i in keep]


def load_set(
    entry: dict[str, Any], dataset: dict[str, Any], root: Path, dedup: dict[str, Any]
) -> tuple[list[dict[str, Any]], Counter[str]]:
    """Mapped rows of one set, deduplicated within the set (exact and MinHash), with drop counts; not capped."""
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
    loaded: dict[str, tuple[list[dict[str, Any]], Counter[str]]] | None = None,
    with_holdout: bool = False,
) -> dict[str, bytes] | None:
    """``{file name: content}`` of one prepared split (JSONL per set, manifest, .ready); None without a ready set.

    ``loaded`` caches mapped, deduplicated sets between the splits of one run, before the cap: contamination
    references hold every row a baseline trained on, only the output corpora are capped. ``with_holdout``: the
    call prepares the holdout as well, so train_dev and report rows are compared against holdout
    training sources (only the contamination flag reaches their output)."""
    problems = check(registry, emap)
    if problems:
        raise ValueError("registry check failed:\n" + "\n".join(problems))
    datasets = {dataset["id"]: dataset for dataset in emap["datasets"]}
    entries = {entry["id"]: entry for entry in registry["datasets"]}
    dedup, sampling = registry["dedup"], registry["sampling"]
    trained_on = {baseline["id"]: list(baseline.get("trained_on") or []) for baseline in emap["baselines"]}
    loaded = {} if loaded is None else loaded

    def rows_of(dataset_id: str) -> list[dict[str, Any]]:
        if dataset_id not in loaded:
            entry = entries[dataset_id]
            loaded[dataset_id] = load_set(entry, datasets[dataset_id], fetch(entry, sources, offline, download), dedup)
        return loaded[dataset_id][0]

    def capped_of(dataset_id: str) -> list[dict[str, Any]]:
        cap = entries[dataset_id].get("cap", sampling["max_rows"])
        return cap_rows(rows_of(dataset_id), cap, str(sampling["seed"]), dataset_id)

    members = [i for i, entry in entries.items() if datasets[i]["split"] == split and is_ready(entry)]
    skipped = {
        i: entry.get("internal") or entry.get("pending")
        for i, entry in entries.items()
        if datasets[i]["split"] == split and not is_ready(entry)
    }
    if not members:
        return None
    # Cross-split: the holdout drops what a train_dev or report set already holds.
    other = None
    if split == "holdout":
        other = _index((row for i, e in entries.items() if datasets[i]["split"] != "holdout" and is_ready(e) for row in capped_of(i)), dedup)
    # Holdout rows are only read by a call that prepares the holdout itself.
    visible = [
        i for i, entry in entries.items() if is_ready(entry) and (split == "holdout" or with_holdout or datasets[i]["split"] != "holdout")
    ]
    references = {
        baseline: _index((row for i in ids if i in visible for row in rows_of(i)), dedup)
        for baseline, ids in sorted(trained_on.items())
        if ids
    }
    # Training sources this split cannot compare against (pending, internal or holdout-only).
    unchecked = {baseline: [i for i in ids if i not in visible] for baseline, ids in sorted(trained_on.items())}
    unchecked = {baseline: ids for baseline, ids in unchecked.items() if ids}

    def contaminated(baseline: str, dataset_id: str, text: str) -> bool | None:
        """True on a hit, False when every training source was compared, None (unknown) otherwise."""
        if dataset_id in trained_on[baseline] or (baseline in references and references[baseline].match(text)[0] is not None):
            return True
        return None if baseline in unchecked else False

    files: dict[str, bytes] = {}
    sets: dict[str, Any] = {}
    for dataset_id in sorted(members):
        rows, dropped = capped_of(dataset_id), Counter(loaded[dataset_id][1])
        rows_before_cap = len(rows_of(dataset_id))
        dropped["cap"] = rows_before_cap - len(rows)
        if other is not None:
            kept = [row for row in rows if other.match(row["text"])[0] is None]
            dropped["cross_split"] = len(rows) - len(kept)
            rows = kept
        # New row dicts: the cached rows stay unmarked for the other splits of the run.
        rows = [
            {
                **row,
                "contamination": {baseline: contaminated(baseline, dataset_id, row["text"]) for baseline in sorted(trained_on)},
            }
            for row in rows
        ]
        contamination = Counter(baseline for row in rows for baseline, hit in row["contamination"].items() if hit)
        unknown = Counter(baseline for row in rows for baseline, hit in row["contamination"].items() if hit is None)
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
            "cap": entry.get("cap", sampling["max_rows"]),
            "rows_before_cap": rows_before_cap,
            "dropped": dict(sorted((key, value) for key, value in dropped.items() if value)),
            "classes": dict(sorted(Counter(name for row in rows for name in row["classes"]).items())),
            "benign": sum(row["benign"] for row in rows),
            "languages": dict(sorted(Counter(row["language"] for row in rows).items())),
            "contamination": {baseline: contamination[baseline] for baseline in sorted(trained_on)},
            "contamination_unchecked": {baseline: unknown[baseline] for baseline in sorted(trained_on)},
        }
    manifest = BENIGN_CODE._manifest_bytes(
        {
            "schema": CORPORA_SCHEMA,
            "generation": registry["generation"],
            "split": split,
            "split_rule": "by source: every dataset belongs to exactly one split (entity_map.yaml)",
            "dedup": dedup,
            "sampling": sampling,
            "trained_on": trained_on,
            "unchecked": unchecked,
            "sets": sets,
            "skipped": dict(sorted(skipped.items())),
        }
    )
    return {**files, "manifest.json": manifest, READY: f"{PRESIDIO._sha256(manifest)}  manifest.json\n".encode("utf-8")}


def verify(directory: Path, schemas: tuple[str, ...] = (CORPORA_SCHEMA,)) -> list[str]:
    """Problems of a prepared (or generated, ``generators.py``) directory (empty list: frozen and intact)."""
    ready, manifest_path = directory / READY, directory / "manifest.json"
    if not ready.is_file() or not manifest_path.is_file():
        return [f"{directory}: no {READY} or manifest.json"]
    manifest_bytes = manifest_path.read_bytes()
    problems = []
    if ready.read_text(encoding="utf-8") != f"{PRESIDIO._sha256(manifest_bytes)}  manifest.json\n":
        problems.append(f"{directory}: {READY} does not match manifest.json")
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") not in schemas:
        problems.append(f"{directory}: manifest schema is not {' or '.join(schemas)}")
    expected = {entry["file"]: entry["sha256"] for entry in manifest.get("sets", {}).values()}
    for name, digest in sorted(expected.items()):
        path = directory / name
        if not path.is_file() or PRESIDIO._sha256(path.read_bytes()) != digest:
            problems.append(f"{path} is missing or does not match its SHA-256 in manifest.json")
    for path in sorted(directory.glob("*.jsonl")):
        if path.name not in expected:
            problems.append(f"{path} is not in manifest.json")
    return problems


def frozen_version(manifest: bytes, key: str = "generation") -> int:
    """Integer ``key`` of a frozen manifest (registry generation, generator version); 1 if absent or unreadable."""
    try:
        return int(json.loads(manifest).get(key, 1))
    except (ValueError, TypeError, AttributeError):
        return 1


def _format_upgrade(out: Path, current: bytes, manifest: bytes) -> bool:
    """True when ``out`` is intact but in an older corpus schema, built from the same inputs as ``manifest``."""
    try:
        frozen = json.loads(current)
    except ValueError:
        return False
    if frozen.get("schema") == CORPORA_SCHEMA or verify(out) != [f"{out}: manifest schema is not {CORPORA_SCHEMA}"]:
        return False

    def inputs(data: dict[str, Any]) -> Any:
        sets = {i: (s.get("source"), s.get("revision"), s.get("source_files")) for i, s in data.get("sets", {}).items()}
        return [data.get(key) for key in ("split", "dedup", "trained_on", "skipped")] + [sets]

    return inputs(frozen) == inputs(json.loads(manifest))


def prepare(
    split: str,
    out: Path,
    registry: dict[str, Any],
    emap: dict[str, Any],
    sources: Path,
    offline: bool,
    force: bool,
    download: Callable[[str], bytes] = PRESIDIO.download,
    loaded: dict[str, tuple[list[dict[str, Any]], Counter[str]]] | None = None,
    with_holdout: bool = False,
) -> int:
    files = build(split, registry, emap, sources, offline, download, loaded, with_holdout)
    if files is None:
        print(f"{split}: no ready set; {out} not written")
        return 0
    if (out / READY).exists():
        current = (out / "manifest.json").read_bytes() if (out / "manifest.json").is_file() else b""
        if not verify(out) and current == files["manifest.json"]:
            print(f"{split}: {out} unchanged (frozen)")
            return 0
        frozen = frozen_version(current)
        if frozen < registry["generation"]:
            print(f"{split}: {out} was frozen as generation {frozen}, the registry is at {registry['generation']}; re-freezing")
        elif _format_upgrade(out, current, files["manifest.json"]):
            print(f"{split}: {out} was frozen in an older corpus format from the same inputs; rewriting")
        elif not force:
            print(f"{split}: {out} is frozen and differs from this run (or was modified); nothing written. Use --force.", file=sys.stderr)
            return 1
    BENIGN_CODE._write(out, files)
    print(f"{split}: {len(files) - 2} sets written to {out}")
    return 0


def prepare_splits(
    dev_out: Path,
    holdout_out: Path,
    sources: Path | None,
    registry: dict[str, Any],
    emap: dict[str, Any],
    offline: bool,
    force: bool,
    download: Callable[[str], bytes] = PRESIDIO.download,
) -> int:
    """Prepare every split under DEV or HOLDOUT (``LAYOUT``); 0 when all are written or unchanged."""
    sources = holdout_out / ".sources" if sources is None else sources
    dev, holdout = dev_out.resolve(), holdout_out.resolve()
    if dev == holdout or dev.is_relative_to(holdout) or holdout.is_relative_to(dev):
        print("prepare_corpora: --dev-out and --holdout-out must be separate, non-nested directories", file=sys.stderr)
        return 1
    if sources.resolve().is_relative_to(dev):
        print("prepare_corpora: --sources must not be inside --dev-out: the cache holds holdout sources", file=sys.stderr)
        return 1
    roots, loaded = {"dev": dev, "holdout": holdout}, {}
    for split, (root, name) in LAYOUT.items():
        if prepare(split, roots[root] / name, registry, emap, sources, offline, force, download, loaded, with_holdout=True):
            return 1
    return 0


def coverage(directories: list[Path]) -> tuple[str, list[str]]:
    """Report and problems of the pool of frozen directories (prepared and generated) of one split.

    The pool needs rows of every taxonomy class, at least MIN_BENIGN_ROWS benign rows from at least
    MIN_BENIGN_SOURCES datasets, and no row whose contamination is unknown for a baseline."""
    problems: list[str] = []
    classes: dict[str, Counter[str]] = {name: Counter() for name in taxonomy.CLASSES}
    benign: Counter[str] = Counter()
    unchecked: Counter[str] = Counter()
    for directory in directories:
        broken = verify(directory, schemas=(CORPORA_SCHEMA, GENERATED_SCHEMA))
        if broken:
            problems.extend(broken)
            continue
        manifest = json.loads((directory / "manifest.json").read_bytes())
        generated = manifest["schema"] == GENERATED_SCHEMA
        for name, entry in sorted(manifest["sets"].items()):
            dataset = entry["dataset"] if generated else name
            source = f"{dataset} ({'synthetic' if generated else 'native'})"
            for class_name, count in entry["classes"].items():
                classes.setdefault(class_name, Counter())[source] += count
            benign[dataset] += entry["benign"]
            unchecked.update(entry.get("contamination_unchecked") or {})
    lines = ["| Class | Rows | Sources |", "|---|---:|---|"]
    for name, by_source in classes.items():
        lines.append(f"| {name} | {sum(by_source.values())} | {', '.join(f'{s}: {n}' for s, n in sorted(by_source.items())) or '-'} |")
        if not by_source:
            problems.append(f"class {name}: no gold rows")
    sources = {dataset: count for dataset, count in benign.items() if count}
    lines.append(f"| benign | {sum(sources.values())} | {', '.join(f'{s}: {n}' for s, n in sorted(sources.items())) or '-'} |")
    if sum(sources.values()) < MIN_BENIGN_ROWS or len(sources) < MIN_BENIGN_SOURCES:
        problems.append(f"benign pool: {sum(sources.values())} rows from {len(sources)} sets (needs {MIN_BENIGN_ROWS} from {MIN_BENIGN_SOURCES})")
    problems.extend(f"contamination unchecked for {baseline}: {count} rows" for baseline, count in sorted(unchecked.items()) if count)
    return "\n".join(lines), problems


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
    parser.add_argument("--overlay", type=Path, help=f"recipes for pending sets (default: HOLDOUT/{OVERLAY_FILE} if present)")
    parser.add_argument("--dev-out", type=Path, help="train_dev and report corpora (visible to agents)")
    parser.add_argument("--holdout-out", type=Path, help="holdout corpora (gate only)")
    parser.add_argument("--sources", type=Path, help="download cache, one directory per set (default: HOLDOUT/.sources)")
    parser.add_argument("--offline", action="store_true", help="never fetch; the cache must be complete")
    parser.add_argument("--force", action="store_true", help="replace frozen corpora that differ")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check")
    sub.add_parser("list")
    ver = sub.add_parser("verify")
    ver.add_argument("directory", type=Path)
    cov = sub.add_parser("coverage")
    cov.add_argument("directories", type=Path, nargs="+", help="frozen directories of one split (prepared and generated)")
    args = parser.parse_args(argv)

    if args.command == "coverage":
        report, problems = coverage(args.directories)
        print("\n".join([report, *problems]))
        return 1 if problems else 0

    if args.command == "verify":
        problems = verify(args.directory)
        print("\n".join(problems) or f"{args.directory}: frozen and intact")
        return 1 if problems else 0
    if args.command is None and (args.dev_out is None or args.holdout_out is None):
        parser.error("--dev-out and --holdout-out are required (or use check, list or verify)")
    overlay = args.overlay
    if overlay is None and args.command is None and (args.holdout_out / OVERLAY_FILE).is_file():
        overlay = args.holdout_out / OVERLAY_FILE
    registry, emap = load(args.registry), entity_map.load(args.entity_map)
    if overlay:
        registry = apply_overlay(registry, load(overlay))
    if args.command == "check":
        problems = check(registry, emap)
        print("\n".join(problems) or f"{args.registry}: ok ({sum(map(is_ready, registry['datasets']))} ready)")
        return 1 if problems else 0
    if args.command == "list":
        print(listing(registry, emap))
        return 0
    return prepare_splits(args.dev_out, args.holdout_out, args.sources, registry, emap, args.offline, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
