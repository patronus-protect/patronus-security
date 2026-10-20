#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""L1-PII scoreboard: exact and overlap P/R/F1 of a head build against its base commit.

``gate`` scores the Ark build of a checkout (``--head``) and of its base commit
(``--base-sha``) on every frozen gold directory below ``--dev`` and ``--holdout``
(directories with ``.ready``, e.g. ``DIR/*.jsonl`` and ``DIR/synthetic/*.jsonl``):

    scoreboard.py gate --head WT --base-sha SHA --dev DIR [--holdout DIR] --cache DIR

Exit code 0 = no regression, 1 = regression, 2 = usage or infrastructure error. A
regression is any F1 loss above the tolerance (default 0.5 pp; exact or overlap) of an
entity, of all L1 entities together, of a source family or of DE/EN, in any split, or any
new prediction on a hard-negative span. The summary goes to stdout; for the holdout it
only names aggregates and regressions, never row ids or text.

Scoring follows ``research/l1-pii/entity_map.yaml``: semantic entities are not L1
scope; a corpus listed in the map is scored only on the ids it annotates, a corpus
without map entry (the synthetic DE/EU set) on every L1 id, and a row with
``scored_entities`` (a Presidio recognizer test case) only on those ids. Exact = same
id, start and end; overlap = a gold span counts as found if a prediction of the same id
overlaps it, a prediction counts as correct if it overlaps gold of the same id.

Predictions come from ``run_ark.py`` of the respective commit. The head runs with
``--ark-python`` (default: ``$VIRTUAL_ENV/bin/python``), which must import the
``patronus_ark`` package of the head checkout (``maturin develop``). The base is
built offline from ``git archive`` into the cache (``cargo build --offline``) unless
its predictions are cached already. Predictions are cached per source key (the git
trees that make up the Ark build) and input SHA-256, so the base of a stacked task,
whose source equals the previously gated head, is never rebuilt. Results land in
``CACHE/scoreboard/results/<sha>.json`` per commit.

``score`` scores one prediction file (Ark or Presidio format) without git:

    scoreboard.py score --gold gold.jsonl --predictions predictions.jsonl

Every bucket also exists per source family (``family/<family>``, ``family_entity/...``;
families from ``source_families`` in the entity map). ``m1`` checks milestone M1 per family
from Ark and Presidio predictions stored under the gold file names:

    scoreboard.py m1 --gold DIR --ark ARK_DIR --presidio PRESIDIO_DIR [--language en] [--check]

``report`` renders the Markdown baseline (research/l1-pii/scoreboard/baseline.md): P/R/F1 per
source family, corpus and entity for Ark and each Presidio profile, hard-negative FP per
family, M1 of the first engine against each other one:

    scoreboard.py report --gold DIR --engine ark=DIR --engine presidio-default=DIR --engine presidio-tuned=DIR
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import entity_map as entity_map_module  # noqa: E402


SCHEMA = "ark-l1-scoreboard-v1"
# Bump when run_ark.py output or the build recipe changes in a way the source key misses.
PREDICTION_VERSION = "1"
TOLERANCE_PP = 0.5
# Everything that goes into the native module and the prediction runner.
KEY_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "rust",
    "python",
    "scripts/l1_presidio/run_ark.py",
)
LANGUAGES = ("de", "en")
METRICS = ("exact", "overlap")
COUNT_FIELDS = ("gold", "predicted", "exact", "gold_found", "predicted_correct")
NATIVE_LIBRARY = "lib_patronus_ark.so"
NATIVE_MODULE = "_patronus_ark.abi3.so"


class ScoreboardError(Exception):
    """Infrastructure or input problem; exit code 2."""


class Dataset(NamedTuple):
    split: str
    name: str  # path relative to the split root, e.g. synthetic/ark-synthetic-de-eu.jsonl
    path: Path
    sha256: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ScoreboardError(f"{path.name}:{number}: invalid JSON ({error.msg})") from None
    return rows


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def discover(split: str, root: Path) -> list[Dataset]:
    """Gold files of every frozen directory (``.ready``) in root and its visible subdirectories."""
    root = root.resolve()
    if not root.is_dir():
        raise ScoreboardError(f"{split}: {root} is not a directory")
    frozen = [root, *sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))]
    datasets = [
        Dataset(split, path.relative_to(root).as_posix(), path, sha256_file(path))
        for directory in frozen
        if (directory / ".ready").is_file()
        for path in sorted(directory.glob("*.jsonl"))
    ]
    if not datasets:
        raise ScoreboardError(f"{split}: no frozen gold JSONL (directory with .ready) in {root}")
    return datasets


# ── scoring ──────────────────────────────────────────────────────────────


def l1_ids(emap: Any) -> set[str]:
    return {entity_id for entity_id, entity in emap.entities.items() if entity.scope != "semantic"}


def scored_ids(emap: Any, corpus: str) -> set[str]:
    """L1 ids a corpus annotates; corpora without map entry annotate every L1 id."""
    l1 = l1_ids(emap)
    if corpus not in emap.corpora():
        return l1
    return {entity_id for entity_id in l1 if corpus in emap.entities[entity_id].corpora}


def resolve_label(span: dict[str, Any], emap: Any) -> str | None:
    """Benchmark id of a predicted span (Ark ``ark_label``, Presidio ``presidio_entity`` or ``label``).

    Native labels win over an embedded ``label``: a base commit's run_ark.py precomputed ``label``
    with its own output map, and the current entity map must decide how its ``ark_label`` counts."""
    if isinstance(span.get("ark_label"), str):
        return emap.ark_label(span["ark_label"])
    if isinstance(span.get("presidio_entity"), str):
        return emap.presidio_entity(span["presidio_entity"])
    label = span.get("label")
    if isinstance(label, str) and label in emap.entities:
        return label
    return None


def _span(item: dict[str, Any], label: str | None, where: str) -> tuple[str | None, int, int]:
    start = item.get("start", item.get("start_char"))
    end = item.get("end", item.get("end_char"))
    if isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, int) or not isinstance(end, int):
        raise ScoreboardError(f"{where}: span without integer offsets")
    if start < 0 or end <= start:
        raise ScoreboardError(f"{where}: empty or negative span {start}..{end}")
    return label, start, end


def _overlaps(a: tuple[str, int, int], b: tuple[str, int, int]) -> bool:
    return a[0] == b[0] and a[1] < b[2] and b[1] < a[2]


def language_bucket(language: Any) -> str:
    return language if language in LANGUAGES else "other"


def empty_counts() -> dict[str, int]:
    return dict.fromkeys(COUNT_FIELDS, 0)


def score_rows(
    gold_rows: Iterable[dict[str, Any]], prediction_rows: Iterable[dict[str, Any]], emap: Any, dataset: str = ""
) -> dict[str, Any]:
    """Count exact and overlap matches per bucket plus predictions on hard-negative spans."""
    gold_rows = list(gold_rows)
    predictions: dict[str, list[dict[str, Any]]] = {}
    for row in prediction_rows:
        row_id = row.get("id")
        if not isinstance(row_id, str) or row_id in predictions:
            raise ScoreboardError(f"{dataset}: prediction rows need unique string ids")
        spans = row.get("evidence_spans")
        if not isinstance(spans, list):
            raise ScoreboardError(f"{dataset}: prediction {row_id!r} has no evidence_spans list")
        predictions[row_id] = spans
    gold_ids = [row.get("id") for row in gold_rows]
    if len(set(gold_ids)) != len(gold_ids) or not all(isinstance(i, str) for i in gold_ids):
        raise ScoreboardError(f"{dataset}: gold rows need unique string ids")
    unknown = predictions.keys() - set(gold_ids)
    missing = set(gold_ids) - predictions.keys()
    if unknown or missing:
        raise ScoreboardError(f"{dataset}: predictions do not match gold ({len(missing)} missing, {len(unknown)} unknown)")

    l1 = l1_ids(emap)
    scopes = {entity_id: emap.entities[entity_id].scope for entity_id in l1}
    buckets: dict[str, dict[str, int]] = defaultdict(empty_counts)
    hard_negative_fp: set[tuple[str, str, str, int, int]] = set()
    rows = 0
    for row in gold_rows:
        rows += 1
        row_id, corpus = row["id"], str(row.get("corpus", ""))
        where = f"{dataset}:{row_id}"
        family = emap.family(corpus)
        if family is None:
            raise ScoreboardError(f"{where}: corpus {corpus!r} has no source family in entity_map.yaml")
        allowed = scored_ids(emap, corpus)
        if "scored_entities" in row:
            # Rows that assert on some ids only (Presidio recognizer test cases).
            scored = row["scored_entities"]
            if not isinstance(scored, list) or not all(isinstance(item, str) for item in scored):
                raise ScoreboardError(f"{where}: scored_entities must be a list of ids")
            allowed = allowed & set(scored)
        gold = {_span(e, e.get("entity_type", e.get("label")), where) for e in row.get("entities", [])}
        gold = {item for item in gold if item[0] in allowed}
        predicted_all = {_span(s, resolve_label(s, emap), where) for s in predictions[row_id]}
        predicted = {item for item in predicted_all if item[0] in allowed}
        for hn in row.get("hard_negatives", []) or []:
            _, start, end = _span(hn, None, where)
            # A hard negative with entity_type only forbids that id (a recognizer's negative case).
            forbidden = {hn["entity_type"]} if isinstance(hn.get("entity_type"), str) else l1
            for item in predicted_all:
                if item[0] in forbidden and item[1] < end and start < item[2]:
                    hard_negative_fp.add((dataset, row_id, item[0], item[1], item[2]))
        language = language_bucket(row.get("language"))
        for label in {item[0] for item in gold | predicted}:
            expected = {item for item in gold if item[0] == label}
            actual = {item for item in predicted if item[0] == label}
            counts = {
                "gold": len(expected),
                "predicted": len(actual),
                "exact": len(expected & actual),
                "gold_found": sum(any(_overlaps(g, p) for p in actual) for g in expected),
                "predicted_correct": sum(any(_overlaps(p, g) for g in expected) for p in actual),
            }
            for bucket in (
                "all",
                f"language/{language}",
                f"corpus/{corpus}",
                f"scope/{scopes[label]}",
                f"entity/{label}",
                f"language_entity/{language}/{label}",
                f"family/{family}",
                f"family_language/{family}/{language}",
                f"family_entity/{family}/{label}",
                f"family_language_entity/{family}/{language}/{label}",
            ):
                for field, value in counts.items():
                    buckets[bucket][field] += value
    buckets.setdefault("all", empty_counts())
    return {
        "rows": rows,
        "buckets": {key: dict(value) for key, value in sorted(buckets.items())},
        "hard_negative_fp": sorted([list(item) for item in hard_negative_fp]),
    }


def merge(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, dict[str, int]] = defaultdict(empty_counts)
    hard_negative_fp: list[list[Any]] = []
    rows = 0
    for result in results:
        rows += result["rows"]
        hard_negative_fp += result["hard_negative_fp"]
        for key, counts in result["buckets"].items():
            for field in COUNT_FIELDS:
                buckets[key][field] += counts[field]
    buckets.setdefault("all", empty_counts())
    return {
        "rows": rows,
        "buckets": {key: dict(value) for key, value in sorted(buckets.items())},
        "hard_negative_fp": sorted(hard_negative_fp),
    }


def _prf(tp_precision: int, predicted: int, tp_recall: int, gold: int) -> dict[str, float]:
    precision = tp_precision / predicted if predicted else 0.0
    recall = tp_recall / gold if gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def metrics(counts: dict[str, int]) -> dict[str, dict[str, float]]:
    return {
        "exact": _prf(counts["exact"], counts["predicted"], counts["exact"], counts["gold"]),
        "overlap": _prf(counts["predicted_correct"], counts["predicted"], counts["gold_found"], counts["gold"]),
    }


def gated_buckets(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    keys = base["buckets"].keys() | head["buckets"].keys()
    return sorted(
        key
        for key in keys
        if key == "all"
        or key in {f"language/{lang}" for lang in LANGUAGES}
        or key.startswith(("entity/", "family/"))
    )


def compare(base: dict[str, Any], head: dict[str, Any], tolerance_pp: float = TOLERANCE_PP) -> dict[str, Any]:
    """Regressions of head against base within one split."""
    regressions = []
    for key in gated_buckets(base, head):
        before = metrics(base["buckets"].get(key, empty_counts()))
        after = metrics(head["buckets"].get(key, empty_counts()))
        for metric in METRICS:
            delta = (after[metric]["f1"] - before[metric]["f1"]) * 100
            if delta < -tolerance_pp - 1e-9:
                regressions.append({
                    "bucket": key, "metric": metric,
                    "base_f1": before[metric]["f1"], "head_f1": after[metric]["f1"], "delta_pp": delta,
                })
    base_fp = {tuple(item) for item in base["hard_negative_fp"]}
    new_fp = sorted(list(item) for item in {tuple(item) for item in head["hard_negative_fp"]} - base_fp)
    return {"regressions": regressions, "new_hard_negative_fp": new_fp}


# ── sources, builds and predictions ──────────────────────────────────────


def git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-c", "core.fsmonitor=false", *args], cwd=repo, text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise ScoreboardError(f"git {' '.join(args)} failed: {proc.stderr.strip()[-500:]}")
    return proc.stdout.strip()


def commit_sha(repo: Path, rev: str) -> str:
    if not rev:
        raise ScoreboardError("empty revision")
    return git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")


def source_key(repo: Path, rev: str) -> str:
    """Digest of the git objects that make up the Ark build and the prediction runner at rev."""
    lines = [f"{SCHEMA} predictions {PREDICTION_VERSION}"]
    for path in KEY_PATHS:
        oid = git(repo, "rev-parse", "--verify", "--quiet", f"{rev}:{path}", check=False)
        lines.append(f"{path} {oid or '-'}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def is_clean(repo: Path) -> bool:
    """True if the checkout matches HEAD on every source key path (tracked and untracked)."""
    return not git(repo, "status", "--porcelain", "--untracked-files=all", "--", *KEY_PATHS)


class ArkBuild(NamedTuple):
    """How to run run_ark.py for one commit: interpreter, script and extra environment."""

    python: str
    run_ark: Path
    env: dict[str, str]
    native: Path | None  # expected native module (checked against run_ark's metadata)


def default_ark_python() -> str:
    venv = os.environ.get("VIRTUAL_ENV")
    if venv and (Path(venv) / "bin" / "python").exists():
        return str(Path(venv) / "bin" / "python")
    return sys.executable


def head_build(head: Path, ark_python: str) -> ArkBuild:
    """The head runs with the installed (maturin develop) package, which must be the head's."""
    probe = subprocess.run(
        [ark_python, "-c", "import patronus_ark; print(patronus_ark.__file__)"],
        cwd="/", text=True, capture_output=True,
    )
    if probe.returncode != 0:
        raise ScoreboardError(f"{ark_python} cannot import patronus_ark: {probe.stderr.strip()[-500:]}")
    package = Path(probe.stdout.strip()).resolve().parent
    if package != (head / "python" / "patronus_ark").resolve():
        raise ScoreboardError(f"{ark_python} imports patronus_ark from {package}, not from the head {head}")
    return ArkBuild(ark_python, head / "scripts" / "l1_presidio" / "run_ark.py", {}, None)


def build_base(
    repo: Path, sha: str, key: str, cache: Path, ark_python: str, cargo: str = "cargo"
) -> ArkBuild:
    """Build the native module of commit sha offline into the cache (reused per source key)."""
    stage = cache / "builds" / key
    package = stage / "patronus_ark"
    run_ark = stage / "run_ark.py"
    if not (stage / ".ready").is_file():
        shutil.rmtree(stage, ignore_errors=True)
        source = cache / "src" / key
        shutil.rmtree(source, ignore_errors=True)
        source.mkdir(parents=True)
        try:
            archive = source.parent / f"{key}.tar"
            with archive.open("wb") as handle:
                proc = subprocess.run(["git", "archive", "--format=tar", sha], cwd=repo, stdout=handle,
                                      stderr=subprocess.PIPE, text=False)
            if proc.returncode != 0:
                raise ScoreboardError(f"git archive {sha} failed: {proc.stderr.decode()[-500:]}")
            with tarfile.open(archive) as tar:
                tar.extractall(source, filter="data")
            archive.unlink()
            env = {**os.environ, "CARGO_TARGET_DIR": str(cache / "target"), "PYO3_PYTHON": ark_python}
            build = subprocess.run(
                [cargo, "build", "--offline", "--locked", "--lib", "--manifest-path", str(source / "python" / "Cargo.toml")],
                cwd=source, env=env, text=True, capture_output=True,
            )
            if build.returncode != 0:
                raise ScoreboardError(f"base build of {sha[:12]} failed:\n{build.stderr.strip()[-3000:]}")
            library = cache / "target" / "debug" / NATIVE_LIBRARY
            runner = source / "scripts" / "l1_presidio" / "run_ark.py"
            if not library.is_file() or not runner.is_file():
                raise ScoreboardError(f"base {sha[:12]} has no {NATIVE_LIBRARY} or run_ark.py")
            stage.mkdir(parents=True)
            shutil.copytree(source / "python" / "patronus_ark", package,
                            ignore=shutil.ignore_patterns("benchmark_data", "__pycache__", "*.so"))
            shutil.copy2(library, package / NATIVE_MODULE)
            shutil.copy2(runner, run_ark)
            (stage / ".ready").write_text(sha + "\n", encoding="utf-8")
        finally:
            shutil.rmtree(source, ignore_errors=True)
    return ArkBuild(ark_python, run_ark, {"PYTHONPATH": str(stage)}, package / NATIVE_MODULE)


def run_predictions(build: ArkBuild, input_path: Path, output_path: Path) -> None:
    meta = output_path.with_name(output_path.name + ".meta.json")
    proc = subprocess.run(
        [build.python, str(build.run_ark), "--input", str(input_path), "--output", str(output_path), "--meta", str(meta)],
        cwd="/", env={**os.environ, **build.env}, text=True, capture_output=True,
    )
    if proc.returncode != 0:
        # The input may be holdout data and runner errors can name rows: keep stderr next to the
        # prediction file in the private cache and report only the exit code.
        stderr = output_path.with_name(output_path.name + ".stderr")
        stderr.parent.mkdir(parents=True, exist_ok=True)
        stderr.write_text(proc.stderr, encoding="utf-8")
        raise ScoreboardError(f"run_ark.py failed (exit {proc.returncode}); stderr in {stderr}")
    if build.native is not None:
        native = json.loads(meta.read_text(encoding="utf-8")).get("build", {}).get("native_sha256")
        if native != sha256_file(build.native):
            raise ScoreboardError(f"run_ark.py did not load the base build {build.native}")


Predictor = Callable[[Dataset, Path], None]


class PredictionCache:
    """Prediction files per source key and input SHA-256 below CACHE/predictions."""

    def __init__(self, root: Path):
        self.root = root / "predictions"
        self.scratch = root / "scratch"

    def path(self, key: str, dataset: Dataset) -> Path:
        return self.root / key / f"{dataset.sha256}.jsonl"

    def has(self, key: str | None, dataset: Dataset) -> bool:
        return key is not None and self.path(key, dataset).is_file()

    def get(self, key: str | None, dataset: Dataset, predict: Callable[[], Predictor]) -> list[dict[str, Any]]:
        if self.has(key, dataset):
            return read_jsonl(self.path(key, dataset))
        self.scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.scratch) as tmp:
            output = Path(tmp) / "predictions.jsonl"
            predict()(dataset, output)
            rows = read_jsonl(output)
            if key is not None:
                write_atomic(self.path(key, dataset), output.read_bytes())
        return rows


# ── gate ─────────────────────────────────────────────────────────────────


class Side(NamedTuple):
    name: str
    sha: str
    key: str | None
    predict: Callable[[], Predictor]


def lazy(factory: Callable[[], ArkBuild]) -> Callable[[], Predictor]:
    """Create the build only when a prediction is actually missing."""
    built: list[ArkBuild] = []

    def get() -> Predictor:
        if not built:
            built.append(factory())
        return lambda dataset, output: run_predictions(built[0], dataset.path, output)

    return get


def score_side(side: Side, datasets: list[Dataset], cache: PredictionCache, emap: Any) -> dict[str, Any]:
    splits: dict[str, Any] = {}
    for split in dict.fromkeys(d.split for d in datasets):
        parts = []
        for dataset in (d for d in datasets if d.split == split):
            predictions = cache.get(side.key, dataset, side.predict)
            parts.append(score_rows(read_jsonl(dataset.path), predictions, emap, dataset.name))
        splits[split] = {
            "datasets": {d.name: d.sha256 for d in datasets if d.split == split},
            **merge(parts),
        }
    return splits


def store_results(root: Path, side: Side, splits: dict[str, Any]) -> None:
    """CACHE/results/<sha>.json; only for committed sources (key known)."""
    if side.key is None:
        return
    path = root / "results" / f"{side.sha}.json"
    previous = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    stored = previous.get("splits", {}) if previous.get("source_key") == side.key else {}
    payload = {"schema": SCHEMA, "commit": side.sha, "source_key": side.key, "splits": {**stored, **splits}}
    write_atomic(path, (json.dumps(payload, indent=1, sort_keys=True) + "\n").encode())


def pct(value: float) -> str:
    return f"{value * 100:5.1f}"


def signed(value: float) -> str:
    return f"{value:+.1f}"


def f1_pair(counts: dict[str, int]) -> tuple[float, float]:
    m = metrics(counts)
    return m["exact"]["f1"], m["overlap"]["f1"]


def entity_table(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    lines = [f"  {'entity':<36} {'gold':>5} {'pred':>5}  {'exact P/R/F1':<17}  {'overlap F1':>10}  {'ΔF1 ex/ov':>11}"]
    for key in sorted(k for k in head["buckets"].keys() | base["buckets"].keys() if k.startswith("entity/")):
        h = head["buckets"].get(key, empty_counts())
        b = base["buckets"].get(key, empty_counts())
        m = metrics(h)
        (be, bo), (he, ho) = f1_pair(b), f1_pair(h)
        lines.append(
            f"  {key[7:]:<36} {h['gold']:>5} {h['predicted']:>5}  "
            f"{pct(m['exact']['precision'])}/{pct(m['exact']['recall'])}/{pct(m['exact']['f1'])}  "
            f"{pct(m['overlap']['f1']):>10}  {signed((he - be) * 100):>5}/{signed((ho - bo) * 100):<5}"
        )
    return lines


def family_lines(split: str, base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    """F1 per source family of one split (all L1 ids and EN), Δ vs base."""
    lines = []
    for family in entity_map_module.FAMILIES:
        key = f"family/{family}"
        if key not in head["buckets"] and key not in base["buckets"]:
            continue
        parts = [f"  {split} {family:<16}"]
        for bucket, name in ((key, "L1"), (f"family_language/{family}/en", "en")):
            (be, bo), (he, ho) = f1_pair(base["buckets"].get(bucket, empty_counts())), f1_pair(head["buckets"].get(bucket, empty_counts()))
            parts.append(f"{name} F1 {pct(he).strip()}/{pct(ho).strip()} ({signed((he - be) * 100)}/{signed((ho - bo) * 100)})")
        note = "" if family in entity_map_module.MILESTONE_FAMILIES else " (reported, decides no milestone)"
        lines.append(" | ".join(parts) + note)
    return lines


def split_line(split: str, base: dict[str, Any], head: dict[str, Any], new_fp: int) -> str:
    parts = [f"{split:<8} rows {head['rows']:>5}"]
    for key, name in (("all", "L1"), *((f"language/{lang}", lang) for lang in LANGUAGES)):
        (be, bo), (he, ho) = f1_pair(base["buckets"].get(key, empty_counts())), f1_pair(head["buckets"].get(key, empty_counts()))
        parts.append(f"{name} F1 {pct(he).strip()}/{pct(ho).strip()} ({signed((he - be) * 100)}/{signed((ho - bo) * 100)})")
    parts.append(f"HN-FP {len(head['hard_negative_fp'])} (new {new_fp})")
    return " | ".join(parts)


def summary(head: Side, base: Side, results: dict[str, Any], tolerance_pp: float) -> tuple[list[str], bool]:
    same = head.key is not None and head.key == base.key
    lines = [
        f"{SCHEMA}: head {head.sha[:12]}{'' if head.key else ' (uncommitted changes)'} vs base {base.sha[:12]}"
        + (" (same Ark sources)" if same else ""),
    ]
    for split, result in results.items():
        if split == "dev":
            lines.append("dev per entity (head; Δ vs base in pp):")
            lines += entity_table(result["base"], result["head"])
    lines.append(f"F1 exact/overlap in % (Δ pp vs base), tolerance {tolerance_pp} pp:")
    regressed = False
    problems = []
    for split, result in results.items():
        verdict = result["compare"]
        lines.append(split_line(split, result["base"], result["head"], len(verdict["new_hard_negative_fp"])))
        lines += family_lines(split, result["base"], result["head"])
        for item in verdict["regressions"]:
            problems.append(
                f"  {split} {item['bucket']} {item['metric']} F1 {pct(item['base_f1']).strip()} -> "
                f"{pct(item['head_f1']).strip()} ({signed(item['delta_pp'])} pp)"
            )
        if verdict["new_hard_negative_fp"]:
            labels: dict[str, int] = defaultdict(int)
            for item in verdict["new_hard_negative_fp"]:
                labels[item[2]] += 1
            problems.append(f"  {split} new hard-negative FP: " + ", ".join(f"{k} {v}" for k, v in sorted(labels.items())))
        regressed = regressed or bool(verdict["regressions"] or verdict["new_hard_negative_fp"])
    lines.append(f"regressions: {len(problems)}" if problems else "regressions: none")
    lines += problems[:20] + ([f"  … {len(problems) - 20} more"] if len(problems) > 20 else [])
    lines.append("RESULT: REGRESSION" if regressed else "RESULT: PASS")
    return lines, regressed


def gate(
    head_dir: Path,
    base_rev: str,
    splits: dict[str, Path],
    cache_dir: Path,
    *,
    ark_python: str | None = None,
    cargo: str = "cargo",
    tolerance_pp: float = TOLERANCE_PP,
    emap: Any = None,
    head_factory: Callable[[], ArkBuild] | None = None,
    base_factory: Callable[[str, str], ArkBuild] | None = None,
) -> tuple[list[str], bool, dict[str, Any]]:
    head_dir = head_dir.resolve()
    root = cache_dir.resolve() / "scoreboard"
    emap = emap or entity_map_module.load()
    ark_python = ark_python or default_ark_python()
    if os.sep in ark_python:
        ark_python = str(Path(ark_python).absolute())  # no resolve(): a venv python is a symlink
    head_sha = commit_sha(head_dir, "HEAD")
    base_sha = commit_sha(head_dir, base_rev)
    head_key = source_key(head_dir, "HEAD") if is_clean(head_dir) else None
    base_key = source_key(head_dir, base_sha)
    head_factory = head_factory or (lambda: head_build(head_dir, ark_python))
    base_factory = base_factory or (lambda sha, key: build_base(head_dir, sha, key, root, ark_python, cargo))
    head = Side("head", head_sha, head_key, lazy(head_factory))
    base = Side("base", base_sha, base_key, head.predict if base_key == head_key else lazy(lambda: base_factory(base_sha, base_key)))

    datasets = [d for split, path in splits.items() for d in discover(split, path)]
    cache = PredictionCache(root)
    head_results = score_side(head, datasets, cache, emap)
    base_results = score_side(base, datasets, cache, emap)
    store_results(root, head, head_results)
    store_results(root, base, base_results)
    results = {
        split: {"base": base_results[split], "head": head_results[split],
                "compare": compare(base_results[split], head_results[split], tolerance_pp)}
        for split in head_results
    }
    lines, regressed = summary(head, base, results, tolerance_pp)
    report = {"schema": SCHEMA, "head": head_sha, "base": base_sha, "head_source_key": head_key,
              "base_source_key": base_key, "tolerance_pp": tolerance_pp, "regressed": regressed, "splits": results}
    return lines, regressed, report


def score_file(gold: Path, predictions: Path, emap: Any = None) -> tuple[list[str], dict[str, Any]]:
    emap = emap or entity_map_module.load()
    result = score_rows(read_jsonl(gold), read_jsonl(predictions), emap, gold.name)
    lines = [f"{SCHEMA}: {gold.name} ({result['rows']} rows) <- {predictions.name}"]
    lines += entity_table(result, result)
    m = metrics(result["buckets"]["all"])
    lines.append(
        f"L1 exact P/R/F1 {pct(m['exact']['precision'])}/{pct(m['exact']['recall'])}/{pct(m['exact']['f1'])} | "
        f"overlap P/R/F1 {pct(m['overlap']['precision'])}/{pct(m['overlap']['recall'])}/{pct(m['overlap']['f1'])} | "
        f"HN-FP {len(result['hard_negative_fp'])}"
    )
    return lines, result


# ── M1 per source family ─────────────────────────────────────────────────


def score_directory(gold_root: Path, predictions_root: Path, emap: Any) -> dict[str, Any]:
    """Merged result of every frozen gold file below gold_root against predictions_root/<same name>."""
    parts = []
    for dataset in discover("gold", gold_root):
        predictions = predictions_root / dataset.name
        if not predictions.is_file():
            raise ScoreboardError(f"no predictions {predictions} for {dataset.name}")
        parts.append(score_rows(read_jsonl(dataset.path), read_jsonl(predictions), emap, dataset.name))
    return merge(parts)


def m1_report(ark: dict[str, Any], presidio: dict[str, Any], emap: Any, language: str = "en",
              metric: str = "exact") -> dict[str, Any]:
    """M1 per source family: every shared id with gold in the family needs F1(Ark) >= F1(Presidio).

    A family holds only if it has at least one such id; M1 is met only if every milestone family
    (neutral, presidio_favored) holds on its own. ark_authored is reported and decides nothing."""
    families = {}
    for family in entity_map_module.FAMILIES:
        entities = {}
        for entity_id in sorted(emap.ids("shared")):
            key = (f"family_entity/{family}/{entity_id}" if language == "all"
                   else f"family_language_entity/{family}/{language}/{entity_id}")
            ark_counts = ark["buckets"].get(key, empty_counts())
            presidio_counts = presidio["buckets"].get(key, empty_counts())
            gold = max(ark_counts["gold"], presidio_counts["gold"])
            if not gold:
                continue
            ark_f1 = metrics(ark_counts)[metric]["f1"]
            presidio_f1 = metrics(presidio_counts)[metric]["f1"]
            entities[entity_id] = {"gold": gold, "ark_f1": ark_f1, "presidio_f1": presidio_f1,
                                   "holds": ark_f1 >= presidio_f1 - 1e-12}
        families[family] = {
            "decides": family in entity_map_module.MILESTONE_FAMILIES,
            "holds": bool(entities) and all(item["holds"] for item in entities.values()),
            "entities": entities,
        }
    met = all(families[family]["holds"] for family in entity_map_module.MILESTONE_FAMILIES)
    return {"language": language, "metric": metric, "met": met, "families": families}


def m1_lines(report: dict[str, Any]) -> list[str]:
    lines = [f"{SCHEMA} M1 ({report['language']}, {report['metric']} F1 in %, Ark vs Presidio):"]
    for family, result in report["families"].items():
        entities = result["entities"]
        verdict = ("HOLDS" if result["holds"] else "NOT MET") if entities else "NO DATA"
        held = sum(item["holds"] for item in entities.values())
        note = "" if result["decides"] else " (reported, decides no milestone)"
        lines.append(f"{family}: {verdict}, {held}/{len(entities)} shared ids{note}")
        for entity_id, item in entities.items():
            lines.append(
                f"  {entity_id:<36} gold {item['gold']:>5}  Ark {pct(item['ark_f1'])}  "
                f"Presidio {pct(item['presidio_f1'])}  {'ok' if item['holds'] else 'below'}"
            )
    deciding = ", ".join(
        f"{family} {'holds' if result['holds'] else 'not met'}"
        for family, result in report["families"].items() if result["decides"]
    )
    lines.append(f"M1: {'MET' if report['met'] else 'NOT MET'} ({deciding})")
    return lines


# ── baseline report ──────────────────────────────────────────────────────


def baseline_report(gold_root: Path, engines: dict[str, Path], emap: Any) -> dict[str, Any]:
    """Every engine's merged result on every frozen gold file, hard-negative FP per family, M1 vs the first engine.

    ``engines`` maps a name to a prediction directory with the gold file names; the first engine
    (Ark) is compared with each of the others (Presidio profiles) for M1."""
    if len(engines) < 2:
        raise ScoreboardError("report needs at least two engines (Ark first, then the Presidio profiles)")
    datasets = discover("gold", gold_root)
    gold = {dataset.name: read_jsonl(dataset.path) for dataset in datasets}
    row_family = {(name, row["id"]): emap.family(str(row.get("corpus", ""))) for name, rows in gold.items() for row in rows}
    results: dict[str, Any] = {}
    hard_negative_fp: dict[str, dict[str, int]] = {}
    for engine, root in engines.items():
        parts = []
        for name, rows in gold.items():
            predictions = root / name
            if not predictions.is_file():
                raise ScoreboardError(f"{engine}: no predictions {predictions} for {name}")
            parts.append(score_rows(rows, read_jsonl(predictions), emap, name))
        results[engine] = merge(parts)
        per_family: dict[str, int] = defaultdict(int)
        for name, row_id, *_ in results[engine]["hard_negative_fp"]:
            per_family[row_family[(name, row_id)]] += 1
        hard_negative_fp[engine] = dict(sorted(per_family.items()))
    corpus_rows: dict[str, int] = defaultdict(int)
    for rows in gold.values():
        for row in rows:
            corpus_rows[str(row.get("corpus", ""))] += 1
    family_rows: dict[str, int] = defaultdict(int)
    for family in row_family.values():
        family_rows[family] += 1
    first, *others = engines
    return {
        "schema": SCHEMA,
        "datasets": {dataset.name: dataset.sha256 for dataset in datasets},
        "corpora": {corpus: emap.family(corpus) for corpus in sorted(corpus_rows)},
        "corpus_rows": dict(sorted(corpus_rows.items())),
        "family_rows": dict(sorted(family_rows.items())),
        "scopes": {entity_id: emap.entities[entity_id].scope for entity_id in sorted(l1_ids(emap))},
        "engines": results,
        "hard_negative_fp": hard_negative_fp,
        "m1": {other: m1_report(results[first], results[other], emap) for other in others},
    }


def _cell(value: float) -> str:
    return pct(value).strip()


def _family_cell(family: str) -> str:
    return family if family in entity_map_module.MILESTONE_FAMILIES else f"{family} ¹"


def report_lines(report: dict[str, Any]) -> list[str]:
    """Markdown tables of a baseline report: per family, per corpus, per entity, M1."""
    engines = report["engines"]
    names = list(engines)
    families = [f for f in entity_map_module.FAMILIES if any(f"family/{f}" in r["buckets"] for r in engines.values())]
    lines = [
        "## Overall per source family",
        "",
        "| Family | Engine | Rows | Gold | Pred | Exact P | Exact R | Exact F1 | Overlap F1 | EN F1 | DE F1 | HN-FP |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for family in families:
        for engine in names:
            buckets = engines[engine]["buckets"]
            counts = buckets.get(f"family/{family}", empty_counts())
            m = metrics(counts)
            languages = []
            for language in LANGUAGES:
                key = f"family_language/{family}/{language}"
                languages.append(_cell(metrics(buckets[key])["exact"]["f1"]) if key in buckets else "–")
            lines.append(
                f"| {_family_cell(family)} | {engine} | {report['family_rows'][family]} | {counts['gold']} | "
                f"{counts['predicted']} | {_cell(m['exact']['precision'])} | {_cell(m['exact']['recall'])} | "
                f"{_cell(m['exact']['f1'])} | {_cell(m['overlap']['f1'])} | {languages[1]} | {languages[0]} | "
                f"{report['hard_negative_fp'][engine].get(family, 0)} |"
            )
    lines += ["", "¹ ark_authored is reported and decides no milestone.", ""]

    lines += [
        "## Per corpus (exact P / R / F1)",
        "",
        "| Corpus | Family | Rows | Gold | " + " | ".join(names) + " |",
        "|---|---|---:|---:|" + "---|" * len(names),
    ]
    for corpus, family in report["corpora"].items():
        key = f"corpus/{corpus}"
        counts = {engine: engines[engine]["buckets"].get(key, empty_counts()) for engine in names}
        f1 = {engine: metrics(c)["exact"]["f1"] for engine, c in counts.items()}
        best = max(f1.values())
        cells = []
        for engine in names:
            m = metrics(counts[engine])["exact"]
            value = _cell(m["f1"])
            cells.append(f"{_cell(m['precision'])} / {_cell(m['recall'])} / "
                         + (f"**{value}**" if best > 0 and f1[engine] == best else value))
        gold = max(c["gold"] for c in counts.values())
        lines.append(f"| {corpus} | {family} | {report['corpus_rows'][corpus]} | {gold} | " + " | ".join(cells) + " |")
    lines.append("")

    lines += [
        "## Per entity (exact F1, best in bold)",
        "",
        "| Family | Entity | Scope | Gold | " + " | ".join(names) + " |",
        "|---|---|---|---:|" + "---:|" * len(names),
    ]
    for family in families:
        prefix = f"family_entity/{family}/"
        ids = sorted({key[len(prefix):] for r in engines.values() for key in r["buckets"] if key.startswith(prefix)})
        for entity_id in ids:
            counts = {engine: engines[engine]["buckets"].get(prefix + entity_id, empty_counts()) for engine in names}
            gold = max(c["gold"] for c in counts.values())
            if not gold:
                continue
            f1 = {engine: metrics(c)["exact"]["f1"] for engine, c in counts.items()}
            best = max(f1.values())
            cells = [f"**{_cell(f1[e])}**" if best > 0 and f1[e] == best else _cell(f1[e]) for e in names]
            lines.append(f"| {family} | {entity_id} | {report['scopes'][entity_id]} | {gold} | " + " | ".join(cells) + " |")
    lines.append("")

    # Milestone families first; ark_authored is shown last and decides nothing.
    m1_families = [*entity_map_module.MILESTONE_FAMILIES,
                   *(f for f in entity_map_module.FAMILIES if f not in entity_map_module.MILESTONE_FAMILIES)]
    lines += [
        f"## M1 ({names[0]} vs each profile; EN rows, exact F1, shared ids with gold)",
        "",
        "| Profile | M1 | " + " | ".join(_family_cell(f) for f in m1_families) + " |",
        "|---|---|" + "---|" * len(m1_families),
    ]
    for other, m1 in report["m1"].items():
        cells = []
        for family in m1_families:
            entities = m1["families"][family]["entities"]
            below = [entity_id for entity_id, item in entities.items() if not item["holds"]]
            cell = f"{len(entities) - len(below)}/{len(entities)}" if entities else "no data"
            cells.append(cell + (f" (below: {', '.join(below)})" if below else ""))
        lines.append(f"| {other} | {'MET' if m1['met'] else 'NOT MET'} | " + " | ".join(cells) + " |")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    gate_parser = commands.add_parser("gate", help="score head and base, exit 1 on regression")
    gate_parser.add_argument("--head", type=Path, required=True, help="checkout of the head commit (git worktree)")
    gate_parser.add_argument("--base-sha", required=True, help="base commit (any git revision)")
    gate_parser.add_argument("--dev", type=Path, required=True, help="dev gold directory")
    gate_parser.add_argument("--holdout", type=Path, help="holdout gold directory (gate only)")
    gate_parser.add_argument("--cache", type=Path, required=True, help="writable cache directory")
    gate_parser.add_argument("--ark-python", help="interpreter with the head's patronus_ark (default: $VIRTUAL_ENV)")
    gate_parser.add_argument("--cargo", default="cargo", help="cargo for the offline base build")
    gate_parser.add_argument("--tolerance-pp", type=float, default=TOLERANCE_PP)
    gate_parser.add_argument("--json", type=Path, help="also write the full report (contains holdout row ids)")
    score_parser = commands.add_parser("score", help="score one prediction file")
    score_parser.add_argument("--gold", type=Path, required=True)
    score_parser.add_argument("--predictions", type=Path, required=True)
    score_parser.add_argument("--json", type=Path, help="also write bucket counts as JSON")
    m1_parser = commands.add_parser("m1", help="M1 per source family: Ark vs Presidio on the shared ids")
    m1_parser.add_argument("--gold", type=Path, required=True, help="gold directory (frozen dirs with .ready)")
    m1_parser.add_argument("--ark", type=Path, required=True, help="Ark predictions, same relative file names")
    m1_parser.add_argument("--presidio", type=Path, required=True, help="Presidio predictions, same relative file names")
    m1_parser.add_argument("--language", choices=(*LANGUAGES, "all"), default="en", help="M1 is EN parity (default en)")
    m1_parser.add_argument("--metric", choices=METRICS, default="exact")
    m1_parser.add_argument("--check", action="store_true", help="exit 1 if M1 is not met")
    m1_parser.add_argument("--json", type=Path, help="also write the report as JSON")
    report_parser = commands.add_parser("report", help="Markdown baseline: Ark vs Presidio profiles per family, corpus, entity, M1")
    report_parser.add_argument("--gold", type=Path, required=True, help="gold directory (frozen dirs with .ready)")
    report_parser.add_argument("--engine", action="append", required=True, metavar="NAME=DIR",
                               help="predictions with the gold file names; Ark first, then the Presidio profiles")
    report_parser.add_argument("--json", type=Path, help="also write the report as JSON")
    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            engines: dict[str, Path] = {}
            for item in args.engine:
                name, sep, directory = item.partition("=")
                if not sep or not name or not directory or name in engines:
                    raise ScoreboardError(f"--engine {item!r}: expected a unique NAME=DIR")
                engines[name] = Path(directory)
            emap = entity_map_module.load()
            report = baseline_report(args.gold, engines, emap)
            print("\n".join(report_lines(report)))
            if args.json:
                args.json.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        if args.command == "m1":
            emap = entity_map_module.load()
            report = m1_report(score_directory(args.gold, args.ark, emap), score_directory(args.gold, args.presidio, emap),
                               emap, args.language, args.metric)
            print("\n".join(m1_lines(report)))
            if args.json:
                args.json.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            return 1 if args.check and not report["met"] else 0
        if args.command == "score":
            lines, result = score_file(args.gold, args.predictions)
            print("\n".join(lines))
            if args.json:
                args.json.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        splits = {"dev": args.dev, **({"holdout": args.holdout} if args.holdout else {})}
        lines, regressed, report = gate(
            args.head, args.base_sha, splits, args.cache,
            ark_python=args.ark_python, cargo=args.cargo, tolerance_pp=args.tolerance_pp,
        )
    except ScoreboardError as error:
        print(f"scoreboard error: {error}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    if args.json:
        args.json.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main())
