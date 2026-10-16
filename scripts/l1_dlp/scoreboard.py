#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""DLP scoreboard: score predictions on the frozen corpora and gate a head against its base.

Metrics per split (``prepare_corpora.py`` layout: ``synthetic/``, ``benign_code/``,
``benign_docs/``):

- carrier value spans (``synthetic/carriers.jsonl``): exact and overlap P/R/F1 per entity
  group, untyped over all groups and per provider (entity id), provider attribution, FP per
  hard-negative variant and language;
- content and document classes: P/R/F1 per class on document level (``content_labels``);
- FP/MB on the benign-code corpus, FP/MB and flagged documents on the benign documents.

Two ARK profiles: ``default`` (what ships: secret groups only) and ``extended`` (plus every
opt-in rule, i.e. business identifiers, content and document classes). Secret groups and
FP/MB are scored on ``default``; opt-in groups and classes on ``extended``.

``gate`` builds the head and the base commit (release module of ``python/``, offline, in the
cache), predicts with ``run_ark.py`` on dev and holdout and fails on a regression: > 0.5 pp
F1 per group, untyped or per content class, more FP on a benign corpus, or a new FP on a
hard negative. stdout carries dev numbers only; the holdout appears as a verdict, its report
stays in the cache. Exit 0 = pass, 1 = regression, 2 = error.

    python3 scripts/l1_dlp/scoreboard.py gate --head WT --base-sha SHA --dev DIR --holdout DIR --cache DIR
    python3 scripts/l1_dlp/scoreboard.py score --split DIR --predictions FILE [--content-predictions FILE]
    python3 scripts/l1_dlp/scoreboard.py compare --base REPORT --head REPORT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, NamedTuple


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENTITY_MAP = Path("research") / "dlp" / "entity_map.yaml"


def _load_file(name: str, path: Path) -> ModuleType:
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


CORPORA = _load_file("_ark_l1_dlp_prepare_corpora", HERE / "prepare_corpora.py")
BENIGN_CODE = CORPORA.BENIGN_CODE
BENIGN_DOCS = CORPORA.BENIGN_DOCS

REPORT_SCHEMA = "ark-dlp-scoreboard-v1"
# Bump when prediction inputs change in a way the cache key does not see.
PREDICTION_VERSION = 1
TOLERANCE_PP = 0.5
# Families of the default-on entity groups; every other family is opt-in.
SECRET_FAMILIES = ("provider_secret", "generic_credential", "key_material")
CONTENT_FAMILIES = ("content_class", "document_class")
UNMAPPED = "(unmapped)"
# Everything that changes the native module, the Python package or the rule-to-entity map.
BUILD_PATHS = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust", "python", str(ENTITY_MAP))
# Prediction code of the head that runs against every build.
PREDICTOR_FILES = ("run_ark.py", "run_baselines.py", "scoreboard.py")
PROFILES = ("default", "extended")
# Component files scanned per profile; FP/MB on benign code is measured on what ships.
PROFILE_COMPONENTS = {"default": ("synthetic", "benign_code", "benign_docs"), "extended": ("synthetic", "benign_docs")}
NATIVE_LIB = "lib_patronus_ark.so"
NATIVE_MODULE = "_patronus_ark.abi3.so"
JOBS = 4
KEEP_BUILDS = 8  # most recently used builds kept in the cache
KEEP_PREDICTIONS_DAYS = 14  # cached predictions unused for longer are removed

Span = tuple[str, int, int]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# ── taxonomy ─────────────────────────────────────────────────────────────────


class Taxonomy(NamedTuple):
    """Group families and opt-in rules of one entity_map.yaml."""

    families: dict[str, str]
    opt_in_rules: tuple[str, ...]  # ARK rules of opt-in groups (off by default)
    opt_in_classes: tuple[str, ...]  # their entity ids
    content_classes: tuple[str, ...]  # entity ids scored per document

    def is_content(self, group: str) -> bool:
        return self.families.get(group) in CONTENT_FAMILIES

    def is_opt_in(self, group: str) -> bool:
        return group in self.families and self.families[group] not in SECRET_FAMILIES


def load_taxonomy(path: Path) -> Taxonomy:
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    families = {str(group): str((meta or {}).get("family", "")) for group, meta in (data.get("taxonomy") or {}).items()}
    entities = data.get("entities") or []
    opt_in = [e for e in entities if str(e.get("group", "")) in families and families[str(e["group"])] not in SECRET_FAMILIES]
    return Taxonomy(
        families=families,
        opt_in_rules=tuple(sorted({str(rule) for e in opt_in for rule in e.get("ark") or []})),
        opt_in_classes=tuple(sorted(str(e["id"]) for e in opt_in)),
        content_classes=tuple(sorted(str(e["id"]) for e in opt_in if families[str(e["group"])] in CONTENT_FAMILIES)),
    )


# ── metrics ──────────────────────────────────────────────────────────────────


def _ratio(count: int, total: int) -> float:
    return round(count / total, 6) if total else 0.0


def _prf(tp_precision: int, predicted: int, tp_recall: int, gold: int) -> dict[str, Any]:
    precision, recall = _ratio(tp_precision, predicted), _ratio(tp_recall, gold)
    f1 = round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0
    return {"tp": tp_recall, "precision": precision, "recall": recall, "f1": f1}


def _overlapping(spans: Iterable[Span], others: set[Span]) -> int:
    """How many of ``spans`` intersect a span of ``others`` in the same row."""
    by_row: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for row, start, end in others:
        by_row[row].append((start, end))
    return sum(any(start < o_end and o_start < end for o_start, o_end in by_row.get(row, ())) for row, start, end in spans)


def match(gold: set[Span], predicted: set[Span]) -> dict[str, Any]:
    """Exact and overlap P/R/F1 of predicted against gold spans (one row id per span)."""
    exact = len(gold & predicted)
    return {
        "gold": len(gold),
        "predicted": len(predicted),
        "exact": _prf(exact, len(predicted), exact, len(gold)),
        "overlap": _prf(_overlapping(predicted, gold), len(predicted), _overlapping(gold, predicted), len(gold)),
    }


def _span_groups(span: dict[str, Any]) -> list[str]:
    """Group labels of a predicted span: the engine label (ARK), else the mapped groups (baselines)."""
    if span.get("group"):
        return [str(span["group"])]
    return [str(group) for group in span.get("groups") or []] or [UNMAPPED]


def _index_predictions(rows: Iterable[dict[str, Any]] | None, known: set[str]) -> dict[str, list[dict[str, Any]]]:
    spans: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows or []:
        if row.get("id") not in known:
            raise ValueError(f"prediction for unknown row {row.get('id')!r}")
        spans[row["id"]].extend(row.get("evidence_spans") or [])
    return spans


def score_synthetic(
    rows: list[dict[str, Any]],
    predictions: Iterable[dict[str, Any]],
    taxonomy: Taxonomy,
    extended_predictions: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Span and document metrics on carrier rows.

    Value spans come from the default run plus the opt-in, non-content spans of the extended
    run; content classes are scored per document on the extended run only.
    """
    by_id = {row["id"]: row for row in rows}
    extended = None if extended_predictions is None else list(extended_predictions)
    spans = _index_predictions(predictions, set(by_id))
    for row_id, found in _index_predictions(extended, set(by_id)).items():
        spans[row_id].extend(s for s in found if all(taxonomy.is_opt_in(g) for g in _span_groups(s)))
    gold_groups: dict[str, set[Span]] = defaultdict(set)
    gold_entities: dict[str, set[Span]] = defaultdict(set)
    gold_rules: dict[Span, str] = {}
    gold_entity: dict[Span, str] = {}
    for row in rows:
        for entity in row.get("entities") or []:
            key = (row["id"], int(entity["start"]), int(entity["end"]))
            gold_groups[str(entity["label"])].add(key)
            gold_entities[str(entity["entity"])].add(key)
            gold_rules[key] = str(entity.get("rule_id", ""))
            gold_entity[key] = str(entity["entity"])
    pred_groups: dict[str, set[Span]] = defaultdict(set)
    pred_entities: dict[str, set[Span]] = defaultdict(set)
    pred_rules: dict[Span, set[str]] = defaultdict(set)
    pred_entity_sets: dict[Span, set[str]] = defaultdict(set)
    for row_id, found in spans.items():
        for span in found:
            groups = _span_groups(span)
            if any(taxonomy.is_content(group) for group in groups):
                continue  # content classes are scored per document
            key = (row_id, int(span["start_char"]), int(span["end_char"]))
            for group in groups:
                pred_groups[group].add(key)
            for entity in span.get("entities") or []:
                pred_entities[str(entity)].add(key)
                pred_entity_sets[key].add(str(entity))
            pred_rules[key].add(str(span.get("rule_id", "")))
    all_gold = set().union(*gold_groups.values()) if gold_groups else set()
    all_pred = set(pred_rules)

    providers = {}
    for entity in sorted(set(gold_entities) | set(pred_entities)):
        gold = gold_entities.get(entity, set())
        found = gold & all_pred
        attributed = sum(entity in pred_entity_sets[key] for key in found)
        rule_attributed = sum(gold_rules[key] in pred_rules[key] for key in found)
        providers[entity] = {
            **match(gold, pred_entities.get(entity, set())),
            "found": len(found),
            "attributed": attributed,
            "rule_attributed": rule_attributed,
            "attribution": _ratio(attributed, len(found)),
        }
    found_all = all_gold & all_pred
    attributed_all = sum(gold_entity[key] in pred_entity_sets[key] for key in found_all)

    negatives = [row for row in rows if row.get("case_type") == "hard_negative"]
    fp_spans = sorted(key for key in all_pred if by_id[key[0]].get("case_type") == "hard_negative")
    fp_rows = Counter(row_id for row_id, _, _ in fp_spans)

    def negative_stats(members: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "rows": len(members),
            "rows_with_fp": sum(row["id"] in fp_rows for row in members),
            "fp": sum(fp_rows[row["id"]] for row in members),
        }

    def negative_table(field_name: str) -> dict[str, dict[str, int]]:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in negatives:
            groups[str(row.get(field_name, ""))].append(row)
        return {name: negative_stats(members) for name, members in sorted(groups.items())}

    return {
        "rows": len(rows),
        "overall": match(all_gold, all_pred),
        "groups": {group: match(gold_groups.get(group, set()), pred_groups.get(group, set()))
                   for group in sorted(set(gold_groups) | set(pred_groups))},
        "providers": providers,
        "attribution": {
            "found": len(found_all),
            "attributed": attributed_all,
            "rule_attributed": sum(gold_rules[key] in pred_rules[key] for key in found_all),
            "rate": _ratio(attributed_all, len(found_all)),
        },
        "hard_negatives": {
            **negative_stats(negatives),
            "by_variant": negative_table("variant"),
            "by_language": negative_table("language"),
            "spans": [list(key) for key in fp_spans],
        },
        "documents": {} if extended is None else score_documents(rows, extended, taxonomy),
    }


def _classes(spans: Iterable[dict[str, Any]], keep) -> set[str]:
    """Entity ids (else ``group:<label>``) of the spans whose groups pass ``keep``."""
    classes: set[str] = set()
    for span in spans:
        groups = _span_groups(span)
        if any(keep(group) for group in groups):
            classes.update(str(entity) for entity in span.get("entities") or [])
            classes.update(f"group:{group}" for group in groups if not span.get("entities"))
    return classes


def score_documents(
    rows: list[dict[str, Any]], predictions: Iterable[dict[str, Any]], taxonomy: Taxonomy
) -> dict[str, dict[str, Any]]:
    """P/R/F1 per content class on document level: a row has a class if any span of it says so."""
    spans = _index_predictions(predictions, {row["id"] for row in rows})
    gold: dict[str, set[str]] = defaultdict(set)
    predicted: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        for label in row.get("content_labels") or []:
            gold[str(label)].add(row["id"])
        for label in _classes(spans.get(row["id"], ()), taxonomy.is_content):
            predicted[label].add(row["id"])
    report = {}
    for label in sorted(set(gold) | set(predicted) | set(taxonomy.content_classes)):
        tp = len(gold[label] & predicted[label])
        report[label] = {"gold": len(gold[label]), "predicted": len(predicted[label]),
                         **_prf(tp, len(predicted[label]), tp, len(gold[label]))}
    return report


def score_benign_docs(
    documents: dict[str, dict[str, Any]],
    predictions: Iterable[dict[str, Any]],
    taxonomy: Taxonomy,
    extended_predictions: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """FP report of the default run plus the opt-in spans and flagged documents per class of the extended run."""
    report: dict[str, Any] = {"default": BENIGN_DOCS.fp_report(documents, predictions)}
    if extended_predictions is not None:
        spans = _index_predictions(extended_predictions, set(documents))
        rows = [
            {"id": doc_id, "evidence_spans": [s for s in found if any(taxonomy.is_opt_in(g) for g in _span_groups(s))]}
            for doc_id, found in spans.items()
        ]
        flagged: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            for label in _classes(row["evidence_spans"], taxonomy.is_opt_in):
                flagged[label].add(row["id"])
        extended = BENIGN_DOCS.fp_report(documents, rows)
        extended["by_class"] = {
            label: {"documents_flagged": len(flagged[label]), "flagged_rate": _ratio(len(flagged[label]), len(documents))}
            for label in sorted(set(flagged) | set(taxonomy.opt_in_classes))
        }
        report["extended"] = extended
    return report


# ── corpora ──────────────────────────────────────────────────────────────────


class Split(NamedTuple):
    directory: Path
    name: str
    files: dict[str, list[Path]]  # component -> JSONL files
    carriers: list[dict[str, Any]]
    code: dict[str, dict[str, Any]]
    docs: dict[str, dict[str, Any]]
    sha256: str


def load_split(directory: Path) -> Split:
    """A frozen split written by prepare_corpora.py; refuses one that is missing or modified."""
    problems = CORPORA.check(directory)
    if problems:
        raise ValueError("; ".join(problems))
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    files = {
        name: [directory / entry["dir"] / file for file in sorted(entry["files"])]
        for name, entry in manifest["components"].items()
    }
    carriers = []
    for path in files["synthetic"]:
        carriers.extend(_read_jsonl(path))
    for row in carriers:  # the scoreboard never needs secret text
        row.pop("text", None)
        for entity in row.get("entities") or []:
            entity.pop("text", None)
    return Split(
        directory=directory,
        name=str(manifest.get("split", directory.name)),
        files=files,
        carriers=carriers,
        code=BENIGN_CODE.load_corpus(directory / "benign_code"),
        docs=BENIGN_DOCS.load_corpus(directory / "benign_docs"),
        sha256=sha256_bytes(manifest_bytes),
    )


def score_split(
    split: Split,
    predictions: Iterable[dict[str, Any]],
    taxonomy: Taxonomy,
    extended_predictions: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Report of one tool on one split; prediction rows of all components may be mixed."""
    parts: dict[str, dict[str, list[dict[str, Any]]]] = {profile: defaultdict(list) for profile in PROFILES}
    carrier_ids = {row["id"] for row in split.carriers}
    for profile, rows in (("default", predictions), ("extended", extended_predictions or [])):
        for row in rows:
            row_id = row.get("id")
            component = ("synthetic" if row_id in carrier_ids else "benign_code" if row_id in split.code
                         else "benign_docs" if row_id in split.docs else None)
            if component is None:
                raise ValueError(f"prediction for unknown row {row_id!r}")
            parts[profile][component].append(row)
    extended = parts["extended"] if extended_predictions is not None else None
    return {
        "schema": REPORT_SCHEMA,
        "split": split.name,
        "corpora_sha256": split.sha256,
        "opt_in_classes": list(taxonomy.opt_in_classes),
        "synthetic": score_synthetic(
            split.carriers, parts["default"]["synthetic"], taxonomy, None if extended is None else extended["synthetic"]
        ),
        "benign_code": BENIGN_CODE.fp_per_mb(split.code, parts["default"]["benign_code"]),
        "benign_docs": score_benign_docs(
            split.docs, parts["default"]["benign_docs"], taxonomy, None if extended is None else extended["benign_docs"]
        ),
    }


# ── comparison ───────────────────────────────────────────────────────────────


def _check(name: str, base: Any, head: Any, ok: bool, **extra: Any) -> dict[str, Any]:
    return {"check": name, "base": base, "head": head, "ok": bool(ok), **extra}


def _f1_check(name: str, base: float, head: float, gold: int, tolerance_pp: float) -> dict[str, Any]:
    delta = round((head - base) * 100, 4)
    return _check(name, base, head, delta >= -tolerance_pp - 1e-9, delta_pp=delta, gold=gold)


def compare(base: dict[str, Any], head: dict[str, Any], tolerance_pp: float = TOLERANCE_PP) -> list[dict[str, Any]]:
    """Checks of head against base on the same split; a check with ``ok: false`` is a regression."""
    checks = []
    b_syn, h_syn = base["synthetic"], head["synthetic"]
    for kind in ("exact", "overlap"):
        entries = [("overall", b_syn["overall"], h_syn["overall"])]
        entries += [(group, b_syn["groups"].get(group), metrics) for group, metrics in sorted(h_syn["groups"].items())]
        for name, b, h in entries:
            if h["gold"] == 0:
                continue  # no gold spans: precision only, reported but not gated
            b_f1 = b[kind]["f1"] if b else 0.0
            checks.append(_f1_check(f"f1.{kind}:{name}", b_f1, h[kind]["f1"], h["gold"], tolerance_pp))
    for label, h in sorted((h_syn.get("documents") or {}).items()):
        b = (b_syn.get("documents") or {}).get(label)
        if h["gold"]:
            checks.append(_f1_check(f"f1.document:{label}", b["f1"] if b else 0.0, h["f1"], h["gold"], tolerance_pp))
    b_fp, h_fp = base["benign_code"]["fp"], head["benign_code"]["fp"]
    checks.append(_check("fp:benign_code", b_fp, h_fp, h_fp <= b_fp,
                         fp_per_mb=[base["benign_code"]["fp_per_mb"], head["benign_code"]["fp_per_mb"]]))
    b_docs, h_docs = base["benign_docs"]["default"], head["benign_docs"]["default"]
    checks.append(_check("fp:benign_docs", b_docs["fp"], h_docs["fp"], h_docs["fp"] <= b_docs["fp"],
                         fp_per_mb=[b_docs["fp_per_mb"], h_docs["fp_per_mb"]]))
    base_classes = set(base.get("opt_in_classes") or [])
    b_flagged = ((base["benign_docs"].get("extended") or {}).get("by_class")) or {}
    for label, h in sorted((((head["benign_docs"].get("extended") or {}).get("by_class")) or {}).items()):
        if label not in base_classes:
            continue  # a new class has no base; its benign-document FP are reported only
        b = b_flagged.get(label, {}).get("documents_flagged", 0)
        checks.append(_check(f"flagged:benign_docs:{label}", b, h["documents_flagged"], h["documents_flagged"] <= b))
    old = {tuple(key) for key in b_syn["hard_negatives"]["spans"]}
    new = [key for key in h_syn["hard_negatives"]["spans"] if not _overlapping([tuple(key)], old)]
    checks.append(_check("hard_negatives:new_fp", len(old), len(h_syn["hard_negatives"]["spans"]), not new,
                         new=[list(key) for key in new]))
    return checks


# ── builds ───────────────────────────────────────────────────────────────────


class Build(NamedTuple):
    """A built ARK package: ``package`` is a directory to put first on ``sys.path``."""

    commit: str
    key: str
    package: Path
    entity_map: Path


def git(tree: Path, *args: str) -> bytes:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    result = subprocess.run(["git", "-C", str(tree), *args], capture_output=True, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def resolve_commit(tree: Path, rev: str) -> str:
    if not rev:
        raise ValueError("empty revision")
    return git(tree, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()


def build_key(tree: Path, commit: str) -> str:
    """SHA-256 over the blobs of BUILD_PATHS: unchanged detector sources share one build."""
    listing = git(tree, "ls-tree", "-r", "--full-tree", commit, "--", *BUILD_PATHS)
    return sha256_bytes(listing)


def extract_tree(tree: Path, commit: str, target: Path) -> None:
    """Replace ``target`` with the files of ``commit``, all with the current mtime."""
    data = git(tree, "archive", "--format=tar", commit)
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    now = time.time()
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = archive.getmembers()
        for member in members:
            member.mtime = now  # cargo fingerprints path dependencies by mtime
        archive.extractall(target, members=members, filter="data")


def _tail(path: Path, lines: int = 40) -> str:
    return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def ensure_build(tree: Path, commit: str, cache: Path) -> Build:
    """Build (or reuse) the release module of ``commit`` under ``cache/builds/<key>``.

    cargo runs ``--offline --locked`` with its own target directory in the cache; the crate
    registry and the ONNX Runtime download cache of the earlier gate steps are only read.
    """
    key = build_key(tree, commit)
    out = cache / "builds" / key
    package = out / "pkg"
    if (out / ".ready").is_file():
        (out / ".ready").touch()  # marks the build as used for prune()
        return Build(commit=commit, key=key, package=package, entity_map=out / "entity_map.yaml")
    src = cache / "src"
    extract_tree(tree, commit, src)
    env = {k: v for k, v in os.environ.items() if k not in ("CARGO_NET_OFFLINE", "ORT_SKIP_DOWNLOAD", "ORT_OFFLINE")}
    env.update({"CARGO_TARGET_DIR": str(cache / "target"), "PYO3_PYTHON": sys.executable})
    log = cache / "builds" / f"{key}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    cargo = shutil.which("cargo", path=env.get("PATH")) or "cargo"
    with log.open("wb") as handle:
        result = subprocess.run(
            [cargo, "build", "--release", "--locked", "--offline", "-p", "patronus-ark-python",
             "--manifest-path", str(src / "Cargo.toml")],
            cwd=src, env=env, stdout=handle, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
    if result.returncode != 0:
        raise RuntimeError(f"cargo build of {commit[:12]} failed (exit {result.returncode}):\n{_tail(log)}")
    tmp = cache / "builds" / f"{key}.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src / "python" / "patronus_ark", tmp / "pkg" / "patronus_ark",
                    ignore=shutil.ignore_patterns("__pycache__", "*.so"))
    shutil.copy2(cache / "target" / "release" / NATIVE_LIB, tmp / "pkg" / "patronus_ark" / NATIVE_MODULE)
    shutil.copy2(src / ENTITY_MAP, tmp / "entity_map.yaml")
    (tmp / "build.json").write_text(json.dumps({"commit": commit, "key": key}, indent=2) + "\n", encoding="utf-8")
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    (out / ".ready").write_text(key + "\n", encoding="utf-8")
    shutil.rmtree(src, ignore_errors=True)
    return Build(commit=commit, key=key, package=package, entity_map=out / "entity_map.yaml")


def predict_file(build: Build, source: Path, rules: list[str], output: Path) -> None:
    """Run run_ark.py (head code) with the module of ``build`` on one JSONL file."""
    cmd = [sys.executable, str(HERE / "scoreboard.py"), "_predict", "--package", str(build.package),
           "--entity-map", str(build.entity_map), "--input", str(source), "--output", str(output)]
    for rule in rules:
        cmd += ["--enable-rule", rule]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("PYTHONPATH", None)
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        # Errors name the input file but never echo its content.
        raise RuntimeError(f"run_ark on {source.name} with build {build.commit[:12]} failed (exit {result.returncode})")


def _predict_worker(package: Path, entity_map: Path, source: Path, output: Path, rules: list[str]) -> int:
    sys.path.insert(0, str(package))
    import patronus_ark

    if Path(patronus_ark.__file__).resolve().parent != (package / "patronus_ark").resolve():
        raise RuntimeError(f"patronus_ark resolved outside the build: {patronus_ark.__file__}")
    run_ark = _load_file("_ark_l1_dlp_run_ark", HERE / "run_ark.py")
    meta = output.with_name(output.stem + ".meta.json")
    run_ark.run(source, output, meta, enabled_rules=rules, entity_map_path=entity_map)
    return 0


class Job(NamedTuple):
    build: Build
    component: str
    source: Path
    profile: str
    rules: list[str]
    key: str
    path: Path


def _predictor_sha() -> str:
    return sha256_bytes(b"".join(sha256_bytes((HERE / name).read_bytes()).encode() for name in PREDICTOR_FILES))


def plan_jobs(build: Build, split: Split, taxonomy: Taxonomy, cache: Path, input_shas: dict[Path, str]) -> list[Job]:
    jobs = []
    predictor = _predictor_sha()
    for profile in PROFILES:
        rules = list(taxonomy.opt_in_rules) if profile == "extended" else []
        for component in PROFILE_COMPONENTS[profile]:
            for source in split.files[component]:
                key = sha256_bytes(json.dumps(
                    [PREDICTION_VERSION, build.key, predictor, rules, input_shas[source]]).encode())
                jobs.append(Job(build, component, source, profile, rules, key, cache / "predictions" / f"{key}.jsonl"))
    return jobs


def run_jobs(jobs: list[Job], workers: int) -> None:
    """Predict every job whose output is not cached yet; identical keys run once."""
    todo = {job.key: job for job in jobs if not job.path.is_file()}
    for job in jobs:
        if job.key not in todo:
            job.path.touch()  # marks the cached prediction as used for prune()

    def one(job: Job) -> None:
        job.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = job.path.with_name(job.key + ".part.jsonl")
        predict_file(job.build, job.source, job.rules, tmp)
        tmp.replace(job.path)
        tmp.with_name(tmp.stem + ".meta.json").unlink(missing_ok=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for future in [pool.submit(one, job) for job in todo.values()]:
            future.result()


def load_predictions(jobs: list[Job]) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {profile: [] for profile in PROFILES}
    for job in jobs:
        rows[job.profile].extend(_read_jsonl(job.path))
    return rows


def prune(cache: Path, keep: Iterable[str], now: float | None = None) -> None:
    """Drop all but the KEEP_BUILDS most recently used builds and stale predictions."""
    now = time.time() if now is None else now
    keep = set(keep)
    builds = sorted(
        (path for path in (cache / "builds").glob("*/.ready")), key=lambda path: path.stat().st_mtime, reverse=True
    )
    for ready in builds[KEEP_BUILDS:]:
        if ready.parent.name not in keep:
            shutil.rmtree(ready.parent, ignore_errors=True)
            (cache / "builds" / f"{ready.parent.name}.log").unlink(missing_ok=True)
    for path in (cache / "predictions").glob("*.jsonl"):
        if now - path.stat().st_mtime > KEEP_PREDICTIONS_DAYS * 86400:
            path.unlink(missing_ok=True)


# ── output ───────────────────────────────────────────────────────────────────


def _pct(value: float) -> str:
    return f"{value * 100:5.1f}"


def summary_lines(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    """Human-readable dev summary: F1 per group and content class, attribution, changed providers."""
    lines = [f"{'group':<36} {'gold':>5}  exact F1 base→head   overlap F1 base→head"]
    b_groups = base["synthetic"]["groups"]
    entries = [("(all)", base["synthetic"]["overall"], head["synthetic"]["overall"])]
    entries += [(g, b_groups.get(g), m) for g, m in head["synthetic"]["groups"].items() if m["gold"]]
    for name, b, h in entries:
        b = b or {"exact": {"f1": 0.0}, "overlap": {"f1": 0.0}}
        lines.append(f"{name:<36} {h['gold']:>5}  {_pct(b['exact']['f1'])} → {_pct(h['exact']['f1'])}"
                     f"        {_pct(b['overlap']['f1'])} → {_pct(h['overlap']['f1'])}")
    for label, h in head["synthetic"]["documents"].items():
        if h["gold"]:
            b = base["synthetic"]["documents"].get(label, {"f1": 0.0})
            lines.append(f"{'doc ' + label:<36} {h['gold']:>5}  {_pct(b['f1'])} → {_pct(h['f1'])}")
    b_att, h_att = base["synthetic"]["attribution"], head["synthetic"]["attribution"]
    lines.append(f"attribution: {_pct(b_att['rate'])} → {_pct(h_att['rate'])} % of exactly found values")
    changed = [
        (entity, base["synthetic"]["providers"].get(entity, {}).get("exact", {}).get("f1", 0.0), m["exact"]["f1"])
        for entity, m in head["synthetic"]["providers"].items() if m["gold"]
    ]
    changed = [item for item in changed if item[1] != item[2]]
    for entity, b_f1, h_f1 in changed[:20]:
        lines.append(f"provider {entity:<40} exact F1 {_pct(b_f1)} → {_pct(h_f1)}")
    if len(changed) > 20:
        lines.append(f"… {len(changed) - 20} more providers changed")
    return lines


def verdict_lines(split: str, base: dict[str, Any], head: dict[str, Any], checks: list[dict[str, Any]]) -> list[str]:
    failed = [check for check in checks if not check["ok"]]
    b_code, h_code = base["benign_code"], head["benign_code"]
    b_docs, h_docs = base["benign_docs"]["default"], head["benign_docs"]["default"]
    b_hn, h_hn = base["synthetic"]["hard_negatives"], head["synthetic"]["hard_negatives"]
    lines = [
        f"{split}: F1 exact {_pct(base['synthetic']['overall']['exact']['f1'])} → "
        f"{_pct(head['synthetic']['overall']['exact']['f1'])}, overlap "
        f"{_pct(base['synthetic']['overall']['overlap']['f1'])} → {_pct(head['synthetic']['overall']['overlap']['f1'])}",
        f"{split}: FP/MB benign code {b_code['fp_per_mb']} → {h_code['fp_per_mb']} ({b_code['fp']} → {h_code['fp']} FP), "
        f"benign docs {b_docs['fp_per_mb']} → {h_docs['fp_per_mb']}",
        f"{split}: hard-negative FP {b_hn['fp']} → {h_hn['fp']} on {h_hn['rows']} rows",
    ]
    for check in failed:
        detail = f" ({check['delta_pp']:+.2f} pp, gold {check['gold']})" if "delta_pp" in check else ""
        new = f", new: {len(check['new'])}" if check.get("new") else ""
        lines.append(f"{split}: REGRESSION {check['check']}: {check['base']} → {check['head']}{detail}{new}")
    lines.append(f"{split}: {'regression' if failed else 'no regression'} ({len(checks)} checks)")
    return lines


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


# ── commands ─────────────────────────────────────────────────────────────────


def gate(head_tree: Path, base_sha: str, dev: Path, holdout: Path | None, cache: Path, jobs: int = JOBS) -> int:
    head_tree = head_tree.resolve()
    head_commit = resolve_commit(head_tree, "HEAD")
    base_commit = resolve_commit(head_tree, base_sha)
    if git(head_tree, "status", "--porcelain", "--untracked-files=no").strip():
        print("note: uncommitted changes in --head are not scored (the gate builds the commit)", file=sys.stderr)
    cache = cache.resolve() / "scoreboard"
    splits = [("dev", load_split(dev))] + ([("holdout", load_split(holdout))] if holdout is not None else [])
    builds = {"base": ensure_build(head_tree, base_commit, cache), "head": ensure_build(head_tree, head_commit, cache)}
    taxonomies = {name: load_taxonomy(build.entity_map) for name, build in builds.items()}
    planned: dict[tuple[str, str], list[Job]] = {}
    for split_name, split in splits:
        input_shas = {path: sha256_bytes(path.read_bytes()) for paths in split.files.values() for path in paths}
        for name, build in builds.items():
            planned[(split_name, name)] = plan_jobs(build, split, taxonomies[name], cache, input_shas)
    run_jobs([job for group in planned.values() for job in group], jobs)
    prune(cache, {build.key for build in builds.values()})

    report_dir = cache / "reports" / f"{head_commit[:12]}-{base_commit[:12]}"
    failed_any = False
    output: list[str] = [f"scoreboard: head {head_commit[:12]} (build {builds['head'].key[:12]}) vs base "
                         f"{base_commit[:12]} (build {builds['base'].key[:12]})"]
    for split_name, split in splits:
        reports = {}
        for name in builds:
            predictions = load_predictions(planned[(split_name, name)])
            # Both sides are scored with the head taxonomy; extended runs used each build's own rules.
            reports[name] = score_split(split, predictions["default"], taxonomies["head"], predictions["extended"])
            reports[name]["opt_in_classes"] = list(taxonomies[name].opt_in_classes)
            reports[name]["build"] = {"commit": builds[name].commit, "key": builds[name].key}
        checks = compare(reports["base"], reports["head"])
        failed = [check for check in checks if not check["ok"]]
        failed_any = failed_any or bool(failed)
        _write_json(report_dir / f"{split_name}.json",
                    {"schema": REPORT_SCHEMA, "split": split_name, "base": reports["base"], "head": reports["head"],
                     "checks": checks, "tolerance_pp": TOLERANCE_PP})
        if split_name == "dev":
            output += summary_lines(reports["base"], reports["head"])
            output += verdict_lines("dev", reports["base"], reports["head"], checks)
        else:
            # The holdout leaves the sandbox only as a verdict.
            output.append(f"{split_name}: {'regression' if failed else 'no regression'}")
    output.append(f"scoreboard: {'FAIL' if failed_any else 'PASS'}")
    print("\n".join(output))
    return 1 if failed_any else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    g = commands.add_parser("gate", help="build head and base, score dev (+ holdout), exit 1 on regression")
    g.add_argument("--head", type=Path, required=True, help="git checkout of the head commit")
    g.add_argument("--base-sha", required=True, help="base commit (any revision the head checkout knows)")
    g.add_argument("--dev", type=Path, required=True, help="dev corpora (prepare_corpora.py)")
    g.add_argument("--holdout", type=Path, help="holdout corpora; reported as a verdict only")
    g.add_argument("--cache", type=Path, required=True, help="builds, predictions and reports")
    g.add_argument("--jobs", type=int, default=JOBS, help=f"parallel prediction processes (default {JOBS})")
    s = commands.add_parser("score", help="score one tool's predictions on one split")
    s.add_argument("--split", type=Path, required=True, help="corpora directory (prepare_corpora.py)")
    s.add_argument("--predictions", type=Path, required=True, help="JSONL with id and evidence_spans")
    s.add_argument("--extended-predictions", type=Path, help="predictions with every opt-in rule switched on")
    s.add_argument("--entity-map", type=Path, default=ROOT / ENTITY_MAP, help="entity_map.yaml for group families")
    s.add_argument("--output", type=Path, help="write the JSON report here instead of stdout")
    c = commands.add_parser("compare", help="compare two score reports of the same split")
    c.add_argument("--base", type=Path, required=True)
    c.add_argument("--head", type=Path, required=True)
    c.add_argument("--tolerance-pp", type=float, default=TOLERANCE_PP)
    p = commands.add_parser("_predict", help=argparse.SUPPRESS)
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--entity-map", type=Path, required=True)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--enable-rule", action="append", default=[])
    args = parser.parse_args(argv)

    try:
        if args.command == "gate":
            return gate(args.head, args.base_sha, args.dev, args.holdout, args.cache, args.jobs)
        if args.command == "score":
            split = load_split(args.split)
            extended = _read_jsonl(args.extended_predictions) if args.extended_predictions else None
            report = score_split(split, _read_jsonl(args.predictions), load_taxonomy(args.entity_map), extended)
            if args.output:
                _write_json(args.output, report)
            else:
                print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
            return 0
        if args.command == "compare":
            base = json.loads(args.base.read_text(encoding="utf-8"))
            head = json.loads(args.head.read_text(encoding="utf-8"))
            checks = compare(base, head, args.tolerance_pp)
            print("\n".join(verdict_lines(str(head.get("split", "split")), base, head, checks)))
            return 1 if any(not check["ok"] for check in checks) else 0
        return _predict_worker(args.package, args.entity_map, args.input, args.output, args.enable_rule)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"scoreboard: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
