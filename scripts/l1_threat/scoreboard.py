#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Threat scoreboard: score ark-core (and cached baselines) on frozen corpora and gate a head against its base.

Inputs are split roots: every subdirectory with a frozen ``manifest.json`` (``prepare_corpora.py``
corpora, ``generators.py`` output) counts, e.g. ``DEV/{train_dev,report,generated,translated}`` or
``HOLDOUT/{holdout,generated}``. Every row is a positive of the classes in ``classes`` (reported-only
classes do not count) and a negative of every class when ``benign``. Sets with the role ``report``
are scored in their own scope and never gate.

Predictions come from ark-core alone: the ``threat_cascade`` example of ``patronus-ark-core`` scans
every row once for the eleven attack classes with the Core scanner and a cascade config (``--cascade
CONFIG``, a JSON file whose ``scanner`` key is a ``ScannerConfig``). The layers are a cascade: the
L1 heuristic, then the L1 model, then L3 (Wolf Defender for ``instruction_injection``, at its default
threshold unless the config sets one), each later layer only on what the earlier ones left undecided;
without a later layer, undecided is clear. L2 is ARK-only and not measured here. Without
``--cascade`` the config is ``L1_CASCADE`` (L1 only), the gated stack. Per row and class the
prediction holds the L1 score curve (``scores``: the confidence of a flagged native result and the
scorer values below the decision; 0 when there is none), the classes L1 detected (``flagged``), the
cascade's answer (``cascade``: L1 outcome, the L1 score the clear threshold compares, final decision,
deciding stage), Wolf's probability where Wolf ran and the milliseconds per stage.

L1 score curve (``score``, ``report``, the gate), per class, language (``all``, ``de``, ``en``) and
origin (``all``, ``native``, ``translated``; runner translations and the German part of a set marked
``translated`` in the entity map, as in ``generators.py``):

- TPR at matched document FPR 1 % and 0.1 % on the benign rows (lowest threshold whose FPR is within
  the target, ``run_baselines.matched_fpr``), each with a seeded percentile bootstrap 95 % CI
  (positives and negatives resampled, threshold re-chosen in every replicate);
- AUPRC (average precision of the class positives against the benign rows);
- hard-benign FPR at the same matched threshold as each TPR: benign look-alike twins (``twin_of``) and
  the benign rows of the security-adjacent sets in ``HARD_BENIGN_SETS``;
- leave-one-dataset-out (``language: all``, ``origin: all``): TPR@1 % with each contributing set left
  out, and the lowest of them;
- obfuscation invariance: per obfuscation kind of the generated slices, the attack rows whose clean
  source row is flagged and how many of them stay flagged obfuscated (reported, not gated).

``report --cascade CONFIG`` renders the cascade report instead: per class and language at the
configured operating point TPR, FPR on the benign rows and hard-benign FPR at the same decision (per
benign source), the share of rows each stage decided and the share L1 escalated, latency per stage
(p50/p95; L3 only on the rows it ran, with its share and mean cost per row), the L1 score curve
next to it, and the ``harmful_content`` positives per hazard subclass (``harmful_subclass.py`` label file):
TPR of the decision, subclasses below 20 positives in a language marked ``gap``, model-only
subclasses below 50 % TPR marked ``off``; ``--counts-only`` leaves
only row counts (the form of the owner's holdout run).

``calibrate`` reads predictions of the gated benign rows (the dev benign pool incl. the hard
benigns; rows of ``--exclude-ids``, e.g. a model's train negatives, are left out) and writes a
cascade config: per class ``cascade.modules.<category>.detect_threshold`` at ``--target-fpr`` (0.1 %)
and ``clear_threshold`` at ``--clear-fpr`` (1 %), both on the cascade's L1 score (``--no-clear``: off,
every undetected row escalates). It never changes ark-core defaults.

``gate`` builds the predictor of the head and the base commit (offline, cached per ark-core
sources), predicts every split with both on the L1 cascade and fails on a regression in the gated
scope: TPR@1 % or TPR@0.1 % of a class (``all``, ``de``, ``en``; origin ``all``) more than 0.5 pp
below the base, or a hard-benign row of a class that the head's L1 detects and the base's does not, unless
the class's head hard-benign FPR (its flags over the hard-benign rows of its ``all``/``all`` cell) stays
within 0.1 % and none of its TPR checks fails; the check line names the head FPR and the budget. The
benign FPR of L1 at its detect cut (benign rows it flags) must stay within 0.1 % per class and language
(``all``, ``de``, ``en``); an overrun the base already has and the head does not raise passes but is named
(``OVER``) in the verdict.
stdout carries the dev numbers as a Markdown table (both TPRs, base -> head with the head's CI); the
holdout leaves as a verdict and the names of failing checks only, its report stays in the cache.
Latency is gated by the runner's own A/B step (``latency.py``). Exit 0 = pass, 1 = regression,
2 = error.

``refresh`` keeps the scoreboard of main current: in a checkout of main it builds the predictor of
HEAD and re-renders ``research/l1-threat/scoreboard/baseline.md`` from the dev split (and
``cascade.md`` when the checkout holds the calibrated ``cascade-config.json``), with a line naming the
commit and a line naming its inputs (the dev split's set hashes, for baseline.md also the cached
baseline predictions). ``--since`` (the commit of the last render) skips the run when no detector,
scorer or gold path (``REFRESH_PATHS``) changed and every report names the current inputs, so a
re-frozen dev split re-renders on its own; a report whose numbers did not change stays as it is. The runner commits
what it rewrote as a follow-up PR after each merge.

    python3 scripts/l1_threat/scoreboard.py predict --split DIR --out PRED_DIR [--cascade CONFIG] [--predictor BIN]
    python3 scripts/l1_threat/scoreboard.py score --split DIR --predictions PRED_DIR [--output REPORT]
    python3 scripts/l1_threat/scoreboard.py compare --base REPORT --head REPORT
    python3 scripts/l1_threat/scoreboard.py report --split DIR --predictions PRED_DIR \\
        [--baseline-cache CACHE] --out research/l1-threat/scoreboard/baseline.md
    python3 scripts/l1_threat/scoreboard.py report --cascade CONFIG [--counts-only] --split DIR \\
        --predictions PRED_DIR --out research/l1-threat/scoreboard/cascade.md
    python3 scripts/l1_threat/scoreboard.py calibrate --split DIR --predictions PRED_DIR [--cascade BASE] \\
        [--target-fpr 0.001] [--clear-fpr 0.01 | --no-clear] [--exclude-ids FILE] --out CONFIG
    python3 scripts/l1_threat/scoreboard.py gate --head WT --base-sha SHA --dev DIR [--holdout DIR] --cache DIR
    python3 scripts/l1_threat/scoreboard.py refresh [--tree MAIN] [--since SHA] --dev DIR --cache DIR \\
        [--baseline-cache CACHE]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import math
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, NamedTuple

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
def _load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BASELINES = sys.modules.get("_ark_l1_threat_run_baselines") or _load_file(
    "_ark_l1_threat_run_baselines", HERE / "run_baselines.py")
CORPORA = BASELINES.prepare_corpora
GENERATORS = BASELINES.generators
CLASSES = tuple(CORPORA.taxonomy.CLASSES)
DLP_SCOREBOARD = sys.modules.get("_ark_l1_dlp_scoreboard") or _load_file(
    "_ark_l1_dlp_scoreboard", ROOT / "scripts" / "l1_dlp" / "scoreboard.py")
HARMFUL_SUBCLASS = sys.modules.get("_ark_l1_threat_harmful_subclass") or _load_file(
    "_ark_l1_threat_harmful_subclass", HERE / "harmful_subclass.py")
MIX = sys.modules.get("_ark_l1_threat_mix") or _load_file("_ark_l1_threat_mix", HERE / "mix.py")

REPORT_SCHEMA = "ark-l1-threat-scoreboard-v3"
CASCADE_SCHEMA = "ark-l1-threat-cascade-v1"
FPRS = (0.01, 0.001)
# Report keys of the gated operating points; both gate with the same tolerance, 1 % first.
GATE_FPRS = tuple(f"{fpr:g}" for fpr in FPRS)
HARD_BENIGN_FPR_BUDGET = 0.001
# Benign FPR of L1 at its detect cut, per class and language.
BENIGN_FPR_BUDGET = 0.001
GATE_LANGUAGES = ("all", "de", "en")
LANGUAGES = ("all", "de", "en")
ORIGINS = ("all", "native", "translated")
TOLERANCE_PP = 0.5
BOOTSTRAP = 200
BOOTSTRAP_SEED = 20261114
# Benign sets of security-adjacent text (trigger words, seemingly harmful prompts, jailbreak-shaped
# prompts without harmful intent, harmless requests that sound risky, hard-negative goldens); together with the generated look-alike twins
# they make up the hard-benign pool.
HARD_BENIGN_SETS = frozenset({"notinject", "or_bench_hard", "xstest", "wildjailbreak", "wildguardmix", "l1_goldens",
                              "trigger_negatives"})
JOBS = 4
# The Core predictor: an example of patronus-ark-core, built from these sources.
PREDICTOR = "threat_cascade"
PREDICTOR_SOURCES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "ark-core")
# The gated stack: L1 only, so whatever L1 does not detect is clear.
L1_CASCADE = {"scanner": {"max_level": "l1", "cascade": {}}}
# The cascade config a prediction directory was made with.
CONFIG_FILE = "cascade.json"
# Stages that decide a module, in cascade order (L2 is ARK-only).
STAGES = ("heuristic", "l1_model", "l3")
TARGET_FPR = 0.001
CLEAR_FPR = 0.01
# The scoreboard of main, relative to a checkout: `refresh` re-renders its reports there.
SCOREBOARD_DIR = Path("research/l1-threat/scoreboard")
# The calibrated cascade config of main (`calibrate` output); with it `refresh` renders cascade.md too.
CASCADE_CONFIG = SCOREBOARD_DIR / "cascade-config.json"
# What changes the numbers of main: the Core detectors and scorers, the scoreboard and corpus tooling,
# the gold labels and the calibrated cascade config.
REFRESH_PATHS = (*PREDICTOR_SOURCES, "scripts/l1_threat", "research/l1-threat/entity_map.yaml",
                 "research/l1-threat/labels", str(SCOREBOARD_DIR / "gold-dev.json"),
                 str(SCOREBOARD_DIR / "gold-leakage.json"), str(CASCADE_CONFIG))
# The line naming the commit a refreshed report was rendered from; the only line a refresh may leave stale.
RENDERED_FROM = "Rendered by `scoreboard.py refresh` from commit"
# The line naming the fingerprint of what a refreshed report read besides the code: the dev split (and the
# baseline cache); a re-frozen split or new cached baselines re-render a report even when main's code did not change.
RENDERED_INPUTS = "Inputs (dev split set hashes, cached baseline predictions):"


def category(cls: str) -> str:
    """The Core category that scans a class; ``instruction_injection`` keeps the name ``injection``."""
    return "injection" if cls == "instruction_injection" else cls


# ── corpora ──────────────────────────────────────────────────────────────────


class SetFile(NamedTuple):
    set_id: str
    path: Path
    sha256: str
    role: str


def split_sets(root: Path) -> list[SetFile]:
    """Every set of every frozen corpus or generated directory directly under ``root`` (or ``root`` itself)."""
    dirs = [root] if (root / "manifest.json").is_file() else sorted(
        d for d in root.iterdir() if d.is_dir() and (d / "manifest.json").is_file())
    if not dirs:
        raise ValueError(f"{root}: no frozen corpus directory")
    found: list[SetFile] = []
    for directory in dirs:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        for set_id, path, sha in BASELINES.corpus_sets(directory):
            found.append(SetFile(set_id, path, sha, manifest["sets"][set_id].get("role", "dev")))
    ids = [s.set_id for s in found]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{root}: a set id appears in two directories")
    return found


def is_hard_benign(row: dict[str, Any]) -> bool:
    return bool(row["benign"]) and (bool(row.get("twin_of")) or row["dataset"] in HARD_BENIGN_SETS)


# ── Core predictions ─────────────────────────────────────────────────────────


def load_config(path: Path | None) -> dict[str, Any]:
    """The cascade config of ``path``; ``L1_CASCADE`` without one."""
    if path is None:
        return copy.deepcopy(L1_CASCADE)
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("scanner", {}), dict):
        raise ValueError(f"{path}: a cascade config is an object with a `scanner` object")
    return config


def config_hash(config: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON of a cascade config."""
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def needs_wolf(config: dict[str, Any]) -> bool:
    """Whether the predictor must be built with Wolf (the config configures the injection L3)."""
    return config.get("scanner", {}).get("wolf") is not None


class Predictor(NamedTuple):
    """A built ``threat_cascade`` example of one commit."""

    commit: str
    key: str
    binary: Path


def predictor_key(tree: Path, commit: str, wolf: bool) -> str:
    """SHA-256 over the blobs of ``PREDICTOR_SOURCES`` and the feature set: unchanged Core sources share one build."""
    listing = DLP_SCOREBOARD.git(tree, "ls-tree", "-r", "--full-tree", commit, "--", *PREDICTOR_SOURCES)
    return DLP_SCOREBOARD.sha256_bytes(listing + (b"features=wolf" if wolf else b""))


def _cargo_build(manifest: Path, target: Path, wolf: bool, log: Path, offline: bool) -> Path:
    env = {k: v for k, v in os.environ.items() if k not in ("CARGO_NET_OFFLINE", "ORT_SKIP_DOWNLOAD", "ORT_OFFLINE")}
    env["CARGO_TARGET_DIR"] = str(target)
    cmd = [shutil.which("cargo", path=env.get("PATH")) or "cargo", "build", "--release", "-p", "patronus-ark-core",
           "--example", PREDICTOR, "--manifest-path", str(manifest)]
    cmd += ["--locked", "--offline"] if offline else []
    cmd += ["--features", "wolf"] if wolf else []
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as handle:
        result = subprocess.run(cmd, cwd=manifest.parent, env=env, stdout=handle, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        raise RuntimeError(f"cargo build of {PREDICTOR} failed (exit {result.returncode}):\n{DLP_SCOREBOARD._tail(log)}")
    return target / "release" / "examples" / PREDICTOR


def ensure_predictor(tree: Path, commit: str, cache: Path, wolf: bool = False) -> Predictor:
    """Build (or reuse) the predictor of ``commit`` under ``cache/builds/<key>``.

    cargo runs ``--offline --locked`` with its own target directory in the cache; the crate registry
    and the ONNX Runtime download cache of the earlier gate steps are only read.
    """
    key = predictor_key(tree, commit, wolf)
    out = cache / "builds" / key
    if (out / ".ready").is_file():
        (out / ".ready").touch()  # marks the build as used for prune()
        return Predictor(commit, key, out / PREDICTOR)
    src = cache / "src"
    DLP_SCOREBOARD.extract_tree(tree, commit, src)
    if not (src / "ark-core" / "examples" / f"{PREDICTOR}.rs").is_file():
        raise RuntimeError(f"commit {commit[:12]} has no ark-core {PREDICTOR} example; base the head on a newer commit")
    built = _cargo_build(src / "Cargo.toml", cache / "target", wolf, cache / "builds" / f"{key}.log", offline=True)
    tmp = cache / "builds" / f"{key}.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    shutil.copy2(built, tmp / PREDICTOR)
    (tmp / "build.json").write_text(json.dumps({"commit": commit, "key": key, "wolf": wolf}, indent=2) + "\n",
                                    encoding="utf-8")
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    (out / ".ready").write_text(key + "\n", encoding="utf-8")
    shutil.rmtree(src, ignore_errors=True)
    return Predictor(commit, key, out / PREDICTOR)


def build_local_predictor(config: dict[str, Any]) -> Path:
    """The predictor of this checkout (``cargo build --release``, Wolf when the config needs it)."""
    target = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")
    return _cargo_build(ROOT / "Cargo.toml", target, needs_wolf(config), target / f"{PREDICTOR}-build.log",
                        offline=False)


def prediction_path(out: Path, entry: SetFile) -> Path:
    return out / f"{entry.set_id}-{entry.sha256[:12]}.jsonl"


def bind_config(out: Path, config: dict[str, Any]) -> Path:
    """Record ``config`` as the cascade config of the prediction directory ``out``; refuse another one."""
    out.mkdir(parents=True, exist_ok=True)
    path = out / CONFIG_FILE
    if path.is_file():
        if config_hash(load_config(path)) != config_hash(config):
            raise ValueError(f"{out}: predictions of another cascade config; use a new directory")
    else:
        path.write_text(json.dumps(config, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def predict_split(sets: list[SetFile], out: Path, binary: Path, config: dict[str, Any], jobs: int = JOBS) -> None:
    """Predict every set not yet in ``out`` with the Core predictor; each set runs in its own process."""
    config_path = bind_config(out, config)

    def one(entry: SetFile) -> None:
        target = prediction_path(out, entry)
        part = target.with_suffix(".part")
        with entry.path.open("rb") as rows, part.open("wb") as predictions:
            result = subprocess.run([str(binary), str(config_path)], stdin=rows, stdout=predictions,
                                    stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            # Errors name the set but never echo corpus text.
            raise RuntimeError(f"Core prediction of {entry.set_id} failed (exit {result.returncode})")
        part.replace(target)

    todo = [entry for entry in sets if not prediction_path(out, entry).is_file()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for future in [pool.submit(one, entry) for entry in todo]:
            future.result()


def load_pairs(sets: list[SetFile], predictions: dict[str, Path]) -> list[tuple[dict[str, Any], dict[str, Any], str]]:
    """``(row, prediction, role)`` of every row with its provenance (``generators.is_translated``); a set
    without predictions is an error."""
    translated = GENERATORS.translated_sets(CORPORA.entity_map.load())
    pairs = []
    for entry in sets:
        path = predictions.get(entry.set_id)
        if path is None:
            raise ValueError(f"no predictions for set {entry.set_id}")
        preds = {p["id"]: p for p in BASELINES.read_rows(path)}
        for row in BASELINES.read_rows(entry.path):
            if row["id"] not in preds:
                raise ValueError(f"set {entry.set_id}: no prediction for row {row['id']}")
            pairs.append(({**row, "translated": GENERATORS.is_translated(row, translated)}, preds[row["id"]], entry.role))
    return pairs


def core_predictions(sets: list[SetFile], out: Path) -> dict[str, Path]:
    return {entry.set_id: prediction_path(out, entry) for entry in sets if prediction_path(out, entry).is_file()}


# ── metrics ──────────────────────────────────────────────────────────────────


def _max_fp(negatives: int, target: float) -> int:
    """Largest ``k`` with ``k / negatives <= target`` (the same comparison as ``matched_fpr``)."""
    k = int(target * negatives)
    while (k + 1) / negatives <= target:
        k += 1
    while k > 0 and k / negatives > target:
        k -= 1
    return k


def tpr_at_fpr(pos: np.ndarray, neg: np.ndarray, target: float) -> np.ndarray:
    """Vectorised ``matched_fpr`` TPR over replicate rows (``pos``: R x P, ``neg``: R x N).

    The matched threshold is the smallest candidate score above the ``k+1``-th highest negative
    (``k`` = most false positives within the target) and above 0, so a positive is caught exactly
    when its score exceeds that negative and 0.
    """
    k = _max_fp(neg.shape[1], target)
    if k >= neg.shape[1]:
        cut = np.zeros(neg.shape[0])
    else:
        cut = np.maximum(-np.partition(-neg, k, axis=1)[:, k], 0.0)
    return (pos > cut[:, None]).mean(axis=1)


def bootstrap_ci(pos: list[float], neg: list[float], target: float, rounds: int = BOOTSTRAP,
                 seed: int = BOOTSTRAP_SEED) -> list[float] | None:
    """Percentile 95 % CI of TPR at matched FPR; positives and negatives are resampled separately."""
    if not pos or not neg:
        return None
    rng = np.random.default_rng(seed)
    p, n = np.asarray(pos, dtype=float), np.asarray(neg, dtype=float)
    tprs = np.concatenate([
        tpr_at_fpr(p[rng.integers(0, len(p), (chunk, len(p)))], n[rng.integers(0, len(n), (chunk, len(n)))], target)
        for chunk in _chunks(rounds, max(1, 2_000_000 // max(len(n), 1)))])
    low, high = np.percentile(tprs, [2.5, 97.5])
    return [round(float(low), 6), round(float(high), 6)]


def _chunks(total: int, size: int) -> list[int]:
    return [min(size, total - start) for start in range(0, total, size)]


def average_precision(pos: list[float], neg: list[float]) -> float | None:
    """Area under the precision-recall step curve (ties form one step), as scikit-learn computes it."""
    if not pos or not neg:
        return None
    scores = np.asarray([*pos, *neg], dtype=float)
    labels = np.asarray([1] * len(pos) + [0] * len(neg))
    order = np.argsort(-scores, kind="stable")
    scores, labels = scores[order], labels[order]
    last = np.r_[np.flatnonzero(np.diff(scores)), len(scores) - 1]
    tp = np.cumsum(labels)[last]
    precision = tp / (last + 1)
    recall = tp / len(pos)
    return round(float(np.sum(np.diff(np.r_[0.0, recall]) * precision)), 6)


def cell_metrics(pos: list[float], neg: list[float], hard: list[float], bootstrap: bool = True) -> dict[str, Any]:
    """Matched-FPR TPRs, AUPRC, bootstrap CI of each TPR and, at each matched threshold, the hard-benign FPR
    (``hard``: the scores of the cell's hard-benign rows)."""
    out: dict[str, Any] = {"positives": len(pos), "negatives": len(neg)}
    hard_benign: dict[str, Any] = {"rows": len(hard)}
    for fpr in FPRS:
        cell = BASELINES.matched_fpr(pos, neg, fpr)
        out[f"{fpr:g}"] = None if cell is None else {k: cell[k] for k in ("threshold", "tpr", "fpr", "tp", "fp")}
        threshold = None if cell is None else cell["threshold"]
        fp = 0 if threshold is None else sum(score >= threshold for score in hard)
        hard_benign[f"{fpr:g}"] = {"fp": fp, "fpr": fp / len(hard) if hard else None}
    out["auprc"] = average_precision(pos, neg)
    if bootstrap:
        out["tpr_ci95"] = {f"{fpr:g}": bootstrap_ci(pos, neg, fpr) for fpr in FPRS}
    out["hard_benign"] = hard_benign
    return out


def score_pairs(pairs: list[tuple[dict[str, Any], dict[str, Any], str]], classes: Iterable[str] = CLASSES,
                bootstrap: bool = True) -> dict[str, Any]:
    """Scores per scope (``gated``: dev/decisive sets, ``report``: report-only sets), class, language, origin."""
    classes = list(classes)
    pos: dict[tuple, list[float]] = defaultdict(list)
    neg: dict[tuple, list[float]] = defaultdict(list)
    hard: dict[tuple, list[float]] = defaultdict(list)
    flagged_neg: dict[tuple, int] = defaultdict(int)
    by_set: dict[tuple, dict[str, tuple[list[float], list[float]]]] = defaultdict(dict)
    flags: dict[str, list[str]] = defaultdict(list)
    for row, pred, role in pairs:
        scope = "report" if role == "report" else "gated"
        origin = "translated" if row.get("translated") else "native"
        hard_row = is_hard_benign(row)
        for cls in classes:
            score = float(pred["scores"].get(cls, 0.0))
            positive = cls in row["classes"]
            if not positive and not row["benign"]:
                continue
            flagged = cls in (pred.get("flagged") or [])
            for language in ("all", row.get("language") or "unknown"):
                for org in ("all", origin):
                    key = (scope, cls, language, org)
                    (pos if positive else neg)[key].append(score)
                    flagged_neg[key] += flagged and not positive
                    if hard_row:
                        hard[key].append(score)
            sets = by_set[(scope, cls)].setdefault(row["dataset"], ([], []))
            sets[0 if positive else 1].append(score)
            if hard_row and flagged and scope == "gated":
                flags[cls].append(row["id"])
    report: dict[str, Any] = {"gated": {}, "report": {}}
    for scope, cls, language, org in sorted(set(pos) | set(neg) | set(hard)):
        if not pos.get((scope, cls, language, org)):
            continue
        cell = cell_metrics(pos[scope, cls, language, org], neg[scope, cls, language, org],
                            hard[scope, cls, language, org], bootstrap)
        # Benign rows L1 flags at its detect cut: the per-language FPR budget of the gate.
        flagged = flagged_neg[scope, cls, language, org]
        cell["flagged_fp"] = flagged
        cell["flagged_fpr"] = flagged / cell["negatives"] if cell["negatives"] else None
        report[scope].setdefault(cls, {}).setdefault(language, {})[org] = cell
    for (scope, cls), sets in sorted(by_set.items()):
        if cls not in report[scope] or len(sets) < 2:
            continue
        folds = {}
        for left_out in sorted(sets):
            p = [s for d, (ps, _) in sets.items() if d != left_out for s in ps]
            n = [s for d, (_, ns) in sets.items() if d != left_out for s in ns]
            cell = BASELINES.matched_fpr(p, n, FPRS[0]) if p else None
            folds[left_out] = None if cell is None else cell["tpr"]
        measured = {d: v for d, v in folds.items() if v is not None}
        low = min(measured.values(), default=None)
        full = report[scope][cls]["all"]["all"][GATE_FPRS[0]]
        # Only a set whose removal lowers the TPR is named; on a tie the first such set wins.
        worst = next((d for d in sorted(measured) if measured[d] == low), None) \
            if low is not None and full is not None and low < full["tpr"] else None
        report[scope][cls]["leave_one_dataset_out"] = {"tpr": folds, "min": low, "worst_left_out": worst}
    report["hard_benign_flags"] = {cls: sorted(ids) for cls, ids in sorted(flags.items())}
    return report


def obfuscation_invariance(pairs: list[tuple[dict[str, Any], dict[str, Any], str]]) -> dict[str, dict[str, int]]:
    """Per obfuscation kind of the generated slices: the attack rows whose clean source row (``source_id``,
    scored in the same split) L1 detects for one of the row's classes (``source_flagged``), and how many
    of them L1 still detects for such a class in the obfuscated form (``kept``)."""
    flagged = {row["id"]: set(pred.get("flagged") or []) for row, pred, _ in pairs}
    out: dict[str, dict[str, int]] = defaultdict(lambda: {"source_flagged": 0, "kept": 0})
    for row, pred, _ in pairs:
        kind = row.get("obfuscation")
        if not kind or row["benign"]:
            continue
        classes = set(row["classes"]) & flagged.get(row.get("source_id"), set())
        if not classes:
            continue
        out[kind]["source_flagged"] += 1
        out[kind]["kept"] += bool(classes & set(pred.get("flagged") or []))
    return {kind: out[kind] for kind in sorted(out)}


def invariance_lines(report: dict[str, Any]) -> list[str]:
    cells = report.get("obfuscation_invariance") or {}
    if not cells:
        return ["- no obfuscated row with a flagged source"]
    return ["| obfuscation | source flagged | obfuscated flagged too |", "|---|---:|---:|",
            *(f"| {kind} | {c['source_flagged']} | {c['kept']} |" for kind, c in cells.items())]


def score_split(sets: list[SetFile], predictions: dict[str, Path], bootstrap: bool = True) -> dict[str, Any]:
    pairs = load_pairs(sets, predictions)
    roles: dict[str, list[str]] = defaultdict(list)
    for entry in sets:
        roles[entry.role].append(entry.set_id)
    return {"schema": REPORT_SCHEMA, "sets": {k: sorted(v) for k, v in sorted(roles.items())},
            "rows": len(pairs), **score_pairs(pairs, bootstrap=bootstrap),
            "obfuscation_invariance": obfuscation_invariance(pairs)}


def _gate_cell(report: dict[str, Any], cls: str, language: str) -> dict[str, Any] | None:
    return report["gated"].get(cls, {}).get(language, {}).get("all")


def _fpr_label(fpr: str) -> str:
    return f"{float(fpr) * 100:g}%"


def compare(base: dict[str, Any], head: dict[str, Any], tolerance_pp: float = TOLERANCE_PP) -> list[dict[str, Any]]:
    """Gate checks of head against base on the gated scope: TPR at every gated FPR, then hard-benign rows."""
    checks = []
    for cls in CLASSES:
        for language in GATE_LANGUAGES:
            for fpr in GATE_FPRS:
                before = _tpr_of(_gate_cell(base, cls, language), fpr)
                head_cell = _gate_cell(head, cls, language)
                after = _tpr_of(head_cell, fpr)
                if before is None and after is None:
                    continue
                delta = None if before is None or after is None else (after - before) * 100
                ok = before is None or (after is not None and delta >= -tolerance_pp - 1e-9)
                checks.append({"name": f"tpr@{_fpr_label(fpr)}fpr {cls} {language}", "base": before, "head": after,
                               "delta_pp": None if delta is None else round(delta, 4),
                               "positives": head_cell["positives"] if after is not None else 0, "ok": ok})
    # The benign FPR of L1 at its detect cut stays within the budget per class and language (owner decision
    # 2026-11-23); `all` alone is not enough.
    for cls in CLASSES:
        for language in GATE_LANGUAGES:
            head_fpr = (_gate_cell(head, cls, language) or {}).get("flagged_fpr")
            if head_fpr is None:
                continue
            base_fpr = (_gate_cell(base, cls, language) or {}).get("flagged_fpr")
            within = head_fpr <= BENIGN_FPR_BUDGET + 1e-12
            # An overrun the base already has and the head does not raise is not this change's; it stays
            # named in the verdict until the class is recalibrated.
            inherited = not within and base_fpr is not None and head_fpr <= base_fpr + 1e-12
            checks.append({"name": f"benign fpr {cls} {language}", "base": base_fpr, "head": head_fpr,
                           "head_fpr": head_fpr, "budget": BENIGN_FPR_BUDGET, "inherited": inherited,
                           "ok": within or inherited})
    for cls in CLASSES:
        new = sorted(set(head["hard_benign_flags"].get(cls, [])) - set(base["hard_benign_flags"].get(cls, [])))
        flagged = len(head["hard_benign_flags"].get(cls, []))
        rows = ((_gate_cell(head, cls, "all") or {}).get("hard_benign") or {}).get("rows", 0)
        head_fpr = flagged / rows if rows else None
        # New hard-benign FPs are a budget (owner decision 2026-11-22): they pass while the class's head
        # hard-benign FPR stays within HARD_BENIGN_FPR_BUDGET and none of its TPR checks falls.
        tpr_ok = all(c["ok"] for c in checks if c["name"].startswith("tpr@") and c["name"].split()[1] == cls)
        within = head_fpr is not None and head_fpr <= HARD_BENIGN_FPR_BUDGET + 1e-12 and tpr_ok
        checks.append({"name": f"hard-benign new fp {cls}", "base": len(base["hard_benign_flags"].get(cls, [])),
                       "head": flagged, "new": len(new), "rows": new, "head_fpr": head_fpr,
                       "budget": HARD_BENIGN_FPR_BUDGET, "ok": not new or within})
    return checks


def _budget_text(check: dict[str, Any]) -> str:
    fpr = "–" if check["head_fpr"] is None else f"{check['head_fpr'] * 100:.3g}%"
    kind = "benign" if check["name"].startswith("benign fpr") else "hard-benign"
    return f"head {kind} FPR {fpr}, budget {check['budget'] * 100:g}%"


# ── rendering ────────────────────────────────────────────────────────────────


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.1f}"


def _ci(cell: dict[str, Any], fpr: str) -> str:
    ci = (cell.get("tpr_ci95") or {}).get(fpr)
    return "–" if not ci else f"{ci[0] * 100:.1f}–{ci[1] * 100:.1f}"


def _tpr_of(cell: dict[str, Any] | None, fpr: str) -> float | None:
    return None if not cell or not cell.get(fpr) else cell[fpr]["tpr"]


BASELINE_KINDS = {
    "heuristic": lambda name: name not in BASELINES.REFERENCE_MODELS,
    "reference": lambda name: name in BASELINES.REFERENCE_MODELS,
    "prompt_guard_2": lambda name: name.startswith("prompt_guard_2_"),
}


def _best_baseline(baselines: dict[str, dict[str, Any]], kind: str, scope: str, cls: str, language: str,
                   origin: str) -> str:
    """``TPR@1% / TPR@0.1% (id)`` of the baseline of one kind (``BASELINE_KINDS``) with the highest
    TPR@1 % in the cell, among the baselines that score the class."""
    cells = [(name, b[scope].get(cls, {}).get(language, {}).get(origin)) for name, b in baselines.items()
             if BASELINE_KINDS[kind](name) and cls in b["classes"]]
    cells = [(name, cell) for name, cell in cells if _tpr_of(cell, "0.01") is not None]
    if not cells:
        return "–"
    name, cell = max(cells, key=lambda item: _tpr_of(item[1], "0.01"))
    return f"{_pct(_tpr_of(cell, '0.01'))} / {_pct(_tpr_of(cell, '0.001'))} ({name})"


def table_lines(report: dict[str, Any], scope: str, baselines: dict[str, dict[str, Any]] | None = None) -> list[str]:
    """Markdown table of one scope: per class, language and origin; best heuristic and reference if given."""
    header = ["class", "lang", "origin", "pos", "neg", "TPR@1%", "95% CI", "TPR@0.1%", "95% CI", "AUPRC",
              "hard-benign FPR@1% / @0.1%"]
    if baselines is not None:
        header += ["best heuristic TPR@1% / 0.1%", "best reference TPR@1% / 0.1%"]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for cls in CLASSES:
        for language in LANGUAGES:
            for origin in ORIGINS:
                cells = report[scope].get(cls, {}).get(language, {})
                cell = cells.get(origin)
                # Without translated positives the native row repeats the ``all`` row.
                if cell is None or (origin == "native" and "translated" not in cells):
                    continue
                hard = cell["hard_benign"]
                values = [cls, language, origin, str(cell["positives"]), str(cell["negatives"]),
                          _pct(_tpr_of(cell, "0.01")), _ci(cell, "0.01"), _pct(_tpr_of(cell, "0.001")),
                          _ci(cell, "0.001"),
                          "–" if cell["auprc"] is None else f"{cell['auprc']:.3f}",
                          f"{_pct(hard['0.01']['fpr'])} / {_pct(hard['0.001']['fpr'])} "
                          f"({hard['0.01']['fp']}/{hard['0.001']['fp']} of {hard['rows']})" if hard["rows"] else "–"]
                if baselines is not None:
                    values += [_best_baseline(baselines, kind, scope, cls, language, origin)
                               for kind in ("heuristic", "reference")]
                lines.append("| " + " | ".join(values) + " |")
    return lines


def lodo_lines(report: dict[str, Any], scope: str) -> list[str]:
    lines = ["| class | TPR@1% all | lowest leaving one set out | set left out |", "|---|---|---|---|"]
    for cls in CLASSES:
        entry = report[scope].get(cls)
        if not entry or "leave_one_dataset_out" not in entry:
            continue
        lodo = entry["leave_one_dataset_out"]
        lines.append(f"| {cls} | {_pct(_tpr_of(entry['all']['all'], '0.01'))} | {_pct(lodo['min'])} | "
                     f"{lodo['worst_left_out'] or '–'} |")
    return lines


def render_baseline(report: dict[str, Any], baselines: dict[str, dict[str, Any]] | None, title: str,
                    left_out: dict[str, str] | None = None, source: str | None = None,
                    inputs: str | None = None) -> str:
    lines = [f"# {title}", "",
             "Generated by `scripts/l1_threat/scoreboard.py report`; do not edit by hand.", "",
             *([source, ""] if source else []), *inputs_lines(inputs),
             f"Sets: {json.dumps(report['sets'], sort_keys=True)}; rows: {report['rows']}.", "",
             "TPR at matched document FPR on the benign rows of the same scope; 95 % CI: percentile bootstrap "
             f"({BOOTSTRAP} rounds) of the TPR to its left; hard-benign FPR at the same matched thresholds (look-alike "
             "twins and security-adjacent benign sets). `–`: no negatives or no rows in the cell.", ""]
    if baselines is None:
        lines += ["Baselines: no cached predictions given; the column is left out.", ""]
    else:
        lines += ["Baselines at the same matched FPR on the same benign rows (`scripts/l1_threat/run_baselines.py`): "
                  + (", ".join(f"{name} `{b['version']}`" for name, b in baselines.items()) or "none") + ".", ""]
        if left_out:
            lines += ["Not in the columns: " + "; ".join(f"{name} ({why})" for name, why in left_out.items()) + ".", ""]
    for scope, name in (("gated", "Gated sets (dev and decisive)"), ("report", "Report-only sets")):
        if not report[scope]:
            continue
        missing = [cls for cls in CLASSES if cls not in report[scope]]
        lines += [f"## {name}", "", *table_lines(report, scope, baselines), "",
                  "Origin `native` is listed only where translated positives exist (otherwise it equals `all`)."
                  + (f" No positives: {', '.join(missing)}." if missing else ""), "",
                  f"### Leave one dataset out ({name.lower()})", "", *lodo_lines(report, scope), ""]
    flags = report["hard_benign_flags"]
    lines += ["## Hard-benign rows L1 detects", "",
              *([f"- {cls}: {len(ids)}" for cls, ids in flags.items()] or ["- none"]), ""]
    lines += ["## Obfuscation invariance", "",
              "Obfuscated attack rows whose clean source row L1 detects for one of the row's classes, and how "
              "many of them L1 detects for such a class in the obfuscated form too.", "",
              *invariance_lines(report), ""]
    return "\n".join(lines)

# ── cascade ──────────────────────────────────────────────────────────────────


# A class the cascade left without a decision (no stage of it ran, e.g. a class without rules and
# without a later layer): not flagged, clear, decided by no stage.
NO_DECISION = {"l1": "none", "l1_score": 0.0, "decision": "clear", "decided_by": None}


def _stage(prediction: dict[str, Any], cls: str) -> dict[str, Any]:
    cascade = prediction.get("cascade")
    if cascade is None:
        raise ValueError(f"prediction {prediction['id']} has no cascade answers")
    return cascade.get(cls, NO_DECISION)


def _benign_source(row: dict[str, Any]) -> str:
    """The hard-benign source of a row: ``twins`` for look-alike twins, else its set."""
    return "twins" if row.get("twin_of") else row["dataset"]


def _new_cascade_cell() -> dict[str, Any]:
    return {"positives": 0, "tp": 0, "negatives": 0, "fp": 0, "decided_by": {stage: 0 for stage in STAGES},
            "escalated": 0, "hard_benign": {}}


def _rates(cell: dict[str, Any]) -> dict[str, Any]:
    rows = cell["positives"] + cell["negatives"]
    return {**cell,
            "tpr": cell["tp"] / cell["positives"] if cell["positives"] else None,
            "fpr": cell["fp"] / cell["negatives"] if cell["negatives"] else None,
            "decided_share": {stage: n / rows if rows else None for stage, n in cell["decided_by"].items()},
            "escalated_share": cell["escalated"] / rows if rows else None,
            "hard_benign": {source: {**h, "fpr": h["fp"] / h["rows"]} for source, h in sorted(cell["hard_benign"].items())}}


def _quantiles(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None}
    p50, p95 = np.percentile(values, [50, 95])
    return {"p50": round(float(p50), 3), "p95": round(float(p95), 3)}


def stage_latency(pairs: list[tuple[dict[str, Any], dict[str, Any], str]]) -> dict[str, dict[str, Any]]:
    """Per language: p50/p95 ms of the scan and of L1 on every row, of L3 on the rows it ran, the share of
    rows L3 ran on and its mean cost per row (0 where it did not run)."""
    ms: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for row, prediction, _ in pairs:
        times = prediction.get("ms")
        if not times:
            raise ValueError(f"prediction {prediction['id']} has no stage timing")
        for language in ("all", row.get("language") or "unknown"):
            for stage in ("scan", "l1"):
                ms[language][stage].append(float(times[stage]))
            if "l3" in times:
                ms[language]["l3"].append(float(times["l3"]))
    out = {}
    for language in LANGUAGES:
        if language not in ms:
            continue
        rows, l3 = len(ms[language]["scan"]), ms[language]["l3"]
        out[language] = {"rows": rows, "scan": _quantiles(ms[language]["scan"]), "l1": _quantiles(ms[language]["l1"]),
                         "l3": {**_quantiles(l3), "runs": len(l3), "share": len(l3) / rows,
                                "mean_per_row": round(sum(l3) / rows, 3)}}
    return out


def cascade_metrics(pairs: list[tuple[dict[str, Any], dict[str, Any], str]],
                    classes: Iterable[str] = CLASSES) -> dict[str, Any]:
    """Cells per scope, class and language (origin ``all``) at the configured operating point: the
    cascade's final decision on the positives and the benign rows, the hard-benign rows it detects per
    source, the stage that decided each row and the rows L1 escalated."""
    classes = list(classes)
    cells: dict[tuple, dict[str, Any]] = defaultdict(_new_cascade_cell)
    for row, prediction, role in pairs:
        scope = "report" if role == "report" else "gated"
        hard_row = is_hard_benign(row)
        for cls in classes:
            positive = cls in row["classes"]
            if not positive and not row["benign"]:
                continue
            stage = _stage(prediction, cls)
            detected = stage["decision"] == "detected"
            for language in ("all", row.get("language") or "unknown"):
                cell = cells[scope, cls, language]
                if positive:
                    cell["positives"] += 1
                    cell["tp"] += detected
                else:
                    cell["negatives"] += 1
                    cell["fp"] += detected
                if stage["decided_by"] is not None:
                    cell["decided_by"][stage["decided_by"]] += 1
                cell["escalated"] += stage["l1"] == "escalate"
                if hard_row:
                    source = cell["hard_benign"].setdefault(_benign_source(row), {"rows": 0, "fp": 0})
                    source["rows"] += 1
                    source["fp"] += detected
    report: dict[str, Any] = {"gated": {}, "report": {}}
    for (scope, cls, language), cell in sorted(cells.items()):
        if cell["positives"]:
            report[scope].setdefault(cls, {})[language] = _rates(cell)
    return report


def subclass_metrics(pairs: list[tuple[dict[str, Any], dict[str, Any], str]],
                     labels: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Per ``harmful_content`` subclass (the label file's subclass of a gated positive; ``unlabelled`` without
    one) and language: positives, the cascade's detections at the configured operating point and the
    detections of the L1 heuristic (the rules) alone, next to it (``rules_tp``). Once there
    is a gated positive, every subclass has a cell in every language, also without positives (TPR ``None``).
    A subclass with fewer than ``MIN_POSITIVES`` positives in a language is a ``gap`` there; a model-only
    subclass whose TPR stays below 50 % is ``off`` (the operating point is at most 1 % FPR)."""
    cls = HARMFUL_SUBCLASS.CLASS
    cells: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))
    for row, prediction, role in pairs:
        if role == "report" or cls not in row["classes"]:
            continue
        answer = _stage(prediction, cls)
        sub = labels.get(row["id"], "unlabelled")
        for language in ("all", row.get("language") or "unknown"):
            cells[sub][language][0] += 1
            cells[sub][language][1] += answer["decision"] == "detected"
            cells[sub][language][2] += answer["l1"] == "detected"
    if cells:
        for sub in HARMFUL_SUBCLASS.SUBCLASSES:
            for language in LANGUAGES:
                cells[sub].setdefault(language, [0, 0, 0])
    return {sub: {language: {"positives": n, "tp": tp, "tpr": tp / n if n else None,
                             "rules_tp": rules, "rules_tpr": rules / n if n else None,
                             "gap": n < HARMFUL_SUBCLASS.MIN_POSITIVES,
                             "off": sub in HARMFUL_SUBCLASS.MODEL_ONLY_SUBCLASSES and n > 0 and tp / n < 0.5}
                  for language, (n, tp, rules) in sorted(by_language.items())}
            for sub, by_language in sorted(cells.items())}


def subclass_lines(report: dict[str, Any], counts_only: bool) -> list[str]:
    cells = report.get("subclasses") or {}
    if not cells:
        return ["No `harmful_content` positives in the gated sets."]
    order = [*HARMFUL_SUBCLASS.SUBCLASSES, "unlabelled"]
    lines = ["| subclass | " + " | ".join(LANGUAGES) + " |", "|---|" + "---:|" * len(LANGUAGES)]
    for sub in sorted(cells, key=order.index):
        row = []
        for language in LANGUAGES:
            cell = cells[sub].get(language)
            if cell is None:
                row.append("–")
                continue
            text = f"{cell['tp']}/{cell['positives']}, rules {cell['rules_tp']}" if counts_only else \
                f"{_share(cell['tpr'])} ({cell['positives']}), rules {_share(cell['rules_tpr'])}"
            marks = [m for m in ("gap", "off") if cell[m] and sub != "unlabelled"]
            row.append(text + (f" {', '.join(marks)}" if marks else ""))
        lines.append(f"| `{sub}` | " + " | ".join(row) + " |")
    return lines


def cascade_split(sets: list[SetFile], predictions: dict[str, Path], counts_only: bool = False,
                  labels: dict[str, str] | None = None) -> dict[str, Any]:
    """The cascade report of a split: decisions, the L1 score curve, the ``harmful_content`` subclasses
    (``labels``: the subclass label file by default) and (unless counts only) latency."""
    pairs = load_pairs(sets, predictions)
    roles: dict[str, list[str]] = defaultdict(list)
    for entry in sets:
        roles[entry.role].append(entry.set_id)
    return {"schema": CASCADE_SCHEMA, "sets": {k: sorted(v) for k, v in sorted(roles.items())}, "rows": len(pairs),
            "decision": cascade_metrics(pairs), "curve": score_pairs(pairs, bootstrap=False),
            "subclasses": subclass_metrics(pairs, HARMFUL_SUBCLASS.load() if labels is None else labels),
            "latency": None if counts_only else stage_latency(pairs)}


def _share(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.1f}"


def config_lines(config: dict[str, Any]) -> list[str]:
    """What the operating point is made of, without paths: hash, deepest layer, L1 cuts, Wolf."""
    scanner = config.get("scanner", {})
    cascade = scanner.get("cascade") or {}

    def cuts(key: str) -> dict[str, float]:
        return {module: t[key] for module, t in sorted((cascade.get("modules") or {}).items())
                if t.get(key) is not None}

    detect, clear = cuts("detect_threshold"), cuts("clear_threshold")
    wolf = scanner.get("wolf")
    lines = [f"Cascade config `{config_hash(config)[:12]}`: deepest layer {str(scanner.get('max_level', 'l3')).upper()}; "
             "detect thresholds " + (", ".join(f"{m} {t:g}" for m, t in detect.items()) or "Core's built-in "
                                     "acceptance") + "; "
             "clear thresholds " + (", ".join(f"{m} {t:g}" for m, t in clear.items()) or "off (L1 escalates every "
                                    "undetected row)") + "; L3 Wolf "
             + ("off" if wolf is None else f"{wolf.get('model', 'default model')} at threshold "
                + (f"{wolf['threshold']:g}" if wolf.get("threshold") is not None else "its default")) + "."]
    calibration = config.get("calibration")
    if calibration:
        lines.append(f"Calibrated by `scoreboard.py calibrate` on {calibration['benign_rows']} benign rows at "
                     f"{calibration['target_fpr'] * 100:g} % FPR (detect) and "
                     + ("no clear threshold" if calibration["clear_fpr"] is None
                        else f"{calibration['clear_fpr'] * 100:g} % FPR (clear)") + ".")
        for key, kept in (("detect", "keep Core's built-in acceptance"), ("clear", "escalate every undetected row")):
            unreachable = [cls for cls, entry in calibration["classes"].items() if entry.get(key) == UNREACHABLE]
            if unreachable:
                lines.append(f"{key.capitalize()} {UNREACHABLE} (too few non-zero benign scores), so these classes "
                             f"{kept}: " + ", ".join(unreachable) + ".")
    return lines


def cascade_table(report: dict[str, Any], scope: str, counts_only: bool) -> list[str]:
    if counts_only:
        header = ["class", "lang", "TP / pos", "FP / neg", "hard-benign FP / rows",
                  *(f"decided {stage}" for stage in STAGES), "escalated"]
    else:
        header = ["class", "lang", "pos", "neg", "TPR", "FPR", "hard-benign FPR",
                  *(f"decided {stage} %" for stage in STAGES), "escalated %"]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for cls in CLASSES:
        for language in LANGUAGES:
            cell = report["decision"][scope].get(cls, {}).get(language)
            if cell is None:
                continue
            hard_rows = sum(h["rows"] for h in cell["hard_benign"].values())
            hard_fp = sum(h["fp"] for h in cell["hard_benign"].values())
            if counts_only:
                values = [cls, language, f"{cell['tp']} / {cell['positives']}", f"{cell['fp']} / {cell['negatives']}",
                          f"{hard_fp} / {hard_rows}" if hard_rows else "–",
                          *(str(cell["decided_by"][stage]) for stage in STAGES), str(cell["escalated"])]
            else:
                values = [cls, language, str(cell["positives"]), str(cell["negatives"]), _pct(cell["tpr"]),
                          f"{cell['fpr'] * 100:.2f}" if cell["fpr"] is not None else "–",
                          f"{_pct(hard_fp / hard_rows)} ({hard_fp}/{hard_rows})" if hard_rows else "–",
                          *(_share(cell["decided_share"][stage]) for stage in STAGES), _share(cell["escalated_share"])]
            lines.append("| " + " | ".join(values) + " |")
    return lines


def hard_benign_lines(report: dict[str, Any], scope: str, counts_only: bool) -> list[str]:
    lines = ["| class | source | rows | FP" + ("" if counts_only else " | FPR") + " |",
             "|---|---|---|---|" + ("" if counts_only else "---|")]
    for cls in CLASSES:
        cell = report["decision"][scope].get(cls, {}).get("all")
        for source, h in (cell or {}).get("hard_benign", {}).items():
            lines.append(f"| {cls} | {source} | {h['rows']} | {h['fp']}" + ("" if counts_only else f" | {_pct(h['fpr'])}")
                         + " |")
    return lines if len(lines) > 2 else ["- no hard-benign rows"]


def curve_lines(report: dict[str, Any], scope: str, counts_only: bool) -> list[str]:
    """The L1 score curve, origin ``all``: TPR (or TP / FP) and hard-benign FP at each matched threshold."""
    if counts_only:
        header = ["class", "lang", *(f"TP / FP@{_fpr_label(fpr)}" for fpr in GATE_FPRS),
                  *(f"hard-benign FP@{_fpr_label(fpr)}" for fpr in GATE_FPRS)]
    else:
        header = ["class", "lang", *(f"TPR@{_fpr_label(fpr)}" for fpr in GATE_FPRS),
                  *(f"hard-benign FPR@{_fpr_label(fpr)}" for fpr in GATE_FPRS)]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for cls in CLASSES:
        for language in LANGUAGES:
            cell = report["curve"][scope].get(cls, {}).get(language, {}).get("all")
            if cell is None:
                continue
            hard = cell["hard_benign"]
            values = [cls, language]
            for fpr in GATE_FPRS:
                point = cell.get(fpr)
                values.append("–" if point is None else f"{point['tp']} / {point['fp']}" if counts_only
                              else _pct(point["tpr"]))
            for fpr in GATE_FPRS:
                values.append("–" if not hard["rows"] else f"{hard[fpr]['fp']}/{hard['rows']}" if counts_only
                              else f"{_pct(hard[fpr]['fpr'])} ({hard[fpr]['fp']}/{hard['rows']})")
            lines.append("| " + " | ".join(values) + " |")
    return lines


def latency_lines(latency: dict[str, dict[str, Any]]) -> list[str]:
    lines = ["| lang | rows | scan p50 / p95 | L1 p50 / p95 | L3 p50 / p95 (rows it ran) | L3 ran on | L3 mean per row |",
             "|---|---|---|---|---|---|---|"]

    def pair(q: dict[str, float | None]) -> str:
        return "–" if q["p50"] is None else f"{q['p50']:.2f} / {q['p95']:.2f}"

    for language, cell in latency.items():
        lines.append(f"| {language} | {cell['rows']} | {pair(cell['scan'])} | {pair(cell['l1'])} | {pair(cell['l3'])} | "
                     f"{_share(cell['l3']['share'])} % | {cell['l3']['mean_per_row']:.2f} |")
    return lines


def render_cascade(report: dict[str, Any], config: dict[str, Any], title: str, counts_only: bool = False,
                   source: str | None = None, inputs: str | None = None) -> str:
    """The cascade report; ``counts_only`` leaves only row counts (no rates, shares or latency)."""
    lines = [f"# {title}", "",
             "Generated by `scripts/l1_threat/scoreboard.py report --cascade CONFIG"
             + (" --counts-only" if counts_only else "") + "`; do not edit by hand.", "",
             *([source, ""] if source else []), *inputs_lines(inputs),
             f"Sets: {json.dumps(report['sets'], sort_keys=True)}; rows: {report['rows']}.", "",
             *config_lines(config), "",
             "ark-core alone, as a cascade: the L1 heuristic, then the L1 model, then L3 (Wolf Defender for "
             "`instruction_injection`), each later layer only on the rows the earlier ones left undecided; "
             "undecided with no later layer is clear. L2 is ARK-only and not measured here. "
             + ("TP and FP count the final decision on the class positives and on the benign rows; hard-benign FP "
                "counts look-alike twins and security-adjacent benign rows it detects. `decided`: rows each stage "
                "answered; `escalated`: rows L1 left undecided." if counts_only else
                "TPR and FPR of the final decision on the class positives and on the benign rows; hard-benign FPR at "
                "the same decision (look-alike twins and security-adjacent benign sets); `decided`: share of the "
                "class's rows each stage answered; `escalated`: share L1 left undecided. `–`: no rows in the cell."), ""]
    for scope, name in (("gated", "Gated sets (dev and decisive)"), ("report", "Report-only sets")):
        if not report["decision"][scope]:
            continue
        lines += [f"## {name}", "", *cascade_table(report, scope, counts_only), "",
                  f"### Hard-benign rows per source ({name.lower()}, language all)", "",
                  *hard_benign_lines(report, scope, counts_only), "",
                  f"### L1 score curve ({name.lower()})", "",
                  "TPR at matched document FPR on the L1 score (the view the gate checks), hard-benign "
                  "FP at the same threshold; origin all.", "", *curve_lines(report, scope, counts_only), ""]
    lines += ["## harmful_content per subclass (gated sets)", "",
              ("Detections of the cascade / positives" if counts_only else
               "TPR of the final decision (in brackets: positives)")
              + " per hazard subclass of the subclass labels (`unlabelled`: rows without one), and after `rules` the"
              " same for the L1 heuristic (the rules) alone. `gap`: fewer than "
              f"{HARMFUL_SUBCLASS.MIN_POSITIVES} positives in the language; `off`: a model-only subclass below "
              "50 % TPR at the configured operating point (at most 1 % FPR).", "", *subclass_lines(report, counts_only), ""]
    if not counts_only:
        lines += ["## Latency per stage", "",
                  "Milliseconds per row in the prediction run (one process per set): the whole scan, the native L1 "
                  "producers, and L3 (the rest of the scan) on the rows it ran; its mean per row is the conditional "
                  "cost the cascade adds to every row.", "", *latency_lines(report["latency"]), ""]
    return "\n".join(lines)


# ── calibration ──────────────────────────────────────────────────────────────


# Calibration note of a cut ``calibrate`` cannot place: the benign pool has too few non-zero scores to fill the
# FPR budget, so any cut above 0 would do and the shipped acceptance stays.
UNREACHABLE = "budget not reachable with the heuristic's scores"


def fpr_threshold(negatives: list[float], target: float) -> float | None:
    """Lowest threshold ``t`` (a row counts when ``score >= t``) with at most ``target`` of the negatives at or above
    it, placed just above a benign score; ``None`` when the non-zero negatives cannot fill the budget (a score of 0
    never counts, so the only such cut would be "any score above 0")."""
    if not negatives:
        raise ValueError("no benign rows to calibrate on")
    k = _max_fp(len(negatives), target)
    ordered = sorted(negatives, reverse=True)
    if k >= len(ordered) or ordered[k] <= 0.0:
        return None
    return math.nextafter(ordered[k], math.inf)


def calibrate(pairs: list[tuple[dict[str, Any], dict[str, Any], str]], base: dict[str, Any],
              target_fpr: float = TARGET_FPR, clear_fpr: float | None = CLEAR_FPR,
              exclude: frozenset[str] = frozenset()) -> dict[str, Any]:
    """A cascade config from ``base`` with the cuts of every class on the gated benign rows.

    Per class, on the cascade's L1 score and written to ``scanner.cascade.modules.<category>``: the
    ``detect_threshold`` holds ``target_fpr``; the ``clear_threshold`` lets at most ``clear_fpr`` of the
    benign rows escalate, or is removed when ``clear_fpr`` is ``None``. Core accepts cuts up to 1.0 and a
    clear cut at most the detect cut. A cut the benign scores cannot place (``fpr_threshold`` is ``None``)
    is removed, so the class keeps the shipped acceptance (detect) or escalates every undetected row
    (clear), and is recorded as ``UNREACHABLE``. ``calibration`` records the pool and the FPRs reached.
    """
    benign = [(row, prediction) for row, prediction, role in pairs
              if role != "report" and row["benign"] and row["id"] not in exclude]
    config = copy.deepcopy(base)
    config.pop("calibration", None)
    modules = config.setdefault("scanner", {}).setdefault("cascade", {}).setdefault("modules", {})
    classes = {}
    for cls in CLASSES:
        l1 = [float(_stage(prediction, cls)["l1_score"]) for _, prediction in benign]
        thresholds = modules.setdefault(category(cls), {})
        entry: dict[str, Any] = {"benign_scored": sum(s > 0 for s in l1)}
        # At 1.0 the rows scoring 1.0 still detect: L1 counts a score at or above its cut.
        detect = fpr_threshold(l1, target_fpr)
        if detect is None:
            thresholds.pop("detect_threshold", None)
            entry["detect"] = UNREACHABLE
        else:
            detect = thresholds["detect_threshold"] = min(detect, 1.0)
            entry["detect_fpr"] = sum(s >= detect for s in l1) / len(l1)
        clear = None if clear_fpr is None else fpr_threshold(l1, clear_fpr)
        if clear is None:
            thresholds.pop("clear_threshold", None)
            if clear_fpr is not None:
                entry["clear"] = UNREACHABLE
        else:
            clear = thresholds["clear_threshold"] = min(clear, 1.0 if detect is None else detect)
            entry["escalate_fpr"] = sum(s >= clear for s in l1) / len(l1)
        if not thresholds:
            modules.pop(category(cls))
        classes[cls] = entry
    config["calibration"] = {"target_fpr": target_fpr, "clear_fpr": clear_fpr, "benign_rows": len(benign),
                             "excluded_rows": sum(row["benign"] and row["id"] in exclude for row, _, _ in pairs),
                             "classes": classes}
    return config


# ── fair measurement on the mix ──────────────────────────────────────────────


class MixRow(NamedTuple):
    """A row of the mix (``part``: train, calibration or measurement) or of a report set (``part``: report)."""

    row: dict[str, Any]
    source: str
    part: str


def mix_sets(dev: Path, mix_root: Path) -> tuple[list[SetFile], list[SetFile]]:
    """The sets of the mix (gated dev sets and the frozen extra sets under ``mix_root/mix``) and the report sets."""
    dev_sets = split_sets(dev)
    extra = split_sets(mix_root / MIX.MIX_DIR)
    return [s for s in dev_sets if s.role != "report"] + extra, [s for s in dev_sets if s.role == "report"]


def mix_files() -> dict[str, bytes]:
    """``{file: bytes}`` of the frozen extra-set directory of the mix, in the form of a generated directory."""
    files, sets = {}, {}
    for set_id, rows in MIX.extra_sets(ROOT).items():
        data = CORPORA.BENIGN_CODE._jsonl(rows)
        files[f"{set_id}.jsonl"] = data
        sets[set_id] = {"dataset": set_id, "file": f"{set_id}.jsonl", "role": "dev", "rows": len(rows),
                        "sha256": CORPORA.PRESIDIO._sha256(data), "benign": len(rows),
                        "languages": dict(sorted(Counter(row["language"] for row in rows).items()))}
    manifest = CORPORA.BENIGN_CODE._manifest_bytes({"schema": GENERATORS.SCHEMA, "generator": "mix", "seed": MIX.SEED,
                                                    "sets": sets})
    return {**files, "manifest.json": manifest,
            CORPORA.READY: f"{CORPORA.PRESIDIO._sha256(manifest)}  manifest.json\n".encode("utf-8")}


def build_mix(dev: Path, out: Path, force: bool = False) -> dict[str, Any]:
    """Freeze the extra sets under ``out/mix`` and the row-wise split of the whole mix in ``out/parts.json``."""
    files, target = mix_files(), out / MIX.MIX_DIR
    if (target / "manifest.json").is_file() and (target / "manifest.json").read_bytes() != files["manifest.json"] \
            and not force:
        raise ValueError(f"{target}: frozen extra sets differ from this run; use --force to re-freeze")
    CORPORA.BENIGN_CODE._write(target, files)
    sets, _ = mix_sets(dev, out)
    sources = {entry.set_id: list(BASELINES.read_rows(entry.path)) for entry in sets}
    document = MIX.parts_document(sources, {entry.set_id: entry.sha256 for entry in sets})
    MIX.freeze_parts(out / MIX.PARTS_FILE, document, force)
    return document


def load_parts(mix_root: Path, sets: list[SetFile]) -> dict[str, Any]:
    """The frozen split of ``mix_root``; it must have been dealt from exactly these sets."""
    document = json.loads((mix_root / MIX.PARTS_FILE).read_text(encoding="utf-8"))
    if document.get("schema") != MIX.PARTS_SCHEMA or document["sets"] != {s.set_id: s.sha256 for s in sets}:
        raise ValueError(f"{mix_root / MIX.PARTS_FILE}: dealt from other sets; run `scoreboard.py mix` again")
    return document


def mix_rows(sets: list[SetFile], report_sets: list[SetFile], parts: dict[str, str]) -> list[MixRow]:
    rows = [MixRow(row, entry.set_id, parts[row["id"]]) for entry in sets for row in BASELINES.read_rows(entry.path)]
    return rows + [MixRow(row, entry.set_id, "report") for entry in report_sets for row in BASELINES.read_rows(entry.path)]


def mix_label(row: dict[str, Any], cls: str) -> bool | None:
    """True for a positive of ``cls``, False for a negative (a benign row or a positive of another class), None for a
    row that is neither (``cls`` only reported, or an attack of no scored class)."""
    if cls in row["classes"]:
        return True
    if cls in (row.get("reported_classes") or ()) or (not row["benign"] and not row["classes"]):
        return None
    return False


def mix_cut(negatives: list[float], target: float) -> float:
    """The detect cut at ``target`` FPR of ``negatives`` (a row counts at or above it); any score above 0 when the
    non-zero negatives cannot fill the budget."""
    cut = fpr_threshold(negatives, target)
    return math.nextafter(0.0, math.inf) if cut is None else cut


def fair_cells(rows: list[MixRow], scores: dict[str, dict[str, float]], classes: Iterable[str]) -> dict[str, Any]:
    """Per class, language and FPR level: the cut from the calibration part's negatives only, TPR, FPR and
    hard-negative FPR on the measurement part at that cut, the same on the report sets, the TPR on the calibration
    part (used only to pick the best heuristic) and the number of sources behind the measured positives.
    ``scores``: row id -> class -> score of one system (a missing row or class scores 0)."""
    part = np.asarray([r.part for r in rows])
    language_of = np.asarray([r.row.get("language") or "unknown" for r in rows])
    source = np.asarray([r.source for r in rows])
    hard = np.asarray([is_hard_benign(r.row) for r in rows], dtype=bool)
    out: dict[str, Any] = {}
    for cls in classes:
        labels = [mix_label(r.row, cls) for r in rows]
        positive = np.asarray([label is True for label in labels])
        negative = np.asarray([label is False for label in labels])
        values = np.asarray([float(scores.get(r.row["id"], {}).get(cls, 0.0)) for r in rows])
        for language in LANGUAGES:
            in_language = np.ones(len(rows), dtype=bool) if language == "all" else language_of == language
            calibration_neg = values[negative & in_language & (part == "calibration")]
            if not len(calibration_neg):
                continue
            measured = positive & in_language & (part == "measurement")
            cell: dict[str, Any] = {"sources": len(set(source[measured].tolist()))}
            for fpr in FPRS:
                cut = mix_cut(calibration_neg.tolist(), fpr)
                hit = values >= cut
                entry: dict[str, Any] = {"cut": cut}
                for name in ("calibration", "measurement", "report"):
                    scope = in_language & (part == name)
                    pos, neg, hb = scope & positive, scope & negative, scope & negative & hard
                    counts = {"pos": int(pos.sum()), "tp": int((hit & pos).sum()), "neg": int(neg.sum()),
                              "fp": int((hit & neg).sum()), "hard": int(hb.sum()), "hard_fp": int((hit & hb).sum())}
                    entry[name] = {**counts, "tpr": counts["tp"] / counts["pos"] if counts["pos"] else None,
                                   "fpr": counts["fp"] / counts["neg"] if counts["neg"] else None,
                                   "hard_fpr": counts["hard_fp"] / counts["hard"] if counts["hard"] else None}
                cell[f"{fpr:g}"] = entry
            out.setdefault(cls, {})[language] = cell
    return out


def core_scores(sets: list[SetFile], predictions: dict[str, Path], key: str) -> dict[str, dict[str, float]]:
    """Row id -> class -> score of Core predictions: ``scores`` (the L1 score curve, rules only) or ``l1_score`` (the
    cascade's L1 score: the heuristic, then the L1 model)."""
    out = {}
    for entry in sets:
        for prediction in BASELINES.read_rows(predictions[entry.set_id]):
            out[prediction["id"]] = (prediction["scores"] if key == "scores" else
                                     {cls: float(stage["l1_score"]) for cls, stage in prediction["cascade"].items()})
    return out


def cached_scores(sets: list[SetFile], cache: Path, baseline_id: str) -> tuple[dict[str, dict[str, float]], list[str]] | None:
    """Row id -> class -> score and the classes of one cached baseline, or None when a set is not cached."""
    version = BASELINES.latest_version(cache, baseline_id)
    if version is None:
        return None
    out, classes = {}, set()
    for entry in sets:
        path = BASELINES.cached_predictions(cache, baseline_id, version, entry.set_id, entry.sha256)
        if path is None:
            return None
        classes |= set(json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))["classes"])
        out.update((p["id"], p["scores"]) for p in BASELINES.read_rows(path))
    return out, sorted(classes)


def best_of(candidates: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Per class and language the candidate with the highest calibration-part TPR at 0.1 % FPR (then 1 %); the
    measurement part never picks it. Each picked cell names its candidate under ``system``."""
    out: dict[str, Any] = {}
    for name, cells in sorted(candidates.items()):
        for cls, languages in cells.items():
            for language, cell in languages.items():
                rank = tuple(cell[fpr]["calibration"]["tpr"] or 0.0 for fpr in GATE_FPRS[::-1])
                current = out.get(cls, {}).get(language)
                if current is None or rank > current[0]:
                    out.setdefault(cls, {})[language] = (rank, {**cell, "system": name})
    return {cls: {language: cell for language, (_, cell) in languages.items()} for cls, languages in out.items()}


FAIR_SYSTEMS = (("rules", "rules only"), ("l1_model", "L1 model"), ("cascade", "cascade"),
                ("prompt_guard_2", "Prompt Guard 2"), ("heuristic", "best heuristic"))


def _tpr_fpr(part: dict[str, Any]) -> str:
    """``TPR / FPR`` in percent; the FPR with two decimals, so 0.1 % budgets stay readable."""
    return f"{_pct(part['tpr'])} / {'–' if part['fpr'] is None else f'{part["fpr"] * 100:.2f}'}"


def fair_lines(report: dict[str, Any], fpr: str, systems: Iterable[str]) -> list[str]:
    """Markdown table at one FPR level: per class and language the measured rows, the sources behind the positives
    and, per system, TPR / FPR on the measurement part and TPR / FPR on the report sets at the same cut."""
    names = dict(FAIR_SYSTEMS)
    systems = [s for s in systems if s in report["systems"]]
    header = ["class", "lang", "pos", "sources", "neg", "hard neg"]
    header += [f"{names[s]} TPR / FPR" for s in systems] + [f"{names[s]} report TPR / FPR" for s in systems]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for cls in CLASSES:
        for language in LANGUAGES:
            cells = {s: report["systems"][s].get(cls, {}).get(language) for s in systems}
            first = next((c for c in cells.values() if c is not None), None)
            if first is None or not first[fpr]["measurement"]["pos"]:
                continue
            m = first[fpr]["measurement"]
            values = [cls, language, str(m["pos"]), str(first["sources"]), str(m["neg"]), str(m["hard"])]
            for part in ("measurement", "report"):
                for s in systems:
                    cell = cells[s]
                    if cell is None:
                        values.append("–")
                        continue
                    p = cell[fpr][part]
                    picked = f" ({cell['system']})" if "system" in cell and part == "measurement" else ""
                    values.append(f"{_tpr_fpr(p)}{picked}")
            lines.append("| " + " | ".join(values) + " |")
    return lines


def render_fair(report: dict[str, Any], title: str, lead: list[str], systems: Iterable[str],
                source: str | None = None, inputs: str | None = None) -> str:
    """A fair-measurement report: one table per FPR level (0.1 % first, the decisive one)."""
    systems = list(systems)
    counts = report["parts"]
    lines = [f"# {title}", "", "Generated by `scripts/l1_threat/scoreboard.py fair`; do not edit by hand.", "",
             *([source, ""] if source else []), *inputs_lines(inputs), *lead,
             f"Mix: {counts['rows']} rows from {counts['sources']} sources, dealt row-wise and stratified by source "
             f"(seed `{report['seed']}`, split `{report['parts_hash']}`): train {counts['train']}, calibration "
             f"{counts['calibration']}, measurement {counts['measurement']}; report sets outside the mix: "
             f"{', '.join(report['report_sets'])} ({counts['report']} rows).", "",
             "For a class, the negatives are the benign rows (benign pool, hard benigns, PII and DLP texts, trigger-word "
             "hard negatives) and the positives of every other class. Every cut comes from the calibration part's "
             "negatives only (per class and language); TPR, FPR and hard-negative FPR come from the measurement part, "
             "the report columns from the report sets at the same cut. `sources`: sets behind the measured positives. "
             "`–`: the system does not score the class.", ""]
    if report["short_sources"]:
        lines += ["Sources too small to reach every part: " + ", ".join(report["short_sources"]) + ".", ""]
    if report.get("missing"):
        lines += ["Not measured: " + "; ".join(f"{k} ({v})" for k, v in sorted(report["missing"].items())) + ".", ""]
    for fpr in GATE_FPRS[::-1]:
        lines += [f"## At {_fpr_label(fpr)} FPR" + (" (decisive)" if fpr == "0.001" else ""), "",
                  *fair_lines(report, fpr, systems), ""]
    return "\n".join(lines)


UPPER_BOUND = ("**Upper bound:** the eleven built-in L1 models were trained before this mix existed, on the train half of a "
               "split inside the same dev sets; part of the mix's calibration and measurement rows were their training "
               "rows, so the `L1 model` and `cascade` columns are upper bounds until the models are retrained on the "
               "mix's train part.")
FAIR_FILES = {
    "baseline.md": ("Threat scoreboard: baseline", ("rules", "prompt_guard_2", "heuristic"),
                    ["Rules only: Core's L1 heuristic score per class (the L1 score curve, no model). Prompt Guard 2 "
                     "22M and the heuristic baselines (`scripts/l1_threat/run_baselines.py`) from their cached "
                     "predictions; the best heuristic is picked per class and language on the calibration part and "
                     "named in brackets."]),
    "cascade.md": ("Threat scoreboard: cascade", ("rules", "l1_model", "cascade"),
                   ["The cascade of `research/l1-threat/scoreboard/cascade-config.json` (the L1 heuristic, then the "
                    "built-in L1 model of every class, then L3 Wolf where the config names it), each cut from the "
                    "calibration part on the cascade's L1 score. `L1 model`: the cascade up to L1 (heuristic, then "
                    "model).", UPPER_BOUND]),
    "builtin-models.md": ("Built-in L1 models in Ark Core", ("rules", "l1_model", "prompt_guard_2", "heuristic"),
                          ["The eleven fastText-type L1 models are compiled into `patronus-ark-core` "
                           "(`ark-core/models/l1/<class>.ftpack`) and run only for the modules a cascade names "
                           "(`cascade.modules.<category>.l1_model: {\"builtin\": \"<class>\"}`); the parity tests "
                           "(`ark-core/tests/text_model_parity.rs`, `scripts/tests/test_l1_threat_category_model.py`) "
                           "pin the packed values. Their shipped cuts are replaced here by the cut from the "
                           "calibration part.", UPPER_BOUND]),
    "fasttext-all-classes.md": ("fastText-type L1 models for all eleven classes", ("rules", "l1_model"),
                                ["Every class's fastText-type model (the built-in models) next to the rules alone, on "
                                 "the same rows and at the same FPR.", UPPER_BOUND]),
}


def write_fair_files(report: dict[str, Any], directory: Path, source: str | None = None,
                     inputs: str | None = None) -> list[str]:
    """Render ``FAIR_FILES`` into ``directory``; the names of the files whose numbers changed."""
    written = []
    for name, (title, systems, lead) in FAIR_FILES.items():
        text = render_fair(report, title, [line for item in lead for line in (item, "")], systems, source, inputs)
        if write_rendered(directory / name, text):
            written.append(name)
    return written


def fair_report(dev: Path, mix_root: Path, predictions: dict[str, Path], baseline_cache: Path | None) -> dict[str, Any]:
    """Every system on the same mix rows: ``predictions`` maps ``rules``, ``l1_model`` and ``cascade`` to Core
    prediction directories (the cascade's L1 score of ``l1_model`` and ``cascade``); the baselines come from the
    cache (Prompt Guard 2 22M, and per class and language the heuristic picked on the calibration part)."""
    sets, report_sets = mix_sets(dev, mix_root)
    document = load_parts(mix_root, sets)
    parts = document["parts"]
    everything = sets + report_sets
    rows = mix_rows(sets, report_sets, parts)
    systems: dict[str, Any] = {}
    missing: dict[str, str] = {}
    for name, directory in predictions.items():
        found = core_predictions(everything, directory)
        if len(found) != len(everything):
            missing[name] = "no Core predictions for every set"
            continue
        systems[name] = fair_cells(rows, core_scores(everything, found, "scores" if name == "rules" else "l1_score"),
                                   CLASSES)
    heuristics = {}
    if baseline_cache is not None:
        for baseline_id in BASELINES.baseline_ids(BASELINES.entity_map.load()):
            cached = cached_scores(everything, baseline_cache, baseline_id)
            if cached is None:
                missing[baseline_id] = "not cached for every set of the mix"
            elif baseline_id == "prompt_guard_2_22m":
                systems["prompt_guard_2"] = fair_cells(rows, cached[0], cached[1])
            elif baseline_id not in BASELINES.REFERENCE_MODELS:
                heuristics[baseline_id] = fair_cells(rows, cached[0], cached[1])
    if heuristics:
        systems["heuristic"] = best_of(heuristics)
    counted = Counter(r.part for r in rows)
    return {"seed": MIX.SEED, "parts_hash": hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:12],
            "report_sets": [s.set_id for s in report_sets], "short_sources": document["short_sources"],
            "systems": systems, "missing": missing,
            "parts": {**{p: counted[p] for p in (*MIX.PARTS, "report")}, "rows": sum(counted[p] for p in MIX.PARTS),
                      "sources": len(sets)}}


def baseline_reports(sets: list[SetFile], cache: Path) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Score reports of every baseline with cached predictions for all sets (latest version each).

    The second value names every expected or cached baseline left out, with the reason.
    """
    out: dict[str, dict[str, Any]] = {}
    left_out: dict[str, str] = {}
    cached = sorted(p.name for p in cache.iterdir() if p.is_dir()) if cache.is_dir() else []
    expected = BASELINES.baseline_ids(BASELINES.entity_map.load())
    for baseline_id in expected + [b for b in cached if b not in expected]:
        version = BASELINES.latest_version(cache, baseline_id)
        if version is None:
            left_out[baseline_id] = "no cached predictions"
            continue
        found = {e.set_id: BASELINES.cached_predictions(cache, baseline_id, version, e.set_id, e.sha256)
                 for e in sets}
        missing = sorted(set_id for set_id, path in found.items() if path is None)
        if missing:
            left_out[baseline_id] = f"`{version}` not cached for {', '.join(missing)}"
            continue
        classes = sorted({cls for path in found.values()
                          for cls in json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))["classes"]})
        out[baseline_id] = {**score_pairs(load_pairs(sets, found), bootstrap=False), "version": version,
                            "classes": classes}
    return out, left_out


def verdict_lines(split: str, checks: list[dict[str, Any]], numbers: bool) -> list[str]:
    failed = [c for c in checks if not c["ok"]]
    lines = [f"{split}: {'regression' if failed else 'no regression'} ({len(checks) - len(failed)}/{len(checks)} checks pass)"]
    for check in failed:
        if not numbers:
            lines.append(f"  FAIL {check['name']}" + (f" ({_budget_text(check)})" if "budget" in check else ""))
        elif "new" in check:
            lines.append(f"  FAIL {check['name']}: {check['new']} new ({', '.join(check['rows'][:10])}); "
                         f"{_budget_text(check)}")
        elif "budget" in check:
            lines.append(f"  FAIL {check['name']}: {_budget_text(check)}")
        else:
            lines.append(f"  FAIL {check['name']}: {_pct(check['base'])} -> {_pct(check['head'])} "
                         f"({check['delta_pp']} pp, {check['positives']} positives)")
    for check in checks:
        if check["ok"] and check.get("new"):
            lines.append(f"  PASS {check['name']}: {check['new']} new within budget ({_budget_text(check)})")
        elif check.get("inherited"):
            lines.append(f"  OVER {check['name']}: over budget on the base too, not raised ({_budget_text(check)})")
    return lines


def summary_lines(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    """Markdown table of the gated dev cells: TPR at every gated FPR, base -> head [95 % CI of the head]."""
    header = ["class", "lang", "pos", *(f"TPR@{_fpr_label(fpr)} base -> head [95% CI]" for fpr in GATE_FPRS),
              "AUPRC head"]
    lines = ["dev TPR at matched FPR (origin all):", "", "| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for cls in CLASSES:
        for language in GATE_LANGUAGES:
            cell = _gate_cell(head, cls, language)
            if cell is None:
                continue
            before = _gate_cell(base, cls, language)
            values = [cls, language, str(cell["positives"]),
                      *(f"{_pct(_tpr_of(before, fpr))} -> {_pct(_tpr_of(cell, fpr))} [{_ci(cell, fpr)}]"
                        for fpr in GATE_FPRS),
                      "–" if cell["auprc"] is None else f"{cell['auprc']:.3f}"]
            lines.append("| " + " | ".join(values) + " |")
    return lines + [""]


# ── gate ─────────────────────────────────────────────────────────────────────


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def gate(head_tree: Path, base_sha: str, dev: Path, holdout: Path | None, cache: Path, jobs: int = JOBS) -> int:
    head_tree = head_tree.resolve()
    head_commit = DLP_SCOREBOARD.resolve_commit(head_tree, "HEAD")
    base_commit = DLP_SCOREBOARD.resolve_commit(head_tree, base_sha)
    cache = cache.resolve() / "threat-scoreboard"
    builds = {"base": ensure_predictor(head_tree, base_commit, cache),
              "head": ensure_predictor(head_tree, head_commit, cache)}
    splits = [("dev", split_sets(dev))] + ([("holdout", split_sets(holdout))] if holdout is not None else [])
    output = [f"threat scoreboard: head {head_commit[:12]} (build {builds['head'].key[:12]}) vs base "
              f"{base_commit[:12]} (build {builds['base'].key[:12]})"]
    failed_any = False
    report_dir = cache / "reports" / f"{head_commit[:12]}-{base_commit[:12]}"
    for split_name, sets in splits:
        reports = {}
        for name, build in builds.items():
            out = cache / "predictions" / f"{build.key[:16]}-{config_hash(L1_CASCADE)[:12]}"
            predict_split(sets, out, build.binary, L1_CASCADE, jobs)
            reports[name] = score_split(sets, core_predictions(sets, out))
        checks = compare(reports["base"], reports["head"])
        failed_any = failed_any or any(not c["ok"] for c in checks)
        _write_json(report_dir / f"{split_name}.json", {"base": reports["base"], "head": reports["head"],
                                                         "checks": checks, "tolerance_pp": TOLERANCE_PP})
        if split_name == "dev":
            output += summary_lines(reports["base"], reports["head"])
            output += verdict_lines("dev", checks, numbers=True)
        else:
            # The holdout leaves the sandbox as a verdict and the names of failing checks only.
            output += verdict_lines(split_name, checks, numbers=False)
    DLP_SCOREBOARD.prune(cache, {build.key for build in builds.values()})
    output.append(f"threat scoreboard: {'FAIL' if failed_any else 'PASS'}")
    print("\n".join(output))
    return 1 if failed_any else 0


# ── refresh ──────────────────────────────────────────────────────────────────


def changed_paths(tree: Path, since: str, commit: str) -> list[str]:
    """The files under ``REFRESH_PATHS`` that differ between ``since`` and ``commit``."""
    return DLP_SCOREBOARD.git(tree, "diff", "--name-only", since, commit, "--", *REFRESH_PATHS).decode().split()


def inputs_fingerprint(sets: list[SetFile], baseline_cache: Path | None = None) -> str:
    """Fingerprint of the data a report reads: every set's id, SHA-256 and role (dev or report scope) and, with
    ``baseline_cache``, the cached baseline prediction files (their metadata names baseline, version, set and
    corpus hash)."""
    digest = hashlib.sha256()
    for entry in sorted(sets):
        digest.update(f"set\0{entry.set_id}\0{entry.sha256}\0{entry.role}\n".encode())
    if baseline_cache is not None and baseline_cache.is_dir():
        for meta in sorted(baseline_cache.glob("*/*/*.json")):
            digest.update(f"baseline\0{meta.relative_to(baseline_cache).as_posix()}\n".encode())
    return digest.hexdigest()[:16]


def inputs_lines(inputs: str | None) -> list[str]:
    return [f"{RENDERED_INPUTS} `{inputs}`.", ""] if inputs else []


def recorded_inputs(path: Path) -> str | None:
    """The inputs fingerprint a refreshed report names, or None (no report, or rendered without one)."""
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(RENDERED_INPUTS):
            return line[len(RENDERED_INPUTS):].strip(" `.")
    return None


def write_rendered(path: Path, text: str) -> bool:
    """Write ``text`` unless ``path`` holds the same report already (only the ``RENDERED_FROM`` line may differ)."""
    def body(value: str) -> list[str]:
        return [line for line in value.splitlines() if not line.startswith(RENDERED_FROM)]

    if path.is_file() and body(path.read_text(encoding="utf-8")) == body(text):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


def refresh(tree: Path, since: str | None, dev: Path, cache: Path, baseline_cache: Path | None,
            jobs: int = JOBS) -> int:
    """Re-render the scoreboard of the checkout ``tree`` (main) from its HEAD on the measurement mix.

    The mix (``build_mix``) is frozen under the cache; Core predicts it and the dev split's report sets with
    ``L1_CASCADE`` (rules only) and, when the checkout holds ``CASCADE_CONFIG``, with that config (``cascade`` when it
    names Wolf, else ``l1_model``); ``fair_report`` scores them with the cached baselines into ``FAIR_FILES``. With
    ``since`` (the commit the reports were last rendered from) nothing runs unless a file under ``REFRESH_PATHS``
    changed or a report names other inputs than the current ones (``inputs_fingerprint`` over the mix's sets, the
    report sets and the cached baselines). A report whose numbers and inputs did not change is left as it is.
    """
    tree = tree.resolve()
    commit = DLP_SCOREBOARD.resolve_commit(tree, "HEAD")
    cache = cache.resolve() / "threat-scoreboard"
    build_mix(dev, cache / "mix", force=True)
    sets, report_sets = mix_sets(dev, cache / "mix")
    everything = sets + report_sets
    inputs = inputs_fingerprint(everything, baseline_cache)
    if (since is not None and not changed_paths(tree, DLP_SCOREBOARD.resolve_commit(tree, since), commit)
            and all(recorded_inputs(tree / SCOREBOARD_DIR / name) == inputs for name in FAIR_FILES)):
        print(f"threat scoreboard refresh: no detector, scorer, gold or input change since {since[:12]}; "
              "nothing to render")
        return 0
    configs = {"rules": L1_CASCADE}
    if (tree / CASCADE_CONFIG).is_file():
        config = load_config(tree / CASCADE_CONFIG)
        configs["cascade" if needs_wolf(config) else "l1_model"] = config
    builds, directories = set(), {}
    for name, config in configs.items():
        build = ensure_predictor(tree, commit, cache, needs_wolf(config))
        builds.add(build.key)
        directories[name] = cache / "predictions" / f"{build.key[:16]}-{config_hash(config)[:12]}"
        predict_split(everything, directories[name], build.binary, config, jobs)
    report = fair_report(dev, cache / "mix", directories, baseline_cache)
    written = write_fair_files(report, tree / SCOREBOARD_DIR, f"{RENDERED_FROM} `{commit[:12]}` on the mix.", inputs)
    DLP_SCOREBOARD.prune(cache, builds)
    print(f"threat scoreboard refresh of {commit[:12]}: "
          + (f"rewrote {', '.join(str(SCOREBOARD_DIR / name) for name in written)}" if written else "numbers unchanged"))
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────


def bound_predictions(sets: list[SetFile], directory: Path, config: dict[str, Any]) -> dict[str, Path]:
    """The predictions of ``directory``, which must have been made with ``config``."""
    path = directory / CONFIG_FILE
    if not path.is_file() or config_hash(load_config(path)) != config_hash(config):
        raise ValueError(f"{directory}: no predictions of cascade config {config_hash(config)[:12]}")
    return core_predictions(sets, directory)


def report_command(args: argparse.Namespace) -> int:
    sets = split_sets(args.split)
    if args.cascade is not None:
        config = load_config(args.cascade)
        report = cascade_split(sets, bound_predictions(sets, args.predictions, config), args.counts_only)
        text = render_cascade(report, config, args.title or "Threat scoreboard: cascade", args.counts_only)
    else:
        if args.counts_only:
            raise ValueError("--counts-only needs --cascade")
        baselines, left_out = baseline_reports(sets, args.baseline_cache) if args.baseline_cache else (None, None)
        report = score_split(sets, core_predictions(sets, args.predictions))
        text = render_baseline(report, baselines, args.title or "Threat scoreboard: baseline", left_out)
    args.out.write_text(text, encoding="utf-8")
    return 0


def calibrate_command(args: argparse.Namespace) -> int:
    sets = split_sets(args.split)
    predictions = core_predictions(sets, args.predictions)
    exclude = frozenset(line.strip() for line in args.exclude_ids.read_text(encoding="utf-8").splitlines()
                        if line.strip()) if args.exclude_ids else frozenset()
    config = calibrate(load_pairs(sets, predictions), load_config(args.cascade), args.target_fpr,
                       None if args.no_clear else args.clear_fpr, exclude)
    _write_json(args.out, config)
    print(f"cascade config {config_hash(config)[:12]} written to {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    g = commands.add_parser("gate", help="build head and base, score dev (+ holdout), exit 1 on regression")
    g.add_argument("--head", type=Path, required=True, help="git checkout of the head commit")
    g.add_argument("--base-sha", required=True, help="base commit (any revision the head checkout knows)")
    g.add_argument("--dev", type=Path, required=True, help="dev split root (prepared and generated directories)")
    g.add_argument("--holdout", type=Path, help="holdout split root; reported as a verdict only")
    g.add_argument("--cache", type=Path, required=True, help="builds, predictions and reports")
    g.add_argument("--jobs", type=int, default=JOBS)
    pr = commands.add_parser("predict", help="Core predictions of a split with a cascade config")
    pr.add_argument("--split", type=Path, required=True)
    pr.add_argument("--out", type=Path, required=True, help="prediction directory (one per cascade config)")
    pr.add_argument("--cascade", type=Path, help="cascade config (default: L1 only)")
    pr.add_argument("--predictor", type=Path, help=f"built {PREDICTOR} example (default: build this checkout)")
    pr.add_argument("--jobs", type=int, default=JOBS)
    s = commands.add_parser("score", help="score the L1 score curve of Core predictions on one split")
    s.add_argument("--split", type=Path, required=True)
    s.add_argument("--predictions", type=Path, required=True, help="directory written by predict")
    s.add_argument("--output", type=Path)
    c = commands.add_parser("compare", help="gate checks of two score reports of the same split")
    c.add_argument("--base", type=Path, required=True)
    c.add_argument("--head", type=Path, required=True)
    c.add_argument("--tolerance-pp", type=float, default=TOLERANCE_PP)
    r = commands.add_parser("report", help="render the baseline or the cascade report (Markdown)")
    r.add_argument("--split", type=Path, required=True)
    r.add_argument("--predictions", type=Path, required=True, help="directory written by predict")
    r.add_argument("--baseline-cache", type=Path, help="run_baselines.py cache (baseline report)")
    r.add_argument("--cascade", type=Path, help="the cascade report at this config's operating point")
    r.add_argument("--counts-only", action="store_true", help="cascade report with row counts only")
    r.add_argument("--title")
    r.add_argument("--out", type=Path, required=True)
    cal = commands.add_parser("calibrate", help="write a cascade config with per-class thresholds")
    cal.add_argument("--split", type=Path, required=True, help="dev split (its gated benign rows are the pool)")
    cal.add_argument("--predictions", type=Path, required=True, help="directory written by predict")
    cal.add_argument("--cascade", type=Path, help="config to start from (default: L1 only)")
    cal.add_argument("--target-fpr", type=float, default=TARGET_FPR, help="detect threshold FPR (default 0.001)")
    clear = cal.add_mutually_exclusive_group()
    clear.add_argument("--clear-fpr", type=float, default=CLEAR_FPR, help="share of benign rows L1 escalates")
    clear.add_argument("--no-clear", action="store_true", help="no clear threshold: every undetected row escalates")
    cal.add_argument("--exclude-ids", type=Path, help="row ids (one per line) left out, e.g. train negatives")
    cal.add_argument("--out", type=Path, required=True)
    mx = commands.add_parser("mix", help="freeze the measurement mix (extra sets and the row-wise split)")
    mx.add_argument("--dev", type=Path, required=True, help="dev split root")
    mx.add_argument("--out", type=Path, required=True, help="mix root (extra sets under mix/, parts.json)")
    mx.add_argument("--force", action="store_true", help="re-deal a frozen mix of other inputs")
    fa = commands.add_parser("fair", help="every system on the same mix rows, cut from the calibration part")
    fa.add_argument("--dev", type=Path, required=True, help="dev split root (its report sets stay outside the mix)")
    fa.add_argument("--mix", type=Path, required=True, help="mix root written by `mix`")
    fa.add_argument("--predictions", action="append", default=[], metavar="SYSTEM=DIR",
                    help="Core predictions of the dev split and the mix: rules=DIR, l1_model=DIR, cascade=DIR")
    fa.add_argument("--baseline-cache", type=Path, help="run_baselines.py cache (Prompt Guard 2, heuristics)")
    fa.add_argument("--output", type=Path, required=True, help="fair report (JSON)")
    fa.add_argument("--scoreboard", type=Path, help=f"also render {', '.join(FAIR_FILES)} into this directory")
    rf = commands.add_parser("refresh", help="re-render baseline.md (and cascade.md) in a checkout of main")
    rf.add_argument("--tree", type=Path, default=ROOT, help="checkout of main; its HEAD is measured, its reports rewritten")
    rf.add_argument("--since", help="commit the reports were last rendered from: render only after a detector, "
                                    "scorer or gold change since then")
    rf.add_argument("--dev", type=Path, required=True, help="dev split root")
    rf.add_argument("--cache", type=Path, required=True, help="builds and predictions (shared with gate)")
    rf.add_argument("--baseline-cache", type=Path, help="run_baselines.py cache (baseline columns)")
    rf.add_argument("--jobs", type=int, default=JOBS)
    args = parser.parse_args(argv)

    try:
        if args.command == "gate":
            return gate(args.head, args.base_sha, args.dev, args.holdout, args.cache, args.jobs)
        if args.command == "refresh":
            return refresh(args.tree, args.since, args.dev, args.cache, args.baseline_cache, args.jobs)
        if args.command == "mix":
            document = build_mix(args.dev, args.out, args.force)
            print(f"mix of {sum(map(sum, (c.values() for c in document['counts'].values())))} rows from "
                  f"{len(document['counts'])} sources frozen under {args.out}")
            return 0
        if args.command == "fair":
            predictions = dict(item.split("=", 1) for item in args.predictions)
            unknown = set(predictions) - {"rules", "l1_model", "cascade"}
            if unknown:
                raise ValueError(f"unknown systems: {', '.join(sorted(unknown))}")
            report = fair_report(args.dev, args.mix, {k: Path(v) for k, v in predictions.items()}, args.baseline_cache)
            _write_json(args.output, report)
            if args.scoreboard:
                write_fair_files(report, args.scoreboard)
            return 0
        if args.command == "predict":
            config = load_config(args.cascade)
            binary = args.predictor or build_local_predictor(config)
            predict_split(split_sets(args.split), args.out, binary, config, args.jobs)
            return 0
        if args.command == "score":
            sets = split_sets(args.split)
            report = score_split(sets, core_predictions(sets, args.predictions))
            text = json.dumps(report, indent=1, sort_keys=True) + "\n"
            if args.output:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            return 0
        if args.command == "compare":
            base = json.loads(args.base.read_text(encoding="utf-8"))
            head = json.loads(args.head.read_text(encoding="utf-8"))
            checks = compare(base, head, args.tolerance_pp)
            print("\n".join(verdict_lines("split", checks, numbers=True)))
            return 1 if any(not c["ok"] for c in checks) else 0
        if args.command == "calibrate":
            return calibrate_command(args)
        return report_command(args)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"threat scoreboard: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
