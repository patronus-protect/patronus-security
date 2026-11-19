#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Threat scoreboard: score ARK (and cached baselines) on frozen corpora and gate a head against its base.

Inputs are split roots: every subdirectory with a frozen ``manifest.json`` (``prepare_corpora.py``
corpora, ``generators.py`` output) counts, e.g. ``DEV/{train_dev,report,generated,translated}`` or
``HOLDOUT/{holdout,generated}``. Every row is a positive of the classes in ``classes`` (reported-only
classes do not count) and a negative of every class when ``benign``. Sets with the role ``report``
are scored in their own scope and never gate.

ARK runs on L1 only, one category per class (``instruction_injection`` is the category
``injection``); the score of a class is the highest attack confidence ARK reports for it (0 when it
reports nothing), the verdict is ARK's own decision (any result that is not ``benign``/``safe``, as
in the golden evaluation). Metrics per class, language (``all``, ``de``, ``en``) and origin (``all``,
``native``, ``translated``; runner translations and the German part of a set marked ``translated`` in
the entity map, as in ``generators.py``):

- TPR at matched document FPR 1 % and 0.1 % on the benign rows (lowest threshold whose FPR is within
  the target, ``run_baselines.matched_fpr``), each with a seeded percentile bootstrap 95 % CI
  (positives and negatives resampled, threshold re-chosen in every replicate);
- AUPRC (average precision of the class positives against the benign rows);
- hard-benign FPR at ARK's own verdict: benign look-alike twins (``twin_of``) and the benign rows of
  the security-adjacent sets in ``HARD_BENIGN_SETS``;
- leave-one-dataset-out (``language: all``, ``origin: all``): TPR@1 % with each contributing set left
  out, and the lowest of them;
- obfuscation invariance: per obfuscation kind of the generated slices, the attack rows whose clean
  source row is flagged and how many of them stay flagged obfuscated (reported, not gated).

``gate`` builds the head and the base commit (the release module of ``python/``, offline, shared
with the DLP scoreboard), predicts every split with both and fails on a regression in the gated scope:
TPR@1 % or TPR@0.1 % of a class (``all``, ``de``, ``en``; origin ``all``) more than 0.5 pp below the
base, or a hard-benign row of a class that the head flags and the base does not. stdout carries the
dev numbers as a Markdown table (both TPRs, base -> head with the head's CI); the holdout leaves as a
verdict and the names of failing checks only, its report stays in the cache.
Latency is gated by the runner's own A/B step (``latency.py``). Exit 0 = pass, 1 = regression,
2 = error.

    python3 scripts/l1_threat/scoreboard.py predict --split DIR --out PRED_DIR
    python3 scripts/l1_threat/scoreboard.py score --split DIR --predictions PRED_DIR [--output REPORT]
    python3 scripts/l1_threat/scoreboard.py compare --base REPORT --head REPORT
    python3 scripts/l1_threat/scoreboard.py report --split DIR --predictions PRED_DIR \
        [--baseline-cache CACHE] --out research/l1-threat/scoreboard/baseline.md
    python3 scripts/l1_threat/scoreboard.py gate --head WT --base-sha SHA --dev DIR [--holdout DIR] --cache DIR
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import subprocess
import sys
from collections import defaultdict
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

REPORT_SCHEMA = "ark-l1-threat-scoreboard-v2"
PREDICTIONS_SCHEMA = "ark-l1-threat-ark-predictions-v1"
PREDICTOR_VERSION = "1"
FPRS = (0.01, 0.001)
# Report keys of the gated operating points; both gate with the same tolerance, 1 % first.
GATE_FPRS = tuple(f"{fpr:g}" for fpr in FPRS)
GATE_LANGUAGES = ("all", "de", "en")
LANGUAGES = ("all", "de", "en")
ORIGINS = ("all", "native", "translated")
TOLERANCE_PP = 0.5
BOOTSTRAP = 200
BOOTSTRAP_SEED = 20261114
# Benign sets of security-adjacent text (trigger words, seemingly harmful prompts, jailbreak-shaped
# prompts without harmful intent, harmless requests that sound risky, hard-negative goldens); together with the generated look-alike twins
# they make up the hard-benign pool.
HARD_BENIGN_SETS = frozenset({"notinject", "or_bench_hard", "xstest", "wildjailbreak", "wildguardmix", "l1_goldens"})
BENIGN_CLASSES = frozenset({"benign", "safe"})
JOBS = 4


def category(cls: str) -> str:
    """The ARK category that scans a class; ``instruction_injection`` keeps the name ``injection``."""
    return "injection" if cls == "instruction_injection" else cls


CATEGORIES = {category(cls): cls for cls in CLASSES}


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


# ── ARK predictions ──────────────────────────────────────────────────────────


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def ark_class_scores(results: Iterable[dict[str, Any]]) -> tuple[dict[str, float], list[str]]:
    """``({class: score}, [flagged classes])`` of one text from ARK's L1 results.

    A class is flagged when one of its results is not benign (ARK's own verdict). Its score is the
    highest of the confidence of such a result and the scorer values below the decision (the
    layer ``score`` of the threat scorer, the candidate ``score`` of the injection scorer); a class
    without any is left out (score 0).
    """
    scores: dict[str, float] = {}
    flagged: set[str] = set()
    for result in results:
        cls = CATEGORIES.get(result.get("category", ""))
        if cls is None:
            continue
        layers = result.get("layers") or []
        if result.get("class_name") == "error" or any(layer.get("layer_type") == "scanner_error" for layer in layers):
            raise RuntimeError(f"ARK scanner {result.get('model')} failed")
        values = []
        if result.get("class_name") not in BENIGN_CLASSES:
            flagged.add(cls)
            values.append(_number(result.get("confidence")))
        for layer in layers:
            details = layer.get("details") or {}
            values.append(_number(details.get("score")))
            values += [_number(c.get("score")) for c in details.get("l1_candidates") or []]
        best = max((v for v in values if v is not None), default=0.0)
        if best > 0:
            scores[cls] = round(max(scores.get(cls, 0.0), best), 6)
    return scores, sorted(flagged)


def predict_rows(rows: Iterable[dict[str, Any]], scan) -> list[dict[str, Any]]:
    """One prediction per row: ``{"id", "scores", "flagged"}``; ``scan(text)`` returns ARK results."""
    out = []
    for row in rows:
        scores, flagged = ark_class_scores(scan(row["text"]))
        out.append({"id": row["id"], "scores": scores, "flagged": flagged})
    return out


def _predict_file(source: Path, output: Path) -> None:
    """Predict one corpus file with the ``patronus_ark`` on ``sys.path``."""
    from patronus_ark import SecurityGateway

    gateway = SecurityGateway(categories=sorted(CATEGORIES), max_level="l1", download_files=False)
    categories = sorted(CATEGORIES)
    predictions = predict_rows(BASELINES.read_rows(source), lambda text: gateway.scan_categories(categories, text))
    tmp = output.with_suffix(".part")
    tmp.write_text("".join(json.dumps(p, sort_keys=True) + "\n" for p in predictions), encoding="utf-8")
    tmp.replace(output)


def _predict_worker(package: Path | None, source: Path, output: Path) -> int:
    if package is not None:
        sys.path.insert(0, str(package))
    import patronus_ark

    if package is not None and Path(patronus_ark.__file__).resolve().parent != (package / "patronus_ark").resolve():
        raise RuntimeError(f"patronus_ark resolved outside the build: {patronus_ark.__file__}")
    _predict_file(source, output)
    return 0


def prediction_path(out: Path, entry: SetFile) -> Path:
    return out / f"{entry.set_id}-{entry.sha256[:12]}.jsonl"


def predict_split(sets: list[SetFile], out: Path, package: Path | None = None, jobs: int = JOBS) -> None:
    """Predict every set not yet in ``out``; each set runs in its own process."""
    out.mkdir(parents=True, exist_ok=True)

    def one(entry: SetFile) -> None:
        cmd = [sys.executable, str(HERE / "scoreboard.py"), "_predict", "--input", str(entry.path),
               "--output", str(prediction_path(out, entry))]
        if package is not None:
            cmd += ["--package", str(package)]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        if package is not None:
            env.pop("PYTHONPATH", None)
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            # Errors name the set but never echo corpus text.
            raise RuntimeError(f"ARK prediction of {entry.set_id} failed (exit {result.returncode})")

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


def ark_predictions(sets: list[SetFile], out: Path) -> dict[str, Path]:
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


def cell_metrics(pos: list[float], neg: list[float], hard: list[bool], bootstrap: bool = True) -> dict[str, Any]:
    """Matched-FPR TPRs, AUPRC, bootstrap CI of each TPR and hard-benign FPR of one cell."""
    out: dict[str, Any] = {"positives": len(pos), "negatives": len(neg)}
    for fpr in FPRS:
        cell = BASELINES.matched_fpr(pos, neg, fpr)
        out[f"{fpr:g}"] = None if cell is None else {k: cell[k] for k in ("threshold", "tpr", "fpr", "tp", "fp")}
    out["auprc"] = average_precision(pos, neg)
    if bootstrap:
        out["tpr_ci95"] = {f"{fpr:g}": bootstrap_ci(pos, neg, fpr) for fpr in FPRS}
    out["hard_benign"] = {"rows": len(hard), "fp": sum(hard), "fpr": sum(hard) / len(hard) if hard else None}
    return out


def score_pairs(pairs: list[tuple[dict[str, Any], dict[str, Any], str]], classes: Iterable[str] = CLASSES,
                bootstrap: bool = True) -> dict[str, Any]:
    """Scores per scope (``gated``: dev/decisive sets, ``report``: report-only sets), class, language, origin."""
    classes = list(classes)
    pos: dict[tuple, list[float]] = defaultdict(list)
    neg: dict[tuple, list[float]] = defaultdict(list)
    hard: dict[tuple, list[bool]] = defaultdict(list)
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
                    if hard_row:
                        hard[key].append(flagged)
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
    scored in the same split) ARK flags for one of the row's classes (``source_flagged``), and how many
    of them ARK still flags for such a class in the obfuscated form (``kept``)."""
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
    for cls in CLASSES:
        new = sorted(set(head["hard_benign_flags"].get(cls, [])) - set(base["hard_benign_flags"].get(cls, [])))
        checks.append({"name": f"hard-benign new fp {cls}", "base": len(base["hard_benign_flags"].get(cls, [])),
                       "head": len(head["hard_benign_flags"].get(cls, [])), "new": len(new), "rows": new,
                       "ok": not new})
    return checks


# ── rendering ────────────────────────────────────────────────────────────────


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.1f}"


def _ci(cell: dict[str, Any], fpr: str) -> str:
    ci = (cell.get("tpr_ci95") or {}).get(fpr)
    return "–" if not ci else f"{ci[0] * 100:.1f}–{ci[1] * 100:.1f}"


def _tpr_of(cell: dict[str, Any] | None, fpr: str) -> float | None:
    return None if not cell or not cell.get(fpr) else cell[fpr]["tpr"]


def _best_baseline(baselines: dict[str, dict[str, Any]], kind: str, scope: str, cls: str, language: str,
                   origin: str) -> str:
    """``TPR@1% / TPR@0.1% (id)`` of the baseline of one kind with the highest TPR@1 % in the cell, among
    the baselines that score the class."""
    cells = [(name, b[scope].get(cls, {}).get(language, {}).get(origin)) for name, b in baselines.items()
             if (name in BASELINES.REFERENCE_MODELS) == (kind == "reference") and cls in b["classes"]]
    cells = [(name, cell) for name, cell in cells if _tpr_of(cell, "0.01") is not None]
    if not cells:
        return "–"
    name, cell = max(cells, key=lambda item: _tpr_of(item[1], "0.01"))
    return f"{_pct(_tpr_of(cell, '0.01'))} / {_pct(_tpr_of(cell, '0.001'))} ({name})"


def table_lines(report: dict[str, Any], scope: str, baselines: dict[str, dict[str, Any]] | None = None) -> list[str]:
    """Markdown table of one scope: per class, language and origin; best heuristic and reference if given."""
    header = ["class", "lang", "origin", "pos", "neg", "TPR@1%", "95% CI", "TPR@0.1%", "95% CI", "AUPRC",
              "hard-benign FPR"]
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
                          f"{_pct(hard['fpr'])} ({hard['fp']}/{hard['rows']})" if hard["rows"] else "–"]
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
                    left_out: dict[str, str] | None = None) -> str:
    lines = [f"# {title}", "",
             "Generated by `scripts/l1_threat/scoreboard.py report`; do not edit by hand.", "",
             f"Sets: {json.dumps(report['sets'], sort_keys=True)}; rows: {report['rows']}.", "",
             "TPR at matched document FPR on the benign rows of the same scope; 95 % CI: percentile bootstrap "
             f"({BOOTSTRAP} rounds) of the TPR to its left; hard-benign FPR at ARK's own verdict (look-alike twins and "
             "security-adjacent benign sets). `–`: no negatives or no rows in the cell.", ""]
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
    lines += ["## Hard-benign rows flagged by ARK", "",
              *([f"- {cls}: {len(ids)}" for cls, ids in flags.items()] or ["- none"]), ""]
    lines += ["## Obfuscation invariance", "",
              "Obfuscated attack rows whose clean source row ARK flags for one of the row's classes, and how "
              "many of them ARK flags for such a class in the obfuscated form too.", "",
              *invariance_lines(report), ""]
    return "\n".join(lines)


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
            lines.append(f"  FAIL {check['name']}")
        elif "new" in check:
            lines.append(f"  FAIL {check['name']}: {check['new']} new ({', '.join(check['rows'][:10])})")
        else:
            lines.append(f"  FAIL {check['name']}: {_pct(check['base'])} -> {_pct(check['head'])} "
                         f"({check['delta_pp']} pp, {check['positives']} positives)")
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


def _predictor_key() -> str:
    return DLP_SCOREBOARD.sha256_bytes(PREDICTOR_VERSION.encode() + (HERE / "scoreboard.py").read_bytes())[:12]


def gate(head_tree: Path, base_sha: str, dev: Path, holdout: Path | None, cache: Path, jobs: int = JOBS) -> int:
    head_tree = head_tree.resolve()
    head_commit = DLP_SCOREBOARD.resolve_commit(head_tree, "HEAD")
    base_commit = DLP_SCOREBOARD.resolve_commit(head_tree, base_sha)
    cache = cache.resolve() / "threat-scoreboard"
    builds = {"base": DLP_SCOREBOARD.ensure_build(head_tree, base_commit, cache),
              "head": DLP_SCOREBOARD.ensure_build(head_tree, head_commit, cache)}
    splits = [("dev", split_sets(dev))] + ([("holdout", split_sets(holdout))] if holdout is not None else [])
    output = [f"threat scoreboard: head {head_commit[:12]} (build {builds['head'].key[:12]}) vs base "
              f"{base_commit[:12]} (build {builds['base'].key[:12]})"]
    failed_any = False
    report_dir = cache / "reports" / f"{head_commit[:12]}-{base_commit[:12]}"
    for split_name, sets in splits:
        reports = {}
        for name, build in builds.items():
            out = cache / "predictions" / f"{build.key[:16]}-{_predictor_key()}"
            predict_split(sets, out, build.package, jobs)
            reports[name] = score_split(sets, ark_predictions(sets, out))
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


# ── CLI ──────────────────────────────────────────────────────────────────────


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
    pr = commands.add_parser("predict", help="ARK predictions with the installed patronus_ark")
    pr.add_argument("--split", type=Path, required=True)
    pr.add_argument("--out", type=Path, required=True)
    pr.add_argument("--jobs", type=int, default=JOBS)
    s = commands.add_parser("score", help="score ARK predictions on one split")
    s.add_argument("--split", type=Path, required=True)
    s.add_argument("--predictions", type=Path, required=True, help="directory written by predict")
    s.add_argument("--output", type=Path)
    c = commands.add_parser("compare", help="gate checks of two score reports of the same split")
    c.add_argument("--base", type=Path, required=True)
    c.add_argument("--head", type=Path, required=True)
    c.add_argument("--tolerance-pp", type=float, default=TOLERANCE_PP)
    r = commands.add_parser("report", help="render the baseline report (Markdown)")
    r.add_argument("--split", type=Path, required=True)
    r.add_argument("--predictions", type=Path, required=True, help="directory written by predict")
    r.add_argument("--baseline-cache", type=Path, help="run_baselines.py cache")
    r.add_argument("--title", default="Threat scoreboard: baseline")
    r.add_argument("--out", type=Path, required=True)
    p = commands.add_parser("_predict", help=argparse.SUPPRESS)
    p.add_argument("--package", type=Path)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "gate":
            return gate(args.head, args.base_sha, args.dev, args.holdout, args.cache, args.jobs)
        if args.command == "predict":
            predict_split(split_sets(args.split), args.out, jobs=args.jobs)
            return 0
        if args.command == "score":
            sets = split_sets(args.split)
            report = score_split(sets, ark_predictions(sets, args.predictions))
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
        if args.command == "report":
            sets = split_sets(args.split)
            report = score_split(sets, ark_predictions(sets, args.predictions))
            baselines, left_out = baseline_reports(sets, args.baseline_cache) if args.baseline_cache else (None, None)
            args.out.write_text(render_baseline(report, baselines, args.title, left_out), encoding="utf-8")
            return 0
        return _predict_worker(args.package, args.input, args.output)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"threat scoreboard: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
