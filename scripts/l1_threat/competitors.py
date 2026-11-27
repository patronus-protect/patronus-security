#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Head-to-head against the open-source competitors on their own benchmarks (E12).

The benchmarks are the ``benchmarks`` section of ``datasets.yaml``: where a set comes from (source, licence,
pinned revision, commercial flag), which classes it measures and the protocol its paper scores it with. Every
benchmark is evaluation only: it never enters the dev split, the mix, training or calibration, and no benchmark
reads a holdout source of ``entity_map.yaml``. A benchmark that reuses a registered set names it in ``dataset``
(rows any shipped L1 model was trained on are left out, as in the fair measurement).

The competitors' published numbers live in ``research/l1-threat/competitors.yaml``, each with the URL and the
table or section it was re-read from; a number without a citation is never quoted.

Protocol adapters (one per benchmark protocol), all on per-row scores (``score >= cut`` flags):

- ``tpr_at_fpr``: TPR at the lowest cut whose FPR on the benchmark's own negatives is within each target
  (PromptShield: 1 % and 0.1 %), ``run_baselines.matched_fpr``;
- ``f1_at_cut``: precision, recall and F1 of the system's own decision (the shipped or calibrated detect cut,
  a classifier's 0.5), the protocol of Sentinel, the MCP tool-poisoning study, WildGuard and RP-Mod;
- ``best_f1``: F1 at the best cut on the set itself (ShieldGemma's optimal-F1 protocol), named as an upper bound;
- ``auroc``: area under the ROC curve (the RP-Mod / RP-Crowd paper);
- ``auprc``: average precision (``scoreboard.average_precision``; Llama Guard's protocol on the OpenAI moderation set).

Every set with negatives also reports TPR at 0.1 % FPR. Robustness: ``obfuscate`` renders a positive under
zero-width characters, Unicode tags, base64, leetspeak or homoglyphs (``generators.OBFUSCATIONS``), and
the sampled positives of every benchmark with English rows in the runner's own German translation
(``research/l1-threat/competitors_de.yaml``, ``ark_authored``, keyed by ``text_key``); ``tpr_drop`` is the TPR lost
at the same cut as on the clean rows.

    python3 scripts/l1_threat/competitors.py check
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DATASETS = HERE / "datasets.yaml"
ENTITY_MAP = ROOT / "research" / "l1-threat" / "entity_map.yaml"
PUBLISHED = ROOT / "research" / "l1-threat" / "competitors.yaml"
TRANSLATIONS = ROOT / "research" / "l1-threat" / "competitors_de.yaml"


SCOREBOARD = sys.modules.get("_ark_l1_threat_scoreboard")
if SCOREBOARD is None:
    _spec = importlib.util.spec_from_file_location("_ark_l1_threat_scoreboard", HERE / "scoreboard.py")
    assert _spec is not None and _spec.loader is not None
    SCOREBOARD = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = SCOREBOARD
    _spec.loader.exec_module(SCOREBOARD)
BASELINES = SCOREBOARD.BASELINES
CLASSES = SCOREBOARD.CLASSES

PROTOCOLS = ("tpr_at_fpr", "f1_at_cut", "best_f1", "auprc", "auroc")
DECISIVE_FPR = 0.001
OBFUSCATION_KINDS = SCOREBOARD.OBFUSCATION_KINDS
BENCHMARK_KEYS = {"id", "name", "classes", "languages", "source", "licence", "revision", "commercial", "eval_only",
                  "protocol", "note"}
SCHEMA = "ark-l1-threat-competitors-v1"
TRANSLATIONS_SCHEMA = "ark-l1-threat-competitors-de-v1"
# Positives per benchmark with English rows that are translated to German: the lowest ``text_key`` values.
TRANSLATION_SAMPLE = 30
OPTIONAL_BENCHMARK_KEYS = {"dataset", "targets", "files", "format", "text", "positive", "rows", "pending", "dropped"}
CORPORA = SCOREBOARD.CORPORA
PII_LATENCY = sys.modules.get("_ark_l1_pii_latency") or SCOREBOARD._load_file(
    "_ark_l1_pii_latency", ROOT / "scripts" / "l1_presidio" / "latency.py")
# Systems measured by ``run``: rules only on the L1 score curve, the L1 model through the calibrated cascade config of
# the scoreboard (its answer as ``scoreboard.decision_score``), as ``refresh`` runs them; the Wolf cascade is not run.


def run_systems() -> dict[str, dict[str, Any]]:
    return {"rules": SCOREBOARD.L1_CASCADE, "l1_model": SCOREBOARD.load_config(ROOT / SCOREBOARD.CASCADE_CONFIG)}
SHA256 = re.compile(r"[0-9a-f]{64}")
CITATION = re.compile(r"https://\S+")


# ── protocol adapters ────────────────────────────────────────────────────────


def f1_at_cut(pos: list[float], neg: list[float], cut: float) -> dict[str, Any]:
    """Precision, recall and F1 of the decision ``score >= cut`` (a score of 0 never flags)."""
    tp = sum(1 for s in pos if s > 0 and s >= cut)
    fp = sum(1 for s in neg if s > 0 and s >= cut)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(pos) if pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"cut": cut, "tp": tp, "fp": fp, "precision": precision, "recall": recall, "f1": f1,
            "fpr": fp / len(neg) if neg else None}


def best_f1(pos: list[float], neg: list[float]) -> dict[str, Any]:
    """F1 at the best cut over every distinct positive score (an upper bound: the cut is chosen on the set)."""
    best = f1_at_cut(pos, neg, float("inf"))
    for cut in sorted({s for s in pos if s > 0}):
        cell = f1_at_cut(pos, neg, cut)
        if cell["f1"] > best["f1"]:
            best = cell
    return best


def auroc(pos: list[float], neg: list[float]) -> float | None:
    """Area under the ROC curve: the share of positive/negative pairs ranked right, ties count half."""
    if not pos or not neg:
        return None
    ranked = sorted(neg)
    wins = sum(bisect.bisect_left(ranked, s) + 0.5 * (bisect.bisect_right(ranked, s) - bisect.bisect_left(ranked, s))
               for s in pos)
    return wins / (len(pos) * len(neg))


def evaluate(benchmark: dict[str, Any], pos: list[float], neg: list[float], pos_flag: list[bool],
             neg_flag: list[bool]) -> dict[str, Any]:
    """One system on one benchmark under the benchmark's protocol: ``pos``/``neg`` are its scores, ``*_flag`` its own
    decisions (the shipped or calibrated detect cut), which ``f1_at_cut`` scores."""
    protocol = benchmark["protocol"]
    out: dict[str, Any] = {"protocol": protocol, "positives": len(pos), "negatives": len(neg)}
    if protocol == "tpr_at_fpr":
        out["tpr_at_fpr"] = {f"{t:g}": BASELINES.matched_fpr(pos, neg, t) for t in benchmark["targets"]}
    elif protocol == "f1_at_cut":
        out["f1"] = f1_at_cut([float(f) for f in pos_flag], [float(f) for f in neg_flag], 1.0)
    elif protocol == "best_f1":
        out["f1"] = best_f1(pos, neg)
    elif protocol == "auroc":
        out["auroc"] = auroc(pos, neg)
    elif protocol == "auprc":
        out["auprc"] = SCOREBOARD.average_precision(pos, neg)
    else:
        raise ValueError(f"unknown protocol {protocol!r}")
    if neg:
        out["tpr_at_0.001"] = BASELINES.matched_fpr(pos, neg, DECISIVE_FPR)
    return out


# ── robustness ───────────────────────────────────────────────────────────────


def obfuscate(text: str, kind: str) -> str:
    if kind not in OBFUSCATION_KINDS:
        raise ValueError(f"unknown obfuscation {kind!r}")
    return SCOREBOARD.GENERATORS.OBFUSCATIONS[kind](text)


def tpr_drop(clean: list[bool], variant: list[bool]) -> float | None:
    """TPR on the clean positives minus TPR on their variants (obfuscated or translated), both at the system's own
    decision."""
    if not clean or not variant:
        return None
    return sum(clean) / len(clean) - sum(variant) / len(variant)


def drops(pos: list[str], flag: Any, variant_ids: set[str]) -> dict[str, float | None]:
    """The TPR drop under each obfuscation over every positive and, under ``de``, over the positives that have a
    German translation (``<id>~de`` in ``variant_ids``), compared with the same positives clean."""
    out = {kind: tpr_drop([flag(i) for i in pos], [flag(f"{i}~{kind}") for i in pos]) for kind in OBFUSCATION_KINDS}
    translated = [i for i in pos if f"{i}~de" in variant_ids]
    if translated:
        out["de"] = tpr_drop([flag(i) for i in translated], [flag(f"{i}~de") for i in translated])
    return out


def text_key(text: str) -> str:
    """The key of a benchmark text in the translation file (no benchmark text is stored next to its translation)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def translation_sample(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The positives of a benchmark that get a German translation: the ``TRANSLATION_SAMPLE`` lowest ``text_key``."""
    return sorted((row for row in rows if row["positive"]), key=lambda row: text_key(row["text"]))[:TRANSLATION_SAMPLE]


# ── registry ─────────────────────────────────────────────────────────────────


def _repo(source: str) -> str:
    """``owner/name`` of a Hugging Face or GitHub source in either spelling (URL or ``hf:``/``github:``)."""
    text = re.sub(r"^(?:https://(?:huggingface\.co/datasets|github\.com)/|hf:|github:)", "", source.strip())
    return "/".join(text.split()[0].split("/")[:2]).lower()


def check(registry: dict[str, Any], emap: dict[str, Any], published: dict[str, Any],
          translations: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    datasets = {d["id"]: d for d in emap.get("datasets") or []}
    holdout_repos = {_repo(d["source"]) for d in datasets.values() if d["split"] == "holdout" and "/" in d["source"]}
    benchmarks = {}
    for entry in registry.get("benchmarks") or []:
        where = f"benchmark {entry.get('id')}"
        benchmarks[entry.get("id")] = entry
        missing, unknown = BENCHMARK_KEYS - set(entry), set(entry) - BENCHMARK_KEYS - OPTIONAL_BENCHMARK_KEYS
        if missing or unknown:
            problems.append(f"{where}: missing {sorted(missing)} or unknown keys {sorted(unknown)}")
            continue
        if entry["eval_only"] is not True:
            problems.append(f"{where}: a competitor benchmark is evaluation only (eval_only: true)")
        if entry["commercial"] not in (True, False, "unknown"):
            problems.append(f"{where}: commercial must be true, false or unknown")
        if entry["protocol"] not in PROTOCOLS:
            problems.append(f"{where}: protocol must be one of {PROTOCOLS}")
        if entry["protocol"] == "tpr_at_fpr" and not entry.get("targets"):
            problems.append(f"{where}: protocol tpr_at_fpr needs targets")
        if not set(entry["classes"]) <= set(CLASSES):
            problems.append(f"{where}: unknown classes {sorted(set(entry['classes']) - set(CLASSES))}")
        if _repo(entry["source"]) in holdout_repos:
            problems.append(f"{where}: {entry['source']} is a holdout source")
        dataset = datasets.get(entry.get("dataset", ""))
        if "dataset" in entry and (dataset is None or dataset["split"] == "holdout"):
            problems.append(f"{where}: dataset {entry['dataset']!r} must be a registered non-holdout set")
        live = not entry.get("pending") and not entry.get("dropped")
        if live and not entry.get("positive"):
            problems.append(f"{where}: a measured benchmark names its positive rows (positive)")
        if live and "dataset" not in entry and not (
                entry.get("files") and all(SHA256.fullmatch(str(f.get("sha256", ""))) for f in entry["files"])):
            problems.append(f"{where}: a measured benchmark pins its files by SHA-256 (or reuses a registered dataset)")
        if live and dataset is not None and dataset["split"] == "train_dev":
            problems.append(f"{where}: dataset {entry['dataset']!r} is dev data (training, calibration)")
    if translations.get("schema") != TRANSLATIONS_SCHEMA or translations.get("family") != "ark_authored":
        problems.append(f"translations: schema must be {TRANSLATIONS_SCHEMA} and family ark_authored")
    for key, text in (translations.get("rows") or {}).items():
        if not re.fullmatch(r"[0-9a-f]{16}", str(key)) or not isinstance(text, str) or not text.strip():
            problems.append(f"translations: {key!r} needs a text_key and a German text")
    if published.get("schema") != SCHEMA:
        problems.append(f"published numbers: schema must be {SCHEMA}")
    for number in published.get("numbers") or []:
        where = f"published {number.get('benchmark')}/{number.get('system')}"
        if number.get("benchmark") not in benchmarks:
            problems.append(f"{where}: unknown benchmark")
        if not CITATION.fullmatch(str(number.get("url", ""))) or not str(number.get("table", "")).strip():
            problems.append(f"{where}: needs the source url and the table or section it was read from")
        if not isinstance(number.get("value"), (int, float)) or not number.get("metric"):
            problems.append(f"{where}: needs a numeric value and its metric")
    return problems


def gaps(registry: dict[str, Any]) -> list[str]:
    """Classes no live benchmark measures."""
    covered = {cls for entry in registry.get("benchmarks") or [] if not entry.get("dropped") for cls in entry["classes"]}
    return [cls for cls in CLASSES if cls not in covered]


# ── measurement ──────────────────────────────────────────────────────────────


def recipe(entry: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    """The fetch-and-read recipe of a benchmark: its own keys over the registered dataset's recipe it reuses."""
    base = next((d for d in registry.get("datasets") or [] if d["id"] == entry.get("dataset")), {})
    merged = {**{k: base[k] for k in ("source", "revision", "files", "format", "text") if k in base}, **entry}
    if "dataset" in entry:
        merged.update({k: base[k] for k in ("source", "revision", "files")})
    # read_records reads the columns the label rules name (parquet).
    merged["labels"] = [*entry["positive"], *entry.get("rows", [])]
    return merged


def benchmark_rows(entry: dict[str, Any], registry: dict[str, Any], sources: Path, offline: bool) -> list[dict[str, Any]]:
    """``{id, text, positive}`` of every row of the benchmark's split (``rows``), fetched and verified."""
    full = recipe(entry, registry)
    root = CORPORA.fetch({**full, "id": entry["id"]}, sources, offline)
    out = []
    for record in CORPORA.read_records(full, root):
        if not all(CORPORA.rule_matches(rule, record) for rule in entry.get("rows", [])):
            continue
        text = CORPORA._text_value(CORPORA._field(record, full["text"]) or "")
        if text.strip():
            out.append({"id": f"{entry['id']}:{len(out)}", "text": text,
                        "positive": any(CORPORA.rule_matches(rule, record) for rule in entry["positive"])})
    return out


def variants(rows: list[dict[str, Any]], translations: dict[str, str]) -> list[dict[str, Any]]:
    """Every positive again under each obfuscation, id ``<id>~<kind>``, and in German, id ``<id>~de``, where
    ``translations`` (text_key -> German text) has it."""
    obfuscated = [{"id": f"{row['id']}~{kind}", "text": obfuscate(row["text"], kind), "positive": True}
                  for row in rows if row["positive"] for kind in OBFUSCATION_KINDS]
    return obfuscated + [{"id": f"{row['id']}~de", "text": translations[text_key(row["text"])], "positive": True}
                         for row in rows if row["positive"] and text_key(row["text"]) in translations]


def predict(rows: list[dict[str, Any]], binary: Path, config: dict[str, Any], work: Path) -> dict[str, dict[str, Any]]:
    """Core predictions by row id (the scoreboard's predictor, one process over all rows)."""
    work.mkdir(parents=True, exist_ok=True)
    config_path = work / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    payload = "".join(json.dumps({"id": r["id"], "text": r["text"]}) + "\n" for r in rows).encode("utf-8")
    result = subprocess.run([str(binary), str(config_path)], input=payload, capture_output=True)
    if result.returncode != 0:
        # Errors never echo benchmark text.
        raise RuntimeError(f"Core prediction failed (exit {result.returncode})")
    return {p["id"]: p for p in map(json.loads, result.stdout.decode("utf-8").splitlines())}


def system_result(entry: dict[str, Any], rows: list[dict[str, Any]], predictions: dict[str, dict[str, Any]],
                  curve: bool) -> dict[str, Any]:
    """Protocol result of one system on one benchmark, with the TPR drop under each obfuscation and in German
    translation (``drops``); the score of a row
    is the highest over the benchmark's classes, of the L1 score curve (``curve``) or of the cascade's answer, and a
    row is flagged by L1's detections (``curve``) or by the cascade's final decision."""
    def score(row_id: str) -> float:
        p = predictions[row_id]
        return max(float((p.get("scores") or {}).get(cls, 0.0)) if curve else
                   SCOREBOARD.decision_score(SCOREBOARD._stage(p, cls)) for cls in entry["classes"])

    def flag(row_id: str) -> bool:
        p = predictions[row_id]
        return any(cls in (p.get("flagged") or []) if curve else SCOREBOARD._stage(p, cls)["decision"] == "detected"
                   for cls in entry["classes"])

    pos = [r["id"] for r in rows if r["positive"]]
    neg = [r["id"] for r in rows if not r["positive"]]
    out = evaluate(entry, [score(i) for i in pos], [score(i) for i in neg], [flag(i) for i in pos],
                   [flag(i) for i in neg])
    out["drops"] = drops(pos, flag, set(predictions))
    return out


def reference_result(entry: dict[str, Any], rows: list[dict[str, Any]], model: Any,
                     translations: dict[str, str]) -> dict[str, Any] | None:
    """A reference classifier (``run_baselines.ReferenceBaseline``) on one benchmark under its protocol, deciding at
    0.5 like its model card; None when it scores none of the benchmark's classes."""
    classes = [cls for cls in entry["classes"] if cls in model.classes]
    if not classes:
        return None
    every = rows + variants(rows, translations)
    scores = {row["id"]: max(out["scores"][cls] for cls in classes)
              for row, out in zip(every, model.score([row["text"] for row in every]))}
    pos = [r["id"] for r in rows if r["positive"]]
    neg = [r["id"] for r in rows if not r["positive"]]
    out = evaluate(entry, [scores[i] for i in pos], [scores[i] for i in neg], [scores[i] >= 0.5 for i in pos],
                   [scores[i] >= 0.5 for i in neg])
    out["drops"] = drops(pos, lambda i: scores[i] >= 0.5, set(scores))
    return out


def reference_latency(texts: list[str], model: Any) -> dict[str, Any]:
    """p50 / p95 ms per window and the 1 KiB throughput of a reference classifier (onnxruntime on CPU)."""
    row: dict[str, Any] = {}
    for name, (size, count) in WINDOWS.items():
        ms = []
        for text in windows(texts, size, count):
            started = time.perf_counter()
            model.score([text])
            ms.append((time.perf_counter() - started) * 1000.0)
        if ms:
            row[name] = SCOREBOARD._quantiles(ms)
            if name == "1KiB":
                row["throughput"] = round(1000.0 * len(ms) / sum(ms))
    return row


# Latency windows: UTF-8 sizes, and how many windows of each the benchmark texts are packed into.
WINDOWS = {"1KiB": (1024, 200), "100KiB": (100 * 1024, 20)}


def windows(texts: list[str], size: int, count: int) -> list[str]:
    """Up to ``count`` windows of exactly ``size`` UTF-8 bytes, packed from the texts in order (cut at a character
    boundary); each text is used once."""
    out, current = [], b""
    for text in texts:
        if len(out) >= count:
            break
        current += (text + "\n").encode("utf-8")
        while len(current) >= size and len(out) < count:
            out.append(current[:size].decode("utf-8", errors="ignore"))
            current = current[size:]
    return out


def latency(texts: list[str], binary: Path, work: Path) -> dict[str, Any]:
    """Per system and window size p50 / p95 of Core's scan milliseconds (one process, one row at a time) and the
    throughput at 1 KiB (rows per second of scan time)."""
    out = {}
    for system, config in run_systems().items():
        row = {}
        for name, (size, count) in WINDOWS.items():
            rows = [{"id": f"{name}:{i}", "text": t} for i, t in enumerate(windows(texts, size, count))]
            ms = [float(p["ms"]["scan"]) for p in predict(rows, binary, config, work / f"latency-{system}").values()]
            if ms:
                row[name] = SCOREBOARD._quantiles(ms)
                if name == "1KiB":
                    row["throughput"] = round(1000.0 * len(ms) / sum(ms)) if sum(ms) else None
        out[dict(SCOREBOARD.COMPETITOR_SYSTEMS)[system]] = row
    return out


def result_key(entry: dict[str, Any], binary: Path | None, references: list[Any], translations: dict[str, str]) -> str:
    """Cache key of one benchmark's result: the benchmark, every system's config (so a changed calibration is
    measured again), the predictor build, the reference classifiers and the German translations."""
    inputs = [entry, run_systems() if binary else {}, binary and binary.stat().st_mtime_ns, [m.id for m in references],
              translations]
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def run(registry: dict[str, Any], binary: Path | None, sources: Path, work: Path, offline: bool = False,
        references: list[Any] = (), only: set[str] | None = None,
        translations: dict[str, str] | None = None) -> dict[str, Any]:
    """Every live benchmark through every ``run_systems`` system and every reference classifier (``references``,
    ``run_baselines.reference_baselines``), on the benchmarks of ``only`` when given; without ``binary`` ARK is not
    run (a separate reference run); ``translations`` (text_key -> German text) adds the German variants. The ``results`` are what ``scoreboard.py competitors`` renders and merges."""
    machine = PII_LATENCY.machine_info()
    results: dict[str, Any] = {"benchmarks": {},
                               "machine": f"{machine['cpu']}, {machine['cpus_usable']} usable CPUs, {machine['system']}"}
    texts: list[str] = []
    live = [e for e in registry.get("benchmarks") or []
            if not e.get("pending") and not e.get("dropped") and (not only or e["id"] in only)]
    # Smallest first; each benchmark's result is kept under ``work`` (per input hash), so an aborted run resumes.
    for entry in sorted(live, key=lambda e: len(benchmark_rows(e, registry, sources, offline))):
        rows = benchmark_rows(entry, registry, sources, offline)
        texts += [row["text"] for row in rows]
        done = work / f"{entry['id']}-{result_key(entry, binary, references, translations or {})}.json"
        if done.is_file():
            results["benchmarks"][entry["id"]] = json.loads(done.read_text(encoding="utf-8"))
            continue
        systems = {}
        for system, config in run_systems().items() if binary else ():
            predictions = predict(rows + variants(rows, translations or {}), binary, config, work / system)
            systems[system] = system_result(entry, rows, predictions, curve=system == "rules")
        for model in references:
            result = reference_result(entry, rows, model, translations or {})
            if result is not None:
                systems[model.id] = result
        results["benchmarks"][entry["id"]] = {"rows": len(rows), "positives": sum(r["positive"] for r in rows),
                                              "systems": systems}
        work.mkdir(parents=True, exist_ok=True)
        done.write_text(json.dumps(results["benchmarks"][entry["id"]]), encoding="utf-8")
    results["latency"] = latency(texts, binary, work) if binary else {}
    for model in references:
        results["latency"][dict(SCOREBOARD.FAIR_SYSTEMS)[model.id]] = reference_latency(texts, model)
    return results


def read(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """The benchmark registry (``datasets.yaml``), the cited published numbers and the German translations."""
    return read(DATASETS), read(PUBLISHED), read(TRANSLATIONS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="check the benchmark recipes, the cited competitor numbers and the translations")
    t = commands.add_parser("sample", help="write the positives to translate to German (text_key -> text, JSON)")
    t.add_argument("--sources", type=Path, required=True, help="download cache of the benchmark files")
    t.add_argument("--offline", action="store_true")
    t.add_argument("--output", type=Path, required=True)
    r = commands.add_parser("run", help="measure ARK on every live benchmark (results JSON for scoreboard.py)")
    r.add_argument("--predictor", type=Path, help=f"built {SCOREBOARD.PREDICTOR} example (without: references only)")
    r.add_argument("--benchmark", action="append", default=[], help="only these benchmark ids (repeatable)")
    r.add_argument("--sources", type=Path, required=True, help="download cache of the benchmark files")
    r.add_argument("--work", type=Path, required=True, help="scratch directory")
    r.add_argument("--offline", action="store_true")
    r.add_argument("--models", type=Path, help="reference models (ONNX), e.g. ~/ark-threat/baselines/models")
    r.add_argument("--reference", action="append", default=[], choices=sorted(BASELINES.REFERENCE_MODELS),
                   help="reference classifier to run next to ARK (repeatable; needs --models)")
    r.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    registry, published, translations = load()
    problems = check(registry, read(ENTITY_MAP), published, translations)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems or args.command == "check":
        return 1 if problems else 0
    if args.command == "sample":
        sample = {text_key(row["text"]): row["text"]
                  for entry in registry.get("benchmarks") or []
                  if not entry.get("pending") and not entry.get("dropped") and "en" in entry["languages"]
                  for row in translation_sample(benchmark_rows(entry, registry, args.sources, args.offline))}
        args.output.write_text(json.dumps(sample, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        return 0
    references = BASELINES.reference_baselines(read(ENTITY_MAP), args.models, set(args.reference)) if args.reference else []
    results = run(registry, args.predictor, args.sources, args.work, args.offline, references, set(args.benchmark),
                  translations.get("rows") or {})
    args.output.write_text(json.dumps(results, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
