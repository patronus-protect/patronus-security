#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the threat baselines over frozen corpora and sweep thresholds for matched FPR (E04).

Every baseline of ``research/l1-threat/entity_map.yaml`` gives one score per document and class:

- heuristic rows (ATR, pipelock, Cisco mcp-scanner YARA, prompt-guard, LlamaFirewall regex, NeMo
  YARA, Vigil YARA): the rule bodies come from the upstream clones at the commit pinned in
  ``oss_rules.yaml``, read by the inventory's own extractors; a rule counts for the class the
  inventory gives it (no class, handoff or out of scope: not run). The score of a class is the
  number of distinct rules of that class that match the document. Regex bodies run with Python
  ``re``, YARA text strings as literals, both case-insensitive; a rule matches when any of its
  bodies does (YARA conditions and ATR operators are not evaluated); hex, semantic and inactive
  rules are not run, and bodies Python cannot compile are listed in the cache metadata.
  LlamaFirewall adds its hidden-ASCII scanner (Unicode tag characters); CodeShield needs its own
  toolchain and is not run.
- reference rows (ProtectAI v2, Prompt Guard 2 86M and 22M): the ONNX model under
  ``--models`` through onnxruntime and ``tokenizers`` (no torch); the score is the highest
  probability of the attack label over 512-token windows, for every class the entity map maps
  that label to.

Predictions are computed once per corpus file and baseline version and cached under
``CACHE/<baseline>/<version>/<set>-<sha12>.jsonl`` with a ``.json`` metadata file: the key is the
SHA-256 of the corpus file from its manifest and the baseline version (runner version, upstream
commit and rule-set hash, or model file hash). A cached file is never recomputed. ``sweep``
reads one version per baseline, the most recently written one, and lists the sets not cached under
it as ``missing`` instead of pooling scores of different versions.

    python3 scripts/l1_threat/run_baselines.py clone --src DIR
    python3 scripts/l1_threat/run_baselines.py run --corpus DIR [--corpus DIR ...] --cache CACHE \
        [--src DIR] [--models DIR] [--baseline ID ...]
    python3 scripts/l1_threat/run_baselines.py sweep --corpus DIR [...] --cache CACHE [--fpr 0.01 0.001] \
        [--output sweep.json]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import multiprocessing
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("_ark_l1_threat_prepare_corpora", HERE / "prepare_corpora.py")
assert _SPEC is not None and _SPEC.loader is not None
prepare_corpora = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = prepare_corpora
_SPEC.loader.exec_module(prepare_corpora)
# Loaded under their own names, like prepare_corpora's entity_map: other script directories have
# modules of the same name.
entity_map = prepare_corpora.entity_map
generators = prepare_corpora._load_file("_ark_l1_threat_generators", HERE / "generators.py")
oss_inventory = prepare_corpora._load_file("_ark_l1_threat_oss_inventory", HERE / "oss_inventory.py")

RUNNER_VERSION = "1"
PREDICTIONS_SCHEMA = "ark-l1-threat-baseline-predictions-v1"
SWEEP_SCHEMA = "ark-l1-threat-baseline-sweep-v1"
DEFAULT_FPRS = (0.01, 0.001)
WINDOW_TOKENS = 512
MAX_WINDOWS = 32
HIDDEN_ASCII = re.compile("[\U000e0000-\U000e007f]")
# Python ``re`` takes global flags only at the start; inventory bodies may carry text before them.
GLOBAL_FLAGS = re.compile(r"\(\?[aiLmsux]+\)")
# Reference rows: run id -> (entity-map baseline, model directory under --models, attack label index).
REFERENCE_MODELS = {
    "protectai_v2": ("protectai_v2", "protectai-v2/onnx", 1),
    "prompt_guard_2_86m": ("prompt_guard_2", "Llama-Prompt-Guard-2-86M-onnx", 1),
    "prompt_guard_2_22m": ("prompt_guard_2", "Llama-Prompt-Guard-2-22M-onnx", 1),
}
# Deterministic scanners of a heuristic baseline beyond its inventory rules: label -> matcher.
EXTRA_SCANNERS: dict[str, dict[str, Callable[[str], bool]]] = {
    "llamafirewall": {"HIDDEN_ASCII scanner: BLOCK": lambda text: HIDDEN_ASCII.search(text) is not None},
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --- baselines -------------------------------------------------------------------------------


class Baseline:
    """One scoreboard row: ``id``, ``version``, the classes it scores and ``score(texts)``."""

    id: str
    version: str
    classes: list[str]
    meta: dict[str, Any]

    def score(self, texts: list[str]) -> list[dict[str, Any]]:
        raise NotImplementedError


def _label_classes(baseline: dict[str, Any], label: str) -> list[str]:
    entry = next(e for e in baseline.get("labels", []) if e["label"] == label)
    return list(entry.get("classes", []))


def _python_regex(body: str, kind: str) -> str:
    if kind == "text":
        return re.escape(body)
    flags = GLOBAL_FLAGS.search(body)
    return body[flags.start():] if flags else body


class HeuristicBaseline(Baseline):
    def __init__(self, baseline: dict[str, Any], source: dict[str, Any], raws: Iterable[dict[str, Any]],
                 inventory_rules: dict[str, dict[str, Any]], commit: str):
        self.id = baseline["id"]
        self.rules: list[tuple[str, str, list[re.Pattern[str]]]] = []
        uncompiled: list[str] = []
        digest = hashlib.sha256()
        for raw in raws:
            rule = inventory_rules.get(raw["id"])
            if rule is None or rule["class"] is None or not raw["active"] or raw["kind"] in ("hex", "semantic"):
                continue
            patterns = []
            for body in raw["bodies"]:
                try:
                    patterns.append(re.compile(_python_regex(body, raw["kind"]), re.IGNORECASE))
                except re.error:
                    uncompiled.append(raw["id"])
            if patterns:
                self.rules.append((raw["id"], rule["class"], patterns))
                digest.update(f"{raw['id']}\0{rule['class']}\0{raw['kind']}\0".encode())
                digest.update("\0".join(raw["bodies"]).encode())
        self.extras = [(label, matcher, _label_classes(baseline, label))
                       for label, matcher in EXTRA_SCANNERS.get(self.id, {}).items()]
        self.classes = sorted({cls for _, cls, _ in self.rules} | {c for *_, cs in self.extras for c in cs})
        self.version = f"r{RUNNER_VERSION}-{commit[:12]}-{digest.hexdigest()[:12]}"
        self.meta = {"kind": "heuristic", "source": source["id"], "commit": commit, "rules": len(self.rules),
                     "uncompiled": sorted(set(uncompiled)), "scanners": [label for label, *_ in self.extras]}

    def score(self, texts: list[str]) -> list[dict[str, Any]]:
        out = []
        for text in texts:
            hits: dict[str, list[str]] = defaultdict(list)
            for rule_id, cls, patterns in self.rules:
                if any(p.search(text) for p in patterns):
                    hits[cls].append(rule_id)
            for label, matcher, classes in self.extras:
                if matcher(text):
                    for cls in classes:
                        hits[cls].append(label)
            out.append({"scores": {cls: len(hits.get(cls, [])) for cls in self.classes},
                        "hits": {cls: ids for cls, ids in sorted(hits.items())}})
        return out


def softmax(row: list[float]) -> list[float]:
    top = max(row)
    exps = [math.exp(v - top) for v in row]
    total = sum(exps)
    return [v / total for v in exps]


def windows(ids: list[int], cls_id: int, sep_id: int, size: int = WINDOW_TOKENS,
            limit: int = MAX_WINDOWS) -> list[list[int]]:
    """``[CLS] chunk [SEP]`` windows over the token ids; an empty text gives one empty window."""
    step = size - 2
    chunks = [ids[i:i + step] for i in range(0, len(ids), step)][:limit] or [[]]
    return [[cls_id, *chunk, sep_id] for chunk in chunks]


class ReferenceBaseline(Baseline):
    def __init__(self, run_id: str, baseline: dict[str, Any], model_dir: Path, attack_index: int,
                 session: Any = None, tokenizer: Any = None):
        self.id = run_id
        self.attack_index = attack_index
        self.window_tokens = WINDOW_TOKENS
        label = next(e for e in baseline["labels"] if e.get("classes"))
        self.classes = list(label["classes"])
        model = model_dir / "model.onnx"
        if session is None:
            import onnxruntime  # baselines venv only

            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = int(os.environ.get("ARK_BASELINE_THREADS", "0"))
            session = onnxruntime.InferenceSession(str(model), options, providers=["CPUExecutionProvider"])
        if tokenizer is None:
            from tokenizers import Tokenizer  # baselines venv only

            tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.session = session
        self.tokenizer = tokenizer
        self.cls_id = tokenizer.token_to_id("[CLS]")
        self.sep_id = tokenizer.token_to_id("[SEP]")
        self.version = f"r{RUNNER_VERSION}-{sha256_file(model)[:12]}"
        self.meta = {"kind": "reference", "baseline": baseline["id"], "model": model_dir.name,
                     "attack_label": label["label"], "window_tokens": WINDOW_TOKENS, "max_windows": MAX_WINDOWS}

    def score(self, texts: list[str]) -> list[dict[str, Any]]:
        import numpy as np

        out = []
        for text in texts:
            ids = self.tokenizer.encode(text, add_special_tokens=False).ids
            best = 0.0
            for window in windows(ids, self.cls_id, self.sep_id, self.window_tokens):
                feed = {"input_ids": np.array([window], dtype=np.int64),
                        "attention_mask": np.ones((1, len(window)), dtype=np.int64)}
                logits = self.session.run(None, feed)[0][0]
                best = max(best, softmax([float(v) for v in logits])[self.attack_index])
            out.append({"scores": {cls: round(best, 6) for cls in self.classes}})
        return out


def heuristic_baselines(emap: dict[str, Any], inventory: dict[str, Any], src: Path,
                        wanted: set[str] | None) -> list[Baseline]:
    sources = {s["id"]: s for s in inventory["sources"]}
    by_source: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for rule in inventory["rules"]:
        by_source[rule["source"]][rule["id"]] = rule
    out: list[Baseline] = []
    for baseline in emap["baselines"]:
        if baseline["kind"] != "heuristic" or (wanted is not None and baseline["id"] not in wanted):
            continue
        source = sources[baseline["rules"]]
        clone = src / source["clone"]
        commit = oss_inventory.git_head(clone)
        if commit != source["commit"]:
            raise SystemExit(f"{baseline['id']}: clone at {commit}, oss_rules.yaml pins {source['commit']}")
        raws = oss_inventory.EXTRACT[source["extractor"]](clone, source["paths"])
        out.append(HeuristicBaseline(baseline, source, raws, by_source[source["id"]], commit))
    return out


def reference_baselines(emap: dict[str, Any], models: Path, wanted: set[str] | None) -> list[Baseline]:
    baselines = {b["id"]: b for b in emap["baselines"]}
    return [ReferenceBaseline(run_id, baselines[map_id], models / directory, index)
            for run_id, (map_id, directory, index) in REFERENCE_MODELS.items()
            if wanted is None or run_id in wanted]


def clone_sources(inventory: dict[str, Any], src: Path, baseline_ids: Iterable[str]) -> None:
    """Clone the sources of the heuristic baselines to ``src/<clone>`` at their pinned commit."""
    sources = {s["id"]: s for s in inventory["sources"]}
    for source_id in baseline_ids:
        source = sources[source_id]
        target = src / source["clone"]
        if not target.exists():
            subprocess.run(["git", "clone", "--quiet", source["repo"], str(target)], check=True)
        subprocess.run(["git", "-C", str(target), "checkout", "--quiet", source["commit"]], check=True)


# --- corpora and cache -----------------------------------------------------------------------


def corpus_sets(directory: Path) -> Iterator[tuple[str, Path, str]]:
    """``(set id, file, sha256)`` of every set of a frozen corpus or generated directory."""
    problems = prepare_corpora.verify(directory, schemas=(prepare_corpora.CORPORA_SCHEMA, generators.SCHEMA))
    if problems:
        raise SystemExit(f"{directory}: " + "; ".join(problems))
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    for set_id, entry in sorted(manifest["sets"].items()):
        yield set_id, directory / entry["file"], entry["sha256"]


def read_rows(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def cache_path(cache: Path, baseline_id: str, version: str, set_id: str, sha: str) -> Path:
    return cache / baseline_id / version / f"{set_id}-{sha[:12]}.jsonl"


_WORKER: Baseline | None = None


def _score_chunk(texts: list[str]) -> list[dict[str, Any]]:
    assert _WORKER is not None
    return _WORKER.score(texts)


def _chunks(rows: Iterable[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    chunk: list[dict[str, Any]] = []
    for row in rows:
        chunk.append(row)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def predict_set(baseline: Baseline, set_id: str, path: Path, sha: str, cache: Path, jobs: int = 1,
                batch: int = 64) -> tuple[Path, bool]:
    """Write the predictions of one corpus file unless cached; returns the path and whether it ran.

    With ``jobs > 1`` the heuristic rows score in forked workers (reference rows use onnxruntime's
    own threads and always run in-process).
    """
    global _WORKER
    target = cache_path(cache, baseline.id, baseline.version, set_id, sha)
    if target.exists() and target.with_suffix(".json").exists():
        return target, False
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".jsonl.tmp")
    rows = 0
    _WORKER = baseline
    chunks = list(_chunks(read_rows(path), batch))
    texts = ([r["text"] for r in chunk] for chunk in chunks)
    pool = None
    if jobs > 1 and isinstance(baseline, HeuristicBaseline) and len(chunks) > 1:
        pool = multiprocessing.get_context("fork").Pool(jobs)
        scored_chunks: Iterable[list[dict[str, Any]]] = pool.imap(_score_chunk, texts)
    else:
        scored_chunks = map(_score_chunk, texts)
    try:
        with tmp.open("w", encoding="utf-8") as out:
            for chunk, scored in zip(chunks, scored_chunks):
                for row, pred in zip(chunk, scored):
                    out.write(json.dumps({"id": row["id"], **pred}, sort_keys=True, ensure_ascii=False) + "\n")
                    rows += 1
    finally:
        if pool is not None:
            pool.close()
            pool.join()
        _WORKER = None
    meta = {"schema": PREDICTIONS_SCHEMA, "baseline": baseline.id, "version": baseline.version, "set": set_id,
            "corpus_sha256": sha, "rows": rows, "classes": baseline.classes, **baseline.meta,
            "sha256": sha256_file(tmp)}
    tmp.replace(target)
    target.with_suffix(".json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return target, True


def latest_version(cache: Path, baseline_id: str) -> str | None:
    """The cached version of a baseline with the most recently written predictions, or None."""
    found = sorted((cache / baseline_id).glob("*/*.json"), key=lambda p: p.stat().st_mtime)
    return found[-1].parent.name if found else None


def cached_predictions(cache: Path, baseline_id: str, version: str, set_id: str, sha: str) -> Path | None:
    """The cached predictions of a corpus file for one baseline version, or None."""
    target = cache_path(cache, baseline_id, version, set_id, sha)
    meta_path = target.with_suffix(".json")
    if meta_path.is_file() and json.loads(meta_path.read_text(encoding="utf-8")).get("corpus_sha256") == sha:
        return target
    return None


# --- matched-FPR sweep -----------------------------------------------------------------------


def matched_fpr(positives: list[float], negatives: list[float], target: float) -> dict[str, Any] | None:
    """Lowest threshold ``t`` (a doc is flagged when ``score >= t``) with FPR <= ``target``.

    A score of 0 never flags; when no positive threshold meets the target, nothing is flagged.
    """
    if not negatives:
        return None
    candidates = sorted({s for s in [*positives, *negatives] if s > 0})
    neg = sorted(negatives)
    threshold = math.inf
    for value in candidates:
        fp = len(neg) - _bisect_left(neg, value)
        if fp / len(neg) <= target:
            threshold = value
            break
    fp = len(neg) - _bisect_left(neg, threshold)
    tp = sum(1 for s in positives if s >= threshold)
    return {"threshold": None if threshold == math.inf else threshold, "tpr": tp / len(positives) if positives else None,
            "fpr": fp / len(neg), "tp": tp, "fp": fp, "positives": len(positives), "negatives": len(neg)}


def _bisect_left(values: list[float], x: float) -> int:
    lo, hi = 0, len(values)
    while lo < hi:
        mid = (lo + hi) // 2
        if values[mid] < x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def sweep(rows: Iterable[tuple[dict[str, Any], dict[str, Any]]], classes: list[str],
          fprs: Iterable[float]) -> dict[str, Any]:
    """Per class and language (and ``all``): matched-FPR threshold and TPR.

    ``rows`` pairs a corpus row (``classes``, ``benign``, ``language``) with its prediction. A row is
    a positive of a class it carries in ``classes`` (reported-only classes do not count) and a
    negative of every class when ``benign``.
    """
    pos: dict[tuple[str, str], list[float]] = defaultdict(list)
    neg: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row, pred in rows:
        for language in ("all", row.get("language") or "unknown"):
            for cls in classes:
                score = pred["scores"].get(cls, 0)
                if cls in row["classes"]:
                    pos[cls, language].append(score)
                elif row["benign"]:
                    neg[cls, language].append(score)
    out: dict[str, Any] = {}
    for cls, language in sorted(set(pos) | set(neg)):
        cell = {f"{fpr:g}": matched_fpr(pos[cls, language], neg[cls, language], fpr) for fpr in fprs}
        out.setdefault(cls, {})[language] = cell
    return out


def sweep_baseline(corpora: list[Path], cache: Path, baseline_id: str, fprs: Iterable[float]) -> dict[str, Any]:
    """Sweep one baseline version (the latest cached one); sets without it are ``missing``.

    Scores of different versions are never pooled: a set cached only under an older version is
    missing, not mixed into the threshold sweep.
    """
    version = latest_version(cache, baseline_id)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    classes: set[str] = set()
    sets: list[str] = []
    missing: list[str] = []
    for directory in corpora:
        for set_id, path, sha in corpus_sets(directory):
            pred_path = cached_predictions(cache, baseline_id, version, set_id, sha) if version else None
            if pred_path is None:
                missing.append(set_id)
                continue
            meta = json.loads(pred_path.with_suffix(".json").read_text(encoding="utf-8"))
            classes.update(meta["classes"])
            sets.append(set_id)
            preds = {p["id"]: p for p in read_rows(pred_path)}
            pairs.extend((row, preds[row["id"]]) for row in read_rows(path))
    return {"baseline": baseline_id, "version": version, "sets": sets, "missing": missing,
            "classes": sweep(pairs, sorted(classes), fprs)}


# --- CLI -------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    clone = sub.add_parser("clone", help="clone the heuristic sources at their pinned commits")
    clone.add_argument("--src", type=Path, required=True)
    run = sub.add_parser("run", help="compute and cache predictions")
    run.add_argument("--corpus", type=Path, action="append", required=True)
    run.add_argument("--cache", type=Path, required=True)
    run.add_argument("--src", type=Path, help="heuristic source clones (see clone)")
    run.add_argument("--models", type=Path, help="reference model directory (ONNX)")
    run.add_argument("--baseline", action="append", help="run only these baselines (repeatable)")
    run.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="worker processes for heuristic rows")
    sw = sub.add_parser("sweep", help="matched-FPR thresholds from cached predictions")
    sw.add_argument("--corpus", type=Path, action="append", required=True)
    sw.add_argument("--cache", type=Path, required=True)
    sw.add_argument("--baseline", action="append", help="sweep only these baselines (repeatable)")
    sw.add_argument("--fpr", type=float, nargs="+", default=list(DEFAULT_FPRS))
    sw.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    emap = entity_map.load()
    inventory = oss_inventory.load()
    heuristic_ids = [b["id"] for b in emap["baselines"] if b["kind"] == "heuristic"]
    if args.command == "clone":
        clone_sources(inventory, args.src, [b["rules"] for b in emap["baselines"] if b["kind"] == "heuristic"])
        return 0
    if args.command == "run":
        wanted = set(args.baseline) if args.baseline else None
        unknown = (wanted or set()) - set(heuristic_ids) - set(REFERENCE_MODELS)
        if unknown:
            parser.error(f"unknown baseline(s): {', '.join(sorted(unknown))}")
        baselines: list[Baseline] = []
        if args.src:
            baselines += heuristic_baselines(emap, inventory, args.src, wanted)
        if args.models:
            baselines += reference_baselines(emap, args.models, wanted)
        if not baselines:
            parser.error("nothing to run: give --src and/or --models")
        for baseline in baselines:
            for directory in args.corpus:
                for set_id, path, sha in corpus_sets(directory):
                    target, ran = predict_set(baseline, set_id, path, sha, args.cache, args.jobs)
                    print(f"{baseline.id} {set_id}: {'computed' if ran else 'cached'} {target}")
        return 0
    ids = args.baseline or heuristic_ids + list(REFERENCE_MODELS)
    report = {"schema": SWEEP_SCHEMA, "fprs": args.fpr,
              "baselines": [sweep_baseline(args.corpus, args.cache, b, args.fpr) for b in ids]}
    text = json.dumps(report, indent=1, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
