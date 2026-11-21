#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Ablation of the score stages of one threat class and the selection rule of the L1-threat README.

Every stage scores the same rows; the comparison shows what each building block adds and costs:

| Stage | Score of a row |
|---|---|
| ``R`` | rules only: the strongest finding ``points`` of the class's category in the facts |
| ``R+A`` | ``R`` plus the hand-set context points (support ``+SUPPORT_POINTS``, counter context ``-COUNTER_POINTS``), only on a rule hit, not below 0 |
| ``B0`` | today's scorer of the category: Core's L1 score curve from ``scoreboard.py predict`` predictions (``--b0-predictions``) |
| ``R+A+L`` | ``R+A`` plus learned integer points per fact token (``LearnedPoints``: ``>= 0``, counter tokens ``<= 0``) |
| ``B1`` | char n-gram TF-IDF + LR alone (``category_model.py``, vocabulary, no token features) |
| ``B4`` | hashed char n-gram + word TF-IDF + LR alone (``tf1`` words without fact tokens) |
| ``B5`` | ``R+A`` plus the ``B4`` logit as points, capped at ``NGRAM_CAP`` |
| ``FT`` | fastText-type model alone (``category_model.FastTextModel``: hashed word, bigram and char n-gram embeddings plus the fact tokens, averaged, linear softmax) |

Rows carry ``id``, ``text``, ``facts`` (``patronus.text_facts/1`` from the ``text_facts`` example),
``classes``, ``benign``, ``language`` and ``dataset``, as in the frozen corpora. A row is a positive
of the class when the class is in ``classes`` and a negative when ``benign``; other rows are left
out. ``--rows`` is split by a hash of the row's template key into train and eval halves unless
``--eval-rows`` is given: a generated row's key is its generator and template family, so every fill of a
template and its look-alike twins land on one side; any other row's key is its id. Learned stages train on the train rows.

Per stage on the eval rows, per language (``all``, ``de``, ``en``): TPR at matched FPR 1 % and
0.1 % and AUPRC (``scoreboard.cell_metrics``), hard-benign FPR at the same matched thresholds on the
security-adjacent benign rows (``scoreboard.is_hard_benign``), the model's RAM
estimate and the ms per 100 KiB it adds to the facts (``text_model_latency`` example on the latency
windows, ``--bench-bin``/``--windows``; points stages sum over the facts and add none).

Selection (``select``): among the model stages ``B0``, ``R+A+L``, ``B1``, ``B4``, ``B5``, ``FT`` within the
budget (RAM <= 2 MB, <= 1 ms per 100 KiB added), the cheapest (ms, then RAM, then stage order) whose
TPR at 1 % FPR is within 1 pp of the best. ``R`` and ``R+A`` are comparison rows only. ``B0`` is the
status quo and adds no cost. A stage whose cost is unknown (``B1``, ``B4``, ``B5``, ``FT`` without
``--bench-bin``/``--windows``) is reported as ``untimed`` and left out of the selection. ``--stage``
limits a run to some stages (e.g. ``--stage FT`` for one candidate's numbers).

Calibration (``calibrate``): a model's cuts read off benign data instead of its train negatives. The
candidate (``--stage``, default ``FT``) trains on the train half of ``--rows``; the other half and
``--eval-rows`` (the gated dev sets, e.g. ``generated``) form the calibration rows, and no row id of the
train half is among them. ``--rows`` repeats: a class with one native train source (jailbreak) also trains
on the hash half of the generated sets, whose look-alike twins are its hard negatives; the other half
calibrates. ``0_1pct_fpr`` (detect) and ``1pct_fpr`` (clear) are the cuts at
``--target-fpr`` and ``--clear-fpr`` on the scores of the benign calibration rows (the dev benign pool
incl. the hard benigns, ``score > threshold`` as in the model's ``decision_rule``). The report gives, per
language, the TPR and FPR at the detect cut, the FPR per benign source (set, ``twins`` for look-alike
twins) and what the train-negative cut would have flagged; ``--report-rows`` (sets with the role
``report``) are scored at the same cuts in their own scope and never move them. The calibrated
``model.json`` (``--model-out``) records the pool in ``calibration``; it is not wired into any scan path.
Per language (``de``, ``en``) the report adds that language's own cuts at the same FPRs on its benign rows
alone (``language_thresholds`` in ``calibration``), the TPR and FPR at its own detect cut, its FPR per benign
source and its positives per source. ``--oversample-de N`` repeats every German train positive ``N`` times.

    cargo run -q -p patronus-ark-core --example text_facts -- --threat-findings < rows.jsonl > rows.facts.jsonl
    cargo build --release -p patronus-ark-core --example text_model_latency
    python3 scripts/l1_threat/ablation.py run --rows rows.facts.jsonl --class exfiltration \\
        [--eval-rows EVAL.facts.jsonl] [--b0-predictions PRED_DIR] \\
        [--bench-bin target/release/examples/text_model_latency --windows windows.jsonl] \\
        --out ablation.json [--markdown ablation.md]
    python3 scripts/l1_threat/ablation.py calibrate --rows train_dev.facts.jsonl --class exfiltration \\
        [--eval-rows generated.facts.jsonl] [--report-rows report.facts.jsonl] [--stage FT] \\
        [--bench-bin ... --windows ...] --model-out exfiltration.model.json --out calibration.json \\
        [--markdown calibration.md]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import category_model as MODEL  # noqa: E402
from text_facts import fact_tokens  # noqa: E402

SCOREBOARD = sys.modules.get("_ark_l1_threat_scoreboard")
if SCOREBOARD is None:
    import importlib.util

    _spec = importlib.util.spec_from_file_location("_ark_l1_threat_scoreboard", HERE / "scoreboard.py")
    assert _spec is not None and _spec.loader is not None
    SCOREBOARD = importlib.util.module_from_spec(_spec)
    sys.modules["_ark_l1_threat_scoreboard"] = SCOREBOARD
    _spec.loader.exec_module(SCOREBOARD)

REPORT_SCHEMA = "ark-l1-threat-ablation-v1"
CALIBRATION_SCHEMA = "ark-l1-threat-calibration-v1"
STAGES = ("R", "R+A", "B0", "R+A+L", "B1", "B4", "B5", "FT")
MODEL_STAGES = ("B0", "R+A+L", "B1", "B4", "B5", "FT")
LANGUAGES = ("all", "de", "en")
# Hand-set context points, as the shared points layer (ark-core detectors/score.rs).
SUPPORT_POINTS = 25
COUNTER_POINTS = 30
# Learned points: integer points per unit of LR weight on binary fact tokens.
POINT_SCALE = 10
# B5: points per unit of the B4 logit, and the cap of the n-gram share.
NGRAM_POINTS_PER_LOGIT = 10
NGRAM_CAP = 40
BUCKETS = (1 << 15, 1 << 14)
# FT: embedding buckets x dimension.
FASTTEXT_SHAPE = (1 << 15, 16)
TOLERANCE_PP = 1.0
MAX_RAM_BYTES = 2 * 1024 * 1024
MAX_EXTRA_MS = 1.0
# Per-entry overhead of a vocabulary or points map entry in the Rust model (hash slot, string header).
ENTRY_BYTES = 32
# ``Box<str>`` header of a vocabulary term's clone in the Rust model's ``names`` vector.
NAME_BYTES = 16
TOKENS = {"B1": "none", "B4": "words", "FT": "tf1"}


def rule_points(facts: dict, category: str) -> int:
    """Strongest finding ``points`` of ``category`` (0 without a finding)."""
    return max((int(f["points"]) for f in facts["findings"] if f["category"] == category), default=0)


def anchor_points(facts: dict, category: str) -> int:
    """``rule_points`` with the support bonus and the counter-context damping, only on a rule hit."""
    points = rule_points(facts, category)
    if not points:
        return 0
    if facts["support"]:
        points += SUPPORT_POINTS
    if facts["counter"]:
        points -= COUNTER_POINTS
    return max(points, 0)


def word_tokens(row: dict) -> list[str]:
    """The ``tf1`` word tokens of a row, without its fact tokens."""
    return [token for token in MODEL.row_tokens(row) if token.startswith("T:")]


def no_tokens(row: dict) -> list[str]:
    return []


def sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value)) if value >= 0 else math.exp(value) / (1.0 + math.exp(value))


class LearnedPoints:
    """Integer points per fact token from a class-balanced L2 logistic regression on binary fact
    tokens, fitted by projected gradient descent: weights of counter tokens (``F:CTR=``) stay
    ``<= 0``, all others ``>= 0``. The score is the sum of the points of a row's tokens."""

    def __init__(self, points: dict[str, int]) -> None:
        self.points = points

    @classmethod
    def fit(cls, labelled: list[tuple[dict, int]], *, min_df: int = 2, c: float = 1.0,
            iterations: int = 400) -> "LearnedPoints":
        docs = [fact_tokens(row["facts"]) for row, _ in labelled]
        df: dict[str, int] = {}
        for doc in docs:
            for token in doc:
                df[token] = df.get(token, 0) + 1
        vocab = sorted(token for token, count in df.items() if count >= min_df)
        if not vocab:
            return cls({})
        index = {token: i for i, token in enumerate(vocab)}
        x = np.zeros((len(docs), len(vocab)))
        for row, doc in enumerate(docs):
            for token in doc:
                if token in index:
                    x[row, index[token]] = 1.0
        y = np.array([label for _, label in labelled], dtype=np.float64)
        n, positives = len(y), float(y.sum())
        if positives in (0.0, float(n)):
            raise ValueError("training rows need both labels")
        sample = np.where(y == 1, n / (2 * positives), n / (2 * (n - positives)))
        sign = np.array([-1.0 if token.startswith("F:CTR=") else 1.0 for token in vocab])
        alpha = 1.0 / (c * n)
        step = 1.0 / (0.25 * float(sample.max()) * (float((x.sum(axis=1)).max()) + 1.0) + alpha)
        w, b = np.zeros(len(vocab)), 0.0
        for _ in range(iterations):
            residual = sample * (1.0 / (1.0 + np.exp(-(x @ w + b))) - y) / n
            w = w - step * (x.T @ residual + alpha * w)
            w = np.where(sign * w < 0.0, 0.0, w)
            b -= step * float(residual.sum())
        points = {token: int(round(weight * POINT_SCALE)) for token, weight in zip(vocab, w)}
        return cls({token: value for token, value in points.items() if value})

    def score(self, row: dict) -> int:
        return sum(self.points.get(token, 0) for token in fact_tokens(row["facts"]))

    def ram_bytes(self) -> int:
        return sum(len(token.encode("utf-8")) + ENTRY_BYTES + 8 for token in self.points)


class Stage:
    """One ablation stage: a row scorer and its cost; a model stage also its token source."""

    def __init__(self, name: str, score: Callable[[dict], float], *, model: dict | None = None,
                 tokens: Callable[[dict], list[str]] | None = None, ram_bytes: int = 0) -> None:
        self.name = name
        self.score = score
        self.model = model
        self.tokens = tokens
        self.ram_bytes = ram_bytes


def model_ram_bytes(document: dict) -> int:
    """RAM estimate of a loaded ``model.json``: f64 weight + f32 idf per feature, vocabulary entries.

    The Rust model owns each vocabulary term twice (``into_vocabulary``): as the lookup map key and
    as a ``Box<str>`` clone in the ``names`` vector. A fastText-type model keeps one f64 value per
    bucket (the folded output layer).
    """
    if document.get("kind") == MODEL.FASTTEXT_KIND:
        return document["buckets"] * 8
    features = len(document["weights"])
    vocab = sum(2 * len(name.encode("utf-8")) + ENTRY_BYTES + NAME_BYTES
                for block in document["blocks"] for name in block.get("vocabulary", {}))
    return features * 12 + vocab


def labelled(rows: Iterable[dict], cls: str) -> list[tuple[dict, int]]:
    """``(row, label)``: 1 for positives of ``cls``, 0 for benign rows; other rows are left out."""
    out = []
    for row in rows:
        if cls in row["classes"]:
            out.append((row, 1))
        elif row["benign"]:
            out.append((row, 0))
    return out


def template_key(row: dict) -> str:
    """The unit of the train/eval split: a generated row's generator and template family (every fill of a
    template, in every language, and its look-alike twins stay on one side), else the row id."""
    if row.get("generator") and row.get("template_family"):
        return f"{row['generator']}:{row['template_family']}"
    return row["id"]


def split_rows(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Train and eval halves by the parity of the first byte of sha256(``template_key``)."""
    train, test = [], []
    for row in rows:
        (test if hashlib.sha256(template_key(row).encode("utf-8")).digest()[0] & 1 else train).append(row)
    return train, test


def oversample(rows: list[dict], cls: str, language: str, factor: int) -> list[dict]:
    """``rows`` with every positive of ``cls`` in ``language`` repeated ``factor`` times in all."""
    if factor < 1:
        raise ValueError("the oversampling factor is at least 1")
    extra = [row for row in rows if row.get("language") == language and cls in row["classes"]]
    return rows + extra * (factor - 1)


def fit_stages(rows: list[dict], cls: str, *, buckets: tuple[int, int] = BUCKETS, iterations: int = 400,
               min_df: int = 2, stages: Iterable[str] = STAGES, oversample_de: int = 1) -> list[Stage]:
    """The chosen ``stages`` but ``B0``, trained on ``rows`` (German positives ``oversample_de`` times)."""
    wanted = set(stages)
    category = SCOREBOARD.category(cls)
    train = labelled(oversample(rows, cls, "de", oversample_de), cls)
    model_rows = [{**row, "label": label} for row, label in train]

    def rules(row: dict) -> int:
        return rule_points(row["facts"], category)

    def anchors(row: dict) -> int:
        return anchor_points(row["facts"], category)

    fitted = [Stage("R", rules), Stage("R+A", anchors)]
    if "R+A+L" in wanted:
        learned = LearnedPoints.fit(train, min_df=min_df, iterations=iterations)
        fitted.append(Stage("R+A+L", lambda row: max(anchors(row) + learned.score(row), 0),
                            ram_bytes=learned.ram_bytes()))
    if "B1" in wanted:
        b1_doc = MODEL.train(model_rows, f"ablation-{cls}-b1", min_df=min_df, iterations=iterations,
                             tokens=no_tokens)
        b1 = MODEL.Model(b1_doc)
        fitted.append(Stage("B1", lambda row: sigmoid(b1.score(row["text"], [])[0]), model=b1_doc,
                            tokens=no_tokens, ram_bytes=model_ram_bytes(b1_doc)))
    if wanted & {"B4", "B5"}:
        b4_doc = MODEL.train(model_rows, f"ablation-{cls}-b4", char_buckets=buckets[0], token_buckets=buckets[1],
                             iterations=iterations, tokens=word_tokens)
        b4 = MODEL.Model(b4_doc)

        def b4_logit(row: dict) -> float:
            return b4.score(row["text"], word_tokens(row))[0]

        def hybrid(row: dict) -> int:
            ngram = min(max(int(round(b4_logit(row) * NGRAM_POINTS_PER_LOGIT)), 0), NGRAM_CAP)
            return anchors(row) + ngram

        fitted += [
            Stage("B4", lambda row: sigmoid(b4_logit(row)), model=b4_doc, tokens=word_tokens,
                  ram_bytes=model_ram_bytes(b4_doc)),
            Stage("B5", hybrid, model=b4_doc, ram_bytes=model_ram_bytes(b4_doc)),
        ]
    if "FT" in wanted:
        ft_doc = MODEL.train_fasttext(model_rows, f"ablation-{cls}-fasttext", buckets=FASTTEXT_SHAPE[0],
                                      dim=FASTTEXT_SHAPE[1])
        ft = MODEL.FastTextModel(ft_doc)
        fitted.append(Stage("FT", lambda row: sigmoid(ft.logit(row["text"], MODEL.fasttext_tokens(row))), model=ft_doc,
                            tokens=MODEL.fasttext_tokens, ram_bytes=model_ram_bytes(ft_doc)))
    return [stage for stage in fitted if stage.name in wanted]


def b0_stage(predictions: dict[str, dict], cls: str) -> Stage:
    """Today's scorer: Core's L1 score curve from the scoreboard predictions."""
    return Stage("B0", lambda row: float(predictions[row["id"]]["scores"].get(cls, 0.0)))


def load_predictions(path: Path) -> dict[str, dict]:
    files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
    return {p["id"]: p for file in files for p in MODEL.read_rows(file)}


def evaluate(stage: Stage, rows: list[tuple[dict, int]]) -> dict[str, Any]:
    """Metrics of a stage per language on labelled eval rows."""
    out: dict[str, Any] = {"stage": stage.name}
    for language in LANGUAGES:
        chosen = [(row, label) for row, label in rows if language == "all" or row.get("language") == language]
        pos = [float(stage.score(row)) for row, label in chosen if label]
        neg = [float(stage.score(row)) for row, label in chosen if not label]
        hard = [float(stage.score(row)) for row, label in chosen if not label and SCOREBOARD.is_hard_benign(row)]
        if pos and neg:
            out[language] = SCOREBOARD.cell_metrics(pos, neg, hard, bootstrap=False)
    return out


def bench(binary: Path, windows: Path, stage: Stage) -> float:
    """p95 ms per 100 KiB the stage's model adds on the latency windows."""
    with tempfile.TemporaryDirectory(prefix="ark-threat-ablation-") as tmp:
        path = Path(tmp) / "model.json"
        path.write_text(MODEL.dump_model(stage.model), encoding="utf-8")
        tokens = TOKENS.get(stage.name, "words")
        proc = subprocess.run([str(binary), str(path), str(windows), "--tokens", tokens],
                              capture_output=True, text=True, check=True)
    return round(float(json.loads(proc.stdout)["p95_ms"]), 4)


def _tpr(result: dict[str, Any]) -> float | None:
    cell = (result.get("all") or {}).get("0.01")
    return None if cell is None else cell["tpr"]


def select(results: list[dict[str, Any]], tolerance_pp: float = TOLERANCE_PP) -> dict[str, Any]:
    """The README's selection rule over the measured stages (see the module docstring)."""
    order = {name: i for i, name in enumerate(MODEL_STAGES)}
    candidates = [r for r in results if r["stage"] in order and _tpr(r) is not None]

    def cost(r: dict[str, Any]) -> tuple[float, int]:
        # B0 is the status quo and adds nothing; the other stages carry their measured cost.
        return (0.0, 0) if r["stage"] == "B0" else (r["ms_per_100kib"], r["ram_bytes"])

    untimed = [r["stage"] for r in candidates
               if r["stage"] != "B0" and (r.get("ms_per_100kib") is None or r.get("ram_bytes") is None)]
    timed = [r for r in candidates if r["stage"] not in untimed]
    over = [r["stage"] for r in timed if cost(r)[1] > MAX_RAM_BYTES or cost(r)[0] > MAX_EXTRA_MS]
    within = [r for r in timed if r["stage"] not in over]
    if not within:
        return {"best": None, "eligible": [], "over_budget": over, "selected": None, "untimed": untimed}
    best = max(within, key=lambda r: (_tpr(r), -order[r["stage"]]))
    floor = _tpr(best) - tolerance_pp / 100.0 - 1e-12
    eligible = [r for r in within if _tpr(r) >= floor]
    cheapest = min(eligible, key=lambda r: (*cost(r), order[r["stage"]]))
    return {"best": best["stage"], "eligible": [r["stage"] for r in sorted(eligible, key=lambda r: order[r["stage"]])],
            "over_budget": over, "selected": cheapest["stage"], "untimed": untimed}


def run_class(train: list[dict], test: list[dict], cls: str, *, predictions: dict[str, dict] | None = None,
              bench_bin: Path | None = None, windows: Path | None = None, buckets: tuple[int, int] = BUCKETS,
              iterations: int = 400, stages: Iterable[str] = STAGES) -> dict[str, Any]:
    stages = [name for name in STAGES if name in set(stages)]
    fitted = {stage.name: stage
              for stage in fit_stages(train, cls, buckets=buckets, iterations=iterations, stages=stages)}
    if predictions is not None and "B0" in stages:
        fitted["B0"] = b0_stage(predictions, cls)
    eval_rows = labelled(test, cls)
    results = []
    timed: dict[int, float] = {}  # B5 scores with the B4 model: one measurement per model
    for name in stages:
        stage = fitted.get(name)
        if stage is None:
            results.append({"stage": name, "measured": False})
            continue
        result = evaluate(stage, eval_rows)
        result["ram_bytes"] = None if name == "B0" else stage.ram_bytes
        if name == "B0" or stage.model is None:
            result["ms_per_100kib"] = None if name == "B0" else 0.0
        elif bench_bin is not None and windows is not None:
            if id(stage.model) not in timed:
                timed[id(stage.model)] = bench(bench_bin, windows, stage)
            result["ms_per_100kib"] = timed[id(stage.model)]
        else:
            result["ms_per_100kib"] = None
        results.append(result)
    return {"class": cls, "rows": {"train": len(train), "eval": len(test)}, "stages": results,
            "selection": select(results)}


# ── calibration on benign data ───────────────────────────────────────────────


def calibration_rows(train: list[dict], rows: Iterable[dict]) -> list[dict]:
    """``rows`` without a row whose id is in ``train`` (a train negative never calibrates)."""
    seen = {row["id"] for row in train}
    return [row for row in rows if row["id"] not in seen]


def _detections(scores: list[tuple[dict, int, float]], cut: float) -> dict[str, Any]:
    """TPR and FPR at ``cut`` (``score > cut``) per language, and the FPR per benign source."""
    out: dict[str, Any] = {}
    for language in LANGUAGES:
        chosen = [(row, label, score) for row, label, score in scores
                  if language == "all" or row.get("language") == language]
        positives = sum(label for _, label, _ in chosen)
        negatives = len(chosen) - positives
        tp = sum(label and score > cut for _, label, score in chosen)
        fp = sum(not label and score > cut for _, label, score in chosen)
        if chosen:
            out[language] = {"positives": positives, "tp": tp, "tpr": tp / positives if positives else None,
                             "negatives": negatives, "fp": fp, "fpr": fp / negatives if negatives else None}
    sources: dict[str, dict[str, int]] = {}
    for row, label, score in scores:
        if not label:
            source = sources.setdefault(SCOREBOARD._benign_source(row), {"rows": 0, "fp": 0})
            source["rows"] += 1
            source["fp"] += score > cut
    out["benign_sources"] = {name: {**cell, "fpr": cell["fp"] / cell["rows"]}
                             for name, cell in sorted(sources.items())}
    return out


def cuts(benign: list[float], target_fpr: float, clear_fpr: float) -> dict[str, float]:
    """The detect cut at ``target_fpr`` and the clear cut at ``clear_fpr`` (never above detect) of benign scores."""
    detect = MODEL.fpr_cut(benign, target_fpr)
    return {MODEL.ASK_THRESHOLD: min(MODEL.fpr_cut(benign, clear_fpr), detect), MODEL.BLOCK_THRESHOLD: detect}


def positive_sources(rows: Iterable[dict]) -> dict[str, int]:
    """Positives per source: a generated row's generator and template family, else its set."""
    counts: dict[str, int] = {}
    for row in rows:
        key = template_key(row) if row.get("generator") else row["dataset"]
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def calibrate(document: dict, rows: list[dict], cls: str, *, tokens: Callable[[dict], list[str]],
              target_fpr: float = SCOREBOARD.TARGET_FPR, clear_fpr: float = SCOREBOARD.CLEAR_FPR,
              report_rows: Iterable[dict] = ()) -> tuple[dict, dict[str, Any]]:
    """``document`` with its ``0_1pct_fpr`` / ``1pct_fpr`` cuts at ``target_fpr`` / ``clear_fpr`` of the
    benign ``rows``, and the report of those cuts on ``rows`` and ``report_rows`` (see the module docstring).
    ``tokens`` is the token source the model was trained with (``Stage.tokens``)."""
    model = MODEL.load_model(document)

    def scored(chosen: Iterable[dict]) -> list[tuple[dict, int, float]]:
        return [(row, label, model.score(row["text"], tokens(row))[0]) for row, label in labelled(chosen, cls)]

    calibration = scored(rows)
    benign = [score for _, label, score in calibration if not label]
    if not benign:
        raise ValueError(f"{cls}: no benign rows to calibrate on")
    thresholds = cuts(benign, target_fpr, clear_fpr)
    detect, clear = thresholds[MODEL.BLOCK_THRESHOLD], thresholds[MODEL.ASK_THRESHOLD]
    per_language: dict[str, Any] = {}
    for language in LANGUAGES[1:]:
        chosen = [entry for entry in calibration if entry[0].get("language") == language]
        own = [score for _, label, score in chosen if not label]
        if not own:
            continue
        language_cuts = cuts(own, target_fpr, clear_fpr)
        detections = _detections(chosen, language_cuts[MODEL.BLOCK_THRESHOLD])
        per_language[language] = {"thresholds": language_cuts, **detections[language],
                                  "benign_sources": detections["benign_sources"],
                                  "positive_sources": positive_sources(row for row, label, _ in chosen if label)}
    train_cut = document["thresholds"].get(MODEL.BLOCK_THRESHOLD)
    calibrated = {**document, "thresholds": thresholds,
                  "calibration": {"target_fpr": target_fpr, "clear_fpr": clear_fpr, "benign_rows": len(benign),
                                  "benign_sources": sorted({SCOREBOARD._benign_source(row)
                                                            for row, label, _ in calibration if not label}),
                                  "language_thresholds": {language: cell["thresholds"]
                                                          for language, cell in per_language.items()}}}
    report: dict[str, Any] = {
        "class": cls, "model": document["name"], "target_fpr": target_fpr, "clear_fpr": clear_fpr,
        "thresholds": thresholds, "calibration": _detections(calibration, detect), "per_language": per_language,
        "escalate_fpr": sum(score > clear for score in benign) / len(benign),
    }
    if train_cut is not None:
        report["train_negative_cut"] = {"threshold": train_cut, **_detections(calibration, train_cut)}
    reported = scored(report_rows)
    if reported:
        report["report"] = _detections(reported, detect)
    return calibrated, report


def calibrate_class(train: list[dict], test: list[dict], cls: str, *, stage: str = "FT",
                    report_rows: Iterable[dict] = (), bench_bin: Path | None = None, windows: Path | None = None,
                    target_fpr: float = SCOREBOARD.TARGET_FPR, clear_fpr: float = SCOREBOARD.CLEAR_FPR,
                    oversample_de: int = 1) -> tuple[dict, dict[str, Any]]:
    """Train ``stage`` on ``train``, calibrate it on the rows of ``test`` that are not in ``train`` and time it."""
    if stage not in TOKENS:
        raise ValueError(f"{stage} is not a model stage with its own model.json")
    fitted = fit_stages(train, cls, stages=[stage], oversample_de=oversample_de)[0]
    rows = calibration_rows(train, test)
    document, report = calibrate(fitted.model, rows, cls, tokens=fitted.tokens, target_fpr=target_fpr,
                                 clear_fpr=clear_fpr, report_rows=calibration_rows(train, report_rows))
    report.update({"stage": stage, "oversample_de": oversample_de, "rows": {"train": len(train), "calibration": len(rows)},
                   "ram_bytes": model_ram_bytes(document),
                   "ms_per_100kib": None if bench_bin is None or windows is None
                   else bench(bench_bin, windows, Stage(stage, fitted.score, model=document))})
    return document, report


def calibration_markdown(reports: list[dict[str, Any]]) -> str:
    """Per class: the calibrated cut, TPR and FPR per language, FPR per benign source, the train-negative cut."""
    lines = ["# Threat model calibration on benign data", "",
             "| Class | Stage | benign rows | detect cut | TPR all | TPR DE | TPR EN | FPR | FPR at train-negative cut "
             "| ms/100 KiB | RAM KiB |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for report in reports:
        cells = report["calibration"]
        train = (report.get("train_negative_cut") or {}).get("all") or {}

        def tpr(language: str) -> str:
            return _pct((cells.get(language) or {}).get("tpr"))

        ms, ram = report.get("ms_per_100kib"), report.get("ram_bytes")
        lines.append(f"| {report['class']} | {report['stage']} | {cells['all']['negatives']} | "
                     f"{report['thresholds'][MODEL.BLOCK_THRESHOLD]:.4f} | {tpr('all')} | {tpr('de')} | {tpr('en')} | "
                     f"{_pct(cells['all']['fpr'], 2)} | {_pct(train.get('fpr'), 2)} | {'–' if ms is None else ms} | "
                     f"{'–' if ram is None else round(ram / 1024, 1)} |")
    lines += ["", "## Per-language cuts", "",
              "Each language's detect cut sits at the target FPR of that language's benign rows.", "",
              "| Class | Language | benign rows | detect cut | TPR | FPR | positives | positive sources |",
              "|---|---|---|---|---|---|---|---|"]
    for report in reports:
        for language, cell in report.get("per_language", {}).items():
            sources = cell["positive_sources"]
            lines.append(f"| {report['class']} | {language.upper()} | {cell['negatives']} | "
                         f"{cell['thresholds'][MODEL.BLOCK_THRESHOLD]:.4f} | {_pct(cell['tpr'])} | "
                         f"{_pct(cell['fpr'], 2)} | {cell['positives']} | {len(sources)} |")
    for report in reports:
        for language, cell in report.get("per_language", {}).items():
            lines += ["", f"## {report['class']} {language.upper()}: sources at the {language.upper()} cut", "",
                      "| Kind | Source | rows | hits | rate |", "|---|---|---|---|---|"]
            lines += [f"| benign | {source} | {c['rows']} | {c['fp']} | {_pct(c['fpr'], 2)} |"
                      for source, c in cell["benign_sources"].items()]
            lines += [f"| positive | {source} | {n} | | |" for source, n in cell["positive_sources"].items()]
    for report in reports:
        lines += ["", f"## {report['class']}: FPR per benign source at the detect cut", "",
                  "| Scope | Source | rows | FP | FPR |", "|---|---|---|---|---|"]
        for scope in ("calibration", "report"):
            for source, cell in (report.get(scope) or {}).get("benign_sources", {}).items():
                lines.append(f"| {scope} | {source} | {cell['rows']} | {cell['fp']} | {_pct(cell['fpr'], 2)} |")
    lines.append("")
    return "\n".join(lines)


def _pct(value: float | None, digits: int = 1) -> str:
    return "–" if value is None else f"{100 * value:.{digits}f}"


def markdown(reports: list[dict[str, Any]]) -> str:
    lines = ["# Threat ablation", ""]
    for report in reports:
        selection = report["selection"]
        lines += [f"## {report['class']}", "",
                  f"Rows: train {report['rows']['train']}, eval {report['rows']['eval']}. "
                  f"Best: {selection['best'] or '–'}; selected: **{selection['selected'] or '–'}**"
                  + (f"; over budget: {', '.join(selection['over_budget'])}" if selection["over_budget"] else "")
                  + (f"; untimed: {', '.join(selection['untimed'])}" if selection["untimed"] else ""),
                  "",
                  "| Stage | TPR@1 % | TPR@0.1 % | DE TPR@1 % | EN TPR@1 % | AUPRC | hard-benign FPR@1 % | ms/100 KiB | RAM KiB |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for result in report["stages"]:
            cells = {language: result.get(language) or {} for language in LANGUAGES}

            def tpr(language: str, fpr: str) -> str:
                cell = cells[language].get(fpr)
                return _pct(None if cell is None else cell["tpr"])

            hard = ((cells["all"].get("hard_benign") or {}).get("0.01") or {}).get("fpr")
            ms = result.get("ms_per_100kib")
            ram = result.get("ram_bytes")
            lines.append(
                f"| {result['stage']} | {tpr('all', '0.01')} | {tpr('all', '0.001')} | {tpr('de', '0.01')} | "
                f"{tpr('en', '0.01')} | {cells['all'].get('auprc') if cells['all'].get('auprc') is not None else '–'} | "
                f"{_pct(hard)} | {'–' if ms is None else ms} | {'–' if ram is None else round(ram / 1024, 1)} |")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="ablate the stages of one or more classes")
    run.add_argument("--rows", type=Path, required=True, help="rows with facts (split into train/eval)")
    run.add_argument("--eval-rows", type=Path, help="separate eval rows with facts")
    run.add_argument("--class", dest="classes", action="append", required=True, choices=SCOREBOARD.CLASSES)
    run.add_argument("--b0-predictions", type=Path, help="scoreboard.py predictions (file or directory)")
    run.add_argument("--bench-bin", type=Path, help="text_model_latency example binary")
    run.add_argument("--windows", type=Path, help="latency windows (latency.py windows.jsonl)")
    run.add_argument("--buckets", type=int, nargs=2, default=BUCKETS, metavar=("CHAR", "TOKEN"))
    run.add_argument("--iterations", type=int, default=400)
    run.add_argument("--stage", dest="stages", action="append", choices=STAGES,
                     help="run only these stages (default: all)")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--markdown", type=Path)
    cal = sub.add_parser("calibrate", help="calibrate a model stage's cuts on benign data")
    cal.add_argument("--rows", type=Path, action="append", required=True,
                     help="rows with facts (train half / calibration half); repeat to train on a mix of sources")
    cal.add_argument("--eval-rows", type=Path, action="append", default=[],
                     help="further calibration rows with facts (gated dev sets)")
    cal.add_argument("--report-rows", type=Path, action="append", default=[],
                     help="rows of report sets: scored at the cuts, never calibrate")
    cal.add_argument("--class", dest="classes", action="append", required=True, choices=SCOREBOARD.CLASSES)
    cal.add_argument("--stage", default="FT", choices=sorted(TOKENS))
    cal.add_argument("--target-fpr", type=float, default=SCOREBOARD.TARGET_FPR)
    cal.add_argument("--clear-fpr", type=float, default=SCOREBOARD.CLEAR_FPR)
    cal.add_argument("--oversample-de", type=int, default=1, help="repeat German train positives this often")
    cal.add_argument("--bench-bin", type=Path, help="text_model_latency example binary")
    cal.add_argument("--windows", type=Path, help="latency windows (latency.py windows.jsonl)")
    cal.add_argument("--model-out", type=Path, help="calibrated model.json (one --class only)")
    cal.add_argument("--out", type=Path, required=True)
    cal.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)

    if args.command == "calibrate":
        if args.model_out is not None and len(args.classes) != 1:
            parser.error("--model-out takes one --class")
        train, held_out = split_rows([row for path in args.rows for row in MODEL.read_rows(path)])
        test = held_out + [row for path in args.eval_rows for row in MODEL.read_rows(path)]
        reported = [row for path in args.report_rows for row in MODEL.read_rows(path)]
        reports = []
        for cls in args.classes:
            document, report = calibrate_class(train, test, cls, stage=args.stage, report_rows=reported,
                                               bench_bin=args.bench_bin, windows=args.windows,
                                               target_fpr=args.target_fpr, clear_fpr=args.clear_fpr,
                                               oversample_de=args.oversample_de)
            if args.model_out is not None:
                args.model_out.write_text(MODEL.dump_model(document), encoding="utf-8")
            reports.append(report)
        args.out.write_text(json.dumps({"schema": CALIBRATION_SCHEMA, "classes": reports}, indent=2, sort_keys=True)
                            + "\n", encoding="utf-8")
        if args.markdown is not None:
            args.markdown.write_text(calibration_markdown(reports), encoding="utf-8")
        return 0
    rows = MODEL.read_rows(args.rows)
    if args.eval_rows is not None:
        train, test = rows, MODEL.read_rows(args.eval_rows)
    else:
        train, test = split_rows(rows)
    predictions = load_predictions(args.b0_predictions) if args.b0_predictions else None
    reports = [run_class(train, test, cls, predictions=predictions, bench_bin=args.bench_bin, windows=args.windows,
                         buckets=tuple(args.buckets), iterations=args.iterations, stages=args.stages or STAGES)
               for cls in args.classes]
    args.out.write_text(json.dumps({"schema": REPORT_SCHEMA, "classes": reports}, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    if args.markdown is not None:
        args.markdown.write_text(markdown(reports), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
