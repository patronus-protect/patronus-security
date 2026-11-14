#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Ablation of the score stages of one threat class and the selection rule of the L1-threat README.

Every stage scores the same rows; the comparison shows what each building block adds and costs:

| Stage | Score of a row |
|---|---|
| ``R`` | rules only: the strongest finding ``points`` of the class's category in the facts |
| ``R+A`` | ``R`` plus the hand-set context points (support ``+SUPPORT_POINTS``, counter context ``-COUNTER_POINTS``), only on a rule hit, not below 0 |
| ``B0`` | today's scorer of the category: ARK's own score from ``scoreboard.py predict`` predictions (``--b0-predictions``) |
| ``R+A+L`` | ``R+A`` plus learned integer points per fact token (``LearnedPoints``: ``>= 0``, counter tokens ``<= 0``) |
| ``B1`` | char n-gram TF-IDF + LR alone (``category_model.py``, vocabulary, no token features) |
| ``B4`` | hashed char n-gram + word TF-IDF + LR alone (``tf1`` words without fact tokens) |
| ``B5`` | ``R+A`` plus the ``B4`` logit as points, capped at ``NGRAM_CAP`` |

Rows carry ``id``, ``text``, ``facts`` (``patronus.text_facts/1`` from the ``text_facts`` example),
``classes``, ``benign``, ``language`` and ``dataset``, as in the frozen corpora. A row is a positive
of the class when the class is in ``classes`` and a negative when ``benign``; other rows are left
out. ``--rows`` is split by a hash of the row id into train and eval halves unless ``--eval-rows``
is given. Learned stages train on the train rows; every stage's operating cut holds 1 % FPR on the
train negatives (``category_model.fpr_cut``).

Per stage on the eval rows, per language (``all``, ``de``, ``en``): TPR at matched FPR 1 % and
0.1 % and AUPRC (``scoreboard.cell_metrics``), hard-benign FPR at the operating cut (B0: ARK's
verdict) on the security-adjacent benign rows (``scoreboard.is_hard_benign``), the model's RAM
estimate and the ms per 100 KiB it adds to the facts (``text_model_latency`` example on the latency
windows, ``--bench-bin``/``--windows``; points stages sum over the facts and add none).

Selection (``select``): among the model stages ``B0``, ``R+A+L``, ``B1``, ``B4``, ``B5`` within the
budget (RAM <= 2 MB, <= 1 ms per 100 KiB added), the cheapest (ms, then RAM, then stage order) whose
TPR at 1 % FPR is within 1 pp of the best. ``R`` and ``R+A`` are comparison rows only. ``B0`` is the
status quo and adds no cost.

    cargo run -q -p patronus-ark-core --example text_facts < rows.jsonl > rows.facts.jsonl
    cargo build --release -p patronus-ark-core --example text_model_latency
    python3 scripts/l1_threat/ablation.py run --rows rows.facts.jsonl --class exfiltration \\
        [--eval-rows EVAL.facts.jsonl] [--b0-predictions PRED_DIR] \\
        [--bench-bin target/release/examples/text_model_latency --windows windows.jsonl] \\
        --out ablation.json [--markdown ablation.md]
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
STAGES = ("R", "R+A", "B0", "R+A+L", "B1", "B4", "B5")
MODEL_STAGES = ("B0", "R+A+L", "B1", "B4", "B5")
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
TOLERANCE_PP = 1.0
MAX_RAM_BYTES = 2 * 1024 * 1024
MAX_EXTRA_MS = 1.0
OPERATING_FPR = 0.01
# Per-entry overhead of a vocabulary or points map entry in the Rust model (hash slot, string header).
ENTRY_BYTES = 32
TOKENS = {"B1": "none", "B4": "words"}


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
    """One ablation stage: a row scorer, its operating cut and its cost."""

    def __init__(self, name: str, score: Callable[[dict], float], *, model: dict | None = None,
                 ram_bytes: int = 0) -> None:
        self.name = name
        self.score = score
        self.model = model
        self.ram_bytes = ram_bytes
        self.cut = 0.0
        self.flagged: Callable[[dict], bool] = lambda row: self.score(row) > self.cut


def model_ram_bytes(document: dict) -> int:
    """RAM estimate of a loaded ``model.json``: f64 weight + f32 idf per feature, vocabulary entries."""
    features = len(document["weights"])
    vocab = sum(len(name.encode("utf-8")) + ENTRY_BYTES
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


def split_rows(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Train and eval halves by the parity of the first byte of sha256(row id)."""
    train, test = [], []
    for row in rows:
        (test if hashlib.sha256(row["id"].encode("utf-8")).digest()[0] & 1 else train).append(row)
    return train, test


def operating_cut(scored: list[tuple[float, int]]) -> float:
    """Cut holding ``OPERATING_FPR`` on the negatives of ``(score, label)`` pairs."""
    return MODEL.fpr_cut([score for score, label in scored if label == 0], OPERATING_FPR)


def fit_stages(rows: list[dict], cls: str, *, buckets: tuple[int, int] = BUCKETS, iterations: int = 400,
               min_df: int = 2) -> list[Stage]:
    """Every stage but ``B0``, trained on ``rows`` and with its operating cut."""
    category = SCOREBOARD.category(cls)
    train = labelled(rows, cls)
    model_rows = [{**row, "label": label} for row, label in train]

    def rules(row: dict) -> int:
        return rule_points(row["facts"], category)

    def anchors(row: dict) -> int:
        return anchor_points(row["facts"], category)

    learned = LearnedPoints.fit(train, min_df=min_df, iterations=iterations)
    b1_doc = MODEL.train(model_rows, f"ablation-{cls}-b1", min_df=min_df, iterations=iterations, tokens=no_tokens)
    b4_doc = MODEL.train(model_rows, f"ablation-{cls}-b4", char_buckets=buckets[0], token_buckets=buckets[1],
                         iterations=iterations, tokens=word_tokens)
    b1, b4 = MODEL.Model(b1_doc), MODEL.Model(b4_doc)

    def b4_logit(row: dict) -> float:
        return b4.score(row["text"], word_tokens(row))[0]

    def hybrid(row: dict) -> int:
        ngram = min(max(int(round(b4_logit(row) * NGRAM_POINTS_PER_LOGIT)), 0), NGRAM_CAP)
        return anchors(row) + ngram

    stages = [
        Stage("R", rules),
        Stage("R+A", anchors),
        Stage("R+A+L", lambda row: max(anchors(row) + learned.score(row), 0), ram_bytes=learned.ram_bytes()),
        Stage("B1", lambda row: sigmoid(b1.score(row["text"], [])[0]), model=b1_doc,
              ram_bytes=model_ram_bytes(b1_doc)),
        Stage("B4", lambda row: sigmoid(b4_logit(row)), model=b4_doc, ram_bytes=model_ram_bytes(b4_doc)),
        Stage("B5", hybrid, model=b4_doc, ram_bytes=model_ram_bytes(b4_doc)),
    ]
    for stage in stages:
        stage.cut = operating_cut([(stage.score(row), label) for row, label in train])
    return stages


def b0_stage(predictions: dict[str, dict], cls: str) -> Stage:
    """Today's scorer from ARK predictions; its verdict is ARK's own."""
    def score(row: dict) -> float:
        return float(predictions[row["id"]]["scores"].get(cls, 0.0))

    stage = Stage("B0", score)
    stage.flagged = lambda row: cls in (predictions[row["id"]].get("flagged") or [])
    return stage


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
        hard = [stage.flagged(row) for row, label in chosen if not label and SCOREBOARD.is_hard_benign(row)]
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
    over = [r["stage"] for r in candidates
            if (r.get("ram_bytes") or 0) > MAX_RAM_BYTES or (r.get("ms_per_100kib") or 0.0) > MAX_EXTRA_MS]
    within = [r for r in candidates if r["stage"] not in over]
    if not within:
        return {"best": None, "eligible": [], "over_budget": over, "selected": None}
    best = max(within, key=lambda r: (_tpr(r), -order[r["stage"]]))
    floor = _tpr(best) - tolerance_pp / 100.0 - 1e-12
    eligible = [r for r in within if _tpr(r) >= floor]
    cheapest = min(eligible, key=lambda r: (r.get("ms_per_100kib") or 0.0, r.get("ram_bytes") or 0, order[r["stage"]]))
    return {"best": best["stage"], "eligible": [r["stage"] for r in sorted(eligible, key=lambda r: order[r["stage"]])],
            "over_budget": over, "selected": cheapest["stage"]}


def run_class(train: list[dict], test: list[dict], cls: str, *, predictions: dict[str, dict] | None = None,
              bench_bin: Path | None = None, windows: Path | None = None, buckets: tuple[int, int] = BUCKETS,
              iterations: int = 400) -> dict[str, Any]:
    fitted = {stage.name: stage for stage in fit_stages(train, cls, buckets=buckets, iterations=iterations)}
    if predictions is not None:
        fitted["B0"] = b0_stage(predictions, cls)
    eval_rows = labelled(test, cls)
    results = []
    for name in STAGES:
        stage = fitted.get(name)
        if stage is None:
            results.append({"stage": name, "measured": False})
            continue
        result = evaluate(stage, eval_rows)
        result["ram_bytes"] = None if name == "B0" else stage.ram_bytes
        if name == "B0" or stage.model is None:
            result["ms_per_100kib"] = None if name == "B0" else 0.0
        elif bench_bin is not None and windows is not None:
            result["ms_per_100kib"] = bench(bench_bin, windows, stage)
        else:
            result["ms_per_100kib"] = None
        results.append(result)
    return {"class": cls, "rows": {"train": len(train), "eval": len(test)}, "stages": results,
            "selection": select(results)}


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{100 * value:.1f}"


def markdown(reports: list[dict[str, Any]]) -> str:
    lines = ["# Threat ablation", ""]
    for report in reports:
        selection = report["selection"]
        lines += [f"## {report['class']}", "",
                  f"Rows: train {report['rows']['train']}, eval {report['rows']['eval']}. "
                  f"Best: {selection['best'] or '–'}; selected: **{selection['selected'] or '–'}**"
                  + (f"; over budget: {', '.join(selection['over_budget'])}" if selection["over_budget"] else ""),
                  "",
                  "| Stage | TPR@1 % | TPR@0.1 % | DE TPR@1 % | EN TPR@1 % | AUPRC | hard-benign FPR | ms/100 KiB | RAM KiB |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for result in report["stages"]:
            cells = {language: result.get(language) or {} for language in LANGUAGES}

            def tpr(language: str, fpr: str) -> str:
                cell = cells[language].get(fpr)
                return _pct(None if cell is None else cell["tpr"])

            hard = (cells["all"].get("hard_benign") or {}).get("fpr")
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
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)

    rows = MODEL.read_rows(args.rows)
    if args.eval_rows is not None:
        train, test = rows, MODEL.read_rows(args.eval_rows)
    else:
        train, test = split_rows(rows)
    predictions = load_predictions(args.b0_predictions) if args.b0_predictions else None
    reports = [run_class(train, test, cls, predictions=predictions, bench_bin=args.bench_bin, windows=args.windows,
                         buckets=tuple(args.buckets), iterations=args.iterations) for cls in args.classes]
    args.out.write_text(json.dumps({"schema": REPORT_SCHEMA, "classes": reports}, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    if args.markdown is not None:
        args.markdown.write_text(markdown(reports), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
