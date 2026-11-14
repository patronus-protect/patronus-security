#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Training and reference inference of the per-category text models in the K26 model form.

A candidate model of one category is the shell-risk K26 form with the ``tf1`` analyzer: two
L2-normalized sublinear TF-IDF blocks (``char_wb`` n-grams of the text and the ``tf1`` tokens of
the text and its ``patronus.text_facts/1``), concatenated before a binary logistic regression. The
``model.json`` is ``format_version: 2`` like K26's, so ``TfidfLrModel`` in
``ark-core/src/detectors/facts_common/model.rs`` loads both; this module is the reference the Rust
inference matches bit for bit.

    # facts per row come from the Rust extractor (text_facts example), labels 0/1 from the gold
    cargo run -q -p patronus-ark-core --example text_facts < rows.jsonl > rows.facts.jsonl
    python3 scripts/l1_threat/category_model.py train --rows rows.facts.jsonl \\
        --category exfiltration --out exfiltration.model.json
    python3 scripts/l1_threat/category_model.py score --model exfiltration.model.json \\
        --rows rows.facts.jsonl
    python3 scripts/l1_threat/category_model.py parity [--check]

- ``train``: vocabulary by ``min_df`` (n-grams and tokens), smoothed idf, an L2-regularized,
  class-balanced logistic regression fitted by deterministic accelerated gradient descent over
  the sparse rows (numpy only), and the ``1pct_fpr`` / ``0_1pct_fpr`` cuts read off the scores of
  the negative rows.
- ``score``: the decision score (logit) and the top positive feature contributions of every row,
  in scikit-learn's float32 feature pipeline and scipy's summation order.
- ``parity``: recomputes the expected scores of the parity goldens from the checked-in synthetic
  model; ``--retrain`` first retrains that model on the rows of the text-facts parity file
  (label: the row has a finding); ``--check`` only verifies that the scores are fresh.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from text_facts import PARITY_PATH as FACTS_PARITY_PATH  # noqa: E402
from text_facts import read_rows, render, tf1  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TESTDATA = ROOT / "ark-core" / "src" / "detectors" / "text" / "testdata"
SYNTHETIC_MODEL_PATH = TESTDATA / "synthetic_model.json"
MODEL_PARITY_PATH = TESTDATA / "model_parity.jsonl"
FORMAT_VERSION = 2
ANALYZER = "tf1"
ASK_THRESHOLD = "1pct_fpr"
BLOCK_THRESHOLD = "0_1pct_fpr"
TOP_FEATURES = 5


def char_wb_ngrams(text: str, min_n: int, max_n: int) -> Iterable[str]:
    """scikit-learn's ``char_wb`` analyzer: every word of ``str.split()``, lowercased and padded
    with one space, cut into n-grams; a word shorter than ``n`` counts once."""
    for word in text.split():
        padded = f" {word.lower()} "
        length = len(padded)
        for n in range(min_n, max_n + 1):
            offset = 0
            yield padded[:n]
            while offset + n < length:
                offset += 1
                yield padded[offset : offset + n]
            if offset == 0:
                break


def row_tokens(row: dict) -> list[str]:
    """The ``tf1`` tokens of a row with its text and facts document."""
    return tf1(row["text"], row["facts"])


class Block:
    """One TF-IDF block: vocabulary (feature -> index) and idf as stored in ``model.json``."""

    def __init__(self, vocabulary: dict[str, int], idf: list[float]) -> None:
        self.vocabulary = vocabulary
        self.idf = np.asarray(idf, dtype=np.float64).astype(np.float32)
        self.names = [""] * len(vocabulary)
        for name, index in vocabulary.items():
            self.names[index] = name

    @classmethod
    def fit(cls, documents: list[list[str]], min_df: int) -> "Block":
        df: Counter[str] = Counter()
        for features in documents:
            df.update(set(features))
        kept = sorted(feature for feature, count in df.items() if count >= min_df)
        vocabulary = {feature: index for index, feature in enumerate(kept)}
        n = len(documents)
        idf = [math.log((1 + n) / (1 + df[feature])) + 1.0 for feature in kept]
        return cls(vocabulary, idf)

    def tfidf(self, features: Iterable[str]) -> list[tuple[int, np.float32]]:
        """L2-normalized sublinear TF-IDF values by vocabulary index, in scikit-learn's float32
        pipeline: ``1 + ln(tf)`` and the idf product in float32, the row norm in double."""
        counts = Counter(self.vocabulary[f] for f in features if f in self.vocabulary)
        values = []
        for index in sorted(counts):
            tf = np.log(np.float32(counts[index])) + np.float32(1.0)
            values.append((index, np.float32(tf * self.idf[index])))
        squared = 0.0
        for _, value in values:
            squared += float(np.float32(value * value))
        if squared > 0.0:
            norm = math.sqrt(squared)
            values = [(index, np.float32(float(value) / norm)) for index, value in values]
        return values


class Model:
    """A ``format_version: 2`` text model: ``char_wb`` block, ``tf1`` block, LR weights."""

    def __init__(self, document: dict) -> None:
        if document["format_version"] != FORMAT_VERSION:
            raise ValueError("unsupported model format_version")
        char_wb, tokens = document["blocks"]
        if tokens["analyzer_func"] != ANALYZER:
            raise ValueError(f"token block must use the {ANALYZER} analyzer")
        self.document = document
        self.ngrams = tuple(char_wb["vectorizer"]["ngram_range"])
        self.char_wb = Block(char_wb["vocabulary"], char_wb["idf"])
        self.tokens = Block(tokens["vocabulary"], tokens["idf"])
        self.weights = [float(w) for w in document["weights"]]
        self.intercept = float(document["intercept"])

    def row(self, text: str, tokens: list[str]) -> list[tuple[int, np.float32]]:
        """Nonzero features over the concatenated space, in index order."""
        offset = len(self.char_wb.names)
        chars = self.char_wb.tfidf(char_wb_ngrams(text, *self.ngrams))
        return chars + [(offset + index, value) for index, value in self.tokens.tfidf(tokens)]

    def feature_name(self, index: int) -> str:
        offset = len(self.char_wb.names)
        if index < offset:
            return f"char:{self.char_wb.names[index]}"
        return f"tok:{self.tokens.names[index - offset]}"

    def score(self, text: str, tokens: list[str]) -> tuple[float, list[dict]]:
        """Decision score (``x @ w`` from zero in index order, then the intercept) and the top
        positive contributions, strongest first, ties by name, rounded to four decimals."""
        dot = 0.0
        contributions = []
        for index, value in self.row(text, tokens):
            contribution = float(value) * self.weights[index]
            dot += contribution
            if contribution > 0.0:
                contributions.append((self.feature_name(index), contribution))
        contributions.sort(key=lambda item: (-item[1], item[0]))
        top = [
            {"feature": name, "weight": round(weight, 4)}
            for name, weight in contributions[:TOP_FEATURES]
        ]
        return dot + self.intercept, top


def fit_logistic(
    rows: list[list[tuple[int, np.float32]]],
    labels: np.ndarray,
    features: int,
    c: float,
    iterations: int,
) -> tuple[np.ndarray, float]:
    """L2-regularized logistic regression with balanced class weights, minimized by Nesterov
    accelerated gradient descent with the fixed step of the loss's Lipschitz bound. Rows are
    sparse ``(index, value)`` lists with norm at most sqrt(2) (two L2-normalized blocks)."""
    row_of = np.concatenate([np.full(len(r), i, dtype=np.int64) for i, r in enumerate(rows)])
    cols = np.array([index for r in rows for index, _ in r], dtype=np.int64)
    vals = np.array([float(value) for r in rows for _, value in r], dtype=np.float64)
    n = len(rows)
    positives = float(labels.sum())
    if positives in (0.0, float(n)):
        raise ValueError("training rows need both labels")
    sample = np.where(labels == 1, n / (2 * positives), n / (2 * (n - positives)))
    alpha = 1.0 / (c * n)
    # Logistic loss curvature <= 1/4, row norm^2 <= 2, balanced weights <= max(sample).
    step = 1.0 / (0.25 * 2.0 * float(sample.max()) + alpha + 0.25 * float(sample.max()))
    weights = np.zeros(features)
    intercept = 0.0
    prev_w, prev_b = weights.copy(), intercept
    for k in range(1, iterations + 1):
        momentum = (k - 1) / (k + 2)
        look_w = weights + momentum * (weights - prev_w)
        look_b = intercept + momentum * (intercept - prev_b)
        margins = np.bincount(row_of, weights=vals * look_w[cols], minlength=n) + look_b
        residual = sample * (1.0 / (1.0 + np.exp(-margins)) - labels) / n
        grad_w = np.bincount(cols, weights=vals * residual[row_of], minlength=features)
        grad_w += alpha * look_w
        prev_w, prev_b = weights, intercept
        weights = look_w - step * grad_w
        intercept = look_b - step * float(residual.sum())
    return weights, intercept


def fpr_cut(negative_scores: list[float], fpr: float) -> float:
    """The lowest cut with at most ``fpr`` of the negative scores strictly above it."""
    ranked = sorted(negative_scores, reverse=True)
    allowed = math.floor(fpr * len(ranked))
    return ranked[min(allowed, len(ranked) - 1)]


def train(
    rows: list[dict],
    name: str,
    *,
    ngram_range: tuple[int, int] = (3, 5),
    min_df: int = 2,
    c: float = 1.0,
    iterations: int = 400,
) -> dict:
    """A ``format_version: 2`` model document trained on rows with text, facts and label."""
    texts = [row["text"] for row in rows]
    token_docs = [row_tokens(row) for row in rows]
    char_docs = [list(char_wb_ngrams(text, *ngram_range)) for text in texts]
    char_block = Block.fit(char_docs, min_df)
    token_block = Block.fit(token_docs, min_df)
    blocks = [
        {
            "kind": "char_wb",
            "vectorizer": {
                "analyzer": "char_wb",
                "ngram_range": list(ngram_range),
                "lowercase": True,
                "min_df": min_df,
                "sublinear_tf": True,
            },
            "feature_dtype": "float32",
            "idf_dtype": "float64",
            "vocabulary": char_block.vocabulary,
            "idf": [float(v) for v in char_block.idf],
        },
        {
            "kind": "tokens",
            "analyzer_func": ANALYZER,
            "vectorizer": {"min_df": min_df, "sublinear_tf": True},
            "feature_dtype": "float32",
            "idf_dtype": "float64",
            "vocabulary": token_block.vocabulary,
            "idf": [float(v) for v in token_block.idf],
        },
    ]
    features = len(char_block.names) + len(token_block.names)
    document = {
        "format_version": FORMAT_VERSION,
        "name": name,
        "blocks": blocks,
        "weights": [0.0] * features,
        "intercept": 0.0,
        "thresholds": {},
        "default_threshold_policy": ASK_THRESHOLD,
        "decision_rule": "score > threshold",
    }
    shell = Model(document)
    sparse = [shell.row(text, tokens) for text, tokens in zip(texts, token_docs)]
    labels = np.array([int(row["label"]) for row in rows], dtype=np.float64)
    weights, intercept = fit_logistic(sparse, labels, features, c, iterations)
    document["weights"] = [float(w) for w in weights]
    document["intercept"] = float(intercept)
    model = Model(document)
    negatives = [
        model.score(text, tokens)[0]
        for text, tokens, label in zip(texts, token_docs, labels)
        if label == 0
    ]
    document["thresholds"] = {
        ASK_THRESHOLD: fpr_cut(negatives, 0.01),
        BLOCK_THRESHOLD: fpr_cut(negatives, 0.001),
    }
    return document


def dump_model(document: dict) -> str:
    return json.dumps(document, sort_keys=True, ensure_ascii=False) + "\n"


def synthetic_rows() -> list[dict]:
    """The text-facts parity rows with a label: positive when the row has a finding."""
    return [
        {**row, "label": int(bool(row["facts"]["findings"]))}
        for row in read_rows(FACTS_PARITY_PATH)
    ]


def synthetic_model() -> str:
    """The synthetic model of the parity goldens, as file content."""
    return dump_model(train(synthetic_rows(), "synthetic-text-tf1", min_df=1, iterations=200))


def parity_scores(model_text: str) -> str:
    """Expected scores of the parity goldens under a model, as file content."""
    rows = synthetic_rows()
    model = Model(json.loads(model_text))
    expected = []
    for row in rows:
        score, top = model.score(row["text"], row_tokens(row))
        expected.append(
            {"id": row["id"], "text": row["text"], "facts": row["facts"], "score": score, "top": top}
        )
    return render(expected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    fit = sub.add_parser("train", help="train a category model on rows with text, facts, label")
    fit.add_argument("--rows", type=Path, required=True)
    fit.add_argument("--category", required=True)
    fit.add_argument("--out", type=Path, required=True)
    fit.add_argument("--min-df", type=int, default=2)
    fit.add_argument("--c", type=float, default=1.0)
    fit.add_argument("--iterations", type=int, default=400)
    score = sub.add_parser("score", help="reference scores of rows with text and facts")
    score.add_argument("--model", type=Path, required=True)
    score.add_argument("--rows", type=Path, required=True)
    parity = sub.add_parser("parity", help="rewrite the synthetic model and its parity goldens")
    parity.add_argument("--check", action="store_true", help="only check, exit 1 when stale")
    parity.add_argument("--retrain", action="store_true", help="retrain the synthetic model")
    args = parser.parse_args(argv)

    if args.command == "train":
        document = train(
            read_rows(args.rows),
            f"text-{args.category}-tf1",
            min_df=args.min_df,
            c=args.c,
            iterations=args.iterations,
        )
        args.out.write_text(dump_model(document), encoding="utf-8")
        return 0
    if args.command == "score":
        model = Model(json.loads(args.model.read_text(encoding="utf-8")))
        for row in read_rows(args.rows):
            value, top = model.score(row["text"], row_tokens(row))
            print(json.dumps({"id": row.get("id"), "score": value, "top": top}, ensure_ascii=False))
        return 0
    if args.retrain:
        SYNTHETIC_MODEL_PATH.write_text(synthetic_model(), encoding="utf-8")
    expected = parity_scores(SYNTHETIC_MODEL_PATH.read_text(encoding="utf-8"))
    if args.check:
        if not MODEL_PARITY_PATH.exists() or MODEL_PARITY_PATH.read_text("utf-8") != expected:
            print(f"{MODEL_PARITY_PATH} is stale: run category_model.py parity", file=sys.stderr)
            return 1
        return 0
    MODEL_PARITY_PATH.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
