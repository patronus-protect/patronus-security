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

- Blocks either keep a vocabulary (``min_df``) or are hashed (``--char-buckets``,
  ``--token-buckets``): a feature's bucket is the 32-bit FNV-1a hash of its UTF-8 bytes modulo the
  bucket count, and its name in the top features is ``#<bucket>``.
- ``train``: vocabulary by ``min_df`` (n-grams and tokens) or buckets, smoothed idf, an L2-regularized,
  class-balanced logistic regression fitted by deterministic accelerated gradient descent over
  the sparse rows (numpy only), and the ``1pct_fpr`` / ``0_1pct_fpr`` cuts read off the scores of
  the negative rows.
- ``score``: the decision score (logit) and the top positive feature contributions of every row,
  in scikit-learn's float32 feature pipeline and scipy's summation order.
- ``parity``: recomputes the expected scores of the parity goldens from the checked-in synthetic
  models (one with vocabularies, one hashed); ``--retrain`` first retrains them on the rows of the text-facts parity file
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
SYNTHETIC_MODELS = {
    "synthetic-text-tf1": (TESTDATA / "synthetic_model.json", {}),
    "synthetic-text-tf1-hashed": (
        TESTDATA / "synthetic_hashed_model.json",
        {"char_buckets": 64, "token_buckets": 32},
    ),
}
SYNTHETIC_MODEL_PATH = SYNTHETIC_MODELS["synthetic-text-tf1"][0]
HASH = "fnv1a_32"
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


def fnv1a_32(feature: str) -> int:
    """32-bit FNV-1a of the UTF-8 bytes of ``feature``."""
    value = 0x811C9DC5
    for byte in feature.encode("utf-8"):
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


class Block:
    """One TF-IDF block as stored in ``model.json``: vocabulary (feature -> index) or ``buckets``
    hashed features, and the idf."""

    def __init__(self, vocabulary: dict[str, int], idf: list[float], buckets: int = 0) -> None:
        self.vocabulary = vocabulary
        self.buckets = buckets
        self.idf = np.asarray(idf, dtype=np.float64).astype(np.float32)
        if buckets:
            self.names = [f"#{index}" for index in range(buckets)]
        else:
            self.names = [""] * len(vocabulary)
            for name, index in vocabulary.items():
                self.names[index] = name

    @classmethod
    def load(cls, block: dict) -> "Block":
        vectorizer = block["vectorizer"]
        buckets = vectorizer.get("n_features", 0)
        if buckets and vectorizer.get("hash") != HASH:
            raise ValueError(f"hashed blocks use {HASH}")
        return cls(block.get("vocabulary", {}), block["idf"], buckets)

    def index(self, feature: str) -> int | None:
        if self.buckets:
            return fnv1a_32(feature) % self.buckets
        return self.vocabulary.get(feature)

    @classmethod
    def fit(cls, documents: list[list[str]], min_df: int, buckets: int = 0) -> "Block":
        n = len(documents)
        df: Counter = Counter()
        if buckets:
            for features in documents:
                df.update({fnv1a_32(f) % buckets for f in features})
            idf = [math.log((1 + n) / (1 + df[index])) + 1.0 for index in range(buckets)]
            return cls({}, idf, buckets)
        for features in documents:
            df.update(set(features))
        kept = sorted(feature for feature, count in df.items() if count >= min_df)
        vocabulary = {feature: index for index, feature in enumerate(kept)}
        idf = [math.log((1 + n) / (1 + df[feature])) + 1.0 for feature in kept]
        return cls(vocabulary, idf)

    def vectorizer(self) -> dict:
        """The hashing keys of the block's vectorizer config."""
        return {"n_features": self.buckets, "hash": HASH} if self.buckets else {}

    def tfidf(self, features: Iterable[str]) -> list[tuple[int, np.float32]]:
        """L2-normalized sublinear TF-IDF values by feature index, in scikit-learn's float32
        pipeline: ``1 + ln(tf)`` and the idf product in float32, the row norm in double. ``ln(tf)``
        is taken in double and rounded to float32, as in the Rust inference (numpy's float32
        ``log`` differs from other single-precision ``ln`` in the last bit, e.g. at tf = 7)."""
        indices = (self.index(feature) for feature in features)
        counts = Counter(index for index in indices if index is not None)
        values = []
        for index in sorted(counts):
            tf = np.float32(math.log(counts[index])) + np.float32(1.0)
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
        self.char_wb = Block.load(char_wb)
        self.tokens = Block.load(tokens)
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
    char_buckets: int = 0,
    token_buckets: int = 0,
    c: float = 1.0,
    iterations: int = 400,
) -> dict:
    """A ``format_version: 2`` model document trained on rows with text, facts and label."""
    texts = [row["text"] for row in rows]
    token_docs = [row_tokens(row) for row in rows]
    char_docs = [list(char_wb_ngrams(text, *ngram_range)) for text in texts]
    char_block = Block.fit(char_docs, min_df, char_buckets)
    token_block = Block.fit(token_docs, min_df, token_buckets)
    blocks = [
        {
            "kind": "char_wb",
            "vectorizer": {
                "analyzer": "char_wb",
                "ngram_range": list(ngram_range),
                "lowercase": True,
                "min_df": min_df,
                "sublinear_tf": True,
                **char_block.vectorizer(),
            },
            "feature_dtype": "float32",
            "idf_dtype": "float64",
            **({} if char_block.buckets else {"vocabulary": char_block.vocabulary}),
            "idf": [float(v) for v in char_block.idf],
        },
        {
            "kind": "tokens",
            "analyzer_func": ANALYZER,
            "vectorizer": {"min_df": min_df, "sublinear_tf": True, **token_block.vectorizer()},
            "feature_dtype": "float32",
            "idf_dtype": "float64",
            **({} if token_block.buckets else {"vocabulary": token_block.vocabulary}),
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


def retrain_synthetic_models() -> None:
    """Retrain the synthetic models of the parity goldens on the parity rows."""
    for name, (path, options) in SYNTHETIC_MODELS.items():
        document = train(synthetic_rows(), name, min_df=1, iterations=200, **options)
        path.write_text(dump_model(document), encoding="utf-8")


def parity_scores() -> str:
    """Expected scores of the parity goldens under every synthetic model, as file content."""
    models = {
        name: Model(json.loads(path.read_text(encoding="utf-8")))
        for name, (path, _) in SYNTHETIC_MODELS.items()
    }
    expected = []
    for row in synthetic_rows():
        scores = {}
        for name, model in models.items():
            score, top = model.score(row["text"], row_tokens(row))
            scores[name] = {"score": score, "top": top}
        expected.append({"id": row["id"], "text": row["text"], "facts": row["facts"], "models": scores})
    return render(expected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    fit = sub.add_parser("train", help="train a category model on rows with text, facts, label")
    fit.add_argument("--rows", type=Path, required=True)
    fit.add_argument("--category", required=True)
    fit.add_argument("--out", type=Path, required=True)
    fit.add_argument("--min-df", type=int, default=2)
    fit.add_argument("--char-buckets", type=int, default=0, help="hash char n-grams (0: vocabulary)")
    fit.add_argument("--token-buckets", type=int, default=0, help="hash tf1 tokens (0: vocabulary)")
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
        hashed = "-hashed" if args.char_buckets or args.token_buckets else ""
        document = train(
            read_rows(args.rows),
            f"text-{args.category}-tf1{hashed}",
            min_df=args.min_df,
            char_buckets=args.char_buckets,
            token_buckets=args.token_buckets,
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
        retrain_synthetic_models()
    expected = parity_scores()
    if args.check:
        if not MODEL_PARITY_PATH.exists() or MODEL_PARITY_PATH.read_text("utf-8") != expected:
            print(f"{MODEL_PARITY_PATH} is stale: run category_model.py parity", file=sys.stderr)
            return 1
        return 0
    MODEL_PARITY_PATH.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
