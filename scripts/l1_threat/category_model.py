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
- ``train --fasttext``: the fastText-type candidate instead (``FastTextModel``): hashed word,
  word-bigram and ``<word>`` char n-gram features plus the ``tf1`` tokens share one embedding table
  (``--buckets`` x ``--dim``); a text's vector is the average of its feature embeddings, followed
  by a linear softmax over the classes (negative, positive). Fitted by deterministic full-batch Adam
  with balanced class weights; the decision score is the positive minus the negative logit.
- ``parity``: recomputes the expected scores of the parity goldens from the checked-in synthetic
  models (one with vocabularies, one hashed, one fastText-type); ``--retrain`` first retrains them on the rows of the text-facts parity file
  (label: the row has a finding); ``--check`` only verifies that the scores are fresh.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable

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
    "synthetic-text-fasttext": (
        TESTDATA / "synthetic_fasttext_model.json",
        {"fasttext": {"buckets": 64, "dim": 4}},
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
FASTTEXT_KIND = "fasttext"
FASTTEXT_FORMAT_VERSION = 1


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
    tokens: Callable[[dict], list[str]] = row_tokens,
) -> dict:
    """A ``format_version: 2`` model document trained on rows with text, facts and label;
    ``tokens`` feeds the token block (``tf1`` by default; the ablation trains n-gram-only stages
    on a subset of it)."""
    texts = [row["text"] for row in rows]
    token_docs = [tokens(row) for row in rows]
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


def fasttext_features(text: str, tokens: list[str], min_n: int, max_n: int) -> Iterable[str]:
    """Features of the fastText-type model in their fixed order: per word of ``str.split()``
    (lowercased) ``w:<word>``, ``b:<previous> <word>`` from the second word on, the char n-grams
    ``c:<gram>`` of ``<word>`` (``min_n``..``max_n`` characters, a padded word shorter than
    ``min_n`` once whole); then every ``tf1`` token as is."""
    previous = None
    for word in text.split():
        word = word.lower()
        yield f"w:{word}"
        if previous is not None:
            yield f"b:{previous} {word}"
        previous = word
        padded = f"<{word}>"
        if len(padded) < min_n:
            yield f"c:{padded}"
            continue
        for n in range(min_n, max_n + 1):
            for offset in range(len(padded) - n + 1):
                yield f"c:{padded[offset : offset + n]}"
    yield from tokens


class FastTextModel:
    """A fastText-type text model (``kind: fasttext``): an embedding table of ``buckets`` x ``dim``
    float32 rows indexed by the FNV-1a bucket of each feature, averaged over a text's features, and
    a linear softmax over ``labels`` (negative, positive).

    Inference folds the output layer into one value per bucket, ``Σ_j E[b][j] * (W[1][j] - W[0][j])``
    (double precision, ``j`` in order); the decision score is ``Σ_b count_b * value_b`` over the
    text's buckets in index order, divided by the feature count, plus ``bias[1] - bias[0]``, i.e.
    the positive minus the negative softmax logit. No feature: the bias difference alone."""

    def __init__(self, document: dict) -> None:
        if document.get("kind") != FASTTEXT_KIND or document["format_version"] != FASTTEXT_FORMAT_VERSION:
            raise ValueError("unsupported fastText model kind or format_version")
        if document["analyzer_func"] != ANALYZER:
            raise ValueError(f"fastText model must use the {ANALYZER} analyzer")
        if document.get("hash") != HASH:
            raise ValueError(f"fastText models use {HASH}")
        self.document = document
        self.buckets = int(document["buckets"])
        self.dim = int(document["dim"])
        self.ngrams = tuple(document["char_ngram_range"])
        embeddings = document["embeddings"]
        output = document["output"]
        if len(embeddings) != self.buckets * self.dim or len(output) != 2 * self.dim:
            raise ValueError("fastText model shape does not match buckets x dim")
        delta = [float(output[self.dim + j]) - float(output[j]) for j in range(self.dim)]
        self.values = []
        for bucket in range(self.buckets):
            value = 0.0
            row = embeddings[bucket * self.dim : (bucket + 1) * self.dim]
            for j in range(self.dim):
                value += float(row[j]) * delta[j]
            self.values.append(value)
        bias = document["bias"]
        self.bias = float(bias[1]) - float(bias[0])

    def counts(self, text: str, tokens: list[str]) -> tuple[Counter, int]:
        counts: Counter = Counter()
        for feature in fasttext_features(text, tokens, *self.ngrams):
            counts[fnv1a_32(feature) % self.buckets] += 1
        return counts, sum(counts.values())

    def score(self, text: str, tokens: list[str]) -> tuple[float, list[dict]]:
        """Decision score and the top positive bucket contributions (``#<bucket>``), strongest
        first, ties by name, rounded to four decimals."""
        counts, total = self.counts(text, tokens)
        if not total:
            return self.bias, []
        dot = 0.0
        contributions = []
        for bucket in sorted(counts):
            value = float(counts[bucket]) * self.values[bucket]
            dot += value
            contribution = value / float(total)
            if contribution > 0.0:
                contributions.append((f"#{bucket}", contribution))
        contributions.sort(key=lambda item: (-item[1], item[0]))
        top = [
            {"feature": name, "weight": round(weight, 4)}
            for name, weight in contributions[:TOP_FEATURES]
        ]
        return dot / float(total) + self.bias, top


def load_model(document: dict) -> "Model | FastTextModel":
    """The model of a ``model.json`` document of either form."""
    return FastTextModel(document) if document.get("kind") == FASTTEXT_KIND else Model(document)


def fit_fasttext(
    docs: list[list[int]],
    labels: np.ndarray,
    buckets: int,
    dim: int,
    *,
    lr: float,
    epochs: int,
    weight_decay: float,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Embeddings, output matrix (2 x dim) and bias of the averaged-embedding softmax, fitted by
    full-batch Adam on the class-balanced cross-entropy (deterministic for a seed). ``docs`` are
    the bucket lists of the rows; embeddings start uniform in ``±1/dim`` as in fastText, the
    output layer at zero."""
    n = len(docs)
    positives = float(labels.sum())
    if positives in (0.0, float(n)):
        raise ValueError("training rows need both labels")
    sample = np.where(labels == 1, n / (2 * positives), n / (2 * (n - positives))) / n
    lengths = np.array([len(doc) for doc in docs], dtype=np.float64)
    row_of = np.concatenate([np.full(len(doc), i, dtype=np.int64) for i, doc in enumerate(docs)] or [np.zeros(0, np.int64)])
    cols = np.array([index for doc in docs for index in doc], dtype=np.int64)
    share = 1.0 / lengths[row_of]
    rng = np.random.default_rng(seed)
    params = [
        rng.uniform(-1.0 / dim, 1.0 / dim, size=(buckets, dim)),
        np.zeros((2, dim)),
        np.zeros(2),
    ]
    moments = [(np.zeros_like(p), np.zeros_like(p)) for p in params]
    onehot = np.stack([1.0 - labels, labels], axis=1)
    beta1, beta2, eps = 0.9, 0.999, 1e-8
    for step in range(1, epochs + 1):
        embeddings, output, bias = params
        hidden = np.zeros((n, dim))
        weighted = embeddings[cols] * share[:, None]
        for j in range(dim):
            hidden[:, j] = np.bincount(row_of, weights=weighted[:, j], minlength=n)
        logits = hidden @ output.T + bias
        logits -= logits.max(axis=1, keepdims=True)
        probs = np.exp(logits)
        probs /= probs.sum(axis=1, keepdims=True)
        residual = (probs - onehot) * sample[:, None]
        grad_hidden = residual @ output
        per_feature = grad_hidden[row_of] * share[:, None]
        grad_embeddings = np.stack(
            [np.bincount(cols, weights=per_feature[:, j], minlength=buckets) for j in range(dim)], axis=1
        )
        grads = [
            grad_embeddings + weight_decay * embeddings,
            residual.T @ hidden + weight_decay * output,
            residual.sum(axis=0),
        ]
        for param, grad, (m, v) in zip(params, grads, moments):
            m *= beta1
            m += (1 - beta1) * grad
            v *= beta2
            v += (1 - beta2) * grad * grad
            param -= lr * (m / (1 - beta1**step)) / (np.sqrt(v / (1 - beta2**step)) + eps)
    return params[0], params[1], params[2]


def train_fasttext(
    rows: list[dict],
    name: str,
    *,
    buckets: int = 1 << 15,
    dim: int = 16,
    ngram_range: tuple[int, int] = (3, 5),
    lr: float = 0.05,
    epochs: int = 100,
    weight_decay: float = 1e-6,
    seed: int = 0,
    tokens: Callable[[dict], list[str]] = row_tokens,
) -> dict:
    """A fastText-type model document trained on rows with text, facts and label, with the
    ``1pct_fpr`` / ``0_1pct_fpr`` cuts on the negative rows' scores. Embeddings and output
    weights are stored as float32 values."""
    token_docs = [tokens(row) for row in rows]
    docs = [
        [fnv1a_32(f) % buckets for f in fasttext_features(row["text"], toks, *ngram_range)]
        for row, toks in zip(rows, token_docs)
    ]
    keep = [i for i, doc in enumerate(docs) if doc]
    labels = np.array([int(rows[i]["label"]) for i in keep], dtype=np.float64)
    embeddings, output, bias = fit_fasttext(
        [docs[i] for i in keep], labels, buckets, dim,
        lr=lr, epochs=epochs, weight_decay=weight_decay, seed=seed,
    )
    document = {
        "kind": FASTTEXT_KIND,
        "format_version": FASTTEXT_FORMAT_VERSION,
        "name": name,
        "analyzer_func": ANALYZER,
        "hash": HASH,
        "buckets": buckets,
        "dim": dim,
        "char_ngram_range": list(ngram_range),
        "labels": ["negative", "positive"],
        "embeddings": [float(v) for v in embeddings.astype(np.float32).ravel()],
        "output": [float(v) for v in output.astype(np.float32).ravel()],
        "bias": [float(v) for v in bias.astype(np.float32)],
        "thresholds": {},
        "default_threshold_policy": ASK_THRESHOLD,
        "decision_rule": "score > threshold",
    }
    model = FastTextModel(document)
    negatives = [
        model.score(row["text"], toks)[0]
        for row, toks in zip(rows, token_docs)
        if int(row["label"]) == 0
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
        if "fasttext" in options:
            document = train_fasttext(synthetic_rows(), name, epochs=200, **options["fasttext"])
        else:
            document = train(synthetic_rows(), name, min_df=1, iterations=200, **options)
        path.write_text(dump_model(document), encoding="utf-8")


def parity_scores() -> str:
    """Expected scores of the parity goldens under every synthetic model, as file content."""
    models = {
        name: load_model(json.loads(path.read_text(encoding="utf-8")))
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
    fit.add_argument("--fasttext", action="store_true", help="train the fastText-type candidate")
    fit.add_argument("--buckets", type=int, default=1 << 15, help="fastText-type: embedding buckets")
    fit.add_argument("--dim", type=int, default=16, help="fastText-type: embedding dimension")
    fit.add_argument("--epochs", type=int, default=100, help="fastText-type: full-batch Adam steps")
    score = sub.add_parser("score", help="reference scores of rows with text and facts")
    score.add_argument("--model", type=Path, required=True)
    score.add_argument("--rows", type=Path, required=True)
    parity = sub.add_parser("parity", help="rewrite the synthetic model and its parity goldens")
    parity.add_argument("--check", action="store_true", help="only check, exit 1 when stale")
    parity.add_argument("--retrain", action="store_true", help="retrain the synthetic model")
    args = parser.parse_args(argv)

    if args.command == "train" and args.fasttext:
        document = train_fasttext(
            read_rows(args.rows),
            f"text-{args.category}-fasttext",
            buckets=args.buckets,
            dim=args.dim,
            epochs=args.epochs,
        )
        args.out.write_text(dump_model(document), encoding="utf-8")
        return 0
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
        model = load_model(json.loads(args.model.read_text(encoding="utf-8")))
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
