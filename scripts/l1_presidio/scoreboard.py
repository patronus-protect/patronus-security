#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""L1-PII scoreboard: exact and overlap P/R/F1 of a head build against its base commit.

``gate`` scores the Ark build of a checkout (``--head``) and of its base commit
(``--base-sha``) on every frozen gold directory below ``--dev`` and ``--holdout``
(directories with ``.ready``, e.g. ``DIR/*.jsonl`` and ``DIR/synthetic/*.jsonl``):

    scoreboard.py gate --head WT --base-sha SHA --dev DIR [--holdout DIR] --cache DIR

Both sides are scored in the PII modes ``strict`` (the default build) and ``balanced`` (the
mode milestones are judged on, T15). Exit code 0 = no regression, 1 = regression, 2 = usage
or infrastructure error. A regression is any F1 loss above the tolerance (default 0.5 pp;
exact or overlap) of an entity, of all L1 entities together, of a source family or of DE/EN,
in any split and either mode, or any new prediction on a hard-negative span. The summary
goes to stdout; for the holdout it only names aggregates and regressions, never row ids or
text.

Scoring follows ``research/l1-pii/entity_map.yaml``: semantic entities are not L1
scope; a corpus listed in the map is scored only on the ids it annotates, a corpus
without map entry (the synthetic DE/EU set) on every L1 id, and a row with
``scored_entities`` (a Presidio recognizer test case) only on those ids. Exact = same
id, start and end; overlap = a gold span counts as found if a prediction of the same id
overlaps it, a prediction counts as correct if it overlaps gold of the same id.
Gold that cannot be a real value is ignored (``IGNORED_GOLD``): a ``pii.iban`` span whose compact
value fails the SWIFT IBAN registry (country in the registry, its exact length, MOD-97) is
neither required nor penalised, i.e. it is no gold and predictions overlapping it are dropped, for
every engine and split alike.

Predictions come from ``run_ark.py`` of the respective commit. The head runs with
``--ark-python`` (default: ``$VIRTUAL_ENV/bin/python``), which must import the
``patronus_ark`` package of the head checkout (``maturin develop``). The base is
built offline from ``git archive`` into the cache (``cargo build --offline``) unless
its predictions are cached already. Predictions are cached per source key (the git
trees that make up the Ark build) and input SHA-256, so the base of a stacked task,
whose source equals the previously gated head, is never rebuilt. Results land in
``CACHE/scoreboard/results/<sha>.json`` per commit.

``score`` scores one prediction file (Ark or Presidio format) without git:

    scoreboard.py score --gold gold.jsonl --predictions predictions.jsonl

Every bucket also exists per source family (``family/<family>``, ``family_entity/...``;
families from ``source_families`` in the entity map). ``m1`` checks milestone M1 per family
from Ark and Presidio predictions stored under the gold file names, for every Ark mode given;
the verdict comes from balanced:

    scoreboard.py m1 --gold DIR --ark strict=DIR --ark balanced=DIR --presidio PRESIDIO_DIR [--language en] [--check]

``m2`` checks milestone M2 per family the same way (D-M2): exact macro-F1 on German rows over the
shared and ark_only ids with gold in the family (presidio_only ids stay out until the entity map
marks them shared); neutral needs Presidio tuned + 15 pp, presidio_favored parity. It exits 1
unless both hold on balanced:

    scoreboard.py m2 --gold DIR --ark strict=DIR --ark balanced=DIR --presidio PRESIDIO_DIR [--language de]

``report`` renders the Markdown baseline (research/l1-pii/scoreboard/baseline.md): P/R/F1 per
source family, corpus and entity for each Ark mode and each Presidio profile, hard-negative FP
per family, M1 and M2 of every Ark mode against each profile, and the gold gaps per corpus and entity
(predictions equal to an annotated gold value elsewhere in the row, gold failing the entity's
checksum validator; reported only, T16):

    scoreboard.py report --gold DIR --ark strict=DIR --ark balanced=DIR \
        --engine presidio-default=DIR --engine presidio-tuned=DIR
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import entity_map as entity_map_module  # noqa: E402
import synth_goldset  # noqa: E402


SCHEMA = "ark-l1-scoreboard-v1"
# Bump when run_ark.py output or the build recipe changes in a way the source key misses.
PREDICTION_VERSION = "1"
TOLERANCE_PP = 0.5
# PII modes the gate scores for head and base; milestones are judged on balanced (T15).
MODES = ("strict", "balanced")
MILESTONE_MODE = "balanced"
ARK_MODES = ("strict", "balanced", "recall")  # accepted by m1, m2 and report
# M2 (D-M2): DE macro-F1 over these scopes; neutral needs Presidio tuned + 15 pp, presidio_favored parity.
M2_SCOPES = ("shared", "ark_only")
M2_MARGIN_PP = 15.0
M2_PARITY_FAMILIES = ("presidio_favored",)
# Everything that goes into the native module and the prediction runner.
KEY_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "rust",
    "ark-core",
    "python",
    "scripts/l1_presidio/run_ark.py",
)
LANGUAGES = ("de", "en")
METRICS = ("exact", "overlap")
COUNT_FIELDS = ("gold", "predicted", "exact", "gold_found", "predicted_correct")
NATIVE_LIBRARY = "lib_patronus_ark.so"
NATIVE_MODULE = "_patronus_ark.abi3.so"


class ScoreboardError(Exception):
    """Infrastructure or input problem; exit code 2."""


class Dataset(NamedTuple):
    split: str
    name: str  # path relative to the split root, e.g. synthetic/ark-synthetic-de-eu.jsonl
    path: Path
    sha256: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ScoreboardError(f"{path.name}:{number}: invalid JSON ({error.msg})") from None
    return rows


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def discover(split: str, root: Path) -> list[Dataset]:
    """Gold files of every frozen directory (``.ready``) in root and its visible subdirectories."""
    root = root.resolve()
    if not root.is_dir():
        raise ScoreboardError(f"{split}: {root} is not a directory")
    frozen = [root, *sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))]
    datasets = [
        Dataset(split, path.relative_to(root).as_posix(), path, sha256_file(path))
        for directory in frozen
        if (directory / ".ready").is_file()
        for path in sorted(directory.glob("*.jsonl"))
    ]
    if not datasets:
        raise ScoreboardError(f"{split}: no frozen gold JSONL (directory with .ready) in {root}")
    return datasets


# ── scoring ──────────────────────────────────────────────────────────────


def l1_ids(emap: Any) -> set[str]:
    return {entity_id for entity_id, entity in emap.entities.items() if entity.scope != "semantic"}


def scored_ids(emap: Any, corpus: str) -> set[str]:
    """L1 ids a corpus annotates; corpora without map entry annotate every L1 id."""
    l1 = l1_ids(emap)
    if corpus not in emap.corpora():
        return l1
    return {entity_id for entity_id in l1 if corpus in emap.entities[entity_id].corpora}


def resolve_label(span: dict[str, Any], emap: Any) -> str | None:
    """Benchmark id of a predicted span (Ark ``ark_label``, Presidio ``presidio_entity`` or ``label``).

    Native labels win over an embedded ``label``: a base commit's run_ark.py precomputed ``label``
    with its own output map, and the current entity map must decide how its ``ark_label`` counts."""
    if isinstance(span.get("ark_label"), str):
        return emap.ark_label(span["ark_label"])
    if isinstance(span.get("presidio_entity"), str):
        return emap.presidio_entity(span["presidio_entity"])
    label = span.get("label")
    if isinstance(label, str) and label in emap.entities:
        return label
    return None


def _span(item: dict[str, Any], label: str | None, where: str) -> tuple[str | None, int, int]:
    start = item.get("start", item.get("start_char"))
    end = item.get("end", item.get("end_char"))
    if isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, int) or not isinstance(end, int):
        raise ScoreboardError(f"{where}: span without integer offsets")
    if start < 0 or end <= start:
        raise ScoreboardError(f"{where}: empty or negative span {start}..{end}")
    return label, start, end


def _overlaps(a: tuple[str, int, int], b: tuple[str, int, int]) -> bool:
    return a[0] == b[0] and a[1] < b[2] and b[1] < a[2]


def language_bucket(language: Any) -> str:
    return language if language in LANGUAGES else "other"


def empty_counts() -> dict[str, int]:
    return dict.fromkeys(COUNT_FIELDS, 0)


def _predictions_by_id(
    gold_rows: list[dict[str, Any]], prediction_rows: Iterable[dict[str, Any]], dataset: str
) -> dict[str, list[dict[str, Any]]]:
    """Predicted spans per row id; the ids must match the gold rows one to one."""
    predictions: dict[str, list[dict[str, Any]]] = {}
    for row in prediction_rows:
        row_id = row.get("id")
        if not isinstance(row_id, str) or row_id in predictions:
            raise ScoreboardError(f"{dataset}: prediction rows need unique string ids")
        spans = row.get("evidence_spans")
        if not isinstance(spans, list):
            raise ScoreboardError(f"{dataset}: prediction {row_id!r} has no evidence_spans list")
        predictions[row_id] = spans
    gold_ids = [row.get("id") for row in gold_rows]
    if len(set(gold_ids)) != len(gold_ids) or not all(isinstance(i, str) for i in gold_ids):
        raise ScoreboardError(f"{dataset}: gold rows need unique string ids")
    unknown = predictions.keys() - set(gold_ids)
    missing = set(gold_ids) - predictions.keys()
    if unknown or missing:
        raise ScoreboardError(f"{dataset}: predictions do not match gold ({len(missing)} missing, {len(unknown)} unknown)")
    return predictions


def _row_scope(row: dict[str, Any], emap: Any, where: str) -> tuple[str, str, set[str]]:
    """Corpus, source family and the ids a gold row is scored on."""
    corpus = str(row.get("corpus", ""))
    family = emap.family(corpus)
    if family is None:
        raise ScoreboardError(f"{where}: corpus {corpus!r} has no source family in entity_map.yaml")
    allowed = scored_ids(emap, corpus)
    if "scored_entities" in row:
        # Rows that assert on some ids only (Presidio recognizer test cases).
        scored = row["scored_entities"]
        if not isinstance(scored, list) or not all(isinstance(item, str) for item in scored):
            raise ScoreboardError(f"{where}: scored_entities must be a list of ids")
        allowed = allowed & set(scored)
    return corpus, family, allowed


Span = tuple[str | None, int, int]


def _row_spans(
    row: dict[str, Any], spans: list[dict[str, Any]], emap: Any, where: str
) -> tuple[str, str, set[Span], set[Span], set[Span]]:
    """Corpus, family, scored gold, all predictions and scored predictions of one gold row.

    Gold of an ``IGNORED_GOLD`` id failing its check is dropped together with every scored prediction
    of that id overlapping it, so it neither counts as missed nor as a false positive."""
    corpus, family, allowed = _row_scope(row, emap, where)
    gold = {_span(e, e.get("entity_type", e.get("label")), where) for e in row.get("entities", [])}
    gold = {item for item in gold if item[0] in allowed}
    predicted_all = {_span(s, resolve_label(s, emap), where) for s in spans}
    predicted = {item for item in predicted_all if item[0] in allowed}
    ignored = {
        item for item in gold if item[0] in IGNORED_GOLD and not IGNORED_GOLD[item[0]](_gold_value(row, item, where))
    }
    if ignored:
        gold -= ignored
        predicted = {item for item in predicted if not any(_overlaps(item, g) for g in ignored)}
    return corpus, family, gold, predicted_all, predicted


def _gold_value(row: dict[str, Any], item: Span, where: str) -> str:
    """Annotated value without surrounding markup (``gap_value``)."""
    text = row.get("text")
    if not isinstance(text, str):
        raise ScoreboardError(f"{where}: gold row without text")
    return gap_value(text[item[1] : item[2]])


def score_rows(
    gold_rows: Iterable[dict[str, Any]], prediction_rows: Iterable[dict[str, Any]], emap: Any, dataset: str = ""
) -> dict[str, Any]:
    """Count exact and overlap matches per bucket plus predictions on hard-negative spans."""
    gold_rows = list(gold_rows)
    predictions = _predictions_by_id(gold_rows, prediction_rows, dataset)
    l1 = l1_ids(emap)
    scopes = {entity_id: emap.entities[entity_id].scope for entity_id in l1}
    buckets: dict[str, dict[str, int]] = defaultdict(empty_counts)
    hard_negative_fp: set[tuple[str, str, str, int, int]] = set()
    rows = 0
    for row in gold_rows:
        rows += 1
        row_id = row["id"]
        where = f"{dataset}:{row_id}"
        corpus, family, gold, predicted_all, predicted = _row_spans(row, predictions[row_id], emap, where)
        for hn in row.get("hard_negatives", []) or []:
            _, start, end = _span(hn, None, where)
            # A hard negative with entity_type only forbids that id (a recognizer's negative case).
            forbidden = {hn["entity_type"]} if isinstance(hn.get("entity_type"), str) else l1
            for item in predicted_all:
                if item[0] in forbidden and item[1] < end and start < item[2]:
                    hard_negative_fp.add((dataset, row_id, item[0], item[1], item[2]))
        language = language_bucket(row.get("language"))
        for label in {item[0] for item in gold | predicted}:
            expected = {item for item in gold if item[0] == label}
            actual = {item for item in predicted if item[0] == label}
            counts = {
                "gold": len(expected),
                "predicted": len(actual),
                "exact": len(expected & actual),
                "gold_found": sum(any(_overlaps(g, p) for p in actual) for g in expected),
                "predicted_correct": sum(any(_overlaps(p, g) for g in expected) for p in actual),
            }
            for bucket in (
                "all",
                f"language/{language}",
                f"corpus/{corpus}",
                f"scope/{scopes[label]}",
                f"entity/{label}",
                f"language_entity/{language}/{label}",
                f"family/{family}",
                f"family_language/{family}/{language}",
                f"family_entity/{family}/{label}",
                f"family_language_entity/{family}/{language}/{label}",
            ):
                for field, value in counts.items():
                    buckets[bucket][field] += value
    buckets.setdefault("all", empty_counts())
    return {
        "rows": rows,
        "buckets": {key: dict(value) for key, value in sorted(buckets.items())},
        "hard_negative_fp": sorted([list(item) for item in hard_negative_fp]),
    }


def merge(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, dict[str, int]] = defaultdict(empty_counts)
    hard_negative_fp: list[list[Any]] = []
    rows = 0
    for result in results:
        rows += result["rows"]
        hard_negative_fp += result["hard_negative_fp"]
        for key, counts in result["buckets"].items():
            for field in COUNT_FIELDS:
                buckets[key][field] += counts[field]
    buckets.setdefault("all", empty_counts())
    return {
        "rows": rows,
        "buckets": {key: dict(value) for key, value in sorted(buckets.items())},
        "hard_negative_fp": sorted(hard_negative_fp),
    }


def _prf(tp_precision: int, predicted: int, tp_recall: int, gold: int) -> dict[str, float]:
    precision = tp_precision / predicted if predicted else 0.0
    recall = tp_recall / gold if gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def metrics(counts: dict[str, int]) -> dict[str, dict[str, float]]:
    return {
        "exact": _prf(counts["exact"], counts["predicted"], counts["exact"], counts["gold"]),
        "overlap": _prf(counts["predicted_correct"], counts["predicted"], counts["gold_found"], counts["gold"]),
    }


# ── gold gaps (T16) ──────────────────────────────────────────────────────


def _digits(value: str) -> list[int]:
    return [int(ch) for ch in value if ch.isascii() and ch.isdigit()]


def luhn(value: str) -> bool:
    """Port of ``validators::luhn``: 12-19 digits (separators ignored), not one repeated digit."""
    digits = _digits(value)
    if not 12 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = sum(d if i % 2 == 0 else (2 * d - 9 if d > 4 else 2 * d) for i, d in enumerate(reversed(digits)))
    return total % 10 == 0


# (lowest prefix, highest prefix, lengths) of ``validators::CARD_IIN_RANGES``.
CARD_IIN_RANGES: tuple[tuple[str, str, tuple[int, ...]], ...] = (
    ("34", "34", (15,)), ("37", "37", (15,)),
    ("300", "305", tuple(range(14, 20))), ("3095", "3095", tuple(range(14, 20))),
    ("36", "36", tuple(range(14, 20))), ("38", "39", tuple(range(14, 20))),
    ("35", "35", tuple(range(16, 20))), ("1800", "1800", (15,)), ("2131", "2131", (15,)),
    ("2200", "2204", tuple(range(16, 20))), ("2221", "2720", (16,)), ("51", "55", (16,)),
    ("4", "4", (13, 16, 19)),
    ("6011", "6011", tuple(range(16, 20))), ("644", "649", tuple(range(16, 20))), ("65", "65", tuple(range(16, 20))),
    ("62", "62", tuple(range(16, 20))),
    ("50", "50", tuple(range(12, 20))), ("56", "69", tuple(range(12, 20))),
    ("1", "1", (15,)),
)


def _valid_date(year: int, month: int, day: int) -> bool:
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    return 1900 <= year <= 2100


def payment_card(value: str) -> bool:
    """Port of ``validators::payment_card``: Luhn, IIN prefix and length of a brand, no birth-date ID or stamp."""
    if not luhn(value):
        return False
    digits = "".join(str(d) for d in _digits(value))
    if not any(len(digits) in lengths and low <= digits[: len(low)] <= high for low, high, lengths in CARD_IIN_RANGES):
        return False
    birth_date_id = len(digits) == 13 and _valid_date(2000 + int(digits[:2]), int(digits[2:4]), int(digits[4:6]))
    stamp = digits[:2] in ("19", "20") and _valid_date(int(digits[:4]), int(digits[4:6]), int(digits[6:8]))
    return not birth_date_id and not stamp


def mod97(value: str) -> bool:
    """Port of ``validators::mod97`` (ISO 7064 MOD 97-10 on the value without whitespace)."""
    normalized = "".join(ch for ch in value if not ch.isspace())
    if len(normalized.encode()) < 5:
        return False
    remainder = 0
    for ch in normalized[4:] + normalized[:4]:
        digits = str(ord(ch) - ord("A") + 10) if "A" <= ch <= "Z" else ch
        for digit in digits:
            if digit.isascii() and digit.isdigit():
                remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


# Total IBAN length per country of the SWIFT IBAN registry (ISO 13616); French, British and Finnish
# territories issue IBANs under FR, GB and FI. Countries outside it (experimental or Faker-made formats)
# have no IBAN.
IBAN_REGISTRY_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27,
    "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
    "GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
    "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28,
    "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}


def iban_registry(value: str) -> bool:
    """Port of ``validators::iban``: known registry country, its exact length, alphanumeric, MOD-97 (any case, any spacing)."""
    compact = "".join(ch for ch in value if not ch.isspace()).upper()
    return (
        IBAN_REGISTRY_LENGTHS.get(compact[:2]) == len(compact)
        and compact.isascii() and compact.isalnum() and compact[2:4].isdigit()
        and mod97(compact)
    )


def steuer_id(value: str) -> bool:
    """Port of ``validators::steuer_id`` (ISO 7064 MOD 11,10, 11 digits, no leading zero)."""
    digits = _digits(value)
    if len(digits) != 11 or digits[0] == 0:
        return False
    product = 10
    for digit in digits[:10]:
        total = (digit + product) % 10 or 10
        product = total * 2 % 11
    return (11 - product) % 10 == digits[10]


def steuer_id_issued(value: str) -> bool:
    """Port of ``validators::steuer_id_issued``: checksum plus the BZSt digit distribution."""
    if not steuer_id(value):
        return False
    digits = _digits(value)[:10]
    repeated = [n for n in (digits.count(d) for d in set(digits)) if n > 1]
    runs = any(digits[i] == digits[i + 1] == digits[i + 2] for i in range(len(digits) - 2))
    return len(repeated) == 1 and repeated[0] in (2, 3) and not runs


def _vat_body(value: str, prefix: str) -> str:
    """Upper-case alphanumerics of a VAT ID without its country prefix (``DE.136.695.976`` → ``136695976``)."""
    compact = "".join(ch.upper() for ch in value if ch.isascii() and ch.isalnum())
    return compact[len(prefix):] if compact.startswith(prefix) else compact


def _vat_digits(body: str, length: int) -> list[int] | None:
    return [int(ch) for ch in body] if len(body) == length and body.isascii() and body.isdigit() else None


def _luhn_checksum(digits: list[int]) -> int:
    """Luhn checksum with the last digit undoubled, in ``0..10``."""
    return sum(d if i % 2 == 0 else (2 * d - 9 if d > 4 else 2 * d) for i, d in enumerate(reversed(digits))) % 10


def _weighted_sum(digits: list[int], weights: tuple[int, ...] | range) -> int:
    return sum(d * w for d, w in zip(digits, weights))


def _number(digits: list[int]) -> int:
    return int("".join(map(str, digits)))


def de_vat_id(value: str) -> bool:
    """Port of ``validators::de_vat_id`` (9 digits, no leading zero, ISO 7064 MOD 11,10)."""
    digits = _vat_digits(_vat_body(value, "DE"), 9)
    if digits is None or digits[0] == 0:
        return False
    product = 10
    for digit in digits[:8]:
        product = ((digit + product) % 10 or 10) * 2 % 11
    return (11 - product) % 10 == digits[8]


def at_vat_id(value: str) -> bool:
    """Port of ``validators::at_vat_id`` (``U`` + 8 digits, check = (6 − Luhn checksum) mod 10)."""
    body = _vat_body(value, "AT")
    digits = _vat_digits(body[1:], 8) if body.startswith("U") else None
    return digits is not None and (16 - _luhn_checksum(digits[:7])) % 10 == digits[7]


def ch_vat_id(value: str) -> bool:
    """Port of ``validators::ch_vat_id`` (9 digits, weighted mod 11, remainder 10 never issued)."""
    body = _vat_body(value, "CHE")
    for suffix in ("MWST", "TVA", "IVA", "TPV"):
        if body.endswith(suffix):
            body = body[: -len(suffix)]
            break
    digits = _vat_digits(body, 9)
    if digits is None:
        return False
    check = (11 - _weighted_sum(digits, (5, 4, 3, 2, 7, 6, 5, 4)) % 11) % 11
    return check != 10 and check == digits[8]


def fr_vat_id(value: str) -> bool:
    """Port of ``validators::fr_vat_id`` (numeric key (12 + 3 × SIREN) mod 97, SIREN Luhn unless 000…)."""
    digits = _vat_digits(_vat_body(value, "FR"), 11)
    if digits is None:
        return False
    siren = digits[2:]
    number = _number(siren)
    return (siren[:3] == [0, 0, 0] or _luhn_checksum(siren) == 0) and digits[0] * 10 + digits[1] == (number * 100 + 12) % 97


def nl_vat_id(value: str) -> bool:
    """Port of ``validators::nl_vat_id`` (9 digits + B + branch 01–99, mod 11 or ISO 7064 MOD 97-10)."""
    body = _vat_body(value, "NL")
    if len(body) != 12 or body[9] != "B":
        return False
    digits, branch = _vat_digits(body[:9], 9), _vat_digits(body[10:], 2)
    if digits is None or branch is None or not any(digits) or branch == [0, 0]:
        return False
    mod11 = _eleven_proof(digits)
    mod97 = int("".join(str(int(ch, 36)) for ch in "NL" + body)) % 97 == 1
    return mod11 or mod97


def be_vat_id(value: str) -> bool:
    """Port of ``validators::be_vat_id`` (10 digits starting 0 or 1, check = 97 − first eight mod 97)."""
    digits = _vat_digits(_vat_body(value, "BE"), 10)
    if digits is None:
        return False
    number = _number(digits[:8])
    return digits[0] <= 1 and number != 0 and 97 - number % 97 == _number(digits[8:])


def it_vat_id(value: str) -> bool:
    """Port of ``validators::it_vat_id`` (11 digits, company not zero, office code, Luhn)."""
    digits = _vat_digits(_vat_body(value, "IT"), 11)
    if digits is None:
        return False
    office = digits[7] * 100 + digits[8] * 10 + digits[9]
    return any(digits[:7]) and (1 <= office <= 100 or office in (120, 121, 888, 999)) and _luhn_checksum(digits) == 0


ES_CONTROL_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def es_vat_id(value: str) -> bool:
    """Port of ``validators::es_vat_id`` (DNI, NIE, NIF K/L/M or CIF with control character)."""
    body = _vat_body(value, "ES")
    if len(body) != 9 or _vat_digits(body[1:8], 7) is None:
        return False
    first, middle, last = body[0], body[1:8], body[8]
    if first.isdigit():
        return last == ES_CONTROL_LETTERS[int(first + middle) % 23]
    if first in "XYZ":
        return last == ES_CONTROL_LETTERS[int(str("XYZ".index(first)) + middle) % 23]
    if first in "KLM":
        return last == ES_CONTROL_LETTERS[int(middle) % 23]
    if first in "ABCDEFGHJNPQRSUVW":
        total = sum(int(d) for d in middle[1::2]) + sum(sum(divmod(2 * int(d), 10)) for d in middle[0::2])
        check = (10 - total % 10) % 10
        return last in (str(check), "JABCDEFGHI"[check])
    return False


# ── B02: VAT IDs part 2 ──────────────────────────────────────────────────────


def _vat_number(body: str, *lengths: int) -> list[int] | None:
    """Digits of ``body`` if its length is one of ``lengths`` and not every digit is zero."""
    digits = _vat_digits(body, len(body)) if len(body) in lengths else None
    return digits if digits and any(digits) else None


def bg_vat_id(value: str) -> bool:
    """Port of ``validators::bg_vat_id`` (9 digits weights 1…8/3…10 mod 11; 10 digits EGN, LNCh or other)."""
    digits = _vat_number(_vat_body(value, "BG"), 9, 10)
    if digits is None:
        return False
    if len(digits) == 9:
        check = _weighted_sum(digits[:8], range(1, 9)) % 11
        if check == 10:
            check = _weighted_sum(digits[:8], range(3, 11)) % 11
        return check % 10 == digits[8]
    year, month, day = digits[0] * 10 + digits[1], digits[2] * 10 + digits[3], digits[4] * 10 + digits[5]
    if month > 40:
        year, month = 2000 + year, month - 40
    elif month > 20:
        year, month = 1800 + year, month - 20
    else:
        year += 1900
    egn = _valid_date(year, month, day) and _weighted_sum(digits[:9], (2, 4, 8, 5, 10, 9, 7, 3, 6)) % 11 % 10 == digits[9]
    foreigner = _weighted_sum(digits[:9], (21, 19, 17, 13, 11, 9, 7, 3, 1)) % 10 == digits[9]
    other = (11 - _weighted_sum(digits[:9], (4, 3, 2, 7, 6, 5, 4, 3, 2)) % 11) % 11 == digits[9]
    return egn or foreigner or other


def cy_vat_id(value: str) -> bool:
    """Port of ``validators::cy_vat_id`` (8 digits not starting 12, check letter mod 26)."""
    body = _vat_body(value, "CY")
    digits = _vat_number(body[:-1], 8)
    if digits is None or digits[:2] == [1, 2]:
        return False
    total = sum((1, 0, 5, 7, 9, 13, 15, 17, 19, 21)[d] for d in digits[::2]) + sum(digits[1::2])
    return body[-1] == chr(ord("A") + total % 26)


def cz_vat_id(value: str) -> bool:
    """Port of ``validators::cz_vat_id`` (legal entity, special 6…, ten-digit birth number)."""
    digits = _vat_number(_vat_body(value, "CZ"), 8, 9, 10)
    if digits is None:
        return False
    weights = range(8, 1, -1)
    if len(digits) == 8:
        check = (11 - _weighted_sum(digits[:7], weights) % 11) % 11
        return digits[0] != 9 and (check or 1) % 10 == digits[7]
    if len(digits) == 9:
        return digits[0] == 6 and (_weighted_sum(digits[1:8], weights) % 11 + 8) % 10 == digits[8]
    year, month, day = digits[0] * 10 + digits[1], digits[2] * 10 + digits[3], digits[4] * 10 + digits[5]
    year += 1900 if year >= 54 else 2000
    valid_month = 1 <= month <= 12 or 21 <= month <= 32 or 51 <= month <= 62 or 71 <= month <= 82
    return (
        valid_month
        and _valid_date(year, month % 50 % 20, day)
        and _number(digits[:9]) % 11 % 10 == digits[9]
    )


def dk_vat_id(value: str) -> bool:
    """Port of ``validators::dk_vat_id`` (8 digits, no leading zero, weights 2-7-6-5-4-3-2-1 mod 11)."""
    digits = _vat_number(_vat_body(value, "DK"), 8)
    return digits is not None and digits[0] != 0 and _weighted_sum(digits, (2, 7, 6, 5, 4, 3, 2, 1)) % 11 == 0


def ee_vat_id(value: str) -> bool:
    """Port of ``validators::ee_vat_id`` (9 digits starting 10, weights 3-7-1 mod 10)."""
    digits = _vat_number(_vat_body(value, "EE"), 9)
    return digits is not None and digits[:2] == [1, 0] and _weighted_sum(digits, (3, 7, 1) * 3) % 10 == 0


def el_vat_id(value: str) -> bool:
    """Port of ``validators::el_vat_id`` (prefix EL or GR, 9 digits, Σ d × 2^(9 − i) mod 11 mod 10)."""
    compact = _vat_body(value, "")
    body = next((compact[2:] for prefix in ("EL", "GR") if compact.startswith(prefix)), compact)
    digits = _vat_number(body, 9)
    if digits is None:
        return False
    total = 0
    for digit in digits[:8]:
        total = total * 2 + digit
    return total * 2 % 11 % 10 == digits[8]


def fi_vat_id(value: str) -> bool:
    """Port of ``validators::fi_vat_id`` (8 digits, weights 7-9-10-5-8-4-2-1 mod 11)."""
    digits = _vat_number(_vat_body(value, "FI"), 8)
    return digits is not None and _weighted_sum(digits, (7, 9, 10, 5, 8, 4, 2, 1)) % 11 == 0


def hr_vat_id(value: str) -> bool:
    """Port of ``validators::hr_vat_id`` (OIB: 11 digits, ISO 7064 MOD 11,10)."""
    digits = _vat_number(_vat_body(value, "HR"), 11)
    if digits is None:
        return False
    product = 10
    for digit in digits[:10]:
        product = ((digit + product) % 10 or 10) * 2 % 11
    return (11 - product) % 10 == digits[10]


def hu_vat_id(value: str) -> bool:
    """Port of ``validators::hu_vat_id`` (8 digits, weights 9-7-3-1 mod 10)."""
    digits = _vat_number(_vat_body(value, "HU"), 8)
    return digits is not None and _weighted_sum(digits, (9, 7, 3, 1) * 2) % 10 == 0


IE_CHECK_LETTERS = "WABCDEFGHIJKLMNOPQRSTUV"


def ie_vat_id(value: str) -> bool:
    """Port of ``validators::ie_vat_id`` (7 digits + check letter + optional letter, or the old form)."""
    # The old form may carry ``+`` or ``*`` as its second character, which ``_vat_body`` drops.
    compact = "".join(ch.upper() for ch in value if ch.isascii() and (ch.isalnum() or ch in "+*"))
    body = compact[2:] if compact.startswith("IE") else compact
    if len(body) not in (8, 9) or not all(ch in IE_CHECK_LETTERS for ch in body[7:]):
        return False
    digits = _vat_digits(body[:7], 7)
    second = IE_CHECK_LETTERS.index(body[8]) if len(body) == 9 else 0
    if digits is None:
        tail, first = _vat_digits(body[2:7], 5), _vat_digits(body[:1], 1)
        if len(body) != 8 or not ("A" <= body[1] <= "Z" or body[1] in "+*") or tail is None or first is None:
            return False
        digits, second = [0, *tail, *first], 0
    return any(digits) and _ie_check_letter(digits, second) == body[7]


def _ie_check_letter(digits: list[int], second: int) -> str:
    return IE_CHECK_LETTERS[(_weighted_sum(digits, range(8, 1, -1)) + 9 * second) % 23]


def lt_vat_id(value: str) -> bool:
    """Port of ``validators::lt_vat_id`` (9 or 12 digits with the 1 marker, weights 1…9 mod 11, second step +2)."""
    digits = _vat_number(_vat_body(value, "LT"), 9, 12)
    if digits is None:
        return False
    number, check = digits[:-1], digits[-1]
    remainder = sum((1 + i % 9) * d for i, d in enumerate(number)) % 11
    if remainder == 10:
        remainder = sum((1 + (i + 2) % 9) * d for i, d in enumerate(number)) % 11
    return number[-1] == 1 and remainder % 10 == check


# ── B16: VAT IDs part 3 ──────────────────────────────────────────────────────


def lu_vat_id(value: str) -> bool:
    """Port of ``validators::lu_vat_id`` (8 digits, last two = first six mod 89)."""
    digits = _vat_digits(_vat_body(value, "LU"), 8)
    return digits is not None and _number(digits[:6]) % 89 == _number(digits[6:])


def lv_vat_id(value: str) -> bool:
    """Port of ``validators::lv_vat_id`` (11 digits of a legal entity, weighted mod 11 = 3)."""
    digits = _vat_digits(_vat_body(value, "LV"), 11)
    return digits is not None and digits[0] > 3 and _weighted_sum(digits, (9, 1, 4, 8, 3, 10, 2, 5, 7, 6, 1)) % 11 == 3


def mt_vat_id(value: str) -> bool:
    """Port of ``validators::mt_vat_id`` (8 digits, no leading zero, weighted mod 37)."""
    digits = _vat_digits(_vat_body(value, "MT"), 8)
    return digits is not None and digits[0] != 0 and _weighted_sum(digits, (3, 4, 6, 7, 8, 9, 10, 1)) % 37 == 0


def pl_vat_id(value: str) -> bool:
    """Port of ``validators::pl_vat_id`` (NIP: 10 digits, weighted mod 11 check digit)."""
    digits = _vat_digits(_vat_body(value, "PL"), 10)
    return digits is not None and _weighted_sum(digits, (6, 5, 7, 2, 3, 4, 5, 6, 7)) % 11 == digits[9]


def pt_vat_id(value: str) -> bool:
    """Port of ``validators::pt_vat_id`` (NIF: 9 digits, no leading zero, weighted 9…2 mod 11)."""
    digits = _vat_digits(_vat_body(value, "PT"), 9)
    return digits is not None and _pt_nif_check(digits)


def _pt_nif_check(digits: list[int]) -> bool:
    return digits[0] != 0 and (11 - _weighted_sum(digits, (9, 8, 7, 6, 5, 4, 3, 2)) % 11) % 11 % 10 == digits[8]


def ro_vat_id(value: str) -> bool:
    """Port of ``validators::ro_vat_id`` (CUI: 2–10 digits, no leading zero, right-aligned weighted mod 11)."""
    body = _vat_body(value, "RO")
    if not 2 <= len(body) <= 10 or body.startswith("0"):
        return False
    digits = _vat_digits(body, len(body))
    if digits is None:
        return False
    weights = (7, 5, 3, 2, 1, 7, 5, 3, 2)[10 - len(digits):]
    return 10 * _weighted_sum(digits[:-1], weights) % 11 % 10 == digits[-1]


def se_vat_id(value: str) -> bool:
    """Port of ``validators::se_vat_id`` (10-digit organisation number with Luhn, then ``01``)."""
    digits = _vat_digits(_vat_body(value, "SE"), 12)
    return digits is not None and digits[10:] == [0, 1] and _luhn_checksum(digits[:10]) == 0


def si_vat_id(value: str) -> bool:
    """Port of ``validators::si_vat_id`` (8 digits, no leading zero, 11 − weighted 8…2 mod 11, 10 → 0)."""
    digits = _vat_digits(_vat_body(value, "SI"), 8)
    if digits is None or digits[0] == 0:
        return False
    check = 11 - _weighted_sum(digits, (8, 7, 6, 5, 4, 3, 2)) % 11
    return check != 11 and check % 10 == digits[7]


def sk_vat_id(value: str) -> bool:
    """Port of ``validators::sk_vat_id`` (10 digits, no leading zero, third in 2 3 4 7 8 9, mod 11)."""
    digits = _vat_digits(_vat_body(value, "SK"), 10)
    return digits is not None and digits[0] != 0 and digits[2] in (2, 3, 4, 7, 8, 9) and _number(digits) % 11 == 0


def no_vat_id(value: str) -> bool:
    """Port of ``validators::no_vat_id`` (9-digit organisation number, weighted mod 11, then ``MVA``)."""
    body = _vat_body(value, "NO")
    digits = _vat_digits(body[:-3], 9) if body.endswith("MVA") else None
    return digits is not None and _weighted_sum(digits, (3, 2, 7, 6, 5, 4, 3, 2, 1)) % 11 == 0


def gb_vat_id(value: str) -> bool:
    """Port of ``validators::gb_vat_id`` (GB or XI, 9 or 12 digits, weighted mod 97 = 0, or 42 from 100…)."""
    body = _vat_body(value, "GB")
    body = body[2:] if body.startswith("XI") else body
    digits = _vat_digits(body, 9) or _vat_digits(body, 12)
    if digits is None:
        return False
    remainder = _weighted_sum(digits, (8, 7, 6, 5, 4, 3, 2, 10, 1)) % 97
    return remainder == 0 or (remainder == 42 and digits[0] != 0)


ICAO_DOCUMENT_ALPHABET = "0123456789CFGHJKLMNPRTVWXYZ"


def icao_check_digit(data: str) -> int | None:
    """Port of ``validators::icao_check_digit`` (ICAO 9303: weights 7-3-1, A=10 … Z=35, ``<`` = 0)."""
    total = 0
    for index, ch in enumerate(data):
        if "0" <= ch <= "9":
            value = int(ch)
        elif "A" <= ch <= "Z":
            value = ord(ch) - ord("A") + 10
        elif ch == "<":
            value = 0
        else:
            return None
        total += value * (7, 3, 1)[index % 3]
    return total % 10


def _de_document_check_digit(value: str, series: str) -> bool:
    """Port of ``validators::de_document_check_digit``: series letter + ICAO alphabet or old numeric serial."""
    if not value.isascii() or len(value) not in (9, 10) or (value != value.upper() and value != value.lower()):
        return False
    upper = value.upper()
    data, check = upper[:-1], upper[-1]
    numeric = len(upper) == 10 and upper.isdigit() and upper.strip("0") != ""
    lettered = data[0] in series and all(ch in ICAO_DOCUMENT_ALPHABET for ch in data)
    return (numeric or lettered) and check.isdigit() and icao_check_digit(data) == int(check)


def de_passport_number(value: str) -> bool:
    """Port of ``validators::de_passport_number`` (series C F G H J K or old numeric, ICAO 9303)."""
    return _de_document_check_digit(value, "CFGHJK")


def de_identity_card_number(value: str) -> bool:
    """Port of ``validators::de_identity_card_number`` (series L M N P R T V W X Y or old numeric, ICAO 9303)."""
    return _de_document_check_digit(value, "LMNPRTVWXY")


def _grouped_digits(value: str, length: int) -> list[int] | None:
    """The digits of ``value`` without spaces and hyphens, if there are exactly ``length`` ASCII digits."""
    body = value.replace(" ", "").replace("-", "")
    if len(body) != length or not body.isascii() or not body.isdigit():
        return None
    return [int(ch) for ch in body]


def uk_nhs_number(value: str) -> bool:
    """Port of ``validators::uk_nhs_number`` (ten digits, weights 10…1 mod 11 = 0, not one repeated digit)."""
    digits = _grouped_digits(value, 10)
    if digits is None or len(set(digits)) == 1:
        return False
    return _weighted_sum(digits, range(10, 0, -1)) % 11 == 0


def au_abn(value: str) -> bool:
    """Port of ``validators::au_abn`` (eleven digits, first minus one, weights 10 1 3 … 19 mod 89)."""
    digits = _grouped_digits(value, 11)
    if digits is None or digits[0] == 0:
        return False
    digits[0] -= 1
    return _weighted_sum(digits, (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)) % 89 == 0


def au_acn(value: str) -> bool:
    """Port of ``validators::au_acn`` (nine digits, complement of weights 8…1 mod 10, not one repeated digit)."""
    digits = _grouped_digits(value, 9)
    if digits is None or len(set(digits)) == 1:
        return False
    return (10 - _weighted_sum(digits[:8], range(8, 0, -1)) % 10) % 10 == digits[8]


def au_tfn(value: str) -> bool:
    """Port of ``validators::au_tfn`` (nine digits, weights 1 4 3 7 5 8 6 9 10 mod 11, not one repeated digit)."""
    digits = _grouped_digits(value, 9)
    if digits is None or len(set(digits)) == 1:
        return False
    return _weighted_sum(digits, (1, 4, 3, 7, 5, 8, 6, 9, 10)) % 11 == 0


def au_medicare(value: str) -> bool:
    """Port of ``validators::au_medicare`` (ten digits from 2 to 6, ninth = weights 1 3 7 9 mod 10)."""
    digits = _grouped_digits(value, 10)
    if digits is None or not 2 <= digits[0] <= 6:
        return False
    return _weighted_sum(digits[:8], (1, 3, 7, 9, 1, 3, 7, 9)) % 10 == digits[8]


def _letter_digits(letter: str) -> list[int]:
    """The alphabet position of an ASCII letter as two digits (``A`` = 0 1 … ``Z`` = 2 6)."""
    position = ord(letter.upper()) - ord("A") + 1
    return [position // 10, position % 10]


def _weighted_cross_sum(digits: list[int], weights: tuple[int, ...]) -> int:
    return sum(digit * weight // 10 + digit * weight % 10 for digit, weight in zip(digits, weights))


def de_social_security_number(value: str) -> bool:
    """Port of ``validators::de_social_security_number`` (VKVV § 4, birth day 01–31/51–81, month 01–12)."""
    body = value.replace(" ", "").replace("\t", "")
    if (
        len(body) != 12
        or not body.isascii()
        or not body[8].isalpha()
        or not (body[:8] + body[9:]).isdigit()
        or not (1 <= int(body[2:4]) <= 31 or 51 <= int(body[2:4]) <= 81)
        or not 1 <= int(body[4:6]) <= 12
    ):
        return False
    digits = [int(ch) for ch in body[:8]] + _letter_digits(body[8]) + [int(ch) for ch in body[9:11]]
    return _weighted_cross_sum(digits, (2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1)) % 10 == int(body[11])


def de_health_insurance_number(value: str) -> bool:
    """Port of ``validators::de_health_insurance_number`` (§ 290 SGB V, not nine zeros)."""
    if len(value) != 10 or not value.isascii() or not value[0].isalpha() or not value[1:].isdigit():
        return False
    if set(value[1:]) == {"0"}:
        return False
    digits = _letter_digits(value[0]) + [int(ch) for ch in value[1:9]]
    return _weighted_cross_sum(digits, (1, 2) * 5) % 10 == int(value[9])


def lanr(value: str) -> bool:
    """Port of ``validators::lanr`` (nine digits, seventh = complement of weights 4 9 mod 10, not one repeated digit)."""
    digits = _grouped_digits(value, 9)
    if digits is None or len(set(digits)) == 1:
        return False
    return (10 - _weighted_sum(digits[:6], (4, 9, 4, 9, 4, 9)) % 10) % 10 == digits[6]


def aba_routing_number(value: str) -> bool:
    """Port of ``validators::aba_routing_number`` (routing symbol 00–12/21–32/61–72/80, weights 3 7 1 mod 10)."""
    digits = _grouped_digits(value, 9)
    if digits is None or len(set(digits)) == 1:
        return False
    symbol = digits[0] * 10 + digits[1]
    if not (symbol <= 12 or 21 <= symbol <= 32 or 61 <= symbol <= 72 or symbol == 80):
        return False
    return _weighted_sum(digits, (3, 7, 1) * 3) % 10 == 0


_NRIC_SERIES = {"S": (0, "JZIHGFEDCBA"), "T": (4, "JZIHGFEDCBA"), "F": (0, "XWUTRQPNMLK"),
                "G": (4, "XWUTRQPNMLK"), "M": (3, "XWUTRQPNJLK")}


def sg_nric_fin(value: str) -> bool:
    """Port of ``validators::sg_nric_fin`` (series letter, seven digits, check letter mod 11, either case)."""
    value = value.upper()
    series = _NRIC_SERIES.get(value[:1])
    if len(value) != 9 or series is None or not value[1:8].isascii() or not value[1:8].isdigit():
        return False
    offset, letters = series
    return letters[(_weighted_sum([int(ch) for ch in value[1:8]], (2, 7, 6, 5, 4, 3, 2)) + offset) % 11] == value[8]


_UEN_ENTITY_TYPES = set(
    "LP LL FC PF RF MQ MM NB CC CS MB FM GS DP CP NR CM CD MD HS VH CH MH CL XL CX HC RP TU TC FB FN PA PB SS "
    "MC SM GA GB".split()
)
_UEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWX0123456789"


def sg_uen(value: str) -> bool:
    """Port of ``validators::sg_uen`` (formats A, B with year 1800–2099, C; check letter mod 11; uppercase)."""
    body, check = value[:-1], value[-1:]
    numeric = body.isascii() and body.isdigit()
    if len(body) == 8 and numeric:
        return "XMKECAWLJDB"[_weighted_sum([int(ch) for ch in body], (10, 4, 9, 3, 8, 2, 7, 1)) % 11] == check
    if len(body) == 9 and numeric:
        return body[:2] in ("18", "19", "20") and (
            "ZKCMDNERGWH"[_weighted_sum([int(ch) for ch in body], (10, 8, 6, 4, 9, 7, 5, 3, 1)) % 11] == check
        )
    if (
        len(body) != 9
        or body[0] not in "TSR"
        or not (body[1:3].isascii() and body[1:3].isdigit())
        or body[3:5] not in _UEN_ENTITY_TYPES
        or not (body[5:9].isascii() and body[5:9].isdigit())
    ):
        return False
    total = sum(_UEN_ALPHABET.index(ch) * weight for ch, weight in zip(body, (4, 3, 5, 3, 10, 2, 2, 5, 7)))
    return _UEN_ALPHABET[(total - 5) % 11] == check


def se_personnummer(value: str) -> bool:
    """Port of ``validators::se_personnummer`` (YYMMDD or YYYYMMDD, ``-``/``+`` before the last four, Luhn)."""
    body = value[:-5] + value[-4:] if value[-5:-4] in ("-", "+") else value
    if not body.isascii() or not body.isdigit() or len(body) not in (10, 12):
        return False
    if len(body) == 12:
        if body[:2] not in ("19", "20"):
            return False
        centuries, body = (int(body[:2]) * 100,), body[2:]
    else:
        centuries = (1900, 2000)
    day = int(body[4:6])
    day = day - 60 if day > 60 else day
    if not any(_valid_date(century + int(body[:2]), int(body[2:4]), day) for century in centuries):
        return False
    return _luhn_checksum([int(ch) for ch in body]) == 0


_HETU_CHECK = "0123456789ABCDEFHJKLMNPRSTUVWXY"


def fi_hetu(value: str) -> bool:
    """Port of ``validators::fi_hetu`` (DDMMYY, century sign, individual number 002–999, check mod 31)."""
    value = value.upper()
    digits = value[:6] + value[7:10]
    if len(value) != 11 or not digits.isascii() or not digits.isdigit():
        return False
    if value[6] in "-YXWVU":
        century = 1900
    elif value[6] in "ABCDEF":
        century = 2000
    else:
        return False
    if not _valid_date(century + int(value[4:6]), int(value[2:4]), int(value[:2])) or int(value[7:10]) < 2:
        return False
    return _HETU_CHECK[int(digits) % 31] == value[10]


def dk_cpr(value: str) -> bool:
    """Port of ``validators::dk_cpr`` (DDMMYY, century from the 7th digit, weights 4 3 2 7 6 5 4 3 2 1 mod 11)."""
    digits = _grouped_digits(value, 10)
    if digits is None:
        return False
    year = digits[4] * 10 + digits[5]
    if digits[6] <= 3 or (digits[6] in (4, 9) and year >= 37):
        century = 1900
    elif digits[6] in (4, 9) or year <= 57:
        century = 2000
    else:
        return False
    if not _valid_date(century + year, digits[2] * 10 + digits[3], digits[0] * 10 + digits[1]):
        return False
    return _weighted_sum(digits, (4, 3, 2, 7, 6, 5, 4, 3, 2, 1)) % 11 == 0


def no_fodselsnummer(value: str) -> bool:
    """Port of ``validators::no_fodselsnummer`` (DDMMYY with D/H-number offsets, individual number, two mod 11)."""
    digits = _grouped_digits(value, 11)
    if digits is None:
        return False
    day, month, year = (digits[i] * 10 + digits[i + 1] for i in (0, 2, 4))
    individual = _number(digits[6:9])
    if individual <= 499 or (individual >= 900 and year >= 40):
        century = 1900
    elif individual >= 500 and year <= 39:
        century = 2000
    else:
        return False
    day, month = (day - 40 if day > 40 else day), (month - 40 if month > 40 else month)
    return (
        _valid_date(century + year, month, day)
        and _weighted_sum(digits, (3, 7, 6, 1, 8, 9, 4, 5, 2, 1)) % 11 == 0
        and _weighted_sum(digits, (5, 4, 3, 2, 7, 6, 5, 4, 3, 2, 1)) % 11 == 0
    )


def _separated_digits(value: str, length: int, separators: str) -> list[int] | None:
    """The digits of ``value`` without ``separators``, if there are exactly ``length`` ASCII digits."""
    body = "".join(ch for ch in value if ch not in separators)
    if len(body) != length or not body.isascii() or not body.isdigit():
        return None
    return [int(ch) for ch in body]


def fr_nir(value: str) -> bool:
    """Port of ``validators::fr_nir`` (sex, month, département incl. 2A/2B, key 97 − first thirteen mod 97)."""
    body = value.replace(" ", "")
    if len(body) != 15 or not body.isascii() or not (body[:5] + body[7:]).isdigit():
        return False
    department = {"2A": "19", "2B": "18"}.get(body[5:7], body[5:7])
    if not department.isdigit() or department == "00":
        return False
    month = int(body[3:5])
    if body[0] not in "123478" or not (1 <= month <= 12 or 20 <= month <= 42 or 50 <= month <= 99):
        return False
    return 97 - int(body[:5] + department + body[7:13]) % 97 == int(body[13:])


def _issued_luhn(digits: list[int]) -> bool:
    return len(set(digits)) > 1 and _luhn_checksum(digits) == 0


def fr_siren(value: str) -> bool:
    """Port of ``validators::fr_siren`` (nine digits, Luhn, not one repeated digit)."""
    digits = _grouped_digits(value, 9)
    return digits is not None and _issued_luhn(digits)


def fr_siret(value: str) -> bool:
    """Port of ``validators::fr_siret`` (SIREN + NIC, Luhn; La Poste 356000000 by digit sum mod 5)."""
    digits = _grouped_digits(value, 14)
    if digits is None or not _issued_luhn(digits[:9]):
        return False
    if _number(digits[:9]) == 356_000_000:
        return sum(digits) % 5 == 0
    return _luhn_checksum(digits) == 0


def _eleven_proof(digits: list[int]) -> bool:
    """The Dutch 11-proof of nine digits: the first eight weighted 9…2 minus the last, mod 11."""
    return (_weighted_sum(digits[:8], range(9, 1, -1)) - digits[8]) % 11 == 0


def nl_bsn(value: str) -> bool:
    """Port of ``validators::nl_bsn`` (nine digits, plain, 3-3-3 or 1234.56.782, 11-proof, not one repeated digit)."""
    digits = _separated_digits(value, 9, " .")
    return digits is not None and len(set(digits)) > 1 and _eleven_proof(digits)


def be_national_number(value: str) -> bool:
    """Port of ``validators::be_national_number`` (YYMMDD, serial 001–998, 97 − mod 97, 2000s with a 2 before)."""
    digits = _separated_digits(value, 11, " .-")
    if digits is None:
        return False
    number, check = _number(digits[:9]), _number(digits[9:])
    month = digits[2] * 10 + digits[3]
    if not (month <= 12 or 20 <= month <= 32 or 40 <= month <= 52) or digits[4] * 10 + digits[5] > 31:
        return False
    if not 1 <= number % 1000 <= 998:
        return False
    return 97 - number % 97 == check or 97 - (2_000_000_000 + number) % 97 == check


def se_organisationsnummer(value: str) -> bool:
    """Port of ``validators::se_organisationsnummer`` (ten digits, ``-`` before the last four, third ≥ 2, Luhn)."""
    if len(value) == 11 and value[6] == "-":
        value = value[:6] + value[7:]
    digits = _separated_digits(value, 10, "")
    return digits is not None and digits[2] >= 2 and _issued_luhn(digits)


def ca_sin(value: str) -> bool:
    """Port of ``validators::ca_sin`` (nine digits, 3-3-3 by spaces or hyphens, first not 0 or 8, Luhn)."""
    digits = _grouped_digits(value, 9)
    return digits is not None and digits[0] not in (0, 8) and _issued_luhn(digits)


def tr_national_id(value: str) -> bool:
    """Port of ``validators::tr_national_id`` (eleven digits, no leading zero, two check digits mod 10)."""
    digits = _separated_digits(value, 11, "")
    if digits is None or digits[0] == 0 or len(set(digits[:10])) == 1:
        return False
    odd, even = sum(digits[0:9:2]), sum(digits[1:8:2])
    return (7 * odd - even) % 10 == digits[9] and sum(digits[:10]) % 10 == digits[10]


def za_id_number(value: str) -> bool:
    """Port of ``validators::za_id_number`` (YYMMDD, sequence, citizenship 0–2, 8 or 9, Luhn over thirteen)."""
    digits = _separated_digits(value, 13, " ")
    if digits is None:
        return False
    year, month, day = (digits[i] * 10 + digits[i + 1] for i in (0, 2, 4))
    return (
        any(_valid_date(century + year, month, day) for century in (1900, 2000))
        and digits[10] <= 2
        and digits[11] in (8, 9)
        and _luhn_checksum(digits) == 0
    )


def at_social_security_number(value: str) -> bool:
    """Port of ``validators::at_social_security_number`` (ten digits or NNNN NNNNNN, serial ≥ 100, weighted mod 11)."""
    if len(value) == 11 and value[4] == " ":
        value = value[:4] + value[5:]
    digits = _separated_digits(value, 10, "")
    if digits is None or digits[0] == 0:
        return False
    return (_weighted_sum(digits[:3], (3, 7, 9)) + _weighted_sum(digits[4:], (5, 8, 4, 2, 1, 6))) % 11 == digits[3]


def ch_ahv_number(value: str) -> bool:
    """Port of ``validators::ch_ahv_number`` (thirteen digits by dots or spaces, prefix 756, EAN-13)."""
    digits = _separated_digits(value, 13, ". ")
    return (
        digits is not None
        and digits[:3] == [7, 5, 6]
        and (10 - _weighted_sum(digits[:12], (1, 3) * 6) % 10) % 10 == digits[12]
    )


def pt_nif(value: str) -> bool:
    """Port of ``validators::pt_nif`` (nine digits, 3-3-3 by spaces or hyphens, the check of the PT VAT ID)."""
    digits = _grouped_digits(value, 9)
    return digits is not None and _pt_nif_check(digits)


def ie_ppsn(value: str) -> bool:
    """Port of ``validators::ie_ppsn`` (seven digits, check letter mod 23, second letter A/B counted, W/T/X not)."""
    if len(value) not in (8, 9) or (len(value) == 9 and value[8] not in "ABWTX"):
        return False
    digits = _separated_digits(value[:7], 7, "")
    second = {"A": 1, "B": 2}.get(value[8:], 0)
    return digits is not None and any(digits) and _ie_check_letter(digits, second) == value[7]



def _kr_registration_number(value: str, sexes: range, base: int) -> bool:
    if len(value) == 14 and value[6] == "-":
        value = value[:6] + value[7:]
    digits = _separated_digits(value, 13, "")
    if digits is None or digits[6] not in sexes:
        return False
    century = 1900 if digits[6] % 4 in (1, 2) else 2000
    year, month, day = (digits[i] * 10 + digits[i + 1] for i in (0, 2, 4))
    total = sum(digit * weight for digit, weight in zip(digits, (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)))
    return (
        _valid_date(century + year, month, day)
        and digits[7] * 10 + digits[8] <= 95
        and (base - total % 11) % 10 == digits[12]
    )


def kr_rrn(value: str) -> bool:
    """Port of ``validators::kr_rrn`` (YYMMDD-GHHSSSC, sex 1–4, region ≤ 95, (11 − sum mod 11) mod 10)."""
    return _kr_registration_number(value, range(1, 5), 11)


def kr_frn(value: str) -> bool:
    """Port of ``validators::kr_frn`` (YYMMDD-GHHSSSC, sex 5–8, region ≤ 95, (13 − sum mod 11) mod 10)."""
    return _kr_registration_number(value, range(5, 9), 13)


def kr_brn(value: str) -> bool:
    """Port of ``validators::kr_brn`` (ten digits or NNN-NN-NNNNN, weighted 1-3-7-1-3-7-1-3-5 mod 10)."""
    if len(value) == 12 and value[3] == "-" and value[6] == "-":
        value = value.replace("-", "")
    digits = _separated_digits(value, 10, "")
    if digits is None or len(set(digits)) == 1:
        return False
    total = sum(digit * weight for digit, weight in zip(digits, (1, 3, 7, 1, 3, 7, 1, 3, 5))) + digits[8] * 5 // 10
    return (10 - total % 10) % 10 == digits[9]


def _es_personal_number(value: str, leads: str) -> bool:
    compact = value.replace("-", "").upper()
    if len(compact) == 8 and compact[:1].isdigit():
        compact = "0" + compact
    if len(compact) != 9 or compact[0] not in leads or _vat_digits(compact[1:8], 7) is None:
        return False
    lead = str("0123456789XYZ".index(compact[0]) % 10)
    return compact[8] == ES_CONTROL_LETTERS[int(lead + compact[1:8]) % 23]


def es_nif(value: str) -> bool:
    """Port of ``validators::es_nif`` (eight digits, seven padded, control letter mod 23)."""
    return _es_personal_number(value, "0123456789")


def es_nie(value: str) -> bool:
    """Port of ``validators::es_nie`` (X/Y/Z as 0/1/2, seven digits, control letter mod 23)."""
    return _es_personal_number(value, "XYZ")


_IT_FISCAL_ODD = (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23)


def it_fiscal_code(value: str) -> bool:
    """Port of ``validators::it_fiscal_code`` (16 characters, omocodia, month letter, day, check mod 26)."""
    code = value.upper()
    if len(code) != 16 or not code.isascii() or not code.isalnum():
        return False
    digits = {index: "0123456789".find(code[index]) if code[index].isdigit() else "LMNPQRSTUV".find(code[index])
              for index in (6, 7, 9, 10, 12, 13, 14)}
    if any(not code[index].isalpha() for index in (0, 1, 2, 3, 4, 5, 8, 11, 15)) or -1 in digits.values():
        return False
    if code[8] not in "ABCDEHLMPRST" or not (1 <= digits[9] * 10 + digits[10] <= 31 or 41 <= digits[9] * 10 + digits[10] <= 71):
        return False
    rank = [int(ch) if ch.isdigit() else ord(ch) - ord("A") for ch in code[:15]]
    total = sum(_IT_FISCAL_ODD[r] if index % 2 == 0 else r for index, r in enumerate(rank))
    return code[15] == chr(ord("A") + total % 26)

def pl_pesel(value: str) -> bool:
    """Port of ``validators::pl_pesel`` (11 digits, birth date 1900–2100 with the century in the month, 1-3-7-9 mod 10)."""
    digits = _separated_digits(value, 11, "")
    if digits is None or digits[2] * 10 + digits[3] >= 60:
        return False
    month = digits[2] * 10 + digits[3]
    year = (1900, 2000, 2100)[month // 20] + digits[0] * 10 + digits[1]
    total = sum(digit * weight for digit, weight in zip(digits, (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)))
    return _valid_date(year, month % 20, digits[4] * 10 + digits[5]) and (10 - total % 10) % 10 == digits[10]


def pl_regon(value: str) -> bool:
    """Port of ``validators::pl_regon`` (9 digits weighted mod 11, or 14 whose first nine are a REGON)."""
    digits = _separated_digits(value, len(value), "") if len(value) in (9, 14) else None
    if digits is None or len(set(digits[:9])) == 1:
        return False

    def check(weights: tuple[int, ...]) -> bool:
        return sum(digit * weight for digit, weight in zip(digits, weights)) % 11 % 10 == digits[len(weights)]

    nine = check((8, 9, 2, 3, 4, 5, 6, 7))
    return nine if len(digits) == 9 else nine and check((2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8))


def in_aadhaar(value: str) -> bool:
    """Port of ``validators::in_aadhaar`` (12 digits, plain or 4-4-4 with one separator, first 2–9, no palindrome, Verhoeff)."""
    grouped = len(value) == 14 and value[4] == value[9] and value[4] in " -:"
    digits = _separated_digits(value, 12, " -:") if grouped or len(value) == 12 else None
    return (
        digits is not None
        and digits[0] >= 2
        and digits != digits[::-1]
        and synth_goldset.verhoeff_valid("".join(map(str, digits)))
    )


def in_gstin(value: str) -> bool:
    """Port of ``validators::in_gstin`` (state 01–38/97/99, PAN, entity number 1–9/A–Z, Z, check character mod 36)."""
    if len(value) != 15 or not value.isascii() or not value[:2].isdigit():
        return False
    if any(char not in synth_goldset.GSTIN_CHARS for char in value):
        return False
    return (
        (1 <= int(value[:2]) <= 38 or int(value[:2]) in (97, 99))
        and value[12] != "0"
        and value[13] == "Z"
        and synth_goldset.gstin_check_char(value[:14]) == value[14]
    )


def us_dea_number(value: str) -> bool:
    """Port of ``validators::us_dea_number`` (registrant type, last-name initial or 9, d1+d3+d5+2(d2+d4+d6) mod 10)."""
    digits = _separated_digits(value[2:], 7, "") if len(value) == 9 else None
    return (
        digits is not None
        and value[0] in "ABCDEFGHJKLMPRSTUX"
        and (value[1] == "9" or "A" <= value[1] <= "Z")
        and (digits[0] + digits[2] + digits[4] + 2 * (digits[1] + digits[3] + digits[5])) % 10 == digits[6]
    )


def us_npi(value: str) -> bool:
    """Port of ``validators::us_npi`` (10 digits, plain or 4-3-3 with one separator, first 1 or 2, Luhn behind 80840)."""
    grouped = len(value) == 12 and value[4] == value[8] and value[4] in " -"
    digits = _separated_digits(value, 10, " -") if grouped or len(value) == 10 else None
    return (
        digits is not None
        and digits[0] in (1, 2)
        and len(set(digits[:9])) > 1
        and synth_goldset.luhn_valid("80840" + "".join(map(str, digits)))
    )


def imei(value: str) -> bool:
    """Port of ``validators::imei`` (15 digits, plain or 2-6-6-1 with one separator, Luhn, not one digit)."""
    grouped = len(value) == 18 and value[2] == value[9] == value[16] and value[2] in " -"
    digits = _separated_digits(value, 15, " -") if grouped or len(value) == 15 else None
    return digits is not None and len(set(digits)) > 1 and synth_goldset.luhn_valid("".join(map(str, digits)))


def meid(value: str) -> bool:
    """Port of ``validators::meid`` (15 upper-case hex digits, regional code A0-FF, Luhn in base 16)."""
    if len(value) != 15 or value[0] not in "ABCDEF" or any(c not in "0123456789ABCDEF" for c in value):
        return False
    total = 0
    for index, char in enumerate(reversed(value)):
        digit = int(char, 16) * (2 if index % 2 else 1)
        total += digit - 15 if digit >= 16 else digit
    return total % 16 == 0


def iccid(value: str) -> bool:
    """Port of ``validators::iccid`` (19 or 20 digits led by 89, plain or in blocks of four, Luhn)."""
    grouped = len(value) in (23, 24) and all((index % 5 == 4) == (char == " ") for index, char in enumerate(value))
    plain = value if not grouped else value.replace(" ", "")
    return (
        len(plain) in (19, 20)
        and plain.isascii()
        and plain.isdigit()
        and plain.startswith("89")
        and synth_goldset.luhn_valid(plain)
    )


# VIN transliteration (49 CFR 565): digits as themselves, letters without I, O and Q.
_VIN_VALUES = {
    **{str(digit): digit for digit in range(10)},
    **dict(zip("ABCDEFGH", range(1, 9))),
    **dict(zip("JKLMN", range(1, 6))),
    "P": 7,
    "R": 9,
    **dict(zip("STUVWXYZ", range(2, 10))),
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def vin_check_digit(value: str) -> bool:
    """Port of ``validators::vin_check_digit`` (17 VIN characters, a letter, last four digits, check digit at 9)."""
    if len(value) != 17 or any(ch not in _VIN_VALUES for ch in value):
        return False
    if not any(ch.isalpha() for ch in value[:13]) or not value[13:].isdigit():
        return False
    check = sum(_VIN_VALUES[ch] * weight for ch, weight in zip(value, _VIN_WEIGHTS)) % 11
    return value[8] == ("X" if check == 10 else str(check))


def _alphanumeric(value: str) -> str | None:
    """Digits and capital letters of ``value`` with the letters read as 10-35, if there is nothing else."""
    if not all("0" <= ch <= "9" or "A" <= ch <= "Z" for ch in value):
        return None
    return "".join(ch if ch.isdigit() else str(ord(ch) - ord("A") + 10) for ch in value)


def isin(value: str) -> bool:
    """Port of ``validators::isin`` (two capital letters, nine alphanumerics, Luhn over the expanded letters)."""
    expanded = _alphanumeric(value)
    return (
        expanded is not None
        and len(value) == 12
        and value[:2].isalpha()
        and value[11].isdigit()
        and synth_goldset.luhn_sum(expanded) == 0
    )


def lei(value: str) -> bool:
    """Port of ``validators::lei`` (eighteen alphanumerics, two digits, ISO 7064 MOD 97-10 leaves 1)."""
    expanded = _alphanumeric(value)
    return expanded is not None and len(value) == 20 and value[18:].isdigit() and int(expanded) % 97 == 1


def de_pzn(value: str) -> bool:
    """Port of ``validators::de_pzn`` (eight or seven digits, not one repeated, weighted 1-7 mod 11)."""
    digits = _separated_digits(value, len(value), "") if len(value) in (7, 8) else None
    if digits is None:
        return False
    digits = [0] * (8 - len(digits)) + digits
    return len(set(digits[:7])) > 1 and sum(d * w for d, w in zip(digits, range(1, 8))) % 11 == digits[7]


# Python ports of every checksum validator (``checksums.ark`` with an algorithm in entity_map.yaml);
# a task that adds one ports it here, or scripts/tests/test_l1_scoreboard.py is red.
CHECKSUM_PORTS: dict[str, Callable[[str], bool]] = {
    "luhn": luhn,
    "payment_card": payment_card,
    "iban": iban_registry,
    "steuer_id": steuer_id,
    "steuer_id_issued": steuer_id_issued,
    "de_vat_id": de_vat_id,
    "at_vat_id": at_vat_id,
    "ch_vat_id": ch_vat_id,
    "fr_vat_id": fr_vat_id,
    "nl_vat_id": nl_vat_id,
    "be_vat_id": be_vat_id,
    "it_vat_id": it_vat_id,
    "es_vat_id": es_vat_id,
    "bg_vat_id": bg_vat_id,
    "cy_vat_id": cy_vat_id,
    "cz_vat_id": cz_vat_id,
    "dk_vat_id": dk_vat_id,
    "ee_vat_id": ee_vat_id,
    "el_vat_id": el_vat_id,
    "fi_vat_id": fi_vat_id,
    "hr_vat_id": hr_vat_id,
    "hu_vat_id": hu_vat_id,
    "ie_vat_id": ie_vat_id,
    "lt_vat_id": lt_vat_id,
    "lu_vat_id": lu_vat_id,
    "lv_vat_id": lv_vat_id,
    "mt_vat_id": mt_vat_id,
    "pl_vat_id": pl_vat_id,
    "pt_vat_id": pt_vat_id,
    "ro_vat_id": ro_vat_id,
    "se_vat_id": se_vat_id,
    "si_vat_id": si_vat_id,
    "sk_vat_id": sk_vat_id,
    "no_vat_id": no_vat_id,
    "gb_vat_id": gb_vat_id,
    "de_passport_number": de_passport_number,
    "de_identity_card_number": de_identity_card_number,
    "uk_nhs_number": uk_nhs_number,
    "au_abn": au_abn,
    "au_acn": au_acn,
    "au_tfn": au_tfn,
    "au_medicare": au_medicare,
    "sg_nric_fin": sg_nric_fin,
    "sg_uen": sg_uen,
    "de_social_security_number": de_social_security_number,
    "de_health_insurance_number": de_health_insurance_number,
    "lanr": lanr,
    "se_personnummer": se_personnummer,
    "fi_hetu": fi_hetu,
    "dk_cpr": dk_cpr,
    "no_fodselsnummer": no_fodselsnummer,
    "aba_routing_number": aba_routing_number,
    "fr_nir": fr_nir,
    "fr_siren": fr_siren,
    "fr_siret": fr_siret,
    "nl_bsn": nl_bsn,
    "be_national_number": be_national_number,
    "se_organisationsnummer": se_organisationsnummer,
    "ca_sin": ca_sin,
    "tr_national_id": tr_national_id,
    "za_id_number": za_id_number,
    "at_social_security_number": at_social_security_number,
    "ch_ahv_number": ch_ahv_number,
    "pt_nif": pt_nif,
    "ie_ppsn": ie_ppsn,
    "kr_rrn": kr_rrn,
    "kr_frn": kr_frn,
    "kr_brn": kr_brn,
    "es_nif": es_nif,
    "es_nie": es_nie,
    "it_fiscal_code": it_fiscal_code,
    "pl_pesel": pl_pesel,
    "pl_regon": pl_regon,
    "in_aadhaar": in_aadhaar,
    "in_gstin": in_gstin,
    "us_dea_number": us_dea_number,
    "us_npi": us_npi,
    "imei": imei,
    "meid": meid,
    "iccid": iccid,
    "vin_check_digit": vin_check_digit,
    "isin": isin,
    "lei": lei,
    "de_pzn": de_pzn,
}

# Gold the scoring ignores when its check fails: values that cannot exist (``_row_spans``).
IGNORED_GOLD: dict[str, Callable[[str], bool]] = {"pii.iban": iban_registry}


def count_validated_module() -> Any:
    import count_validated  # noqa: PLC0415 - only the gold-gap report needs the registry

    return count_validated


def gold_validators(emap: Any) -> dict[str, tuple[str, ...]]:
    """Checksum validators per benchmark id, from the PII_PATTERNS registry and ``checksums.ark``."""
    counter = count_validated_module()
    rules = counter.load_rules()
    found: dict[str, set[str]] = defaultdict(set)
    for rule in counter.ark_rules_from_source():
        if rule.validator is None or rules.ark.get(rule.validator) is None:
            continue
        entity_id = emap.ark_label(rule.label)
        if entity_id is not None:
            found[entity_id].add(rule.validator)
    return {entity_id: tuple(sorted(names)) for entity_id, names in sorted(found.items())}


# Markup around a value does not make it another value: Gretel annotates "[x@y.com]" or "mailto:x@y.com"
# of "[x@y.com](mailto:x@y.com)".
VALUE_EDGES = " \t\r\n[](){}<>\"'`*_.,;:"


def gap_value(value: str) -> str:
    value = value.strip(VALUE_EDGES)
    if value[:7].lower() == "mailto:":
        value = value[7:].strip(VALUE_EDGES)
    return value


def gold_gaps(
    gold_rows: Iterable[dict[str, Any]], prediction_rows: Iterable[dict[str, Any]], emap: Any, dataset: str = "",
    validators: dict[str, tuple[str, ...]] | None = None,
) -> dict[str, dict[str, dict[str, int | None]]]:
    """Gold gaps of one engine per corpus and scored id; reported next to the metrics, never part of them.

    ``duplicate_fp``: predictions that are false positives under exact scoring, overlap no gold span of
    their id with the same value, and whose text equals an annotated gold value of the same id elsewhere
    in the row (e.g. the unannotated ``mailto:`` copy of a mail link); values compare without
    surrounding brackets, quotes and punctuation (``VALUE_EDGES``) and without a ``mailto:`` prefix.
    ``gold_invalid``: gold values failing every checksum validator of their id, ``invalid_found``: those
    the engine reports with the exact span; both None for ids without a checksum validator."""
    gold_rows = list(gold_rows)
    predictions = _predictions_by_id(gold_rows, prediction_rows, dataset)
    validators = gold_validators(emap) if validators is None else validators
    unported = {name for names in validators.values() for name in names} - CHECKSUM_PORTS.keys()
    if unported:
        raise ScoreboardError(f"no Python port in CHECKSUM_PORTS for checksum validator(s) {', '.join(sorted(unported))}")
    gaps: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"gold": 0, "gold_invalid": 0, "invalid_found": 0, "duplicate_fp": 0})
    )
    for row in gold_rows:
        where = f"{dataset}:{row['id']}"
        text = row.get("text")
        if not isinstance(text, str):
            raise ScoreboardError(f"{where}: gold row without text")
        corpus, _, gold, _, predicted = _row_spans(row, predictions[row["id"]], emap, where)
        values: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
        for label, start, end in gold:
            values[label].append((gap_value(text[start:end]), start, end))
            counts = gaps[corpus][label]
            counts["gold"] += 1
            names = validators.get(label)
            if names and not any(CHECKSUM_PORTS[name](text[start:end]) for name in names):
                counts["gold_invalid"] += 1
                counts["invalid_found"] += (label, start, end) in predicted
        for label, start, end in predicted - gold:
            value = gap_value(text[start:end])
            same = [(g_start, g_end) for g_value, g_start, g_end in values[label] if value and g_value == value]
            if same and not any(g_start < end and start < g_end for g_start, g_end in same):
                gaps[corpus][label]["duplicate_fp"] += 1
    result: dict[str, dict[str, dict[str, int | None]]] = {}
    for corpus in sorted(gaps):
        result[corpus] = {}
        for label in sorted(gaps[corpus]):
            counts: dict[str, int | None] = dict(gaps[corpus][label])
            if label not in validators:
                counts["gold_invalid"] = counts["invalid_found"] = None
            result[corpus][label] = counts
    return result


def gated_buckets(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    keys = base["buckets"].keys() | head["buckets"].keys()
    return sorted(
        key
        for key in keys
        if key == "all"
        or key in {f"language/{lang}" for lang in LANGUAGES}
        or key.startswith(("entity/", "family/"))
    )


def compare(base: dict[str, Any], head: dict[str, Any], tolerance_pp: float = TOLERANCE_PP) -> dict[str, Any]:
    """Regressions of head against base within one split."""
    regressions = []
    for key in gated_buckets(base, head):
        before = metrics(base["buckets"].get(key, empty_counts()))
        after = metrics(head["buckets"].get(key, empty_counts()))
        for metric in METRICS:
            delta = (after[metric]["f1"] - before[metric]["f1"]) * 100
            if delta < -tolerance_pp - 1e-9:
                regressions.append({
                    "bucket": key, "metric": metric,
                    "base_f1": before[metric]["f1"], "head_f1": after[metric]["f1"], "delta_pp": delta,
                })
    base_fp = {tuple(item) for item in base["hard_negative_fp"]}
    new_fp = sorted(list(item) for item in {tuple(item) for item in head["hard_negative_fp"]} - base_fp)
    return {"regressions": regressions, "new_hard_negative_fp": new_fp}


# ── sources, builds and predictions ──────────────────────────────────────


def git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-c", "core.fsmonitor=false", *args], cwd=repo, text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise ScoreboardError(f"git {' '.join(args)} failed: {proc.stderr.strip()[-500:]}")
    return proc.stdout.strip()


def commit_sha(repo: Path, rev: str) -> str:
    if not rev:
        raise ScoreboardError("empty revision")
    return git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")


def source_key(repo: Path, rev: str) -> str:
    """Digest of the git objects that make up the Ark build and the prediction runner at rev."""
    lines = [f"{SCHEMA} predictions {PREDICTION_VERSION}"]
    for path in KEY_PATHS:
        oid = git(repo, "rev-parse", "--verify", "--quiet", f"{rev}:{path}", check=False)
        lines.append(f"{path} {oid or '-'}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def is_clean(repo: Path) -> bool:
    """True if the checkout matches HEAD on every source key path (tracked and untracked)."""
    return not git(repo, "status", "--porcelain", "--untracked-files=all", "--", *KEY_PATHS)


class ArkBuild(NamedTuple):
    """How to run run_ark.py for one commit: interpreter, script and extra environment."""

    python: str
    run_ark: Path
    env: dict[str, str]
    native: Path | None  # expected native module (checked against run_ark's metadata)


def default_ark_python() -> str:
    venv = os.environ.get("VIRTUAL_ENV")
    if venv and (Path(venv) / "bin" / "python").exists():
        return str(Path(venv) / "bin" / "python")
    return sys.executable


def head_build(head: Path, ark_python: str) -> ArkBuild:
    """The head runs with the installed (maturin develop) package, which must be the head's."""
    probe = subprocess.run(
        [ark_python, "-c", "import patronus_ark; print(patronus_ark.__file__)"],
        cwd="/", text=True, capture_output=True,
    )
    if probe.returncode != 0:
        raise ScoreboardError(f"{ark_python} cannot import patronus_ark: {probe.stderr.strip()[-500:]}")
    package = Path(probe.stdout.strip()).resolve().parent
    if package != (head / "python" / "patronus_ark").resolve():
        raise ScoreboardError(f"{ark_python} imports patronus_ark from {package}, not from the head {head}")
    return ArkBuild(ark_python, head / "scripts" / "l1_presidio" / "run_ark.py", {}, None)


def build_base(
    repo: Path, sha: str, key: str, cache: Path, ark_python: str, cargo: str = "cargo"
) -> ArkBuild:
    """Build the native module of commit sha offline into the cache (reused per source key)."""
    stage = cache / "builds" / key
    package = stage / "patronus_ark"
    run_ark = stage / "run_ark.py"
    if not (stage / ".ready").is_file():
        shutil.rmtree(stage, ignore_errors=True)
        source = cache / "src" / key
        shutil.rmtree(source, ignore_errors=True)
        source.mkdir(parents=True)
        try:
            archive = source.parent / f"{key}.tar"
            with archive.open("wb") as handle:
                proc = subprocess.run(["git", "archive", "--format=tar", sha], cwd=repo, stdout=handle,
                                      stderr=subprocess.PIPE, text=False)
            if proc.returncode != 0:
                raise ScoreboardError(f"git archive {sha} failed: {proc.stderr.decode()[-500:]}")
            with tarfile.open(archive) as tar:
                tar.extractall(source, filter="data")
            archive.unlink()
            env = {**os.environ, "CARGO_TARGET_DIR": str(cache / "target"), "PYO3_PYTHON": ark_python}
            build = subprocess.run(
                [cargo, "build", "--offline", "--locked", "--lib", "--manifest-path", str(source / "python" / "Cargo.toml")],
                cwd=source, env=env, text=True, capture_output=True,
            )
            if build.returncode != 0:
                raise ScoreboardError(f"base build of {sha[:12]} failed:\n{build.stderr.strip()[-3000:]}")
            library = cache / "target" / "debug" / NATIVE_LIBRARY
            runner = source / "scripts" / "l1_presidio" / "run_ark.py"
            if not library.is_file() or not runner.is_file():
                raise ScoreboardError(f"base {sha[:12]} has no {NATIVE_LIBRARY} or run_ark.py")
            stage.mkdir(parents=True)
            shutil.copytree(source / "python" / "patronus_ark", package,
                            ignore=shutil.ignore_patterns("benchmark_data", "__pycache__", "*.so"))
            shutil.copy2(library, package / NATIVE_MODULE)
            shutil.copy2(runner, run_ark)
            (stage / ".ready").write_text(sha + "\n", encoding="utf-8")
        finally:
            shutil.rmtree(source, ignore_errors=True)
    return ArkBuild(ark_python, run_ark, {"PYTHONPATH": str(stage)}, package / NATIVE_MODULE)


def run_predictions(build: ArkBuild, input_path: Path, output_path: Path, mode: str = "strict") -> None:
    meta = output_path.with_name(output_path.name + ".meta.json")
    proc = subprocess.run(
        [build.python, str(build.run_ark), "--input", str(input_path), "--output", str(output_path), "--meta", str(meta),
         "--pii-mode", mode],
        cwd="/", env={**os.environ, **build.env}, text=True, capture_output=True,
    )
    if proc.returncode != 0:
        # The input may be holdout data and runner errors can name rows: keep stderr next to the
        # prediction file in the private cache and report only the exit code.
        stderr = output_path.with_name(output_path.name + ".stderr")
        stderr.parent.mkdir(parents=True, exist_ok=True)
        stderr.write_text(proc.stderr, encoding="utf-8")
        raise ScoreboardError(f"run_ark.py failed (exit {proc.returncode}); stderr in {stderr}")
    try:
        info = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ScoreboardError(f"run_ark.py wrote no readable metadata {meta}") from None
    # run_ark.py records a non-default mode as engine.pii_mode; a runner that ignored the flag scored strict.
    if (info.get("engine") or {}).get("pii_mode", "strict") != mode:
        raise ScoreboardError(f"run_ark.py {build.run_ark} did not run in PII mode {mode}")
    if build.native is not None:
        native = info.get("build", {}).get("native_sha256")
        if native != sha256_file(build.native):
            raise ScoreboardError(f"run_ark.py did not load the base build {build.native}")


Predictor = Callable[[Dataset, Path, str], None]


class PredictionCache:
    """Prediction files per source key, PII mode and input SHA-256 below CACHE/predictions."""

    def __init__(self, root: Path):
        self.root = root / "predictions"
        self.scratch = root / "scratch"

    def path(self, key: str, dataset: Dataset, mode: str = "strict") -> Path:
        # strict keeps the layout from before T15, so its cached predictions stay valid.
        directory = self.root / key if mode == "strict" else self.root / key / mode
        return directory / f"{dataset.sha256}.jsonl"

    def has(self, key: str | None, dataset: Dataset, mode: str = "strict") -> bool:
        return key is not None and self.path(key, dataset, mode).is_file()

    def get(
        self, key: str | None, dataset: Dataset, mode: str, predict: Callable[[], Predictor]
    ) -> list[dict[str, Any]]:
        if self.has(key, dataset, mode):
            return read_jsonl(self.path(key, dataset, mode))
        self.scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.scratch) as tmp:
            output = Path(tmp) / "predictions.jsonl"
            predict()(dataset, output, mode)
            rows = read_jsonl(output)
            if key is not None:
                write_atomic(self.path(key, dataset, mode), output.read_bytes())
        return rows


# ── gate ─────────────────────────────────────────────────────────────────


class Side(NamedTuple):
    name: str
    sha: str
    key: str | None
    predict: Callable[[], Predictor]


def lazy(factory: Callable[[], ArkBuild]) -> Callable[[], Predictor]:
    """Create the build only when a prediction is actually missing."""
    built: list[ArkBuild] = []

    def get() -> Predictor:
        if not built:
            built.append(factory())
        return lambda dataset, output, mode: run_predictions(built[0], dataset.path, output, mode)

    return get


def score_side(
    side: Side, datasets: list[Dataset], cache: PredictionCache, emap: Any, mode: str = "strict"
) -> dict[str, Any]:
    splits: dict[str, Any] = {}
    for split in dict.fromkeys(d.split for d in datasets):
        parts = []
        for dataset in (d for d in datasets if d.split == split):
            predictions = cache.get(side.key, dataset, mode, side.predict)
            parts.append(score_rows(read_jsonl(dataset.path), predictions, emap, dataset.name))
        splits[split] = {
            "datasets": {d.name: d.sha256 for d in datasets if d.split == split},
            **merge(parts),
        }
    return splits


def store_results(root: Path, side: Side, modes: dict[str, dict[str, Any]]) -> None:
    """CACHE/results/<sha>.json with the splits per PII mode; only for committed sources (key known)."""
    if side.key is None:
        return
    path = root / "results" / f"{side.sha}.json"
    previous = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    stored = previous.get("modes", {}) if previous.get("source_key") == side.key else {}
    merged = {mode: {**stored.get(mode, {}), **splits} for mode, splits in modes.items()}
    payload = {"schema": SCHEMA, "commit": side.sha, "source_key": side.key, "modes": {**stored, **merged}}
    write_atomic(path, (json.dumps(payload, indent=1, sort_keys=True) + "\n").encode())


def pct(value: float) -> str:
    return f"{value * 100:5.1f}"


def signed(value: float) -> str:
    return f"{value:+.1f}"


def f1_pair(counts: dict[str, int]) -> tuple[float, float]:
    m = metrics(counts)
    return m["exact"]["f1"], m["overlap"]["f1"]


def entity_table(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    lines = [f"  {'entity':<36} {'gold':>5} {'pred':>5}  {'exact P/R/F1':<17}  {'overlap F1':>10}  {'ΔF1 ex/ov':>11}"]
    for key in sorted(k for k in head["buckets"].keys() | base["buckets"].keys() if k.startswith("entity/")):
        h = head["buckets"].get(key, empty_counts())
        b = base["buckets"].get(key, empty_counts())
        m = metrics(h)
        (be, bo), (he, ho) = f1_pair(b), f1_pair(h)
        lines.append(
            f"  {key[7:]:<36} {h['gold']:>5} {h['predicted']:>5}  "
            f"{pct(m['exact']['precision'])}/{pct(m['exact']['recall'])}/{pct(m['exact']['f1'])}  "
            f"{pct(m['overlap']['f1']):>10}  {signed((he - be) * 100):>5}/{signed((ho - bo) * 100):<5}"
        )
    return lines


def family_lines(split: str, base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    """F1 per source family of one split (all L1 ids and EN), Δ vs base; split may carry the mode."""
    lines = []
    for family in entity_map_module.FAMILIES:
        key = f"family/{family}"
        if key not in head["buckets"] and key not in base["buckets"]:
            continue
        parts = [f"  {split} {family:<16}"]
        for bucket, name in ((key, "L1"), (f"family_language/{family}/en", "en")):
            (be, bo), (he, ho) = f1_pair(base["buckets"].get(bucket, empty_counts())), f1_pair(head["buckets"].get(bucket, empty_counts()))
            parts.append(f"{name} F1 {pct(he).strip()}/{pct(ho).strip()} ({signed((he - be) * 100)}/{signed((ho - bo) * 100)})")
        note = "" if family in entity_map_module.MILESTONE_FAMILIES else " (reported, decides no milestone)"
        lines.append(" | ".join(parts) + note)
    return lines


def split_line(split: str, base: dict[str, Any], head: dict[str, Any], new_fp: int) -> str:
    parts = [f"{split:<16} rows {head['rows']:>5}"]
    for key, name in (("all", "L1"), *((f"language/{lang}", lang) for lang in LANGUAGES)):
        (be, bo), (he, ho) = f1_pair(base["buckets"].get(key, empty_counts())), f1_pair(head["buckets"].get(key, empty_counts()))
        parts.append(f"{name} F1 {pct(he).strip()}/{pct(ho).strip()} ({signed((he - be) * 100)}/{signed((ho - bo) * 100)})")
    parts.append(f"HN-FP {len(head['hard_negative_fp'])} (new {new_fp})")
    return " | ".join(parts)


def summary(head: Side, base: Side, results: dict[str, Any], tolerance_pp: float) -> tuple[list[str], bool]:
    same = head.key is not None and head.key == base.key
    lines = [
        f"{SCHEMA}: head {head.sha[:12]}{'' if head.key else ' (uncommitted changes)'} vs base {base.sha[:12]}"
        + (" (same Ark sources)" if same else ""),
    ]
    for mode, splits in results.items():
        if "dev" in splits:
            lines.append(f"dev per entity, {mode} (head; Δ vs base in pp):")
            lines += entity_table(splits["dev"]["base"], splits["dev"]["head"])
    lines.append(
        f"F1 exact/overlap in % (Δ pp vs base), tolerance {tolerance_pp} pp, gated in {', '.join(results)}; "
        f"milestones on {MILESTONE_MODE}:"
    )
    regressed = False
    problems = []
    for mode, splits in results.items():
        for split, result in splits.items():
            verdict = result["compare"]
            where = f"{mode} {split}"
            lines.append(split_line(where, result["base"], result["head"], len(verdict["new_hard_negative_fp"])))
            lines += family_lines(where, result["base"], result["head"])
            for item in verdict["regressions"]:
                problems.append(
                    f"  {where} {item['bucket']} {item['metric']} F1 {pct(item['base_f1']).strip()} -> "
                    f"{pct(item['head_f1']).strip()} ({signed(item['delta_pp'])} pp)"
                )
            if verdict["new_hard_negative_fp"]:
                labels: dict[str, int] = defaultdict(int)
                for item in verdict["new_hard_negative_fp"]:
                    labels[item[2]] += 1
                problems.append(f"  {where} new hard-negative FP: " + ", ".join(f"{k} {v}" for k, v in sorted(labels.items())))
            regressed = regressed or bool(verdict["regressions"] or verdict["new_hard_negative_fp"])
    lines.append(f"regressions: {len(problems)}" if problems else "regressions: none")
    lines += problems[:20] + ([f"  … {len(problems) - 20} more"] if len(problems) > 20 else [])
    lines.append("RESULT: REGRESSION" if regressed else "RESULT: PASS")
    return lines, regressed


def gate(
    head_dir: Path,
    base_rev: str,
    splits: dict[str, Path],
    cache_dir: Path,
    *,
    ark_python: str | None = None,
    cargo: str = "cargo",
    tolerance_pp: float = TOLERANCE_PP,
    emap: Any = None,
    head_factory: Callable[[], ArkBuild] | None = None,
    base_factory: Callable[[str, str], ArkBuild] | None = None,
    modes: tuple[str, ...] = MODES,
) -> tuple[list[str], bool, dict[str, Any]]:
    head_dir = head_dir.resolve()
    root = cache_dir.resolve() / "scoreboard"
    emap = emap or entity_map_module.load()
    ark_python = ark_python or default_ark_python()
    if os.sep in ark_python:
        ark_python = str(Path(ark_python).absolute())  # no resolve(): a venv python is a symlink
    head_sha = commit_sha(head_dir, "HEAD")
    base_sha = commit_sha(head_dir, base_rev)
    head_key = source_key(head_dir, "HEAD") if is_clean(head_dir) else None
    base_key = source_key(head_dir, base_sha)
    head_factory = head_factory or (lambda: head_build(head_dir, ark_python))
    base_factory = base_factory or (lambda sha, key: build_base(head_dir, sha, key, root, ark_python, cargo))
    head = Side("head", head_sha, head_key, lazy(head_factory))
    base = Side("base", base_sha, base_key, head.predict if base_key == head_key else lazy(lambda: base_factory(base_sha, base_key)))

    datasets = [d for split, path in splits.items() for d in discover(split, path)]
    cache = PredictionCache(root)
    head_results = {mode: score_side(head, datasets, cache, emap, mode) for mode in modes}
    base_results = {mode: score_side(base, datasets, cache, emap, mode) for mode in modes}
    store_results(root, head, head_results)
    store_results(root, base, base_results)
    results = {
        mode: {
            split: {"base": base_results[mode][split], "head": head_results[mode][split],
                    "compare": compare(base_results[mode][split], head_results[mode][split], tolerance_pp)}
            for split in head_results[mode]
        }
        for mode in modes
    }
    lines, regressed = summary(head, base, results, tolerance_pp)
    report = {"schema": SCHEMA, "head": head_sha, "base": base_sha, "head_source_key": head_key,
              "base_source_key": base_key, "tolerance_pp": tolerance_pp, "regressed": regressed,
              "milestone_mode": MILESTONE_MODE, "modes": results}
    return lines, regressed, report


def score_file(gold: Path, predictions: Path, emap: Any = None) -> tuple[list[str], dict[str, Any]]:
    emap = emap or entity_map_module.load()
    result = score_rows(read_jsonl(gold), read_jsonl(predictions), emap, gold.name)
    lines = [f"{SCHEMA}: {gold.name} ({result['rows']} rows) <- {predictions.name}"]
    lines += entity_table(result, result)
    m = metrics(result["buckets"]["all"])
    lines.append(
        f"L1 exact P/R/F1 {pct(m['exact']['precision'])}/{pct(m['exact']['recall'])}/{pct(m['exact']['f1'])} | "
        f"overlap P/R/F1 {pct(m['overlap']['precision'])}/{pct(m['overlap']['recall'])}/{pct(m['overlap']['f1'])} | "
        f"HN-FP {len(result['hard_negative_fp'])}"
    )
    return lines, result


# ── M1 per source family ─────────────────────────────────────────────────


def score_directory(gold_root: Path, predictions_root: Path, emap: Any) -> dict[str, Any]:
    """Merged result of every frozen gold file below gold_root against predictions_root/<same name>."""
    parts = []
    for dataset in discover("gold", gold_root):
        predictions = predictions_root / dataset.name
        if not predictions.is_file():
            raise ScoreboardError(f"no predictions {predictions} for {dataset.name}")
        parts.append(score_rows(read_jsonl(dataset.path), read_jsonl(predictions), emap, dataset.name))
    return merge(parts)


def m1_report(ark: dict[str, Any], presidio: dict[str, Any], emap: Any, language: str = "en",
              metric: str = "exact") -> dict[str, Any]:
    """M1 per source family: every shared id with gold in the family needs F1(Ark) >= F1(Presidio).

    A family holds only if it has at least one such id; M1 is met only if every milestone family
    (neutral, presidio_favored) holds on its own. ark_authored is reported and decides nothing."""
    families = {}
    for family in entity_map_module.FAMILIES:
        entities = {}
        for entity_id in sorted(emap.ids("shared")):
            key = (f"family_entity/{family}/{entity_id}" if language == "all"
                   else f"family_language_entity/{family}/{language}/{entity_id}")
            ark_counts = ark["buckets"].get(key, empty_counts())
            presidio_counts = presidio["buckets"].get(key, empty_counts())
            gold = max(ark_counts["gold"], presidio_counts["gold"])
            if not gold:
                continue
            ark_f1 = metrics(ark_counts)[metric]["f1"]
            presidio_f1 = metrics(presidio_counts)[metric]["f1"]
            entities[entity_id] = {"gold": gold, "ark_f1": ark_f1, "presidio_f1": presidio_f1,
                                   "holds": ark_f1 >= presidio_f1 - 1e-12}
        families[family] = {
            "decides": family in entity_map_module.MILESTONE_FAMILIES,
            "holds": bool(entities) and all(item["holds"] for item in entities.values()),
            "entities": entities,
        }
    met = all(families[family]["holds"] for family in entity_map_module.MILESTONE_FAMILIES)
    return {"language": language, "metric": metric, "met": met, "families": families}


def _deciding(report: dict[str, Any]) -> str:
    return ", ".join(
        f"{family} {'holds' if result['holds'] else 'not met'}"
        for family, result in report["families"].items() if result["decides"]
    )


def m1_lines(report: dict[str, Any], label: str = "M1") -> list[str]:
    lines = [f"{SCHEMA} M1 ({report['language']}, {report['metric']} F1 in %, Ark vs Presidio):"]
    for family, result in report["families"].items():
        entities = result["entities"]
        verdict = ("HOLDS" if result["holds"] else "NOT MET") if entities else "NO DATA"
        held = sum(item["holds"] for item in entities.values())
        note = "" if result["decides"] else " (reported, decides no milestone)"
        lines.append(f"{family}: {verdict}, {held}/{len(entities)} shared ids{note}")
        for entity_id, item in entities.items():
            lines.append(
                f"  {entity_id:<36} gold {item['gold']:>5}  Ark {pct(item['ark_f1'])}  "
                f"Presidio {pct(item['presidio_f1'])}  {'ok' if item['holds'] else 'below'}"
            )
    lines.append(f"{label}: {'MET' if report['met'] else 'NOT MET'} ({_deciding(report)})")
    return lines


def m1_by_mode(ark: dict[str, dict[str, Any]], presidio: dict[str, Any], emap: Any, language: str = "en",
               metric: str = "exact") -> dict[str, Any]:
    """M1 of every Ark mode against one Presidio result; the milestone is judged on balanced (T15)."""
    if MILESTONE_MODE not in ark:
        raise ScoreboardError(f"M1 needs Ark predictions in {MILESTONE_MODE} mode (milestones are judged on it)")
    modes = {mode: m1_report(ark[mode], presidio, emap, language, metric) for mode in ARK_MODES if mode in ark}
    return {"milestone_mode": MILESTONE_MODE, "language": language, "metric": metric,
            "met": modes[MILESTONE_MODE]["met"], "modes": modes}


def m1_mode_lines(report: dict[str, Any]) -> list[str]:
    lines = [f"{SCHEMA} M1 ({report['language']}, {report['metric']} F1 in %, Ark vs Presidio; "
             f"milestones on {MILESTONE_MODE}):"]
    for mode, item in report["modes"].items():
        lines.append(f"== Ark {mode} " + ("(milestone mode)" if mode == MILESTONE_MODE else "(reported, decides no milestone)"))
        lines += m1_lines(item, label=f"M1 {mode}")[1:]
    milestone = report["modes"][MILESTONE_MODE]
    lines.append(f"M1: {'MET' if report['met'] else 'NOT MET'} ({MILESTONE_MODE}: {_deciding(milestone)})")
    return lines


# ── M2 per source family ─────────────────────────────────────────────────


def m2_margin_pp(family: str) -> float:
    return 0.0 if family in M2_PARITY_FAMILIES else M2_MARGIN_PP


def m2_report(ark: dict[str, Any], presidio: dict[str, Any], emap: Any, language: str = "de",
              metric: str = "exact") -> dict[str, Any]:
    """M2 per source family: macro-F1(Ark) >= macro-F1(Presidio) + margin (15 pp, 0 on presidio_favored).

    The macro average is the unweighted mean F1 over the shared and ark_only ids with gold in the
    family; presidio_only ids with gold are listed as excluded until the entity map marks them shared.
    A family holds only if it has at least one such id; M2 is met only if both milestone families hold."""
    families = {}
    for family in entity_map_module.FAMILIES:
        entities, excluded = {}, {}
        for entity_id in sorted(l1_ids(emap)):
            key = (f"family_entity/{family}/{entity_id}" if language == "all"
                   else f"family_language_entity/{family}/{language}/{entity_id}")
            ark_counts = ark["buckets"].get(key, empty_counts())
            presidio_counts = presidio["buckets"].get(key, empty_counts())
            gold = max(ark_counts["gold"], presidio_counts["gold"])
            if not gold:
                continue
            scope = emap.entities[entity_id].scope
            if scope not in M2_SCOPES:
                excluded[entity_id] = {"gold": gold, "scope": scope}
                continue
            entities[entity_id] = {"gold": gold, "scope": scope, "ark_f1": metrics(ark_counts)[metric]["f1"],
                                   "presidio_f1": metrics(presidio_counts)[metric]["f1"]}
        margin = m2_margin_pp(family)
        ark_macro = sum(item["ark_f1"] for item in entities.values()) / len(entities) if entities else 0.0
        presidio_macro = sum(item["presidio_f1"] for item in entities.values()) / len(entities) if entities else 0.0
        target = presidio_macro + margin / 100
        families[family] = {
            "decides": family in entity_map_module.MILESTONE_FAMILIES,
            "holds": bool(entities) and ark_macro >= target - 1e-12,
            "margin_pp": margin,
            "ids": sorted(entities),
            "ark_macro_f1": ark_macro,
            "presidio_macro_f1": presidio_macro,
            "target": target,
            "entities": entities,
            "excluded": excluded,
        }
    met = all(families[family]["holds"] for family in entity_map_module.MILESTONE_FAMILIES)
    return {"language": language, "metric": metric, "scopes": list(M2_SCOPES), "met": met, "families": families}


def m2_lines(report: dict[str, Any], label: str = "M2") -> list[str]:
    lines = [f"{SCHEMA} M2 ({report['language']}, {report['metric']} F1 in %, macro over "
             f"{' + '.join(report['scopes'])} ids, Ark vs Presidio):"]
    for family, result in report["families"].items():
        note = "" if result["decides"] else " (reported, decides no milestone)"
        if not result["ids"]:
            lines.append(f"{family}: NO DATA, 0 ids{note}")
        else:
            verdict, op = ("HOLDS", ">=") if result["holds"] else ("NOT MET", "<")
            lines.append(
                f"{family}: {verdict}, macro-F1 Ark {pct(result['ark_macro_f1'])} {op} target {pct(result['target'])} "
                f"(Presidio {pct(result['presidio_macro_f1'])} + {result['margin_pp']:.1f} pp), "
                f"{len(result['ids'])} ids{note}"
            )
        for entity_id, item in result["entities"].items():
            lines.append(f"  {entity_id:<36} gold {item['gold']:>5}  Ark {pct(item['ark_f1'])}  "
                         f"Presidio {pct(item['presidio_f1'])}")
        for entity_id, item in result["excluded"].items():
            lines.append(f"  excluded {entity_id} ({item['scope']}, gold {item['gold']})")
    lines.append(f"{label}: {'MET' if report['met'] else 'NOT MET'} ({_deciding(report)})")
    return lines


def m2_by_mode(ark: dict[str, dict[str, Any]], presidio: dict[str, Any], emap: Any, language: str = "de",
               metric: str = "exact") -> dict[str, Any]:
    """M2 of every Ark mode against one Presidio result; the milestone is judged on balanced (T15)."""
    if MILESTONE_MODE not in ark:
        raise ScoreboardError(f"M2 needs Ark predictions in {MILESTONE_MODE} mode (milestones are judged on it)")
    modes = {mode: m2_report(ark[mode], presidio, emap, language, metric) for mode in ARK_MODES if mode in ark}
    return {"milestone_mode": MILESTONE_MODE, "language": language, "metric": metric,
            "met": modes[MILESTONE_MODE]["met"], "modes": modes}


def m2_mode_lines(report: dict[str, Any]) -> list[str]:
    lines = [f"{SCHEMA} M2 ({report['language']}, {report['metric']} F1 in %, macro over "
             f"{' + '.join(M2_SCOPES)} ids, Ark vs Presidio; milestones on {MILESTONE_MODE}):"]
    for mode, item in report["modes"].items():
        lines.append(f"== Ark {mode} " + ("(milestone mode)" if mode == MILESTONE_MODE else "(reported, decides no milestone)"))
        lines += m2_lines(item, label=f"M2 {mode}")[1:]
    milestone = report["modes"][MILESTONE_MODE]
    lines.append(f"M2: {'MET' if report['met'] else 'NOT MET'} ({MILESTONE_MODE}: {_deciding(milestone)})")
    return lines


# ── baseline report ──────────────────────────────────────────────────────


def ark_engine(mode: str) -> str:
    return f"ark-{mode}"


def merge_gaps(parts: Iterable[dict[str, dict[str, dict[str, int | None]]]]) -> dict[str, dict[str, dict[str, int | None]]]:
    """Sum gold gaps of several gold files (None, i.e. no checksum validator, stays None)."""
    merged: dict[str, dict[str, dict[str, int | None]]] = {}
    for part in parts:
        for corpus, entities in part.items():
            for entity_id, counts in entities.items():
                target = merged.setdefault(corpus, {}).get(entity_id)
                if target is None:
                    merged[corpus][entity_id] = dict(counts)
                    continue
                for field, value in counts.items():
                    if value is not None and target[field] is not None:
                        target[field] += value
    return {corpus: dict(sorted(entities.items())) for corpus, entities in sorted(merged.items())}


def baseline_report(gold_root: Path, ark: dict[str, Path], presidio: dict[str, Path], emap: Any) -> dict[str, Any]:
    """Every engine's merged result on every frozen gold file, hard-negative FP per family, M1, gold gaps.

    ``ark`` maps a PII mode, ``presidio`` a profile name to a prediction directory with the gold file
    names. Every Ark mode is compared with every profile for M1; the milestone comes from balanced (T15).
    The gold gaps (T16) are counted per corpus and entity for every engine and change no metric."""
    if MILESTONE_MODE not in ark:
        raise ScoreboardError(f"report needs Ark predictions in {MILESTONE_MODE} mode (milestones are judged on it)")
    if not presidio:
        raise ScoreboardError("report needs at least one Presidio profile")
    engines = {ark_engine(mode): ark[mode] for mode in ARK_MODES if mode in ark}
    for name, root in presidio.items():
        if name in engines:
            raise ScoreboardError(f"engine name {name!r} is taken by an Ark mode")
        engines[name] = root
    datasets = discover("gold", gold_root)
    gold = {dataset.name: read_jsonl(dataset.path) for dataset in datasets}
    row_family = {(name, row["id"]): emap.family(str(row.get("corpus", ""))) for name, rows in gold.items() for row in rows}
    validators = gold_validators(emap)
    results: dict[str, Any] = {}
    gaps: dict[str, dict[str, dict[str, dict[str, int | None]]]] = {}
    hard_negative_fp: dict[str, dict[str, int]] = {}
    for engine, root in engines.items():
        parts, gap_parts = [], []
        for name, rows in gold.items():
            predictions = root / name
            if not predictions.is_file():
                raise ScoreboardError(f"{engine}: no predictions {predictions} for {name}")
            prediction_rows = read_jsonl(predictions)
            parts.append(score_rows(rows, prediction_rows, emap, name))
            gap_parts.append(gold_gaps(rows, prediction_rows, emap, name, validators))
        results[engine] = merge(parts)
        gaps[engine] = merge_gaps(gap_parts)
        per_family: dict[str, int] = defaultdict(int)
        for name, row_id, *_ in results[engine]["hard_negative_fp"]:
            per_family[row_family[(name, row_id)]] += 1
        hard_negative_fp[engine] = dict(sorted(per_family.items()))
    corpus_rows: dict[str, int] = defaultdict(int)
    for rows in gold.values():
        for row in rows:
            corpus_rows[str(row.get("corpus", ""))] += 1
    family_rows: dict[str, int] = defaultdict(int)
    for family in row_family.values():
        family_rows[family] += 1
    corpora: dict[str, dict[str, Any]] = {}
    for corpus in sorted({corpus for engine_gaps in gaps.values() for corpus in engine_gaps}):
        ids = sorted({entity_id for engine_gaps in gaps.values() for entity_id in engine_gaps.get(corpus, {})})
        corpora[corpus] = {}
        for entity_id in ids:
            checked = entity_id in validators
            counts = {engine: gaps[engine].get(corpus, {}).get(entity_id) for engine in engines}
            # Gold counts do not depend on the engine; an engine without entry has no gap there.
            known = next(c for c in counts.values() if c is not None)
            corpora[corpus][entity_id] = {
                "gold": known["gold"],
                "gold_invalid": known["gold_invalid"],
                "engines": {
                    engine: {"duplicate_fp": c["duplicate_fp"] if c else 0,
                             "invalid_found": (c["invalid_found"] if c else 0) if checked else None}
                    for engine, c in counts.items()
                },
            }
    profiles = list(presidio)
    ark_results = {mode: results[ark_engine(mode)] for mode in ARK_MODES if mode in ark}
    return {
        "schema": SCHEMA,
        "datasets": {dataset.name: dataset.sha256 for dataset in datasets},
        "corpora": {corpus: emap.family(corpus) for corpus in sorted(corpus_rows)},
        "corpus_rows": dict(sorted(corpus_rows.items())),
        "family_rows": dict(sorted(family_rows.items())),
        "scopes": {entity_id: emap.entities[entity_id].scope for entity_id in sorted(l1_ids(emap))},
        "engines": results,
        "hard_negative_fp": hard_negative_fp,
        "milestone_mode": MILESTONE_MODE,
        "m1": {profile: m1_by_mode(ark_results, results[profile], emap) for profile in profiles},
        "m2": {profile: m2_by_mode(ark_results, results[profile], emap) for profile in profiles},
        "gold_gaps": {"validators": {entity_id: list(names) for entity_id, names in validators.items()},
                      "corpora": corpora},
    }


def _cell(value: float) -> str:
    return pct(value).strip()


def _family_cell(family: str) -> str:
    return family if family in entity_map_module.MILESTONE_FAMILIES else f"{family} ¹"


def report_lines(report: dict[str, Any]) -> list[str]:
    """Markdown tables of a baseline report: per family, per corpus, per entity, M1."""
    engines = report["engines"]
    names = list(engines)
    families = [f for f in entity_map_module.FAMILIES if any(f"family/{f}" in r["buckets"] for r in engines.values())]
    lines = [
        "## Overall per source family",
        "",
        "| Family | Engine | Rows | Gold | Pred | Exact P | Exact R | Exact F1 | Overlap F1 | EN F1 | DE F1 | HN-FP |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for family in families:
        for engine in names:
            buckets = engines[engine]["buckets"]
            counts = buckets.get(f"family/{family}", empty_counts())
            m = metrics(counts)
            languages = []
            for language in LANGUAGES:
                key = f"family_language/{family}/{language}"
                languages.append(_cell(metrics(buckets[key])["exact"]["f1"]) if key in buckets else "–")
            lines.append(
                f"| {_family_cell(family)} | {engine} | {report['family_rows'][family]} | {counts['gold']} | "
                f"{counts['predicted']} | {_cell(m['exact']['precision'])} | {_cell(m['exact']['recall'])} | "
                f"{_cell(m['exact']['f1'])} | {_cell(m['overlap']['f1'])} | {languages[1]} | {languages[0]} | "
                f"{report['hard_negative_fp'][engine].get(family, 0)} |"
            )
    lines += ["", "¹ ark_authored is reported and decides no milestone.", ""]

    lines += [
        "## Per corpus (exact P / R / F1)",
        "",
        "| Corpus | Family | Rows | Gold | " + " | ".join(names) + " |",
        "|---|---|---:|---:|" + "---|" * len(names),
    ]
    for corpus, family in report["corpora"].items():
        key = f"corpus/{corpus}"
        counts = {engine: engines[engine]["buckets"].get(key, empty_counts()) for engine in names}
        f1 = {engine: metrics(c)["exact"]["f1"] for engine, c in counts.items()}
        best = max(f1.values())
        cells = []
        for engine in names:
            m = metrics(counts[engine])["exact"]
            value = _cell(m["f1"])
            cells.append(f"{_cell(m['precision'])} / {_cell(m['recall'])} / "
                         + (f"**{value}**" if best > 0 and f1[engine] == best else value))
        gold = max(c["gold"] for c in counts.values())
        lines.append(f"| {corpus} | {family} | {report['corpus_rows'][corpus]} | {gold} | " + " | ".join(cells) + " |")
    lines.append("")

    lines += [
        "## Per entity (exact F1, best in bold)",
        "",
        "| Family | Entity | Scope | Gold | " + " | ".join(names) + " |",
        "|---|---|---|---:|" + "---:|" * len(names),
    ]
    for family in families:
        prefix = f"family_entity/{family}/"
        ids = sorted({key[len(prefix):] for r in engines.values() for key in r["buckets"] if key.startswith(prefix)})
        for entity_id in ids:
            counts = {engine: engines[engine]["buckets"].get(prefix + entity_id, empty_counts()) for engine in names}
            gold = max(c["gold"] for c in counts.values())
            if not gold:
                continue
            f1 = {engine: metrics(c)["exact"]["f1"] for engine, c in counts.items()}
            best = max(f1.values())
            cells = [f"**{_cell(f1[e])}**" if best > 0 and f1[e] == best else _cell(f1[e]) for e in names]
            lines.append(f"| {family} | {entity_id} | {report['scopes'][entity_id]} | {gold} | " + " | ".join(cells) + " |")
    lines.append("")

    # Milestone families first; ark_authored is shown last and decides nothing.
    m1_families = [*entity_map_module.MILESTONE_FAMILIES,
                   *(f for f in entity_map_module.FAMILIES if f not in entity_map_module.MILESTONE_FAMILIES)]
    milestone = report["milestone_mode"]
    modes = list(next(iter(report["m1"].values()))["modes"])
    lines += [
        f"## M1 (each Ark mode vs each profile; EN rows, exact F1, shared ids with gold; milestone on {milestone})",
        "",
        "| Ark mode | Profile | M1 | " + " | ".join(_family_cell(f) for f in m1_families) + " |",
        "|---|---|---|" + "---|" * len(m1_families),
    ]
    for mode in [milestone, *(m for m in modes if m != milestone)]:
        for profile, by_mode in report["m1"].items():
            m1 = by_mode["modes"][mode]
            cells = []
            for family in m1_families:
                entities = m1["families"][family]["entities"]
                below = [entity_id for entity_id, item in entities.items() if not item["holds"]]
                cell = f"{len(entities) - len(below)}/{len(entities)}" if entities else "no data"
                cells.append(cell + (f" (below: {', '.join(below)})" if below else ""))
            mode_cell = mode if mode == milestone else f"{mode} ²"
            lines.append(f"| {mode_cell} | {profile} | {'MET' if m1['met'] else 'NOT MET'} | " + " | ".join(cells) + " |")
    lines += ["", f"² reported; milestones are judged on {milestone} (T15).", ""]
    lines += [
        f"## M2 (each Ark mode vs each profile; DE rows, exact macro-F1 over {' + '.join(M2_SCOPES)} ids with gold; "
        f"Ark vs target = Presidio + margin; milestone on {milestone})",
        "",
        "| Ark mode | Profile | M2 | " + " | ".join(_family_cell(f) for f in m1_families) + " |",
        "|---|---|---|" + "---|" * len(m1_families),
    ]
    for mode in [milestone, *(m for m in modes if m != milestone)]:
        for profile, by_mode in report["m2"].items():
            m2 = by_mode["modes"][mode]
            cells = []
            for family in m1_families:
                item = m2["families"][family]
                cells.append(
                    f"{_cell(item['ark_macro_f1'])} vs {_cell(item['target'])} ({_cell(item['presidio_macro_f1'])} + "
                    f"{item['margin_pp']:g}), {len(item['ids'])} ids" if item["ids"] else "no data"
                )
            mode_cell = mode if mode == milestone else f"{mode} ²"
            lines.append(f"| {mode_cell} | {profile} | {'MET' if m2['met'] else 'NOT MET'} | " + " | ".join(cells) + " |")
    lines += ["", "presidio_only ids stay out of the macro average until entity_map.yaml marks them shared (D-M2).", ""]
    lines += gold_gap_lines(report["gold_gaps"], names)
    return lines


def gold_gap_lines(gaps: dict[str, Any], names: list[str]) -> list[str]:
    """Markdown tables of the gold gaps per corpus and entity (T16); the metrics above include them unchanged."""
    lines = [
        "## Gold gaps (reported only; no metric changes, T16)",
        "",
        "The frozen corpora are never edited; these counts are already part of the scores above.",
        "",
        "### Predictions equal to an annotated gold value elsewhere in the row",
        "",
        "Exact-span false positives whose text equals a gold value of the same id in the same row.",
        "",
        "| Corpus | Entity | Gold | " + " | ".join(names) + " |",
        "|---|---|---:|" + "---:|" * len(names),
    ]
    rows = 0
    for corpus, entities in gaps["corpora"].items():
        for entity_id, item in entities.items():
            counts = [item["engines"][engine]["duplicate_fp"] for engine in names]
            if any(counts):
                rows += 1
                lines.append(f"| {corpus} | {entity_id} | {item['gold']} | " + " | ".join(map(str, counts)) + " |")
    if not rows:
        lines.append("| – | – | – |" + " – |" * len(names))
    lines += [
        "",
        "### Gold values failing the entity's validator",
        "",
        "Gold of ids with a checksum validator (Python ports of the Rust validators) that fails every one of",
        "them; the engine columns count those gold values reported with the exact span.",
        "",
        "| Corpus | Entity | Validator | Gold | Invalid | " + " | ".join(names) + " |",
        "|---|---|---|---:|---:|" + "---:|" * len(names),
    ]
    rows = 0
    for corpus, entities in gaps["corpora"].items():
        for entity_id, item in entities.items():
            if item["gold_invalid"] is None or not item["gold"]:
                continue
            rows += 1
            found = [str(item["engines"][engine]["invalid_found"]) for engine in names]
            lines.append(
                f"| {corpus} | {entity_id} | {', '.join(gaps['validators'][entity_id])} | {item['gold']} | "
                f"{item['gold_invalid']} | " + " | ".join(found) + " |"
            )
    if not rows:
        lines.append("| – | – | – | – | – |" + " – |" * len(names))
    return lines


def named_dirs(items: Iterable[str], option: str, allowed: tuple[str, ...] | None = None) -> dict[str, Path]:
    """Parse repeated NAME=DIR options; names are unique and, with allowed, one of those."""
    result: dict[str, Path] = {}
    for item in items:
        name, sep, directory = item.partition("=")
        if not sep or not name or not directory or name in result:
            raise ScoreboardError(f"{option} {item!r}: expected a unique NAME=DIR")
        if allowed is not None and name not in allowed:
            raise ScoreboardError(f"{option} {item!r}: mode must be one of {', '.join(allowed)}")
        result[name] = Path(directory)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    gate_parser = commands.add_parser("gate", help="score head and base, exit 1 on regression")
    gate_parser.add_argument("--head", type=Path, required=True, help="checkout of the head commit (git worktree)")
    gate_parser.add_argument("--base-sha", required=True, help="base commit (any git revision)")
    gate_parser.add_argument("--dev", type=Path, required=True, help="dev gold directory")
    gate_parser.add_argument("--holdout", type=Path, help="holdout gold directory (gate only)")
    gate_parser.add_argument("--cache", type=Path, required=True, help="writable cache directory")
    gate_parser.add_argument("--ark-python", help="interpreter with the head's patronus_ark (default: $VIRTUAL_ENV)")
    gate_parser.add_argument("--cargo", default="cargo", help="cargo for the offline base build")
    gate_parser.add_argument("--tolerance-pp", type=float, default=TOLERANCE_PP)
    gate_parser.add_argument("--json", type=Path, help="also write the full report (contains holdout row ids)")
    score_parser = commands.add_parser("score", help="score one prediction file")
    score_parser.add_argument("--gold", type=Path, required=True)
    score_parser.add_argument("--predictions", type=Path, required=True)
    score_parser.add_argument("--json", type=Path, help="also write bucket counts as JSON")
    m1_parser = commands.add_parser("m1", help="M1 per source family: Ark vs Presidio on the shared ids")
    m1_parser.add_argument("--gold", type=Path, required=True, help="gold directory (frozen dirs with .ready)")
    m1_parser.add_argument("--ark", action="append", required=True, metavar="MODE=DIR",
                           help="Ark predictions of one PII mode (run_ark.py --pii-mode), same relative file names; "
                                f"{MILESTONE_MODE} is required and decides")
    m1_parser.add_argument("--presidio", type=Path, required=True, help="Presidio predictions, same relative file names")
    m1_parser.add_argument("--language", choices=(*LANGUAGES, "all"), default="en", help="M1 is EN parity (default en)")
    m1_parser.add_argument("--metric", choices=METRICS, default="exact")
    m1_parser.add_argument("--check", action="store_true", help=f"exit 1 if M1 is not met on {MILESTONE_MODE}")
    m1_parser.add_argument("--json", type=Path, help="also write the report as JSON")
    m2_parser = commands.add_parser("m2", help="M2 per source family: DE macro-F1 of Ark vs Presidio, exit 1 unless met")
    m2_parser.add_argument("--gold", type=Path, required=True, help="gold directory (frozen dirs with .ready)")
    m2_parser.add_argument("--ark", action="append", required=True, metavar="MODE=DIR",
                           help="Ark predictions of one PII mode (run_ark.py --pii-mode), same relative file names; "
                                f"{MILESTONE_MODE} is required and decides")
    m2_parser.add_argument("--presidio", type=Path, required=True,
                           help="Presidio tuned predictions, same relative file names")
    m2_parser.add_argument("--language", choices=(*LANGUAGES, "all"), default="de", help="M2 is DE/EU (default de)")
    m2_parser.add_argument("--metric", choices=METRICS, default="exact")
    m2_parser.add_argument("--json", type=Path, help="also write the report as JSON")
    report_parser = commands.add_parser("report", help="Markdown baseline: Ark vs Presidio profiles per family, corpus, entity, M1")
    report_parser.add_argument("--gold", type=Path, required=True, help="gold directory (frozen dirs with .ready)")
    report_parser.add_argument("--ark", action="append", required=True, metavar="MODE=DIR",
                               help=f"Ark predictions of one PII mode with the gold file names; {MILESTONE_MODE} is required")
    report_parser.add_argument("--engine", action="append", required=True, metavar="NAME=DIR",
                               help="Presidio predictions of one profile with the gold file names")
    report_parser.add_argument("--json", type=Path, help="also write the report as JSON")
    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            ark = named_dirs(args.ark, "--ark", ARK_MODES)
            presidio = named_dirs(args.engine, "--engine")
            emap = entity_map_module.load()
            report = baseline_report(args.gold, ark, presidio, emap)
            print("\n".join(report_lines(report)))
            if args.json:
                args.json.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        if args.command in ("m1", "m2"):
            ark = named_dirs(args.ark, "--ark", ARK_MODES)
            if MILESTONE_MODE not in ark:
                raise ScoreboardError(f"{args.command} needs --ark {MILESTONE_MODE}=DIR "
                                      f"(milestones are judged on {MILESTONE_MODE})")
            emap = entity_map_module.load()
            ark_results = {mode: score_directory(args.gold, directory, emap) for mode, directory in ark.items()}
            by_mode, mode_lines = (m1_by_mode, m1_mode_lines) if args.command == "m1" else (m2_by_mode, m2_mode_lines)
            report = by_mode(ark_results, score_directory(args.gold, args.presidio, emap), emap,
                             args.language, args.metric)
            print("\n".join(mode_lines(report)))
            if args.json:
                args.json.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            # m1 fails only with --check; m2 always exits 1 unless both family rules hold (D-M2).
            check = args.check if args.command == "m1" else True
            return 1 if check and not report["met"] else 0
        if args.command == "score":
            lines, result = score_file(args.gold, args.predictions)
            print("\n".join(lines))
            if args.json:
                args.json.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        splits = {"dev": args.dev, **({"holdout": args.holdout} if args.holdout else {})}
        lines, regressed, report = gate(
            args.head, args.base_sha, splits, args.cache,
            ark_python=args.ark_python, cargo=args.cargo, tolerance_pp=args.tolerance_pp,
        )
    except ScoreboardError as error:
        print(f"scoreboard error: {error}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    if args.json:
        args.json.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main())
