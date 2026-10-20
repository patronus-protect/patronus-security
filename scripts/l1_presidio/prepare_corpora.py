#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Download the pinned external PII corpora and freeze the L1-PII dev/holdout split.

Two source families are split separately. ``neutral`` (default): Gretel Finance (all six
test shards), OpenPII Nano and TAB (ECHR test). ``presidio_favored``: the synthetic
presidio-evaluator dataset of microsoft/presidio-research and the positive/negative cases
of the presidio-analyzer recognizer tests (release 2.2.364), read with ``ast`` and never
executed. Sources are fetched at the revisions of
``python/patronus_ark/benchmark_data/external_pii/manifest.json``, checked against the
pinned SHA-256, normalized to the ``patronus_ark.external_pii_eval`` schema and split
group-atomically: a group (Gretel ``expanded_type``, presidio-evaluator template, recognizer
test text, otherwise the document) goes to the holdout when ``sha256(seed:corpus:group)``
falls below the holdout fraction. Seed and fraction are constants, so the split is a
function of the pinned sources alone.

    python3 scripts/l1_presidio/prepare_corpora.py --dev-out DIR --holdout-out DIR
    python3 scripts/l1_presidio/prepare_corpora.py --family presidio_favored \
        --dev-out DEV/presidio_favored --holdout-out HOLDOUT/presidio_favored
    python3 scripts/l1_presidio/prepare_corpora.py --check DIR

Each output directory gets one normalized JSONL per corpus, ``manifest.json`` (sources,
counts, SHA-256 of every file) and, written last, ``.ready`` with the manifest's SHA-256.
A directory that already has ``.ready`` is frozen: a rerun must reproduce it byte for
byte, otherwise nothing is written and the exit code is 1 (``--force`` rewrites it).
Raw sources are cached in ``--sources`` (default ``HOLDOUT/.sources``), never in the dev
directory. Only standard library: the gate runs this with the Presidio venv, which has no
pyarrow, so the Gretel Parquet shards are read by a minimal reader below.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, NamedTuple


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXTERNAL_PII_EVAL_PATH = ROOT / "python" / "patronus_ark" / "external_pii_eval.py"
MANIFEST_PATH = ROOT / "python" / "patronus_ark" / "benchmark_data" / "external_pii" / "manifest.json"
SCHEMA = "ark-l1-corpus-split-v1"
SPLIT_SEED = "ark-l1-e04-split-v1"
HOLDOUT_FRACTION = 0.6
SPLITS = ("dev", "holdout")
CORPORA = ("gretel-synthetic-pii-finance", "ai4privacy-openpii-nano-1k", "tab")
PRESIDIO_FAVORED_CORPORA = ("presidio-evaluator-synth-v2", "presidio-analyzer-recognizer-tests")
# Upstream directory of verified_files inside the snapshot (manifest: input_root).
UPSTREAM_DIRS = {"gretel-synthetic-pii-finance": "data", "presidio-analyzer-recognizer-tests": "presidio-analyzer/tests"}


class Family(NamedTuple):
    corpora: tuple[str, ...]
    grouping: str


# Source families (research/l1-pii/README.md, fairness rule). Each family is frozen in its own
# directory pair; the neutral manifest keeps the E04 layout so its frozen split still reproduces.
FAMILIES = {
    "neutral": Family(CORPORA, "group_id is Gretel expanded_type, otherwise the document id"),
    "presidio_favored": Family(
        PRESIDIO_FAVORED_CORPORA,
        "group_id is the presidio-evaluator template_id, for recognizer test cases the SHA-256 of the text",
    ),
}
GRETEL_COLUMNS = ("language", "expanded_type", "generated_text", "pii_spans")
READY = ".ready"


# ── Snappy ───────────────────────────────────────────────────────────────────


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise ValueError("truncated or oversized varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def snappy_decompress(data: bytes) -> bytes:
    """Decompress one raw Snappy block (the Parquet SNAPPY codec)."""
    length, pos = _varint(data, 0)
    out = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        kind = tag & 3
        if kind == 0:
            size = tag >> 2
            if size >= 60:
                extra = size - 59
                if pos + extra > len(data):
                    raise ValueError("truncated Snappy literal length")
                size = int.from_bytes(data[pos : pos + extra], "little")
                pos += extra
            size += 1
            if pos + size > len(data):
                raise ValueError("truncated Snappy literal")
            out += data[pos : pos + size]
            pos += size
            continue
        width = {1: 1, 2: 2, 3: 4}[kind]
        if pos + width > len(data):
            raise ValueError("truncated Snappy copy")
        if kind == 1:
            size = ((tag >> 2) & 7) + 4
            offset = ((tag >> 5) << 8) | data[pos]
        else:
            size = (tag >> 2) + 1
            offset = int.from_bytes(data[pos : pos + width], "little")
        pos += width
        if offset == 0 or offset > len(out):
            raise ValueError("Snappy copy offset outside the output")
        pattern = out[len(out) - offset :] if size > offset else out[len(out) - offset : len(out) - offset + size]
        out += (pattern * (size // len(pattern) + 1))[:size]
    if len(out) != length:
        raise ValueError(f"Snappy block declares {length} bytes, decoded {len(out)}")
    return bytes(out)


# ── minimal Parquet reader ───────────────────────────────────────────────────
# Enough for the pinned Gretel shards: flat optional/required BYTE_ARRAY columns, PLAIN and
# (RLE_|PLAIN_)DICTIONARY pages, data page v1 and v2, UNCOMPRESSED or SNAPPY. Anything else
# is rejected rather than misread; the source SHA-256 pins the files it has to read.


class _Thrift:
    """Thrift compact protocol; structs decode to ``{field id: value}``."""

    def __init__(self, data: bytes, pos: int):
        self.data = data
        self.pos = pos

    def _byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("truncated Thrift data")
        self.pos += 1
        return self.data[self.pos - 1]

    def _zigzag(self) -> int:
        value, self.pos = _varint(self.data, self.pos)
        return (value >> 1) ^ -(value & 1)

    def _value(self, kind: int, in_collection: bool = False) -> Any:
        if kind in (1, 2):
            return self._byte() == 1 if in_collection else kind == 1
        if kind == 3:
            return struct.unpack("b", bytes([self._byte()]))[0]
        if kind in (4, 5, 6):
            return self._zigzag()
        if kind in (7, 8):
            if kind == 7:
                size = 8
            else:
                size, self.pos = _varint(self.data, self.pos)
            if self.pos + size > len(self.data):
                raise ValueError("truncated Thrift value")
            raw = self.data[self.pos : self.pos + size]
            self.pos += size
            return struct.unpack("<d", raw)[0] if kind == 7 else raw
        if kind in (9, 10):
            header = self._byte()
            size = header >> 4
            if size == 15:
                size, self.pos = _varint(self.data, self.pos)
            return [self._value(header & 0x0F, True) for _ in range(size)]
        if kind == 11:
            size, self.pos = _varint(self.data, self.pos)
            if not size:
                return {}
            types = self._byte()
            return [(self._value(types >> 4, True), self._value(types & 0x0F, True)) for _ in range(size)]
        if kind == 12:
            return self.struct()
        raise ValueError(f"unknown Thrift type {kind}")

    def struct(self) -> dict[int, Any]:
        fields: dict[int, Any] = {}
        last = 0
        while True:
            header = self._byte()
            if header == 0:
                return fields
            delta = header >> 4
            field = last + delta if delta else self._zigzag()
            fields[field] = self._value(header & 0x0F)
            last = field


def _rle_hybrid(data: bytes, bit_width: int, count: int) -> list[int]:
    values: list[int] = []
    pos = 0
    mask = (1 << bit_width) - 1
    byte_width = (bit_width + 7) // 8
    while len(values) < count:
        header, pos = _varint(data, pos)
        if header & 1:
            groups = header >> 1
            size = groups * bit_width
            if pos + size > len(data):
                raise ValueError("truncated bit-packed run")
            packed = int.from_bytes(data[pos : pos + size], "little")
            pos += size
            values.extend((packed >> (index * bit_width)) & mask for index in range(groups * 8))
        else:
            if pos + byte_width > len(data):
                raise ValueError("truncated RLE run")
            values.extend([int.from_bytes(data[pos : pos + byte_width], "little")] * (header >> 1))
            pos += byte_width
    return values[:count]


def _plain_byte_arrays(data: bytes, count: int) -> list[bytes]:
    values = []
    pos = 0
    for _ in range(count):
        if pos + 4 > len(data):
            raise ValueError("truncated PLAIN byte array")
        size = int.from_bytes(data[pos : pos + 4], "little")
        if pos + 4 + size > len(data):
            raise ValueError("truncated PLAIN byte array")
        values.append(data[pos + 4 : pos + 4 + size])
        pos += 4 + size
    return values


def _decompress(codec: int, data: bytes) -> bytes:
    if codec == 0:
        return data
    if codec == 1:
        return snappy_decompress(data)
    raise ValueError(f"unsupported Parquet codec {codec}")


def _column_chunk(data: bytes, meta: dict[int, Any], optional: bool) -> list[bytes | None]:
    codec, total = meta[4], meta[5]
    pos = meta.get(11) or meta[9]
    dictionary: list[bytes] | None = None
    values: list[bytes | None] = []
    while len(values) < total:
        reader = _Thrift(data, pos)
        header = reader.struct()
        page_type, compressed_size = header[1], header[3]
        start = reader.pos
        if start + compressed_size > len(data):
            raise ValueError("Parquet page outside the file")
        payload = data[start : start + compressed_size]
        pos = start + compressed_size
        if page_type == 2:
            dictionary = _plain_byte_arrays(_decompress(codec, payload), header[7][1])
            continue
        if page_type == 0:
            page = _decompress(codec, payload)
            count, encoding = header[5][1], header[5][2]
            if optional:
                size = int.from_bytes(page[:4], "little")
                levels = _rle_hybrid(page[4 : 4 + size], 1, count)
                body = page[4 + size :]
            else:
                levels, body = [1] * count, page
        elif page_type == 3:
            v2 = header[8]
            count, encoding, def_size, rep_size = v2[1], v2[4], v2[5], v2[6]
            if rep_size:
                raise ValueError("repeated Parquet columns are not supported")
            levels = _rle_hybrid(payload[:def_size], 1, count) if optional else [1] * count
            body = payload[def_size:]
            if v2.get(7, True):
                body = _decompress(codec, body)
        else:
            continue  # index pages carry no values
        present = sum(levels)
        if encoding == 0:
            decoded = _plain_byte_arrays(body, present)
        elif encoding in (2, 8):
            if dictionary is None or not body:
                raise ValueError("dictionary-encoded Parquet page without a dictionary")
            try:
                decoded = [dictionary[index] for index in _rle_hybrid(body[1:], body[0], present)]
            except IndexError as error:
                raise ValueError("Parquet dictionary index out of range") from error
        else:
            raise ValueError(f"unsupported Parquet encoding {encoding}")
        iterator = iter(decoded)
        values.extend(next(iterator) if level else None for level in levels)
    if len(values) != total:
        raise ValueError("Parquet column chunk has more values than declared")
    return values


def read_parquet_columns(path: Path, columns: list[str] | tuple[str, ...]) -> list[dict[str, str | None]]:
    """Rows of the requested top-level UTF-8 columns of a Parquet file, nulls as ``None``."""
    data = path.read_bytes()
    if len(data) < 12 or data[:4] != b"PAR1" or data[-4:] != b"PAR1":
        raise ValueError(f"{path} is not a Parquet file")
    size = int.from_bytes(data[-8:-4], "little")
    if size > len(data) - 12:
        raise ValueError(f"{path}: Parquet footer outside the file")
    metadata = _Thrift(data, len(data) - 8 - size).struct()
    schema = metadata[2]
    leaves: dict[str, dict[int, Any]] = {}
    index = 1
    while index < len(schema):  # top-level children of the root; nested groups are skipped
        element = schema[index]
        name = element[4].decode("utf-8")
        children = element.get(5, 0)
        if not children:
            leaves[name] = element
        index += 1
        pending = children
        while pending:
            pending += schema[index].get(5, 0) - 1
            index += 1
    for column in columns:
        element = leaves.get(column)
        if element is None:
            raise ValueError(f"{path}: no top-level column {column!r}")
        if element.get(1) != 6 or element.get(3) == 2:
            raise ValueError(f"{path}: column {column!r} is not a flat BYTE_ARRAY column")
    result: dict[str, list[bytes | None]] = {column: [] for column in columns}
    for row_group in metadata[4]:
        for chunk in row_group[1]:
            meta = chunk[3]
            name = b".".join(meta[3]).decode("utf-8")
            if name in result:
                result[name].extend(_column_chunk(data, meta, leaves[name].get(3) == 1))
    rows = metadata[3]
    for column, values in result.items():
        if len(values) != rows:
            raise ValueError(f"{path}: column {column!r} has {len(values)} values for {rows} rows")
    return [
        {column: None if result[column][row] is None else result[column][row].decode("utf-8") for column in columns}
        for row in range(rows)
    ]


# ── sources ──────────────────────────────────────────────────────────────────


class Source(NamedTuple):
    path: str  # relative to the corpus directory under --sources
    sha256: str
    url: str


def _load_file(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


# Loaded by path: the package __init__ needs the native module, this script does not.
EXTERNAL_PII_EVAL = _load_file("_ark_external_pii_eval", EXTERNAL_PII_EVAL_PATH)


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, dict[str, Any]]:
    return EXTERNAL_PII_EVAL.load_manifest(path)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _upstream_url(base: str, revision: str, path: str) -> str:
    if base.startswith("https://huggingface.co/datasets/"):
        return f"{base}/resolve/{revision}/{path}"
    if base.startswith("https://github.com/"):
        return f"https://raw.githubusercontent.com/{base.removeprefix('https://github.com/')}/{revision}/{path}"
    raise ValueError(f"no download rule for source {base!r}")


def source_files(corpus: dict[str, Any]) -> list[Source]:
    """Pinned upstream files of one manifest corpus with their download URLs."""
    revision = corpus.get("revision")
    if not isinstance(revision, str) or not revision:
        raise ValueError(f"corpus {corpus['id']!r} has no pinned revision")
    if corpus.get("verified_files") is not None:
        entries = [(entry["path"], entry["sha256"]) for entry in corpus["verified_files"]]
    else:
        entries = [(corpus["verified_file"], corpus["verified_sha256"])]
    prefix = UPSTREAM_DIRS.get(corpus["id"])
    sources = []
    for path, digest in entries:
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError(f"unsafe source path {path!r}")
        upstream = f"{prefix}/{path}" if prefix else path
        sources.append(Source(path, digest, _upstream_url(corpus["source"].rstrip("/"), revision, upstream)))
    return sources


def download(url: str, attempts: int = 3) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "patronus-ark-l1-prepare-corpora"})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError) as error:
            if attempt == attempts - 1:
                raise ValueError(f"download of {url} failed: {error}") from error
            time.sleep(2 * (attempt + 1))
    raise AssertionError("unreachable")


def fetch_sources(
    corpus: dict[str, Any], source_dir: Path, offline: bool, fetch: Callable[[str], bytes] = download
) -> Path:
    """Make every pinned file of a corpus present and verified; return the adapter input path."""
    root = source_dir / corpus["id"]
    for source in source_files(corpus):
        target = root / source.path
        if target.is_file() and _sha256(target.read_bytes()) == source.sha256:
            continue
        if offline:
            raise ValueError(f"{corpus['id']}: {target} is missing or does not match the pinned SHA-256")
        data = fetch(source.url)
        actual = _sha256(data)
        if actual != source.sha256:
            raise ValueError(f"{source.url}: SHA-256 {actual}, pinned {source.sha256}")
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(target.name + ".part")
        partial.write_bytes(data)
        os.replace(partial, target)
    return root if corpus.get("verified_files") is not None else root / corpus["verified_file"]


def load_corpus(corpus: dict[str, Any], input_path: Path, manifest_path: Path) -> list[dict[str, Any]]:
    """Normalized rows of one corpus in source order (``external_pii_eval`` schema)."""
    if corpus.get("adapter") == "presidio_evaluator_json_v1":
        return load_presidio_evaluator(input_path, corpus)
    if corpus.get("adapter") == "presidio_recognizer_tests_v1":
        return load_recognizer_tests(input_path, corpus)
    if corpus.get("adapter") != "gretel_parquet_v1":
        return EXTERNAL_PII_EVAL.normalize_file(input_path, corpus["id"], manifest_path, verify_source=True)
    rows = []
    for entry in corpus["verified_files"]:
        for number, row in enumerate(read_parquet_columns(input_path / entry["path"], GRETEL_COLUMNS)):
            rows.append(EXTERNAL_PII_EVAL.normalize_gretel_row(row, corpus, f"{entry['path']}:{number}"))
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError(f"{corpus['id']}: duplicate row ids")
    return rows


# ── presidio_favored sources ─────────────────────────────────────────────────


def load_presidio_evaluator(path: Path, corpus: dict[str, Any]) -> list[dict[str, Any]]:
    """Rows of a presidio-evaluator synthetic dataset (``full_text``, ``spans``, ``template_id``)."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"{corpus['id']}: expected a JSON list of samples")
    stem = Path(corpus["verified_file"]).stem
    rows = []
    for number, sample in enumerate(payload):
        where = f"{corpus['id']}:{number}"
        text, spans, template = sample.get("full_text"), sample.get("spans"), sample.get("template_id")
        if not isinstance(text, str) or not text or not isinstance(spans, list):
            raise ValueError(f"{where}: sample needs full_text and a spans list")
        if isinstance(template, bool) or not isinstance(template, int):
            raise ValueError(f"{where}: sample needs an integer template_id")
        entities = []
        for span in spans:
            start, end = span.get("start_position"), span.get("end_position")
            if not isinstance(start, int) or not isinstance(end, int) or text[start:end] != span.get("entity_value"):
                raise ValueError(f"{where}: span offsets do not match entity_value")
            entities.append({"label": span.get("entity_type"), "start": start, "end": end})
        rows.append(
            EXTERNAL_PII_EVAL.normalize_row(
                {"id": f"{stem}:{number}", "group_id": f"template:{template}", "text": text, "entities": entities},
                corpus,
            )
        )
    return rows


# The recognizer tests are read with ``ast``, never imported or executed. A parametrized test
# yields cases if its first argument is the analyzed text, it states the expected result count
# and/or spans, and it runs the default-constructed recognizer of its file.
TEST_TEXT_ARGS = ("text", "iban")
TEST_POSITION_ARGS = ("expected_positions", "expected_position", "expected_res")
TEST_IGNORED_ARGS = {"expected_scores", "expected_score", "expected_score_ranges", "score"}
TEST_SHARED_FIXTURES = {"entities", "max_score", "min_score", "spacy_nlp_engine"}
# A case with one expected result but no spans counts if its text is one bare token.
WHOLE_VALUE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9./-]*[A-Za-z0-9])?\Z")
# Recognizer fixtures with constructor arguments that only widen the default, checked by hand
# for the pinned release (PhoneRecognizer: default regions plus JP and CN).
TEST_WIDENED_FIXTURES = {("test_phone_recognizer.py", "recognizer")}
# Test file prefix -> language of the recognizer; everything else is English.
TEST_LANGUAGES = {
    "de": "de", "es": "es", "fi": "fi", "it": "it", "kr": "ko", "pl": "pl", "se": "sv", "th": "th", "tr": "tr",
}


class RecognizerCase(NamedTuple):
    test: str  # file::function[index]
    text: str
    spans: tuple[tuple[str, int, int], ...]  # (Presidio entity, start, end); empty for a negative
    entities: tuple[str, ...]  # Presidio entities the case asserts on


class _Unresolved(Exception):
    pass


def _literal(node: ast.AST, names: dict[str, Any]) -> Any:
    """Value of a literal expression; names resolve to literal module constants only."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(_literal(item, names) for item in node.elts)
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _literal(node.operand, names)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return -value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left, names), _literal(node.right, names)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue) and part.conversion == -1 and part.format_spec is None:
                value = _literal(part.value, names)
                if not isinstance(value, str):
                    raise _Unresolved
                parts.append(value)
            else:
                raise _Unresolved
        return "".join(parts)
    raise _Unresolved


def _decorator_name(node: ast.AST) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    return target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")


def _fixtures(tree: ast.Module, names: dict[str, Any]) -> dict[str, Any]:
    """Module fixtures: ``entities`` -> its literal list, recognizer fixtures -> default-constructed?"""
    fixtures: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or "fixture" not in map(_decorator_name, node.decorator_list):
            continue
        returned = next((item.value for item in node.body if isinstance(item, ast.Return)), None)
        if node.name == "entities":
            try:
                fixtures[node.name] = _literal(returned, names) if returned is not None else None
            except _Unresolved:
                fixtures[node.name] = None
        else:
            fixtures[node.name] = isinstance(returned, ast.Call) and not returned.args and not returned.keywords
    return fixtures


def _spans(value: Any) -> list[tuple[int, int]]:
    if isinstance(value, tuple) and len(value) == 2 and all(isinstance(item, int) for item in value):
        return [value]  # expected_position: one (start, end) pair
    if not isinstance(value, tuple) or not all(
        isinstance(item, tuple) and len(item) == 2 and all(isinstance(bound, int) for bound in item) for item in value
    ):
        raise _Unresolved
    return list(value)


def _function_skip(
    node: ast.FunctionDef, filename: str, argnames: list[str], fixtures: dict[str, Any]
) -> str | None:
    """Why a parametrized test yields no cases, or None."""
    if not argnames or argnames[0] not in TEST_TEXT_ARGS:
        return "first argument is not the analyzed text"
    positions = [name for name in TEST_POSITION_ARGS if name in argnames]
    if {"expected_start", "expected_end"} <= set(argnames):
        positions.append("expected_start/expected_end")
    if "expected_len" not in argnames and not positions:
        return "no expected count or spans"
    known = {argnames[0], "expected_len", "entities", "expected_start", "expected_end", *TEST_POSITION_ARGS}
    extra = sorted(set(argnames) - known - TEST_IGNORED_ARGS)
    if extra:
        return f"argument {extra[0]} changes the recognizer call"
    for name in [arg.arg for arg in node.args.args if arg.arg not in argnames and arg.arg not in TEST_SHARED_FIXTURES]:
        if fixtures.get(name) is not True and (filename, name) not in TEST_WIDENED_FIXTURES:
            return f"fixture {name} is not the default recognizer"
    if "entities" not in argnames:
        entities = fixtures.get("entities")
        if not (isinstance(entities, tuple) and len(entities) == 1 and isinstance(entities[0], str)):
            return "no single entity fixture"
    return None


def recognizer_test_cases(source: str, filename: str) -> tuple[list[RecognizerCase], Counter]:
    """Positive and negative cases of one presidio-analyzer recognizer test file, plus skip reasons."""
    tree = ast.parse(source, filename=filename)
    names: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                names[node.targets[0].id] = _literal(node.value, names)
            except _Unresolved:
                pass
    fixtures = _fixtures(tree, names)
    cases: list[RecognizerCase] = []
    skipped: Counter = Counter()
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        marks = [dec for dec in node.decorator_list if isinstance(dec, ast.Call) and _decorator_name(dec) == "parametrize"]
        if len(marks) != 1 or len(marks[0].args) < 2 or not isinstance(marks[0].args[1], (ast.List, ast.Tuple)):
            continue
        try:
            argnames = _literal(marks[0].args[0], names)
        except _Unresolved:
            argnames = None
        if isinstance(argnames, str):
            argnames = [name.strip() for name in argnames.split(",") if name.strip()]
        elif not (isinstance(argnames, tuple) and all(isinstance(name, str) for name in argnames)):
            skipped["unreadable argument names"] += len(marks[0].args[1].elts)
            continue
        argnames = list(argnames)
        reason = _function_skip(node, filename, argnames, fixtures)
        if reason is not None:
            skipped[reason] += len(marks[0].args[1].elts)
            continue
        for index, element in enumerate(marks[0].args[1].elts):
            test = f"{filename}::{node.name}[{index}]"
            if not isinstance(element, ast.Tuple) or len(element.elts) != len(argnames):
                skipped["case is not a plain tuple"] += 1
                continue
            values = dict(zip(argnames, element.elts))
            try:
                text = _literal(values[argnames[0]], names)
                if "expected_start" in values:
                    positions = [(_literal(values["expected_start"], names), _literal(values["expected_end"], names))]
                else:
                    position = next((values[name] for name in TEST_POSITION_ARGS if name in values), None)
                    positions = _spans(_literal(position, names)) if position is not None else None
                expected = _literal(values["expected_len"], names) if "expected_len" in values else len(positions)
                entities = _literal(values["entities"], names) if "entities" in values else None
            except _Unresolved:
                skipped["value is not a literal"] += 1
                continue
            if not isinstance(text, str) or not text.strip() or isinstance(expected, bool) or not isinstance(expected, int):
                skipped["value is not a literal"] += 1
                continue
            if "entities" not in values:
                entities = fixtures["entities"] * max(expected, 1)  # one-entity fixture, see _function_skip
            if not isinstance(entities, tuple) or not all(isinstance(name, str) for name in entities):
                skipped["value is not a literal"] += 1
                continue
            if expected == 0:
                if len(set(entities)) != 1:
                    skipped["negative without a single entity"] += 1
                    continue
                cases.append(RecognizerCase(test, text, (), (entities[0],)))
                continue
            if positions is None and expected == 1 and WHOLE_VALUE.match(text):
                positions = [(0, len(text))]  # the text is the bare value, e.g. ("BO12345678A", 1)
            if positions is None:
                skipped["positive without spans"] += 1
                continue
            if len(positions) != expected or len(entities) != expected:
                skipped["spans do not match the expected count"] += 1
                continue
            if not all(
                isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text)
                for start, end in positions
            ):
                skipped["span outside the text"] += 1
                continue
            spans = tuple((entity, start, end) for entity, (start, end) in zip(entities, positions))
            cases.append(RecognizerCase(test, text, spans, tuple(sorted(set(entities)))))
    return cases, skipped


def recognizer_test_language(filename: str) -> str:
    prefix = filename.removeprefix("test_").split("_", 1)[0]
    return TEST_LANGUAGES.get(prefix, "en")


def load_recognizer_tests(root: Path, corpus: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per recognizer test case whose entities have a benchmark id.

    A row is scored only on the ids its recognizer asserts on (``scored_entities``); a negative
    case (the recognizer must find nothing) is one hard-negative span over the whole text for
    those ids. Repeated cases are kept once; a text that is positive in one test and negative
    or differently annotated in another for the same ids is dropped."""
    label_map = corpus["label_map"]
    selected: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    conflicting: set[tuple[str, tuple[str, ...]]] = set()
    for entry in corpus["verified_files"]:
        filename = entry["path"]
        cases, _ = recognizer_test_cases((root / filename).read_text(encoding="utf-8"), filename)
        for case in cases:
            ids = [label_map.get(entity) for entity in case.entities]
            if None in ids or any(label_map.get(entity) is None for entity, _, _ in case.spans):
                continue
            scored = tuple(sorted(set(ids)))
            entities = sorted(
                {(label_map[entity], start, end) for entity, start, end in case.spans}, key=lambda item: (item[1], item[2], item[0])
            )
            row = {
                "id": case.test.replace(".py::", ":").replace("[", ":").rstrip("]"),
                "group_id": "text:" + _sha256(case.text.encode("utf-8")),
                "corpus": corpus["id"],
                "language": recognizer_test_language(filename),
                "text": case.text,
                "entities": [{"entity_type": label, "start": start, "end": end} for label, start, end in entities],
                "scored_entities": list(scored),
                "source_test": case.test,
            }
            if not entities:
                row["hard_negatives"] = [
                    {"start": 0, "end": len(case.text), "kind": "presidio_recognizer_negative", "entity_type": label}
                    for label in scored
                ]
            key = (case.text, scored)
            previous = selected.get(key)
            if previous is None:
                selected[key] = row
            elif previous["entities"] != row["entities"]:
                conflicting.add(key)
    rows = [row for key, row in selected.items() if key not in conflicting]
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError(f"{corpus['id']}: duplicate row ids")
    return rows


# ── split ────────────────────────────────────────────────────────────────────


def split_of(corpus_id: str, group_id: str, seed: str = SPLIT_SEED, fraction: float = HOLDOUT_FRACTION) -> str:
    digest = hashlib.sha256(f"{seed}:{corpus_id}:{group_id}".encode("utf-8")).digest()
    return "holdout" if int.from_bytes(digest[:8], "big") < fraction * 2**64 else "dev"


def _jsonl(rows: list[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows).encode("utf-8")


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_splits(
    corpora: dict[str, tuple[dict[str, Any], list[dict[str, Any]]]], seed: str, fraction: float, family: str = "neutral"
) -> dict[str, dict[str, bytes]]:
    """``{split: {file name: content}}`` including ``manifest.json`` and ``.ready``."""
    outputs: dict[str, dict[str, bytes]] = {}
    for split in SPLITS:
        files: dict[str, bytes] = {}
        entries = []
        for corpus_id, (corpus, rows) in corpora.items():
            selected = [row for row in rows if split_of(corpus_id, row["group_id"], seed, fraction) == split]
            name = f"{corpus_id}.jsonl"
            files[name] = _jsonl(selected)
            entries.append(
                {
                    "id": corpus_id,
                    "source": corpus["source"],
                    "revision": corpus["revision"],
                    "license": corpus["license"],
                    "sources": [
                        {"path": source.path, "url": source.url, "sha256": source.sha256}
                        for source in source_files(corpus)
                    ],
                    "file": name,
                    "sha256": _sha256(files[name]),
                    "bytes": len(files[name]),
                    "rows": len(selected),
                    "groups": len({row["group_id"] for row in selected}),
                    "languages": dict(sorted(Counter(row["language"] for row in selected).items())),
                    "entities": dict(
                        sorted(Counter(entity["entity_type"] for row in selected for entity in row["entities"]).items())
                    ),
                }
            )
        manifest = {
            "schema": SCHEMA,
            "split": split,
            "seed": seed,
            "holdout_fraction": fraction,
            "grouping": f"holdout iff sha256(seed:corpus:group_id)[:8] < fraction * 2^64; {FAMILIES[family].grouping}",
            "corpora": entries,
        }
        if family != "neutral":
            manifest["family"] = family
        manifest = _manifest_bytes(manifest)
        files["manifest.json"] = manifest
        files[READY] = f"{_sha256(manifest)}  manifest.json\n".encode("utf-8")
        outputs[split] = files
    return outputs


def check_split(directory: Path) -> list[str]:
    """Problems of a written split directory (empty list: ready and intact)."""
    ready, manifest_path = directory / READY, directory / "manifest.json"
    if not ready.is_file() or not manifest_path.is_file():
        return [f"{directory}: no {READY} or manifest.json"]
    manifest_bytes = manifest_path.read_bytes()
    problems = []
    if ready.read_text(encoding="utf-8") != f"{_sha256(manifest_bytes)}  manifest.json\n":
        problems.append(f"{directory}: {READY} does not match manifest.json")
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        return problems + [f"{directory}: manifest.json is not JSON"]
    if manifest.get("schema") != SCHEMA:
        problems.append(f"{directory}: manifest schema is not {SCHEMA}")
    for corpus in manifest.get("corpora", []):
        path = directory / corpus["file"]
        if not path.is_file():
            problems.append(f"{path} is missing")
        elif _sha256(path.read_bytes()) != corpus["sha256"]:
            problems.append(f"{path} does not match its SHA-256 in manifest.json")
    return problems


def _write(directory: Path, files: dict[str, bytes]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / READY).unlink(missing_ok=True)
    for stale in directory.glob("*.jsonl"):
        if stale.name not in files:
            stale.unlink()
    for name in [*sorted(name for name in files if name not in ("manifest.json", READY)), "manifest.json", READY]:
        partial = directory / f"{name}.part"
        partial.write_bytes(files[name])
        os.replace(partial, directory / name)


def default_source_dir(holdout_out: Path) -> Path:
    return holdout_out / ".sources"


def prepare(
    dev_out: Path,
    holdout_out: Path,
    source_dir: Path | None = None,
    manifest_path: Path = MANIFEST_PATH,
    offline: bool = False,
    force: bool = False,
    seed: str = SPLIT_SEED,
    fraction: float = HOLDOUT_FRACTION,
    fetch: Callable[[str], bytes] = download,
    family: str = "neutral",
) -> int:
    """Write both splits of one source family; 0 on success or an unchanged frozen split, 1 on any problem."""
    source_dir = default_source_dir(holdout_out) if source_dir is None else source_dir
    dev, holdout, sources = (path.resolve() for path in (dev_out, holdout_out, source_dir))
    try:
        if dev == holdout or dev.is_relative_to(holdout) or holdout.is_relative_to(dev):
            raise ValueError("--dev-out and --holdout-out must be separate, non-nested directories")
        if sources.is_relative_to(dev):
            raise ValueError("--sources must not be inside --dev-out: raw sources contain holdout text")
        manifest = load_manifest(manifest_path)
        corpora = {}
        for corpus_id in FAMILIES[family].corpora:
            corpus = manifest[corpus_id]
            input_path = fetch_sources(corpus, sources, offline, fetch)
            corpora[corpus_id] = (corpus, load_corpus(corpus, input_path, manifest_path))
        outputs = build_splits(corpora, seed, fraction, family)
    except (ValueError, OSError, KeyError, SyntaxError) as error:
        print(f"prepare_corpora: {error}", file=sys.stderr)
        return 1

    pending = {}
    for split, directory in (("dev", dev), ("holdout", holdout)):
        if (directory / READY).exists():
            unchanged = not check_split(directory) and (directory / "manifest.json").read_bytes() == outputs[split][
                "manifest.json"
            ]
            if unchanged:
                continue
            if not force:
                print(
                    f"prepare_corpora: {split} split in {directory} is frozen and differs from this run "
                    "(or was modified); nothing written. Use --force to replace it.",
                    file=sys.stderr,
                )
                return 1
        pending[split] = directory
    for split, directory in pending.items():
        _write(directory, outputs[split])

    dev_manifest = json.loads(outputs["dev"]["manifest.json"])
    for corpus in dev_manifest["corpora"]:
        print(f"dev {corpus['id']}: {corpus['rows']} rows, {corpus['groups']} groups")
    for split, directory in (("dev", dev), ("holdout", holdout)):
        state = "written" if split in pending else "unchanged (frozen)"
        digest = _sha256(outputs[split]["manifest.json"])
        print(f"{split}: {state} in {directory}, manifest sha256 {digest}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dev-out", type=Path, help="dev split directory (visible to agents)")
    parser.add_argument("--holdout-out", type=Path, help="holdout split directory (gate only)")
    parser.add_argument("--sources", type=Path, help="raw source cache (default: HOLDOUT/.sources)")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH, help="external PII corpus manifest")
    parser.add_argument("--offline", action="store_true", help="never download; sources must be cached")
    parser.add_argument("--force", action="store_true", help="replace a frozen split that differs")
    parser.add_argument("--check", type=Path, metavar="DIR", help="only verify a written split directory")
    parser.add_argument(
        "--family", choices=sorted(FAMILIES), default="neutral",
        help="source family to split (default: neutral = Gretel Finance, OpenPII Nano, TAB)",
    )
    args = parser.parse_args(argv)
    if args.check is not None:
        problems = check_split(args.check)
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(f"{args.check}: split ok")
        return 1 if problems else 0
    if args.dev_out is None or args.holdout_out is None:
        parser.error("--dev-out and --holdout-out are required (or use --check DIR)")
    return prepare(
        args.dev_out,
        args.holdout_out,
        args.sources,
        manifest_path=args.manifest,
        offline=args.offline,
        force=args.force,
        family=args.family,
    )


if __name__ == "__main__":
    sys.exit(main())
