#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run Ark PII-L1 through the Python bindings and write predictions like run_presidio.py.

The input is the normalized JSONL from ``patronus_ark.external_pii_eval normalize``
(``id``, ``language``, ``text``). Each output row carries ``id``, ``language`` and
``evidence_spans`` with the benchmark label, Ark's own label, code-point
``start_char``/``end_char`` and the span ``score``, i.e. the same row and span shape
as the Presidio baseline, so ``external_pii_eval evaluate --predictions`` and later
comparisons treat both engines alike. Ark labels without a benchmark id are
namespaced as ``ark.<LABEL>`` and are therefore never scored by accident.

The engine is ``SecurityGateway(categories=["pii"], max_level="l1")`` without model
downloads, in the default PII mode ``strict`` unless ``--pii-mode balanced|recall`` asks for
the scored modes (K02; the sidecar then records ``engine.pii_mode``). Only primary findings
are written: a span the result lists under ``details.secondary_evidence`` (in ``strict`` the
card-shaped part of a valid IBAN and an account finding on an IBAN value, T07) is dropped
and counted as ``secondary_spans`` in the sidecar. The metadata sidecar records input and output digests and the SHA-256
of the native module but no timestamps, so a rerun on the same build is
byte-identical.

``--dynamic-pii`` adds Ark's L3 ``dynamic-pii`` pipeline (GLiNER) next to L1: a second gateway
``SecurityGateway(categories=["dynamic-pii"], max_level="l3", download_files=True)`` with the
given labels and thresholds (``--dynamic-pii-labels``, ``--dynamic-pii-threshold``,
``--dynamic-pii-label-threshold LABEL=X``) scans every row after L1. Its spans carry
``dynamic_pii_label`` and the benchmark id from ``dynamic_pii`` in entity_map.yaml (unmapped labels
are rejected); the sidecar records the configuration and the machine under ``engine.dynamic_pii``,
because the GLiNER asset's scores depend on the CPU's integer matmul kernels.

``--latency PATH`` writes the wall time of every row (L1, plus L3 with ``--dynamic-pii``) in
nanoseconds per language to a separate JSON file, so the predictions and the sidecar stay
byte-identical; ``scoreboard.py ner`` reads it as ``<output stem>.latency.json``.

Run it with the Ark environment (``maturin develop`` into ``.venv``):

    .venv/bin/python scripts/l1_presidio/run_ark.py --input gold.jsonl --output ark.jsonl
    .venv/bin/python scripts/l1_presidio/run_ark.py --input gold.jsonl --output ark-ner.jsonl \\
        --dynamic-pii --latency ark-ner.latency.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from collections import Counter, defaultdict
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable

from patronus_ark.external_pii_eval import ARK_OUTPUT_MAP, read_jsonl


HERE = Path(__file__).resolve().parent
SCHEMA = "ark-l1-predictions-v1"
CATEGORY = "pii"
MAX_LEVEL = "l1"
PII_MODES = ("strict", "balanced", "recall")
DEFAULT_PII_MODE = "strict"
DYNAMIC_CATEGORY = "dynamic-pii"
DYNAMIC_MAX_LEVEL = "l3"
DEFAULT_DYNAMIC_LABELS = ("person", "organization", "location")
DEFAULT_DYNAMIC_THRESHOLD = 0.5


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def benchmark_label(ark_label: str) -> str:
    return ARK_OUTPUT_MAP.get(ark_label, f"ark.{ark_label}")


def _sibling(name: str) -> Any:
    """A module next to this script (entity_map needs PyYAML, so it is imported on demand)."""
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    return __import__(name)


def dynamic_label_map() -> dict[str, str]:
    """dynamic-pii label -> benchmark id from entity_map.yaml."""
    return _sibling("entity_map").load().dynamic_pii_labels()


def dynamic_config(labels: Iterable[str], threshold: float, label_thresholds: dict[str, float],
                   label_map: dict[str, str]) -> dict[str, Any]:
    """The ``dynamic_pii_config`` of the benchmark engine; every label must map to a benchmark id."""
    labels = list(labels)
    unmapped = [label for label in labels if label not in label_map]
    if not labels or unmapped:
        raise ValueError("dynamic-pii labels need a benchmark id (dynamic_pii in entity_map.yaml): "
                         f"{unmapped or 'none given'}")
    unknown = sorted(set(label_thresholds) - set(labels))
    if unknown:
        raise ValueError(f"dynamic-pii label thresholds for labels that are not configured: {unknown}")
    return {
        "labels": labels,
        "threshold": threshold,
        "label_thresholds": dict(sorted(label_thresholds.items())),
        "execution_gate": {"type": "always"},
        "conditional_labels": [],
    }


def build_dynamic_gateway(config: dict[str, Any]) -> Any:
    """Create and warm up the L3 dynamic-pii gateway (downloads the GLiNER asset if missing)."""
    from patronus_ark import SecurityGateway

    gateway = SecurityGateway(categories=[DYNAMIC_CATEGORY], max_level=DYNAMIC_MAX_LEVEL, download_files=True,
                              dynamic_pii_config=config)
    gateway.warmup()
    return gateway


def _check_pii_mode(pii_mode: str) -> None:
    if pii_mode not in PII_MODES:
        raise ValueError(f"pii_mode must be one of {', '.join(PII_MODES)}, got {pii_mode!r}")


def build_gateway(pii_mode: str = DEFAULT_PII_MODE) -> Any:
    """Create the L1 PII gateway (imports the native binding lazily)."""
    from patronus_ark import SecurityGateway

    _check_pii_mode(pii_mode)
    gateway = SecurityGateway(categories=[CATEGORY], max_level=MAX_LEVEL, download_files=False)
    if pii_mode != DEFAULT_PII_MODE:
        gateway.set_execution_gates({"pii_mode": pii_mode})
    return gateway


def build_info() -> dict[str, str]:
    """Identify the Ark build that produced the predictions."""
    from patronus_ark import _patronus_ark

    try:
        version = metadata.version("patronus-ark")
    except metadata.PackageNotFoundError:
        version = "none"
    return {
        "native_sha256": sha256_bytes(Path(_patronus_ark.__file__).read_bytes()),
        "package_version": version,
    }


def _evidence_span(span: dict[str, Any], text: str, row_id: str,
                   dynamic_labels: dict[str, str] | None = None) -> dict[str, Any]:
    """One output span; with ``dynamic_labels`` a dynamic-pii span (``dynamic_pii_label``)."""
    start, end = span.get("start_char"), span.get("end_char")
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end > len(text):
        raise ValueError(f"Ark span outside text for {row_id!r}: {start}..{end}")
    if "text" in span and text[start:end] != span["text"]:
        raise ValueError(f"Ark span text does not match code-point offsets for {row_id!r}: {start}..{end}")
    score = span.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError(f"Ark span for {row_id!r} has no numeric score")
    native_label = str(span.get("label", ""))
    if dynamic_labels is None:
        labels = {"label": benchmark_label(native_label), "ark_label": native_label}
    else:
        labels = {"label": dynamic_labels.get(native_label, f"dynamic-pii.{native_label}"),
                  "dynamic_pii_label": native_label}
    return {**labels, "start_char": start, "end_char": end, "score": round(float(score), 6)}


def _native_label(span: dict[str, Any]) -> str:
    return span.get("ark_label", span.get("dynamic_pii_label", ""))


def secondary_evidence(result: dict[str, Any]) -> set[tuple[str, int, int]]:
    """``(label, start_byte, end_byte)`` of the spans a result marks as secondary evidence (T07)."""
    return {
        (str(entry.get("label", "")), entry.get("start_byte"), entry.get("end_byte"))
        for layer in result.get("layers", [])
        for entry in (layer.get("details") or {}).get("secondary_evidence", [])
    }


def predict_rows(
    rows: Iterable[dict[str, Any]], gateway: Any, counts: Counter | None = None, dynamic: Any = None,
    dynamic_labels: dict[str, str] | None = None, timings: dict[str, list[int]] | None = None,
) -> Iterable[dict[str, Any]]:
    """Yield one prediction row per Gold row, in input order; count dropped secondary spans.

    ``dynamic`` (a dynamic-pii gateway, with ``dynamic_labels``) scans every row after L1;
    ``timings`` collects the wall time of each row in nanoseconds per language."""
    seen = set()
    for row in rows:
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id or row_id in seen:
            raise ValueError("every input row requires a unique non-empty id")
        seen.add(row_id)
        text = row.get("text")
        if not isinstance(text, str):
            raise ValueError(f"row {row_id!r} requires text")
        language = str(row.get("language", "und"))
        started = time.perf_counter_ns()
        scans = [(result, None) for result in gateway.scan_category(CATEGORY, text)]
        if dynamic is not None:
            scans += [(result, dynamic_labels or {}) for result in dynamic.scan_category(DYNAMIC_CATEGORY, text)]
        if timings is not None:
            timings[language].append(time.perf_counter_ns() - started)
        # Several rules may report the same span; keep it once with its best score.
        best: dict[tuple[str, str, int, int], dict[str, Any]] = {}
        for result, labels in scans:
            secondary = secondary_evidence(result)
            for raw in result.get("evidence_spans", []):
                if (raw.get("label"), raw.get("start_byte"), raw.get("end_byte")) in secondary:
                    if counts is not None:
                        counts["secondary_spans"] += 1
                    continue
                item = _evidence_span(raw, text, row_id, labels)
                key = (result.get("category", CATEGORY), _native_label(item), item["start_char"], item["end_char"])
                if key not in best or item["score"] > best[key]["score"]:
                    best[key] = item
        spans = sorted(best.values(), key=lambda s: (s["start_char"], s["end_char"], _native_label(s)))
        yield {
            "id": row_id,
            "language": language,
            "evidence_spans": spans,
        }


def run(
    input_path: Path,
    output_path: Path,
    meta_path: Path,
    gateway: Any = None,
    build: dict[str, str] | None = None,
    pii_mode: str = DEFAULT_PII_MODE,
    dynamic_pii: dict[str, Any] | None = None,
    dynamic: Any = None,
    dynamic_labels: dict[str, str] | None = None,
    latency_path: Path | None = None,
) -> dict[str, Any]:
    """Write predictions plus a timestamp-free metadata sidecar; return the metadata.

    ``dynamic_pii`` (a ``dynamic_config`` checked against ``dynamic_labels``) adds the L3 dynamic-pii
    engine; ``latency_path`` writes the per-row wall times (``latency.write_row_latency``)."""
    _check_pii_mode(pii_mode)
    if gateway is None:
        gateway = build_gateway(pii_mode)
    if dynamic_pii is not None:
        if dynamic_labels is None:
            dynamic_labels = dynamic_label_map()
        if dynamic is None:
            dynamic = build_dynamic_gateway(dynamic_pii)
    if build is None:
        build = build_info()
    source = input_path.read_bytes()
    counts: Counter = Counter()
    timings: dict[str, list[int]] | None = defaultdict(list) if latency_path is not None else None
    predictions = list(predict_rows(read_jsonl(input_path), gateway, counts,
                                    dynamic if dynamic_pii is not None else None, dynamic_labels, timings))
    encoded = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in predictions
    ).encode("utf-8")
    output_path.write_bytes(encoded)
    engine: dict[str, Any] = {"categories": [CATEGORY], "max_level": MAX_LEVEL}
    if pii_mode != DEFAULT_PII_MODE:
        engine["pii_mode"] = pii_mode
    if dynamic_pii is not None:
        engine["categories"].append(DYNAMIC_CATEGORY)
        engine["max_level"] = DYNAMIC_MAX_LEVEL
        engine["dynamic_pii"] = {
            "labels": dynamic_pii["labels"],
            "threshold": dynamic_pii["threshold"],
            "label_thresholds": dynamic_pii["label_thresholds"],
            "label_map": {label: dynamic_labels[label] for label in dynamic_pii["labels"]},
            "machine": platform.machine(),
        }
    if timings is not None:
        _sibling("latency").write_row_latency(latency_path, engine, timings)
    meta = {
        "schema": SCHEMA,
        "engine": engine,
        "input_sha256": sha256_bytes(source),
        "output_sha256": sha256_bytes(encoded),
        "rows": len(predictions),
        "spans": sum(len(row["evidence_spans"]) for row in predictions),
        "secondary_spans": counts["secondary_spans"],
        "languages": dict(sorted(Counter(row["language"] for row in predictions).items())),
        "label_map": ARK_OUTPUT_MAP,
        "build": build,
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True, help="normalized Gold JSONL")
    parser.add_argument("--output", type=Path, required=True, help="prediction JSONL")
    parser.add_argument("--meta", type=Path, help="metadata JSON (default: OUTPUT with .meta.json)")
    parser.add_argument(
        "--pii-mode", choices=PII_MODES, default=DEFAULT_PII_MODE, help="PII output mode (default: strict)"
    )
    parser.add_argument("--dynamic-pii", action="store_true", help="add the L3 dynamic-pii pipeline (GLiNER)")
    parser.add_argument("--dynamic-pii-labels", default=",".join(DEFAULT_DYNAMIC_LABELS),
                        help="comma-separated GLiNER labels (default: %(default)s)")
    parser.add_argument("--dynamic-pii-threshold", type=float, default=DEFAULT_DYNAMIC_THRESHOLD,
                        help="GLiNER score threshold (default: %(default)s)")
    parser.add_argument("--dynamic-pii-label-threshold", action="append", default=[], metavar="LABEL=X",
                        help="threshold of one label (repeatable)")
    parser.add_argument("--latency", type=Path, help="per-row wall times in nanoseconds per language (JSON)")
    args = parser.parse_args(argv)
    dynamic_pii = None
    if args.dynamic_pii:
        label_thresholds: dict[str, float] = {}
        for item in args.dynamic_pii_label_threshold:
            label, sep, value = item.partition("=")
            try:
                threshold = float(value)
            except ValueError:
                threshold = None
            if not sep or not label or label in label_thresholds or threshold is None:
                parser.error(f"--dynamic-pii-label-threshold {item!r}: expected a unique LABEL=X")
            label_thresholds[label] = threshold
        labels = [label.strip() for label in args.dynamic_pii_labels.split(",") if label.strip()]
        dynamic_labels = dynamic_label_map()
        try:
            dynamic_pii = dynamic_config(labels, args.dynamic_pii_threshold, label_thresholds, dynamic_labels)
        except ValueError as error:
            parser.error(str(error))
    elif args.dynamic_pii_label_threshold:
        parser.error("--dynamic-pii-label-threshold needs --dynamic-pii")
    meta_path = args.meta or args.output.with_name(args.output.stem + ".meta.json")
    meta = run(args.input, args.output, meta_path, pii_mode=args.pii_mode, dynamic_pii=dynamic_pii,
               dynamic_labels=dynamic_labels if dynamic_pii else None, latency_path=args.latency)
    print(
        f"ark {meta['engine']['max_level']}: {meta['rows']} rows, {meta['spans']} spans -> {args.output} "
        f"(sha256 {meta['output_sha256'][:12]})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
