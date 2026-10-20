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
the scored modes (K02; the sidecar then records ``engine.pii_mode``). The metadata sidecar records input and output digests and the SHA-256
of the native module but no timestamps, so a rerun on the same build is
byte-identical.

Run it with the Ark environment (``maturin develop`` into ``.venv``):

    .venv/bin/python scripts/l1_presidio/run_ark.py --input gold.jsonl --output ark.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable

from patronus_ark.external_pii_eval import ARK_OUTPUT_MAP, read_jsonl


SCHEMA = "ark-l1-predictions-v1"
CATEGORY = "pii"
MAX_LEVEL = "l1"
PII_MODES = ("strict", "balanced", "recall")
DEFAULT_PII_MODE = "strict"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def benchmark_label(ark_label: str) -> str:
    return ARK_OUTPUT_MAP.get(ark_label, f"ark.{ark_label}")


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


def _evidence_span(span: dict[str, Any], text: str, row_id: str) -> dict[str, Any]:
    start, end = span.get("start_char"), span.get("end_char")
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end > len(text):
        raise ValueError(f"Ark span outside text for {row_id!r}: {start}..{end}")
    if "text" in span and text[start:end] != span["text"]:
        raise ValueError(f"Ark span text does not match code-point offsets for {row_id!r}: {start}..{end}")
    score = span.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError(f"Ark span for {row_id!r} has no numeric score")
    ark_label = str(span.get("label", ""))
    return {
        "label": benchmark_label(ark_label),
        "ark_label": ark_label,
        "start_char": start,
        "end_char": end,
        "score": round(float(score), 6),
    }


def predict_rows(rows: Iterable[dict[str, Any]], gateway: Any) -> Iterable[dict[str, Any]]:
    """Yield one prediction row per Gold row, in input order."""
    seen = set()
    for row in rows:
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id or row_id in seen:
            raise ValueError("every input row requires a unique non-empty id")
        seen.add(row_id)
        text = row.get("text")
        if not isinstance(text, str):
            raise ValueError(f"row {row_id!r} requires text")
        # Several rules may report the same span; keep it once with its best score.
        best: dict[tuple[str, int, int], dict[str, Any]] = {}
        for result in gateway.scan_category(CATEGORY, text):
            for raw in result.get("evidence_spans", []):
                item = _evidence_span(raw, text, row_id)
                key = (item["ark_label"], item["start_char"], item["end_char"])
                if key not in best or item["score"] > best[key]["score"]:
                    best[key] = item
        spans = sorted(best.values(), key=lambda s: (s["start_char"], s["end_char"], s["ark_label"]))
        yield {
            "id": row_id,
            "language": str(row.get("language", "und")),
            "evidence_spans": spans,
        }


def run(
    input_path: Path,
    output_path: Path,
    meta_path: Path,
    gateway: Any = None,
    build: dict[str, str] | None = None,
    pii_mode: str = DEFAULT_PII_MODE,
) -> dict[str, Any]:
    """Write predictions plus a timestamp-free metadata sidecar; return the metadata."""
    _check_pii_mode(pii_mode)
    if gateway is None:
        gateway = build_gateway(pii_mode)
    if build is None:
        build = build_info()
    source = input_path.read_bytes()
    predictions = list(predict_rows(read_jsonl(input_path), gateway))
    encoded = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in predictions
    ).encode("utf-8")
    output_path.write_bytes(encoded)
    engine: dict[str, Any] = {"categories": [CATEGORY], "max_level": MAX_LEVEL}
    if pii_mode != DEFAULT_PII_MODE:
        engine["pii_mode"] = pii_mode
    meta = {
        "schema": SCHEMA,
        "engine": engine,
        "input_sha256": sha256_bytes(source),
        "output_sha256": sha256_bytes(encoded),
        "rows": len(predictions),
        "spans": sum(len(row["evidence_spans"]) for row in predictions),
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
    args = parser.parse_args(argv)
    meta_path = args.meta or args.output.with_name(args.output.stem + ".meta.json")
    meta = run(args.input, args.output, meta_path, pii_mode=args.pii_mode)
    print(
        f"ark l1: {meta['rows']} rows, {meta['spans']} spans -> {args.output} "
        f"(sha256 {meta['output_sha256'][:12]})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
