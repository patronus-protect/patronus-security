#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run ARK L1-DLP through the Python bindings; write the baseline prediction format.

Input is the same JSONL as for ``run_baselines.py`` (``id`` and ``text``: DLP goldens,
carrier rows, benign-code or benign-document corpora). Every row is scanned with
``SecurityGateway(categories=["dlp"], max_level="l1")`` in the default rule profile
(content and document classes stay off unless enabled with ``--enable-rule``).

Each output row carries ``id``, ``tool`` (``ark``) and ``evidence_spans`` with the fields
of the baseline runner: code-point ``start_char``/``end_char``, ``rule_id`` (the ``dlp_*``
rule), ``label`` (``ark.<rule_id>``), ``entities``/``groups`` from
``research/dlp/entity_map.yaml`` and ``normalization`` (always empty: ARK spans are
already value spans). ARK adds ``group`` (the engine's entity group, i.e. the span
label) and ``score``. ``--dlp-mode balanced|recall`` scans in a scored DLP mode (K04):
``score`` is then the model score and spans below the mode's threshold are dropped; the
default ``strict`` scores every span 1.0. No secret text is written. ``<output>.meta.json`` records the
engine profile, the SHA-256 of the native module, entity-map and I/O digests and
counters, without timestamps; a rerun on the same build is byte-identical.

Run it with the ARK environment (``maturin develop`` into ``.venv``):

    .venv/bin/python scripts/l1_dlp/run_ark.py --input rows.jsonl --output ark.jsonl
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
SCHEMA = "ark-l1-dlp-predictions-v1"
TOOL = "ark"
CATEGORY = "dlp"
MAX_LEVEL = "l1"
DLP_MODES = ("strict", "balanced", "recall")


def _load_baselines():
    """``run_baselines.py`` as a module (shared input, entity map and digest helpers)."""
    name = "l1_dlp_run_baselines"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / "run_baselines.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


baselines = _load_baselines()
ENTITY_MAP_PATH = baselines.ENTITY_MAP_PATH
sha256_bytes = baselines.sha256_bytes


def load_rule_index(path: Path = ENTITY_MAP_PATH) -> dict[str, tuple[list[str], list[str]]]:
    """``{dlp rule id: (entity ids, groups)}`` from the ``ark`` field of entity_map.yaml."""
    return baselines.load_entity_index(path, {TOOL: "ark"})[TOOL]


def execution_gates(
    enabled_rules: Iterable[str], index: dict[str, Any], mode: str = "strict"
) -> dict[str, Any] | None:
    """Gates that switch on ``enabled_rules`` and the DLP ``mode`` on top of the default
    profile, or None for the default profile itself."""
    rules = sorted(set(enabled_rules))
    unknown = [rule for rule in rules if rule not in index]
    if unknown:
        raise ValueError(f"unknown ARK DLP rule(s): {', '.join(unknown)}")
    if mode not in DLP_MODES:
        raise ValueError(f"unknown dlp_mode {mode!r}; expected one of {', '.join(DLP_MODES)}")
    gates: dict[str, Any] = {"rules": {rule: True for rule in rules}} if rules else {}
    if mode != "strict":
        gates["dlp_mode"] = mode
    return gates or None


def build_gateway(
    enabled_rules: Iterable[str] = (), index: dict[str, Any] | None = None, mode: str = "strict"
) -> Any:
    """Create the L1 DLP gateway (imports the native binding lazily)."""
    from patronus_ark import SecurityGateway

    gates = execution_gates(enabled_rules, load_rule_index() if index is None else index, mode)
    return SecurityGateway(
        categories=[CATEGORY], max_level=MAX_LEVEL, download_files=False, execution_gates=gates
    )


def build_info() -> dict[str, str]:
    """Identify the ARK build that produced the predictions."""
    from patronus_ark import _patronus_ark

    try:
        version = metadata.version("patronus-ark")
    except metadata.PackageNotFoundError:
        version = "none"
    return {
        "native_sha256": sha256_bytes(Path(_patronus_ark.__file__).read_bytes()),
        "package_version": version,
    }


def _checked_span(span: dict[str, Any], text: str, row_id: str) -> tuple[int, int, float]:
    start, end = span.get("start_char"), span.get("end_char")
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end > len(text):
        raise ValueError(f"ARK span outside text for {row_id!r}: {start}..{end}")
    if "text" in span and text[start:end] != span["text"]:
        raise ValueError(f"ARK span text does not match code-point offsets for {row_id!r}: {start}..{end}")
    score = span.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError(f"ARK span for {row_id!r} has no numeric score")
    return start, end, round(float(score), 6)


def _matched_rules(result: dict[str, Any]) -> list[tuple[int, int, str]]:
    """``(start_byte, end_byte, rule_id)`` of every rule match the scanner reported."""
    found = []
    for layer in result.get("layers") or []:
        for item in (layer.get("details") or {}).get("matched_rules") or []:
            found.append((int(item["start_byte"]), int(item["end_byte"]), str(item["rule_id"])))
    return found


def attribute(
    span: dict[str, Any], rules: list[tuple[int, int, str]], index: dict[str, Any], row_id: str
) -> str:
    """The rule that produced ``span``: a match on the same byte range in the same result.

    Several rules can match one range (cross-label overlaps, or a later rule the engine
    dropped as an overlap). The span label is the engine's entity group, so the first
    match whose mapped group is that label wins; the engine keeps the first match per
    group, in rule order. Without such a rule (unmapped or stale map) the first match wins.
    """
    label = str(span.get("label", ""))
    candidates = [rule for start, end, rule in rules if (start, end) == (span.get("start_byte"), span.get("end_byte"))]
    if not candidates:
        raise ValueError(
            f"ARK span {label} at {span.get('start_char')}..{span.get('end_char')} in {row_id!r} has no matched rule"
        )
    for rule in candidates:
        if label in index.get(rule, ([], []))[1]:
            return rule
    return candidates[0]


def predict_rows(
    rows: Iterable[dict[str, Any]], gateway: Any, index: dict[str, tuple[list[str], list[str]]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """One prediction row per input row, in input order, and counters for the sidecar."""
    stats: dict[str, Counter] = {
        "findings": Counter(), "groups": Counter(), "unmapped": Counter(), "group_mismatch": Counter(),
    }
    predictions, seen = [], set()
    for row in rows:
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id or row_id in seen:
            raise ValueError("every input row requires a unique non-empty id")
        seen.add(row_id)
        text = row.get("text")
        if not isinstance(text, str):
            raise ValueError(f"row {row_id!r} requires text")
        # Several spans may share range and rule; keep each once with its best score.
        best: dict[tuple[int, int, str], dict[str, Any]] = {}
        for result in gateway.scan_category(CATEGORY, text):
            if result.get("class_name") == "error" or any(
                layer.get("layer_type") == "scanner_error" for layer in result.get("layers") or []
            ):
                raise RuntimeError(f"ARK scanner {result.get('model')} failed on {row_id!r}")
            rules = _matched_rules(result)
            for raw in result.get("evidence_spans") or []:
                start, end, score = _checked_span(raw, text, row_id)
                rule_id = attribute(raw, rules, index, row_id)
                key = (start, end, rule_id)
                if key in best:
                    best[key]["score"] = max(best[key]["score"], score)
                    continue
                entities, groups = index.get(rule_id, ([], []))
                best[key] = {
                    "start_char": start,
                    "end_char": end,
                    "rule_id": rule_id,
                    "label": f"{TOOL}.{rule_id}",
                    "group": str(raw.get("label", "")),
                    "entities": list(entities),
                    "groups": list(groups),
                    "score": score,
                    "normalization": [],
                }
        spans = [best[key] for key in sorted(best)]
        for item in spans:
            stats["findings"][item["rule_id"]] += 1
            stats["groups"][item["group"]] += 1
            if not item["entities"]:
                stats["unmapped"][item["rule_id"]] += 1
            elif item["groups"] and item["group"] not in item["groups"]:
                stats["group_mismatch"][f"{item['rule_id']}:{item['group']}"] += 1
        predictions.append({"id": row_id, "tool": TOOL, "evidence_spans": spans})
    summary = {name: dict(sorted(counter.items())) for name, counter in stats.items()}
    return predictions, summary


def run(
    input_path: Path,
    output_path: Path,
    meta_path: Path,
    gateway: Any = None,
    build: dict[str, str] | None = None,
    enabled_rules: Iterable[str] = (),
    entity_map_path: Path = ENTITY_MAP_PATH,
    mode: str = "strict",
) -> dict[str, Any]:
    """Write predictions plus a timestamp-free metadata sidecar; return the metadata."""
    index = load_rule_index(entity_map_path)
    enabled = sorted(set(enabled_rules))
    execution_gates(enabled, index, mode)  # validate before scanning
    if gateway is None:
        gateway = build_gateway(enabled, index, mode)
    if build is None:
        build = build_info()
    source = input_path.read_bytes()
    rows = baselines.read_rows(input_path)
    predictions, summary = predict_rows(rows, gateway, index)
    encoded = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in predictions
    ).encode("utf-8")
    output_path.write_bytes(encoded)
    engine: dict[str, Any] = {"categories": [CATEGORY], "max_level": MAX_LEVEL, "enabled_rules": enabled}
    if mode != "strict":
        engine["dlp_mode"] = mode
    meta = {
        "schema": SCHEMA,
        "tool": TOOL,
        "engine": engine,
        "build": build,
        "entity_map_sha256": sha256_bytes(entity_map_path.read_bytes()),
        "input_sha256": sha256_bytes(source),
        "output_sha256": sha256_bytes(encoded),
        "rows": len(predictions),
        "spans": sum(len(row["evidence_spans"]) for row in predictions),
        "span_unit": "unicode_code_point",
        **summary,
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True, help="JSONL with id and text")
    parser.add_argument("--output", type=Path, required=True, help="prediction JSONL")
    parser.add_argument("--meta", type=Path, help="metadata JSON (default: OUTPUT with .meta.json)")
    parser.add_argument(
        "--enable-rule", action="append", default=[], metavar="RULE",
        help="switch on a default-off dlp_* rule (content/document classes); repeatable",
    )
    parser.add_argument(
        "--dlp-mode", choices=DLP_MODES, default="strict",
        help="DLP output mode (K04): strict (default, every score 1.0), balanced or recall (model scores)",
    )
    args = parser.parse_args(argv)
    meta_path = args.meta or args.output.with_name(args.output.stem + ".meta.json")
    meta = run(args.input, args.output, meta_path, enabled_rules=args.enable_rule, mode=args.dlp_mode)
    print(
        f"ark dlp: {meta['rows']} rows, {meta['spans']} spans -> {args.output} "
        f"(sha256 {meta['output_sha256'][:12]})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
