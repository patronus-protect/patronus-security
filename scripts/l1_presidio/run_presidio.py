#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run Microsoft Presidio on normalized PII Gold JSONL and write Ark-shaped predictions.

The input is the normalized JSONL from ``patronus_ark.external_pii_eval normalize``
(``id``, ``language``, ``text``). Each output row carries ``id`` and ``evidence_spans``
with code-point ``start_char``/``end_char``, the benchmark label, Presidio's entity
type and score, so ``external_pii_eval evaluate --predictions`` scores it unchanged.
Presidio entities without a benchmark id are namespaced as ``presidio.<ENTITY>`` and
are therefore never scored by accident.

Two checked-in profiles (``profiles/*.yaml``): ``default`` is ``AnalyzerEngine()`` as
shipped, ``tuned`` adds German models, recognizers and context. Installed packages
must match ``requirements.txt``; the metadata sidecar records profile, input and
output digests but no timestamps, so a rerun is byte-identical.

Run it with the Presidio environment, not the Ark one:

    ~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py \
        --profile tuned --input gold.jsonl --output presidio-tuned.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from importlib import metadata
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml


HERE = Path(__file__).resolve().parent
PROFILE_DIR = HERE / "profiles"
REQUIREMENTS_PATH = HERE / "requirements.txt"
PROFILES = ("default", "tuned")
SCHEMA = "ark-l1-presidio-predictions-v1"

# Presidio entity type -> benchmark id of patronus_ark.external_pii_eval. Only exact
# semantic equivalents are listed; the full ARK <-> Presidio <-> corpus map is E03.
PRESIDIO_OUTPUT_MAP = {
    "EMAIL_ADDRESS": "pii.email",
    "PHONE_NUMBER": "pii.phone",
    "IP_ADDRESS": "pii.ip_address",
    "IBAN_CODE": "pii.iban",
    "CREDIT_CARD": "pii.credit_card.pan",
    "US_SSN": "pii.us.social_security_number",
    "US_BANK_NUMBER": "pii.financial_account_number",
    "US_PASSPORT": "entity.passport_number",
    "UK_PASSPORT": "entity.passport_number",
    "DE_PASSPORT": "entity.passport_number",
    "US_DRIVER_LICENSE": "entity.driver_license_number",
    "UK_DRIVING_LICENCE": "entity.driver_license_number",
    "DE_FUEHRERSCHEIN": "entity.driver_license_number",
    "PERSON": "entity.person_name",
    "LOCATION": "entity.location",
    "ORGANIZATION": "entity.organization",
    "DATE_TIME": "entity.date",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_profile(name: str) -> dict[str, Any]:
    if name not in PROFILES:
        raise ValueError(f"unknown profile {name!r}; expected one of {', '.join(PROFILES)}")
    profile = yaml.safe_load((PROFILE_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
    if profile.get("name") != name:
        raise ValueError(f"profile file {name}.yaml declares name {profile.get('name')!r}")
    if profile.get("fallback_language") not in profile.get("languages", []):
        raise ValueError(f"profile {name!r} fallback_language must be one of its languages")
    return profile


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path) -> dict[str, str]:
    """Return ``{canonical name: version}`` for ``name==ver`` and wheel-URL pins."""
    pins = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " @ " in line:
            name, url = line.split(" @ ", 1)
            parts = url.split("#", 1)[0].rsplit("/", 1)[-1].split("-")
            if len(parts) < 2:
                raise ValueError(f"cannot read a version from {raw!r}")
            version = parts[1]
        elif "==" in line:
            name, version = line.split("==", 1)
        else:
            raise ValueError(f"requirement is not pinned exactly: {raw!r}")
        pins[_canonical_name(name.strip())] = version.strip()
    return pins


def _installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def check_pins(
    pins: dict[str, str], installed: Callable[[str], str | None] = _installed_version
) -> list[str]:
    """Describe every pinned package whose installed version differs."""
    problems = []
    for name in sorted(pins):
        version = installed(name)
        if version != pins[name]:
            problems.append(f"{name}: pinned {pins[name]}, installed {version or 'none'}")
    return problems


def analysis_language(language: str, profile: dict[str, Any]) -> str:
    return language if language in profile["languages"] else profile["fallback_language"]


def benchmark_label(entity_type: str) -> str:
    return PRESIDIO_OUTPUT_MAP.get(entity_type, f"presidio.{entity_type}")


def build_analyzer(profile: dict[str, Any]) -> Any:
    """Create the Presidio engine for a profile (imports Presidio lazily)."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_analyzer.recognizer_registry import RecognizerRegistryProvider

    config = profile["presidio"]
    if config is None:
        return AnalyzerEngine()
    nlp_engine = NlpEngineProvider(nlp_configuration=config["nlp_configuration"]).create_engine()
    registry = RecognizerRegistryProvider(
        registry_configuration={
            **config["recognizer_registry"],
            "supported_languages": profile["languages"],
        },
        nlp_engine=nlp_engine,
    ).create_recognizer_registry()
    return AnalyzerEngine(
        nlp_engine=nlp_engine,
        registry=registry,
        supported_languages=profile["languages"],
        default_score_threshold=profile["score_threshold"],
        context_aware_enhancer=LemmaContextAwareEnhancer(**profile.get("context_enhancer", {})),
    )


def _evidence_span(result: Any, text: str, row_id: str) -> dict[str, Any]:
    start, end = int(result.start), int(result.end)
    if start < 0 or end <= start or end > len(text):
        raise ValueError(f"Presidio span outside text for {row_id!r}: {start}..{end}")
    recognizer = (getattr(result, "recognition_metadata", None) or {}).get("recognizer_name")
    return {
        "label": benchmark_label(result.entity_type),
        "presidio_entity": result.entity_type,
        "start_char": start,
        "end_char": end,
        "score": round(float(result.score), 6),
        "recognizer": recognizer,
    }


def predict_rows(
    rows: Iterable[dict[str, Any]], analyzer: Any, profile: dict[str, Any]
) -> Iterable[dict[str, Any]]:
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
        language = str(row.get("language", "und"))
        target = analysis_language(language, profile)
        results = analyzer.analyze(
            text=text, language=target, score_threshold=profile["score_threshold"]
        )
        spans = [_evidence_span(result, text, row_id) for result in results]
        spans.sort(key=lambda s: (s["start_char"], s["end_char"], s["presidio_entity"], -s["score"]))
        yield {
            "id": row_id,
            "language": language,
            "analysis_language": target,
            "evidence_spans": spans,
        }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON") from exc
    return rows


def run(
    input_path: Path,
    output_path: Path,
    meta_path: Path,
    profile_name: str,
    analyzer: Any = None,
    versions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Write predictions plus a timestamp-free metadata sidecar; return the metadata."""
    profile_file = PROFILE_DIR / f"{profile_name}.yaml"
    profile = load_profile(profile_name)
    if versions is None:
        pins = parse_requirements(REQUIREMENTS_PATH)
        versions = {name: _installed_version(name) or "none" for name in sorted(pins)}
    if analyzer is None:
        analyzer = build_analyzer(profile)
    source = input_path.read_bytes()
    rows = _read_jsonl(input_path)
    predictions = list(predict_rows(rows, analyzer, profile))
    encoded = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in predictions
    ).encode("utf-8")
    output_path.write_bytes(encoded)
    languages: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in predictions:
        languages[row["language"]][row["analysis_language"]] += 1
    meta = {
        "schema": SCHEMA,
        "profile": profile_name,
        "profile_sha256": sha256_bytes(profile_file.read_bytes()),
        "score_threshold": profile["score_threshold"],
        "input_sha256": sha256_bytes(source),
        "output_sha256": sha256_bytes(encoded),
        "rows": len(predictions),
        "analysis_languages": {
            language: dict(sorted(targets.items())) for language, targets in sorted(languages.items())
        },
        "label_map": PRESIDIO_OUTPUT_MAP,
        "versions": versions,
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--input", type=Path, required=True, help="normalized Gold JSONL")
    parser.add_argument("--output", type=Path, required=True, help="prediction JSONL")
    parser.add_argument("--meta", type=Path, help="metadata JSON (default: OUTPUT with .meta.json)")
    args = parser.parse_args()
    problems = check_pins(parse_requirements(REQUIREMENTS_PATH))
    if problems:
        print("installed packages differ from requirements.txt:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 2
    meta_path = args.meta or args.output.with_name(args.output.stem + ".meta.json")
    meta = run(args.input, args.output, meta_path, args.profile)
    print(
        f"presidio {args.profile}: {meta['rows']} rows -> {args.output} "
        f"(sha256 {meta['output_sha256'][:12]})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
