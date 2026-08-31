"""Normalize approved local PII corpora and score exact Ark entity spans.

External raw data is deliberately kept outside the repository.  The checked-in
manifest records the upstream licence and the input shape; this module only
reads a local JSONL export and produces a small, reviewable Ark-shaped JSONL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


DATA_DIR = Path(__file__).resolve().parent / "benchmark_data" / "external_pii"
MANIFEST_PATH = DATA_DIR / "manifest.json"

# These are benchmark IDs, not Rust output labels.  Keeping this vocabulary
# stable means source-specific labels never leak into result comparisons.
ENTITY_MAP = {
    "email": "pii.email",
    "email_address": "pii.email",
    "phone": "pii.phone",
    "phone_number": "pii.phone",
    "ip": "pii.ip_address",
    "ip_address": "pii.ip_address",
    "iban": "pii.iban",
    "bic": "pii.swift_bic",
    "swift": "pii.swift_bic",
    "swift_code": "pii.swift_bic",
    "credit_card": "pii.credit_card.pan",
    "credit_card_number": "pii.credit_card.pan",
    "date_of_birth": "pii.date_of_birth",
    "dob": "pii.date_of_birth",
    "employee_id": "pii.employee_id",
    "employee_identifier": "pii.employee_id",
    "customer_id": "pii.customer_id",
    "patient_id": "pii.patient_id",
    "medical_record_number": "pii.patient_id",
    "student_id": "pii.student_id",
    "student_identifier": "pii.student_id",
    "applicant_id": "pii.applicant_id",
    "applicant_identifier": "pii.applicant_id",
    "username": "pii.username",
    "user_name": "pii.username",
    "person": "entity.person_name",
    "name": "entity.person_name",
    "givenname": "entity.person_name",
    "surname": "entity.person_name",
    "organization": "entity.organization",
    "org": "entity.organization",
    "location": "entity.location",
    "loc": "entity.location",
    "city": "entity.location",
    "country": "entity.location",
    "date": "entity.date",
    "datetime": "entity.date",
    "street_address": "entity.street_address",
    "street": "entity.street_address",
    "address": "entity.street_address",
    "passport_number": "entity.passport_number",
    "passportnum": "entity.passport_number",
    "driver_license_number": "entity.driver_license_number",
    "driverlicensenum": "entity.driver_license_number",
}

ARK_OUTPUT_MAP = {
    "EMAIL": "pii.email",
    "PHONE": "pii.phone",
    "IP_ADDRESS": "pii.ip_address",
    "IBAN": "pii.iban",
    "SWIFT_CODE": "pii.swift_bic",
    "CREDITCARD": "pii.credit_card.pan",
    "DOB": "pii.date_of_birth",
    "EMPLOYEE_ID": "pii.employee_id",
    "CUSTOMER_ID": "pii.customer_id",
    "PATIENT_ID": "pii.patient_id",
    "STUDENT_ID": "pii.student_id",
    "APPLICANT_ID": "pii.applicant_id",
    "USERNAME": "pii.username",
    "PASSPORT_NUMBER": "entity.passport_number",
    "DRIVER_LICENSE_NUMBER": "entity.driver_license_number",
}


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, dict[str, Any]]:
    """Return corpus entries keyed by their stable corpus id."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in payload["corpora"]}


def ark_entity_id(label: str, mapping: dict[str, str] | None = None) -> str | None:
    """Map an upstream label to a stable Ark benchmark id, if in scope."""
    if label.startswith(("pii.", "entity.", "dlp.")):
        return label
    labels = mapping or ENTITY_MAP
    return labels.get(label.strip().lower())


def _span_values(span: dict[str, Any]) -> tuple[int, int, str]:
    start = span.get("start", span.get("start_char", span.get("offset")))
    end = span.get("end", span.get("end_char"))
    label = span.get("label", span.get("entity_type", span.get("type")))
    if not isinstance(start, int) or not isinstance(end, int) or not isinstance(label, str):
        raise ValueError(f"invalid span: {span!r}")
    return start, end, label


def normalize_row(row: dict[str, Any], corpus: dict[str, Any]) -> dict[str, Any]:
    """Convert an offset-based JSONL source row into the Ark benchmark schema."""
    text = row.get("text")
    if not isinstance(text, str) or not text:
        raise ValueError("row requires non-empty text")
    source_spans = row.get("entities", row.get("spans", []))
    if not isinstance(source_spans, list):
        raise ValueError("row entities/spans must be a list")
    mapping = {
        **ENTITY_MAP,
        **{key.strip().lower(): value for key, value in corpus.get("label_map", {}).items()},
    }
    entities = []
    for span in source_spans:
        start, end, label = _span_values(span)
        entity_type = ark_entity_id(label, mapping)
        if entity_type is None:
            continue  # Explicitly unsupported labels do not become false negatives.
        if start < 0 or end <= start or end > len(text):
            raise ValueError(f"span outside text for {row.get('id', '<no id>')}: {span!r}")
        entities.append({"entity_type": entity_type, "start": start, "end": end})
    return {
        "id": str(row.get("id", row.get("document_id", ""))) or None,
        "corpus": corpus["id"],
        "language": str(row.get("language", corpus.get("default_language", "und"))),
        "text": text,
        "entities": sorted(entities, key=lambda item: (item["start"], item["end"], item["entity_type"])),
    }


def normalize_openpii_row(row: dict[str, Any], corpus: dict[str, Any]) -> dict[str, Any]:
    """Normalize the official OpenPII ``source_text``/``privacy_mask`` schema."""
    text = row.get("source_text")
    masks = row.get("privacy_mask", [])
    if not isinstance(text, str) or not isinstance(masks, list):
        raise ValueError("OpenPII row requires source_text and privacy_mask list")
    for mask in masks:
        start, end, _ = _span_values(mask)
        if text[start:end] != mask.get("value"):
            raise ValueError(f"OpenPII value/offset mismatch for {row.get('uid', '<no id>')}")
    return normalize_row(
        {
            "id": row.get("uid"),
            "language": row.get("language"),
            "text": text,
            "entities": masks,
        },
        corpus,
    )


def normalize_tab_document(row: dict[str, Any], corpus: dict[str, Any]) -> dict[str, Any]:
    """Normalize one official TAB standoff document.

    TAB may contain several annotator views of one document. For entity/span
    evaluation we take their deterministic union and deduplicate identical
    mentions. ``identifier_types`` controls whether the privacy-oriented gold
    includes DIRECT, QUASI, and/or NO_MASK mentions.
    """
    text = row.get("text")
    annotations = row.get("annotations")
    if not isinstance(text, str) or not text or not isinstance(annotations, dict):
        raise ValueError("TAB row requires text and annotations object")
    allowed_identifier_types = set(corpus.get("identifier_types", ["DIRECT", "QUASI"]))
    source_spans = []
    for annotator in sorted(annotations):
        view = annotations[annotator]
        mentions = view.get("entity_mentions", []) if isinstance(view, dict) else None
        if not isinstance(mentions, list):
            raise ValueError(f"TAB annotator {annotator!r} requires entity_mentions list")
        for mention in mentions:
            if mention.get("identifier_type") not in allowed_identifier_types:
                continue
            start = mention.get("start_offset")
            end = mention.get("end_offset")
            span_text = mention.get("span_text")
            if not isinstance(start, int) or not isinstance(end, int) or text[start:end] != span_text:
                raise ValueError(
                    f"TAB span text/offset mismatch for {row.get('doc_id', '<no id>')}"
                )
            source_spans.append(
                {"label": mention.get("entity_type"), "start": start, "end": end}
            )
    normalized = normalize_row(
        {
            "id": row.get("doc_id"),
            "language": corpus.get("default_language", "en"),
            "text": text,
            "entities": source_spans,
        },
        corpus,
    )
    unique = sorted(
        {_key(entity) for entity in normalized["entities"]},
        key=lambda item: (item[1], item[2], item[0]),
    )
    normalized["entities"] = [
        {"entity_type": label, "start": start, "end": end}
        for label, start, end in unique
    ]
    return normalized


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc


def normalize_file(
    input_path: Path,
    corpus_id: str,
    manifest_path: Path = MANIFEST_PATH,
    verify_source: bool = False,
) -> list[dict[str, Any]]:
    corpora = load_manifest(manifest_path)
    if corpus_id not in corpora:
        raise ValueError(f"unknown corpus {corpus_id!r}")
    corpus = corpora[corpus_id]
    if verify_source:
        expected = corpus.get("verified_sha256")
        if not isinstance(expected, str):
            raise ValueError(f"corpus {corpus_id!r} has no verified_sha256")
        actual = hashlib.sha256(input_path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(
                f"source SHA-256 mismatch for {corpus_id!r}: expected {expected}, got {actual}"
            )
    adapter = corpus.get("adapter")
    if adapter == "offset_jsonl_v1":
        rows = [normalize_row(row, corpus) for row in read_jsonl(input_path)]
    elif adapter == "openpii_jsonl_v1":
        rows = [normalize_openpii_row(row, corpus) for row in read_jsonl(input_path)]
    elif adapter == "tab_standoff_v1":
        payload = json.loads(input_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("TAB input must be a JSON document list")
        rows = [normalize_tab_document(row, corpus) for row in payload]
    else:
        raise ValueError(f"unsupported adapter {adapter!r}")
    ids = [row["id"] for row in rows]
    if None in ids or len(set(ids)) != len(ids):
        raise ValueError("external source rows require unique id or document_id values")
    return rows


def _key(entity: dict[str, Any]) -> tuple[str, int, int]:
    return (entity["entity_type"], entity["start"], entity["end"])


def _scores(gold: int, predicted: int, true_positives: int) -> dict[str, float | int]:
    precision = true_positives / predicted if predicted else 0.0
    recall = true_positives / gold if gold else 0.0
    return {
        "gold": gold,
        "predicted": predicted,
        "true_positives": true_positives,
        "false_positives": predicted - true_positives,
        "false_negatives": gold - true_positives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
    }


def exact_span_metrics(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Score exact `(entity_type, start, end)` matches, stratified by corpus/entity/language."""
    totals: dict[tuple[str, ...], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    samples = 0
    for row in rows:
        samples += 1
        gold = {_key(entity) for entity in row["entities"]}
        if "predicted_entities" not in row:
            raise ValueError("every normalized gold row requires predicted_entities")
        predicted = {_key(entity) for entity in row["predicted_entities"]}
        matches = gold & predicted
        dimensions = [("overall",), ("corpus", row["corpus"]), ("language", row["corpus"], row["language"])]
        labels = {entity_type for entity_type, _, _ in gold | predicted}
        for scope, prefix in (("native_pii", "pii."), ("semantic_entity", "entity.")):
            if any(label.startswith(prefix) for label in labels):
                dimensions.extend([
                    ("scope", scope),
                    ("corpus_scope", row["corpus"], scope),
                    ("language_scope", row["corpus"], row["language"], scope),
                ])
        dimensions.extend(("entity", row["corpus"], entity_type) for entity_type in labels)
        dimensions.extend(("language_entity", row["corpus"], row["language"], entity_type) for entity_type in labels)
        for dimension in dimensions:
            bucket = totals[dimension]
            if dimension[0].endswith("scope"):
                prefix = "pii." if dimension[-1] == "native_pii" else "entity."
                expected = {item for item in gold if item[0].startswith(prefix)}
                actual = {item for item in predicted if item[0].startswith(prefix)}
                bucket["gold"] += len(expected)
                bucket["predicted"] += len(actual)
                bucket["true_positives"] += len(expected & actual)
            elif dimension[0] in {"entity", "language_entity"}:
                label = dimension[-1]
                expected = {item for item in gold if item[0] == label}
                actual = {item for item in predicted if item[0] == label}
                bucket["gold"] += len(expected)
                bucket["predicted"] += len(actual)
                bucket["true_positives"] += len(expected & actual)
            else:
                bucket["gold"] += len(gold)
                bucket["predicted"] += len(predicted)
                bucket["true_positives"] += len(matches)

    def entities_for(kind: str, corpus: str, language: str | None = None) -> dict[str, Any]:
        prefix = (kind, corpus) if language is None else (kind, corpus, language)
        return {
            key[-1]: _scores(**totals[key])
            for key in sorted(totals)
            if key[:-1] == prefix and key[-1].startswith(("pii.", "entity.", "dlp."))
        }

    def scopes_for(kind: str, corpus: str, language: str | None = None) -> dict[str, Any]:
        prefix = (kind, corpus) if language is None else (kind, corpus, language)
        return {
            key[-1]: _scores(**totals[key])
            for key in sorted(totals)
            if key[:-1] == prefix
        }

    return {
        "metric": "exact_span_v1",
        "samples": samples,
        "overall": _scores(**totals[("overall",)]),
        "per_scope": {
            scope: _scores(**totals[("scope", scope)])
            for _, scope in sorted(key for key in totals if key[0] == "scope")
        },
        "per_corpus": {
            corpus: {
                "overall": _scores(**totals[("corpus", corpus)]),
                "per_language": {
                    language: {
                        "overall": _scores(**totals[("language", corpus, language)]),
                        "per_scope": scopes_for("language_scope", corpus, language),
                        "per_entity": entities_for("language_entity", corpus, language),
                    }
                    for _, source, language in sorted(key for key in totals if key[0] == "language" and key[1] == corpus)
                    if source == corpus
                },
                "per_scope": scopes_for("corpus_scope", corpus),
                "per_entity": entities_for("entity", corpus),
            }
            for _, corpus in sorted(key for key in totals if key[0] == "corpus")
        },
    }


def attach_ark_predictions(
    gold_rows: Iterable[dict[str, Any]],
    prediction_rows: Iterable[dict[str, Any]],
    manifest_path: Path = MANIFEST_PATH,
) -> list[dict[str, Any]]:
    """Attach native Ark ``evidence_spans`` to normalized rows by id.

    Prediction rows are intentionally plain JSONL so callers may use the Rust
    API, the Python binding, or an HTTP client. Unknown output labels and labels
    outside a corpus's declared ontology stay out of that corpus metric rather
    than being incorrectly counted as false positives.
    """
    gold_rows = list(gold_rows)
    gold_ids = {row.get("id") for row in gold_rows}
    if None in gold_ids or len(gold_ids) != len(gold_rows):
        raise ValueError("normalized gold rows require unique ids")
    manifest = load_manifest(manifest_path)
    supported_by_corpus = {
        corpus_id: set(corpus.get("label_map", {}).values())
        for corpus_id, corpus in manifest.items()
    }
    corpus_by_id = {row["id"]: row["corpus"] for row in gold_rows}
    predictions = {}
    for row in prediction_rows:
        row_id = str(row.get("id", row.get("request_id", "")))
        if not row_id:
            raise ValueError("prediction row requires id or request_id")
        if row_id not in gold_ids:
            raise ValueError(f"prediction has unknown id {row_id!r}")
        if row_id in predictions:
            raise ValueError(f"duplicate prediction id {row_id!r}")
        spans = row.get("evidence_spans", row.get("result", {}).get("evidence_spans", []))
        if not isinstance(spans, list):
            raise ValueError(f"prediction {row_id!r} evidence_spans must be a list")
        entities = []
        for span in spans:
            label = ARK_OUTPUT_MAP.get(str(span.get("label", "")), ark_entity_id(str(span.get("label", ""))))
            start = span.get("start_char", span.get("start"))
            end = span.get("end_char", span.get("end"))
            supported = supported_by_corpus.get(corpus_by_id[row_id])
            if (
                label is not None
                and (supported is None or label in supported)
                and isinstance(start, int)
                and isinstance(end, int)
            ):
                entities.append({"entity_type": label, "start": start, "end": end})
        predictions[row_id] = entities
    missing = gold_ids - predictions.keys()
    if missing:
        raise ValueError(f"predictions missing {len(missing)} gold ids")
    output = []
    for row in gold_rows:
        if not row.get("id"):
            raise ValueError("normalized rows require ids when attaching predictions")
        output.append({**row, "predicted_entities": predictions.get(row["id"], [])})
    return output


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    normalize = commands.add_parser("normalize", help="normalize a local upstream JSONL export")
    normalize.add_argument("--corpus", required=True)
    normalize.add_argument("--input", type=Path, required=True)
    normalize.add_argument("--output", type=Path, required=True)
    normalize.add_argument(
        "--verify-source",
        action="store_true",
        help="require the input SHA-256 pinned in the corpus manifest",
    )
    evaluate = commands.add_parser("evaluate", help="score normalized JSONL with predicted_entities")
    evaluate.add_argument("--input", type=Path, required=True, help="normalized JSONL")
    evaluate.add_argument("--predictions", type=Path, help="Ark result JSONL with ids and evidence_spans")
    evaluate.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "normalize":
        _write_jsonl(
            args.output,
            normalize_file(args.input, args.corpus, verify_source=args.verify_source),
        )
    else:
        rows = read_jsonl(args.input)
        if args.predictions:
            rows = attach_ark_predictions(rows, read_jsonl(args.predictions))
        report = exact_span_metrics(rows)
        encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        else:
            print(encoded, end="")


if __name__ == "__main__":
    main()
