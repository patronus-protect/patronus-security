#!/usr/bin/env python3
"""Build a text-free, HMAC-bound review inventory from local document corpora.

The input documents may be private. Neither their text nor Ark's matched text is
written to stdout or to the generated files. All detections remain machine
candidates until a reviewer records a separate decision.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator


SENSITIVE_CLASSES = {
    0: "legal",
    1: "hr",
    2: "finance",
    3: "internal_and_tech",
    4: "source_code",
    5: "marketing",
    6: "other",
    7: "education",
    8: "medical",
}
SUPPORTED_CORPORA = ("document_classifier", "v4_1_sensitive", "ap9_documents")
_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_DE_WORDS = frozenset(
    "aber als auch bei das dem den der des die ein eine einer für im ist mit nicht oder "
    "sich sie und von zu zum zur".split()
)
_EN_WORDS = frozenset(
    "a an and are as at by for from in is it of on or that the this to with".split()
)


@dataclass(frozen=True)
class Document:
    corpus: str
    split: str
    source_id: str
    text: str
    document_class: str
    declared_language: str
    source: str
    provenance_kind: str
    license_review: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"expected object at {path}:{line_number}")
            yield value


def infer_language(text: str, declared: str | None) -> str:
    declared = (declared or "unknown").lower()
    if declared in {"de", "en", "code"}:
        return declared
    words = [word.lower() for word in _WORD_RE.findall(text[:20_000])]
    de_score = sum(word in _DE_WORDS for word in words)
    en_score = sum(word in _EN_WORDS for word in words)
    if max(de_score, en_score) < 3 or de_score == en_score:
        return "unknown"
    return "de" if de_score > en_score else "en"


def _document_classifier(root: Path) -> Iterator[tuple[Document, Path]]:
    data = root / "patronus-document-classifier-dataset" / "data"
    for split, name in (("train", "train"), ("validation", "val"), ("test", "test")):
        path = data / f"{name}.jsonl"
        for index, row in enumerate(_read_jsonl(path)):
            generated = bool(row.get("generated"))
            yield Document(
                corpus="document_classifier",
                split=split,
                source_id=f"{name}:{index}",
                text=str(row.get("text", "")),
                document_class=str(row.get("label", "unknown")),
                declared_language=str(row.get("language", "unknown")),
                source=str(row.get("source", "unknown")),
                provenance_kind="synthetic" if generated else "third_party_real",
                license_review=str(row.get("license_review", "unknown")),
            ), path


def _v4_sensitive(root: Path) -> Iterator[tuple[Document, Path]]:
    data = root / "v4.1_run" / "base_training"
    for split in ("train", "val", "test"):
        path = data / f"{split}.jsonl"
        for index, row in enumerate(_read_jsonl(path)):
            sensitive = (row.get("labels") or {}).get("sensitive_document")
            if sensitive is None:
                continue
            source = str(row.get("source", "unknown"))
            if source == "synthetic_hybrid":
                provenance = "synthetic"
            elif source == "unified_real_runs_1":
                provenance = "internal_runtime_real_unverified"
            else:
                provenance = "imported_mixed_provenance"
            yield Document(
                corpus="v4_1_sensitive",
                split="validation" if split == "val" else split,
                source_id=str(row.get("id", f"{split}:{index}")),
                text=str(row.get("text", "")),
                document_class=SENSITIVE_CLASSES.get(sensitive, f"unknown_{sensitive}"),
                declared_language=str(row.get("language", "unknown")),
                source=source,
                provenance_kind=provenance,
                license_review="not_carried_into_v4_1",
            ), path


def _ap9_documents(root: Path) -> Iterator[tuple[Document, Path]]:
    data = root / "v4.1_run" / "ap9" / "documents_final"
    for split, name in (("train", "train"), ("validation", "validation"), ("benchmark", "benchmark")):
        path = data / f"{name}.jsonl"
        for index, row in enumerate(_read_jsonl(path)):
            sensitive = (row.get("labels") or {}).get("sensitive_document")
            meta = row.get("meta") or {}
            yield Document(
                corpus="ap9_documents",
                split=split,
                source_id=str(row.get("id", f"{name}:{index}")),
                text=str(row.get("text", "")),
                document_class=SENSITIVE_CLASSES.get(sensitive, f"unknown_{sensitive}"),
                declared_language=str(row.get("language", "unknown")),
                source=str(row.get("source", "unknown")),
                provenance_kind="anonymized_structured_derived",
                license_review=str(meta.get("license_review", "unknown")),
            ), path


READERS: dict[str, Callable[[Path], Iterable[tuple[Document, Path]]]] = {
    "document_classifier": _document_classifier,
    "v4_1_sensitive": _v4_sensitive,
    "ap9_documents": _ap9_documents,
}


def _binding(key: bytes, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def _sample_documents(
    documents: Iterable[Document], key: bytes, maximum_per_stratum: int
) -> list[Document]:
    if maximum_per_stratum <= 0:
        return list(documents)
    strata: dict[tuple[str, ...], list[tuple[str, Document]]] = defaultdict(list)
    for document in documents:
        language = infer_language(document.text, document.declared_language)
        stratum = (
            document.corpus,
            document.document_class,
            language,
            document.provenance_kind,
        )
        rank = _binding(key, "sample", document.corpus, document.split, document.source_id)
        strata[stratum].append((rank, document))
    return [
        document
        for values in strata.values()
        for _, document in sorted(values)[:maximum_per_stratum]
    ]


def _candidate_base(document: Document, key: bytes) -> dict:
    language = infer_language(document.text, document.declared_language)
    document_binding = _binding(key, "document", document.text)
    record_binding = _binding(
        key,
        "record",
        document.corpus,
        document.split,
        document.source_id,
        document_binding,
    )
    return {
        "corpus": document.corpus,
        "split": document.split,
        "record_binding": record_binding,
        "document_binding": document_binding,
        "document_class_context": document.document_class,
        "language": language,
        "declared_language": document.declared_language,
        "source": document.source,
        "provenance_kind": document.provenance_kind,
        "license_review": document.license_review,
        "review_status": "unreviewed",
        "gold_status": "not_gold_machine_candidate",
    }


def observations(document: Document, results: list[dict], key: bytes) -> list[dict]:
    """Convert Ark output to records that contain no source or matched text."""
    base = _candidate_base(document, key)
    findings: dict[tuple, dict] = {}
    anchors: dict[tuple, dict] = {}
    for result in results:
        category = str(result.get("category", "unknown"))
        model = str(result.get("model", "unknown"))
        for span in result.get("evidence_spans") or []:
            start = int(span["start_char"])
            end = int(span["end_char"])
            if start < 0 or end < start or end > len(document.text):
                continue
            label = str(span.get("label", result.get("class_name", "unknown")))
            dedup_key = (category, model, label, start, end)
            span_text = document.text[start:end]
            candidate_id = _binding(
                key, "finding", base["record_binding"], *dedup_key, span_text
            )
            findings[dedup_key] = {
                **base,
                "candidate_id": candidate_id,
                "candidate_kind": "ark_l1_finding",
                "ark_category": category,
                "ark_model": model,
                "ark_label": label,
                "start_char": start,
                "end_char": end,
                "span_binding": _binding(key, "span", span_text),
            }
        for layer in result.get("layers") or []:
            for anchor in (layer.get("details") or {}).get("l1_anchors", []):
                start = int(anchor.get("start_char", -1))
                end = int(anchor.get("end_char", -1))
                if start < 0 or end < start or end > len(document.text):
                    continue
                anchor_category = str(anchor.get("category", "unknown"))
                anchor_key = (category, model, anchor_category, start, end)
                anchors[anchor_key] = {
                    "ark_category": category,
                    "ark_model": model,
                    "anchor_category": anchor_category,
                    "anchor_strength": str(anchor.get("strength", "unknown")),
                    "start_char": start,
                    "end_char": end,
                }
    if findings:
        return list(findings.values())
    if not anchors:
        return []
    anchor_summary = sorted(
        {
            (value["ark_category"], value["ark_model"], value["anchor_category"])
            for value in anchors.values()
        }
    )
    candidate_id = _binding(key, "anchor_negative", base["record_binding"], anchor_summary)
    return [
        {
            **base,
            "candidate_id": candidate_id,
            "candidate_kind": "anchor_hard_negative_candidate",
            "anchor_categories": [
                {"ark_category": category, "ark_model": model, "anchor_category": anchor}
                for category, model, anchor in anchor_summary
            ],
            "anchor_count": len(anchors),
        }
    ]


def _counts(records: Iterable[dict], *keys: str) -> dict[str, int]:
    counts = Counter(tuple(str(record.get(key, "n/a")) for key in keys) for record in records)
    return {" | ".join(group): count for group, count in sorted(counts.items())}


def _deduplicate_candidates(records: Iterable[dict]) -> list[dict]:
    """Remove repeated content imported through more than one local corpus."""
    corpus_priority = {"document_classifier": 0, "ap9_documents": 1, "v4_1_sensitive": 2}
    unique: dict[tuple, dict] = {}
    for record in records:
        if record["candidate_kind"] == "ark_l1_finding":
            key = (
                "finding",
                record["document_binding"],
                record["ark_category"],
                record["ark_label"],
                record["start_char"],
                record["end_char"],
                record["span_binding"],
            )
        else:
            anchors = tuple(
                (item["ark_category"], item["ark_model"], item["anchor_category"])
                for item in record["anchor_categories"]
            )
            key = ("anchor_negative", record["document_binding"], anchors)
        current = unique.get(key)
        rank = (corpus_priority.get(record["corpus"], 99), record["candidate_id"])
        if current is None or rank < (
            corpus_priority.get(current["corpus"], 99),
            current["candidate_id"],
        ):
            unique[key] = record
    return list(unique.values())


def build_inventory(
    documents: Iterable[Document], scanner, key: bytes, maximum_per_label: int, workers: int = 1
) -> tuple[list[dict], dict]:
    discovered: list[dict] = []
    scanned = Counter()
    documents = list(documents)
    if workers <= 1:
        scanned_results = ((document, scanner(document.text)) for document in documents)
    else:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        scanned_results = zip(documents, executor.map(lambda item: scanner(item.text), documents))
    try:
        for document, results in scanned_results:
            language = infer_language(document.text, document.declared_language)
            scanned[(document.corpus, document.document_class, language)] += 1
            discovered.extend(observations(document, results, key))
    finally:
        if workers > 1:
            executor.shutdown()

    raw_candidate_count = len(discovered)
    discovered = _deduplicate_candidates(discovered)
    grouped: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for record in discovered:
        if record["candidate_kind"] == "ark_l1_finding":
            group = ("finding", str(record["ark_category"]), str(record["ark_label"]))
        else:
            group = (
                "anchor_negative",
                str(record["corpus"]),
                str(record["document_class_context"]),
                str(record["language"]),
            )
        grouped[group].append(record)
    inventory = []
    for values in grouped.values():
        values.sort(key=lambda value: value["candidate_id"])
        inventory.extend(values if maximum_per_label <= 0 else values[:maximum_per_label])
    inventory.sort(key=lambda value: value["candidate_id"])

    summary = {
        "schema_version": 1,
        "status_contract": {
            "ark_l1_finding": "machine candidate; not human-verified gold",
            "anchor_hard_negative_candidate": "machine-selected review candidate; not a verified negative",
        },
        "documents_scanned": sum(scanned.values()),
        "documents_scanned_by_corpus_class_language": {
            " | ".join(group): count for group, count in sorted(scanned.items())
        },
        "candidates_discovered_raw": raw_candidate_count,
        "candidates_discovered_unique": len(discovered),
        "candidates_in_inventory": len(inventory),
        "discovered_by_kind": _counts(discovered, "candidate_kind"),
        "discovered_findings_by_ark_class_corpus_language": _counts(
            (item for item in discovered if item["candidate_kind"] == "ark_l1_finding"),
            "ark_category",
            "ark_label",
            "corpus",
            "language",
        ),
        "inventory_by_kind": _counts(inventory, "candidate_kind"),
        "inventory_by_provenance": _counts(inventory, "provenance_kind"),
    }
    return inventory, summary


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--datasets-root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument(
        "--corpora", nargs="+", choices=SUPPORTED_CORPORA, default=list(SUPPORTED_CORPORA)
    )
    parser.add_argument(
        "--hmac-key-env",
        default="PATRONUS_PREANNOTATION_HMAC_KEY",
        help="environment variable containing at least 32 bytes; never written to output",
    )
    parser.add_argument(
        "--hmac-key-file",
        type=Path,
        help="private file containing at least 32 bytes; preferred for reproducible review runs",
    )
    parser.add_argument(
        "--max-documents-per-stratum",
        type=int,
        default=100,
        help="deterministic cap per corpus/class/language/provenance; 0 scans all",
    )
    parser.add_argument(
        "--max-candidates-per-label",
        type=int,
        default=300,
        help="deterministic review cap per Ark label and anchor-negative stratum; 0 keeps all",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="parallel scanners; each thread receives its own Ark gateway",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    secret = (
        args.hmac_key_file.read_bytes()
        if args.hmac_key_file is not None
        else os.environ.get(args.hmac_key_env, "").encode("utf-8")
    )
    if len(secret) < 32:
        location = str(args.hmac_key_file) if args.hmac_key_file else args.hmac_key_env
        raise SystemExit(f"{location} must contain at least 32 bytes")

    documents: list[Document] = []
    input_files: set[Path] = set()
    for corpus in args.corpora:
        for document, path in READERS[corpus](args.datasets_root):
            documents.append(document)
            input_files.add(path)
    sampled = _sample_documents(documents, secret, args.max_documents_per_stratum)

    from patronus_ark import SecurityGateway

    gateways = threading.local()

    def scan(text: str) -> list[dict]:
        try:
            if not hasattr(gateways, "value"):
                gateways.value = SecurityGateway(
                    categories=["pii", "dlp"], max_level="l1", download_files=False
                )
            return gateways.value.scan_categories(["pii", "dlp"], text)
        except Exception as exc:
            raise RuntimeError(f"Ark scan failed ({type(exc).__name__}); input withheld") from None

    inventory, summary = build_inventory(
        sampled,
        scan,
        secret,
        args.max_candidates_per_label,
        workers=args.workers,
    )
    summary["corpora"] = list(args.corpora)
    summary["documents_available"] = len(documents)
    summary["sampling"] = {
        "maximum_documents_per_stratum": args.max_documents_per_stratum,
        "maximum_candidates_per_label": args.max_candidates_per_label,
        "workers": args.workers,
    }
    summary["input_files"] = [
        {"logical_path": str(path.relative_to(args.datasets_root)), "sha256": _sha256_file(path)}
        for path in sorted(input_files)
    ]
    summary["inventory_sha256"] = hashlib.sha256(
        "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in inventory).encode()
    ).hexdigest()

    args.inventory.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with args.inventory.open("w", encoding="utf-8") as handle:
        for item in inventory:
            handle.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"documents_scanned": len(sampled), "inventory_records": len(inventory)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
