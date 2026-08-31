"""Normalize admitted, permissively licensed external DLP content corpora.

No upstream raw text is redistributed. The first adapter deliberately handles
derived *content* ground truth: a Go source file is an exact whole-document
``dlp.content.source_code`` document label. It produces no exact span and is
not an upstream secret annotation.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).resolve().parent / "benchmark_data" / "external_dlp"
MANIFEST_PATH = DATA_DIR / "manifest.json"


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in payload["corpora"]}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"{root} is not a readable git checkout")
    return result.stdout.strip()


def normalize_git_tree(
    root: Path, corpus_id: str, manifest_path: Path = MANIFEST_PATH
) -> list[dict[str, Any]]:
    """Return deterministic document-level content labels for an admitted tree."""
    corpus = load_manifest(manifest_path).get(corpus_id)
    if corpus is None:
        raise ValueError(f"unknown corpus {corpus_id!r}")
    if corpus.get("admission_status") != "admitted":
        raise ValueError(f"corpus {corpus_id!r} is not admitted")
    if corpus.get("adapter") != "git_tree_content_v1":
        raise ValueError(f"unsupported adapter {corpus.get('adapter')!r}")
    if _git_head(root) != corpus["revision"]:
        raise ValueError(f"git revision mismatch for {corpus_id!r}")
    license_path = root / "LICENSE"
    if not license_path.is_file() or _sha256(license_path) != corpus["license_file_sha256"]:
        raise ValueError(f"license file SHA-256 mismatch for {corpus_id!r}")

    positive = corpus["positive"]
    negative = corpus["negative"]
    positive_ext = set(positive["extensions"])
    negative_ext = set(negative["extensions"])
    paths = sorted(path for path in root.rglob("*") if path.is_file() and ".git" not in path.parts)
    rows: list[dict[str, Any]] = []
    for path in paths:
        suffix = path.suffix.lower()
        if suffix not in positive_ext | negative_ext:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if not text:
            continue
        rel = path.relative_to(root).as_posix()
        is_positive = suffix in positive_ext
        rows.append({
            "id": f"{corpus_id}:{rel}",
            "corpus": corpus_id,
            "language": "go" if suffix == ".go" else "en",
            "text": text,
            "document_label": positive["entity_type"] if is_positive else None,
            "derived": True,
            "source_path": rel,
        })
    positives = [row for row in rows if row["document_label"]]
    negatives = [row for row in rows if not row["document_label"]]
    if len(positives) != positive["expected_documents"]:
        raise ValueError(f"unexpected positive file count: {len(positives)}")
    if len(negatives) < negative["expected_minimum_documents"]:
        raise ValueError(f"insufficient negative files: {len(negatives)}")
    return rows


def _sql_statement_spans(text: str) -> list[tuple[int, int]]:
    """Return semicolon-terminated SQL statement offsets without parsing SQL.

    This small lexer avoids delimiters in quoted identifiers/literals and the
    common line/block comment forms.  It intentionally admits only terminated
    statements; malformed or delimiter-less trailing text is not Gold.
    """
    spans: list[tuple[int, int]] = []
    start = 0
    index = 0
    quote: str | None = None
    line_comment = False
    block_comment = False
    while index < len(text):
        pair = text[index:index + 2]
        if line_comment:
            if text[index] in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if pair == "*/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if text[index] == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if pair == "--":
            line_comment = True
            index += 2
            continue
        if pair == "/*":
            block_comment = True
            index += 2
            continue
        if text[index] in "'\"`":
            quote = text[index]
            index += 1
            continue
        if text[index] == ";":
            left = start
            right = index + 1
            while left < right and text[left].isspace():
                left += 1
            while right > left and text[right - 1].isspace():
                right -= 1
            if right > left:
                spans.append((left, right))
            start = index + 1
        index += 1
    return spans


def normalize_sql_archive(
    archive_path: Path, corpus_id: str, manifest_path: Path = MANIFEST_PATH
) -> list[dict[str, Any]]:
    """Extract a capped, deterministic exact-statement SQL Gold set."""
    corpus = load_manifest(manifest_path).get(corpus_id)
    if corpus is None or corpus.get("admission_status") != "admitted":
        raise ValueError(f"corpus {corpus_id!r} is not admitted")
    if corpus.get("adapter") != "tar_sql_statement_v1":
        raise ValueError(f"unsupported adapter {corpus.get('adapter')!r}")
    if _sha256(archive_path) != corpus["verified_sha256"]:
        raise ValueError(f"source SHA-256 mismatch for {corpus_id!r}")
    cap = corpus["positive"]["target_cap"]
    rows: list[dict[str, Any]] = []
    with tarfile.open(archive_path, "r:gz") as archive:
        members = sorted(
            (member for member in archive.getmembers() if member.isfile() and member.name.endswith(".sql")),
            key=lambda member: member.name,
        )
        for member in members:
            raw = archive.extractfile(member)
            if raw is None:
                continue
            try:
                text = raw.read().decode("utf-8")
            except UnicodeDecodeError:
                continue
            for start, end in _sql_statement_spans(text):
                rows.append({
                    "id": f"{corpus_id}:{member.name}:{start}:{end}",
                    "corpus": corpus_id,
                    "language": "sql",
                    "text": text,
                    "entities": [{"entity_type": corpus["positive"]["entity_type"], "start": start, "end": end}],
                    "derived": True,
                    "source_path": member.name,
                })
                if len(rows) == cap:
                    return rows
    raise ValueError(f"insufficient terminated SQL statements: {len(rows)}, expected {cap}")
