#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Benign-document corpus (DE/EN) for false positives of L1-DLP content and document classes.

Public-domain and CC-licensed texts listed in ``benign_docs_sources.json``: Wikipedia
articles (prose), German federal laws and US agency guides (government) and Wikimedia
Foundation policies, legal pages and board minutes (corporate), each in German and
English. A source is either a git repository pinned to a commit (selected files by glob)
or a MediaWiki site with pages pinned to a revision id. The split is by source: each
entry names its split, and no document or identical text may appear in both splits.
Each source pins the SHA-256 of its JSONL; a build that does not reproduce it is an error.
Data stays on the VPS, never in the repo.

    python3 scripts/l1_dlp/benign_docs.py prepare --dev-out DIR --holdout-out DIR
    python3 scripts/l1_dlp/benign_docs.py check DIR
    python3 scripts/l1_dlp/benign_docs.py fp-report --corpus DIR --predictions FILE
    python3 scripts/l1_dlp/benign_docs.py pin --sources DIR [--write]

``prepare`` follows ``benign_code.py``: each output directory gets ``<source>.jsonl``,
``manifest.json`` (license, SHA-256, documents and bytes for every source) and, written
last, ``.ready``. A directory with ``.ready`` is frozen (``--force`` replaces it). Caches
live in ``--sources`` (default ``HOLDOUT/.sources/benign_docs``); stdout names only dev
numbers.

The corpus is assumed to contain no secrets and no confidential documents, so every
reported span and every flagged document is a false positive. Only the standard library
and the git CLI are needed.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import importlib.util
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
SOURCES_PATH = HERE / "benign_docs_sources.json"


def _load_file(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


# Git helpers, JSONL/manifest encoding and split writing are shared with the code corpus.
BENIGN_CODE = _load_file("_ark_l1_dlp_benign_code", HERE / "benign_code.py")
GIT_ENV = BENIGN_CODE.GIT_ENV
git = BENIGN_CODE.git

SCHEMA = "ark-dlp-benign-docs-v1"
LIST_SCHEMA = "ark-dlp-benign-docs-sources-v1"
SPLITS = ("dev", "holdout")
LANGS = ("de", "en")
GENRES = ("prose", "government", "corporate")
SOURCE_TYPES = ("git", "mediawiki")
READY = ".ready"
MB = 1_000_000

# Selection limits (part of the pinned output: changing them changes every source SHA-256).
MIN_DOC_CHARS = 200
MAX_DOC_BYTES = 1024 * 1024
SOURCE_BUDGET_BYTES = 4 * 1024 * 1024

# Public domain or CC without NC/ND. The Unlicense covers bundestag/gesetze; the law texts
# themselves are official works without copyright (§ 5 UrhG).
OPEN_CONTENT_LICENSES = frozenset(
    {"CC0-1.0", "CC-BY-3.0", "CC-BY-4.0", "CC-BY-SA-3.0", "CC-BY-SA-4.0", "Unlicense"}
)
LICENSE_FILE = BENIGN_CODE.LICENSE_FILE
TEXT_SUFFIXES = (".md", ".markdown", ".txt")

USER_AGENT = "PatronusARK-dlp-benign-docs/1.0 (https://github.com/patronus-protect/patronus-security)"
REQUEST_DELAY_SECONDS = 1.0
RETRIES = 5
API_BATCH = 50


# ── source list ──────────────────────────────────────────────────────────────


def is_open_content_license(license_id: str) -> bool:
    return license_id in OPEN_CONTENT_LICENSES


def _check_git_source(source: dict[str, Any]) -> None:
    source_id = source["id"]
    if not re.fullmatch(r"[0-9a-f]{40}", source.get("commit", "")):
        raise ValueError(f"{source_id}: commit must be a full 40-hex SHA")
    if not isinstance(source.get("url"), str) or not source["url"]:
        raise ValueError(f"{source_id}: url is required")
    paths = source.get("paths")
    if not isinstance(paths, list) or not paths or not all(isinstance(path, str) and path for path in paths):
        raise ValueError(f"{source_id}: paths must be a non-empty list of globs")
    for path in paths:
        if path.startswith("/") or ".." in PurePosixPath(path).parts:
            raise ValueError(f"{source_id}: path {path!r} must be relative to the repository root")


def _check_mediawiki_source(source: dict[str, Any]) -> None:
    source_id = source["id"]
    if not re.fullmatch(r"https://[a-z0-9.-]+", source.get("site", "")):
        raise ValueError(f"{source_id}: site must be an https origin without path")
    pages = source.get("pages")
    if not isinstance(pages, list) or not pages:
        raise ValueError(f"{source_id}: pages must be a non-empty list")
    titles, revids = set(), set()
    for page in pages:
        title, revid = page.get("title"), page.get("revid")
        if not isinstance(title, str) or not title.strip():
            raise ValueError(f"{source_id}: every page needs a title")
        if not isinstance(revid, int) or isinstance(revid, bool) or revid <= 0:
            raise ValueError(f"{source_id}: page {title!r} needs a positive integer revid")
        if title in titles or revid in revids:
            raise ValueError(f"{source_id}: duplicate page {title!r} / revision {revid}")
        titles.add(title)
        revids.add(revid)


def load_sources(path: Path = SOURCES_PATH) -> list[dict[str, Any]]:
    """Validated source entries of the pinned list."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != LIST_SCHEMA:
        raise ValueError(f"{path}: schema is not {LIST_SCHEMA}")
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError(f"{path}: no sources")
    seen_ids: set[str] = set()
    seen_pages: dict[tuple[str, str], str] = {}
    for source in sources:
        source_id = source.get("id", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", source_id):
            raise ValueError(f"{path}: invalid source id {source_id!r}")
        if source_id in seen_ids:
            raise ValueError(f"{path}: duplicate source {source_id!r}")
        seen_ids.add(source_id)
        if source.get("type") not in SOURCE_TYPES:
            raise ValueError(f"{source_id}: type must be one of {SOURCE_TYPES}")
        if source.get("split") not in SPLITS:
            raise ValueError(f"{source_id}: split must be one of {SPLITS}")
        if source.get("lang") not in LANGS:
            raise ValueError(f"{source_id}: lang must be one of {LANGS}")
        if source.get("genre") not in GENRES:
            raise ValueError(f"{source_id}: genre must be one of {GENRES}")
        if not is_open_content_license(source.get("license", "")):
            raise ValueError(f"{source_id}: license {source.get('license')!r} is not public domain or CC (BY, BY-SA)")
        digest = source.get("sha256")
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{source_id}: sha256 must be 64 lowercase hex characters or null")
        if source["type"] == "git":
            _check_git_source(source)
            continue
        _check_mediawiki_source(source)
        for page in source["pages"]:
            for key in (("title", page["title"]), ("revid", str(page["revid"]))):
                owner = seen_pages.setdefault((source["site"], *key), source_id)
                if owner != source_id:
                    raise ValueError(f"{source_id}: duplicate page {page['title']!r} (also in {owner})")
    return sources


# ── text extraction ──────────────────────────────────────────────────────────


_NESTED = (
    (re.compile(r"\{\{(?:(?!\{\{|\}\}).)*\}\}", re.DOTALL), ""),  # templates, innermost first
    (re.compile(r"\{\|(?:(?!\{\||\|\}).)*\|\}", re.DOTALL), ""),  # tables, innermost first
    (re.compile(r"\[\[[^\[\]]*\]\]"), None),  # wiki links, innermost first
)
_MEDIA_PREFIX = re.compile(r"^\s*:?\s*(?:file|image|datei|bild|category|kategorie|media)\s*:", re.IGNORECASE)
_INTERLANGUAGE = re.compile(r"^[a-z]{2,3}(?:-[a-z]+)*:[^|]*$")
_DROPPED_ELEMENTS = re.compile(
    r"<(ref|gallery|math|chem|score|timeline|graph|mapframe|syntaxhighlight|source|pre|code|templatedata|imagemap)"
    r"\b[^>]*?(?<!/)>.*?</\1\s*>",
    re.DOTALL | re.IGNORECASE,
)


def _link(match: re.Match[str]) -> str:
    inner = match.group(0)[2:-2]
    if _MEDIA_PREFIX.match(inner) or _INTERLANGUAGE.match(inner):
        return ""
    target, _, label = inner.partition("|")
    return (label or target.split("#")[0] or target).strip()


def wikitext_to_text(wikitext: str) -> str:
    """Plain prose from MediaWiki markup (deterministic, markup that does not close is kept)."""
    text = re.sub(r"<!--.*?-->", "", wikitext, flags=re.DOTALL)
    text = re.sub(r"</?(?:translate|languages|tvar)\b[^>]*>", "", text)
    text = _DROPPED_ELEMENTS.sub("", text)
    text = re.sub(r"<ref\b[^>]*/>", "", text, flags=re.IGNORECASE)
    for pattern, replacement in _NESTED:
        while True:
            text, count = pattern.subn(_link if replacement is None else replacement, text)
            if not count:
                break
    text = re.sub(r"\[(?:(?:https?:)?//[^\s\]]*)?\s+([^\[\]]+)\]", r"\1", text)  # [url label]
    text = re.sub(r"\[(?:https?:)?//[^\s\]]*\]", "", text)  # bare [url]
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</?[a-zA-Z][^<>]*>", "", text)  # remaining tags, content kept
    text = re.sub(r"__[A-Z]+__", "", text)
    text = re.sub(r"'{2,}", "", text)
    lines = []
    for line in text.split("\n"):
        line = re.sub(r"^(=+)\s*(.*?)\s*\1\s*$", r"\2", line)
        line = re.sub(r"^[*#:;]+\s*", "", line)
        lines.append(html.unescape(line).strip())
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    return text + "\n" if text else ""


def markdown_text(text: str) -> str:
    """Markdown as in the source, without a leading Jekyll/YAML front matter block."""
    match = re.match(r"---\n.*?\n---\n", text, re.DOTALL)
    return text[match.end() :].lstrip("\n") if match else text


# ── fetching ─────────────────────────────────────────────────────────────────


class RetryableError(Exception):
    """HTTP 429/5xx or a network error; the request is retried."""


def _open_url(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code == 429 or error.code >= 500:
            raise RetryableError(f"HTTP {error.code} for {url}") from error
        raise ValueError(f"HTTP {error.code} for {url}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise RetryableError(f"{error} for {url}") from error


def fetch_url(url: str) -> bytes:
    """GET with exponential backoff on rate limits and server errors."""
    for attempt in range(RETRIES):
        try:
            return _open_url(url)
        except RetryableError as error:
            if attempt == RETRIES - 1:
                raise ValueError(str(error)) from error
            time.sleep(5 * 2**attempt)
    raise AssertionError("unreachable")


def _complete(directory: Path, key: str) -> bool:
    marker = directory / "ark-complete"
    return marker.is_file() and marker.read_text() == key


def _key(source: dict[str, Any]) -> str:
    fields = ("url", "commit", "paths") if source["type"] == "git" else ("site", "pages")
    return hashlib.sha256(json.dumps([source[field] for field in fields], sort_keys=True).encode()).hexdigest()


def _ls_tree(git_dir: Path, commit: str) -> list[tuple[str, str]]:
    """``(path, blob oid)`` of regular files at ``commit``; needs no blob contents."""
    out = git(["ls-tree", "-r", "-z", "--full-tree", commit], git_dir)
    entries = []
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, kind, oid = meta.split()
        if kind == b"blob" and mode in (b"100644", b"100755"):
            entries.append((path.decode("utf-8", "surrogateescape"), oid.decode()))
    return entries


def _selected(source: dict[str, Any], entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    selected = [
        (path, oid)
        for path, oid in entries
        if path.lower().endswith(TEXT_SUFFIXES) and any(fnmatch.fnmatchcase(path, glob) for glob in source["paths"])
    ]
    if not selected:
        raise ValueError(f"{source['id']}: paths {source['paths']} matches no file at {source['commit']}")
    return selected


def fetch_git(source: dict[str, Any], cache: Path, offline: bool = False) -> Path:
    """Bare git dir with the pinned tree and only the selected blobs (partial fetch)."""
    git_dir = cache / source["id"] / "files.git"
    if _complete(git_dir, _key(source)):
        return git_dir
    if offline:
        raise ValueError(f"{source['id']}: {git_dir} is not cached (--offline)")
    if git_dir.exists():
        shutil.rmtree(git_dir)
    git_dir.parent.mkdir(parents=True, exist_ok=True)
    git(["init", "--quiet", "--bare", str(git_dir)])
    fetch = ["fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--filter=blob:none"]
    git([*fetch, "--depth=1", source["url"], source["commit"]], git_dir)
    git(["cat-file", "-e", f"{source['commit']}^{{commit}}"], git_dir)
    entries = _ls_tree(git_dir, source["commit"])
    wanted = [oid for path, oid in entries if "/" not in path and LICENSE_FILE.match(path)]
    wanted += [oid for _, oid in _selected(source, entries)]
    wanted = sorted(set(wanted))
    for start in range(0, len(wanted), 500):
        git([*fetch, source["url"], *wanted[start : start + 500]], git_dir)
    # A filtered fetch registers the URL as promisor remote; without it, reads never go online.
    git(["config", "--remove-section", f"remote.{source['url']}"], git_dir)
    (git_dir / "ark-complete").write_text(_key(source))
    return git_dir


def _api_titles(site: str, revids: list[int]) -> dict[int, str]:
    query = urllib.parse.urlencode(
        {"action": "query", "prop": "revisions", "rvprop": "ids", "revids": "|".join(map(str, revids)),
         "format": "json", "formatversion": "2"}
    )  # fmt: skip
    data = json.loads(fetch_url(f"{site}/w/api.php?{query}"))
    titles = {}
    for page in data.get("query", {}).get("pages", []):
        for revision in page.get("revisions", []):
            titles[revision["revid"]] = page["title"]
    return titles


def fetch_mediawiki(source: dict[str, Any], cache: Path, offline: bool = False) -> dict[int, bytes]:
    """Raw wikitext per pinned revision; each revision's page title is checked against the list."""
    directory = cache / source["id"]
    key = _key(source)
    revids = [page["revid"] for page in source["pages"]]
    if not _complete(directory, key):
        if offline:
            raise ValueError(f"{source['id']}: {directory} is not cached (--offline)")
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        site = source["site"]
        titles: dict[int, str] = {}
        for start in range(0, len(revids), API_BATCH):
            titles.update(_api_titles(site, revids[start : start + API_BATCH]))
            time.sleep(REQUEST_DELAY_SECONDS)
        for page in source["pages"]:
            found = titles.get(page["revid"])
            if found is None:
                raise ValueError(f"{source['id']}: revision {page['revid']} ({page['title']!r}) does not exist on {site}")
            if found != page["title"]:
                raise ValueError(f"{source['id']}: revision {page['revid']} belongs to {found!r}, not {page['title']!r}")
        for revid in revids:
            raw = fetch_url(f"{site}/w/index.php?" + urllib.parse.urlencode({"action": "raw", "oldid": revid}))
            (directory / f"{revid}.wiki").write_bytes(raw)
            time.sleep(REQUEST_DELAY_SECONDS)
        (directory / "ark-complete").write_text(key)
    return {revid: (directory / f"{revid}.wiki").read_bytes() for revid in revids}


# ── documents ────────────────────────────────────────────────────────────────


def _order(source_id: str, name: str) -> str:
    return hashlib.sha256(f"{source_id}:{name}".encode("utf-8", "surrogateescape")).hexdigest()


def _document(source: dict[str, Any], name: str, url: str, text: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"{source['id']}:{name}",
        "source": source["id"],
        "lang": source["lang"],
        "genre": source["genre"],
        "license": source["license"],
        "url": url,
        **extra,
        "text": text,
    }


def source_documents(source: dict[str, Any], cache: Path, offline: bool = False) -> tuple[list[dict[str, Any]], int, str | None]:
    """Selected documents of one source, the number of skipped candidates and the license file."""
    candidates: list[dict[str, Any]] = []
    license_file = None
    if source["type"] == "git":
        git_dir = fetch_git(source, cache, offline)
        entries = _ls_tree(git_dir, source["commit"])
        license_file = next((path for path, _ in sorted(entries) if "/" not in path and LICENSE_FILE.match(path)), None)
        selected = _selected(source, entries)
        base = source["url"].removesuffix(".git")
        for (path, _), blob in zip(selected, BENIGN_CODE._blobs(git_dir, [oid for _, oid in selected])):
            text = BENIGN_CODE.decode_text(blob)
            url = f"{base}/blob/{source['commit']}/{urllib.parse.quote(path)}"
            candidates.append(_document(source, path, url, markdown_text(text) if text else "", path=path))
    else:
        raw = fetch_mediawiki(source, cache, offline)
        for page in source["pages"]:
            text = BENIGN_CODE.decode_text(raw[page["revid"]])
            url = f"{source['site']}/w/index.php?oldid={page['revid']}"
            extra = {"title": page["title"], "revid": page["revid"]}
            candidates.append(_document(source, page["title"], url, wikitext_to_text(text) if text else "", **extra))
    candidates.sort(key=lambda doc: _order(source["id"], doc["id"]))
    documents, used = [], 0
    for doc in candidates:
        size = len(doc["text"].encode("utf-8"))
        if len(doc["text"].strip()) < MIN_DOC_CHARS or size > MAX_DOC_BYTES or used + size > SOURCE_BUDGET_BYTES:
            continue
        used += size
        documents.append(doc)
    documents.sort(key=lambda doc: doc["id"])
    return documents, len(candidates) - len(documents), license_file


def build_source(source: dict[str, Any], cache: Path, offline: bool = False) -> tuple[bytes, dict[str, Any]]:
    """JSONL bytes and manifest entry of one source (not yet checked against the pin)."""
    documents, skipped, license_file = source_documents(source, cache, offline)
    if source["type"] == "git" and license_file is None:
        raise ValueError(f"{source['id']}: no license file in the repository root at {source['commit']}")
    if not documents:
        raise ValueError(f"{source['id']}: no documents left after the size limits")
    data = BENIGN_CODE._jsonl(documents)
    entry: dict[str, Any] = {"id": source["id"], "type": source["type"]}
    if source["type"] == "git":
        entry.update(url=source["url"], commit=source["commit"], paths=source["paths"], license_file=license_file)
    else:
        entry.update(site=source["site"], pages=len(source["pages"]))
    entry.update(
        license=source["license"],
        lang=source["lang"],
        genre=source["genre"],
        split=source["split"],
        file=f"{source['id']}.jsonl",
        sha256=_sha256(data),
        documents=len(documents),
        skipped=skipped,
        bytes=sum(len(doc["text"].encode("utf-8")) for doc in documents),
    )
    return data, entry


# ── output ───────────────────────────────────────────────────────────────────


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity(source: dict[str, Any], doc: dict[str, Any]) -> str:
    if source["type"] == "git":
        return f"{source['url'].removesuffix('.git')}:{doc['path']}"
    return f"{source['site']}:{doc['title']}"


def build_splits(
    sources: list[dict[str, Any]], cache: Path, offline: bool = False, require_pins: bool = True
) -> dict[str, dict[str, bytes]]:
    """``{split: {file name: content}}`` including ``manifest.json`` and ``.ready``."""
    built: dict[str, list[tuple[bytes, dict[str, Any]]]] = {split: [] for split in SPLITS}
    owners: dict[str, str] = {}
    texts: dict[str, str] = {}
    for source in sources:
        data, entry = build_source(source, cache, offline)
        if source.get("sha256") is None:
            if require_pins:
                raise ValueError(f"{source['id']}: no pinned sha256 (run the pin subcommand)")
        elif entry["sha256"] != source["sha256"]:
            raise ValueError(f"{source['id']}: corpus SHA-256 {entry['sha256']}, pinned {source['sha256']}")
        for doc in map(json.loads, data.decode("utf-8").splitlines()):
            identity = _identity(source, doc)
            if owners.setdefault(identity, source["id"]) != source["id"]:
                name = doc.get("path") or doc["title"]
                raise ValueError(f"{name} is in more than one source ({owners[identity]}, {source['id']})")
            digest = _sha256(doc["text"].encode("utf-8"))
            split = texts.setdefault(digest, source["split"])
            if split != source["split"]:
                raise ValueError(f"{doc['id']}: the same text in dev and holdout")
        built[source["split"]].append((data, entry))
    outputs = {}
    for split in SPLITS:
        entries = [entry for _, entry in built[split]]
        tables: dict[str, dict[str, dict[str, int]]] = {"by_lang": {}, "by_genre": {}, "by_lang_genre": {}}
        for entry in entries:
            for table, name in (
                ("by_lang", entry["lang"]),
                ("by_genre", entry["genre"]),
                ("by_lang_genre", f"{entry['lang']}/{entry['genre']}"),
            ):
                stat = tables[table].setdefault(name, {"documents": 0, "bytes": 0})
                stat["documents"] += entry["documents"]
                stat["bytes"] += entry["bytes"]
        missing = [f"{lang}/{genre}" for lang in LANGS for genre in GENRES if f"{lang}/{genre}" not in tables["by_lang_genre"]]
        if missing:
            raise ValueError(f"{split} split has no {', '.join(missing)} documents")
        files = {entry["file"]: data for data, entry in built[split]}
        manifest = BENIGN_CODE._manifest_bytes(
            {
                "schema": SCHEMA,
                "split": split,
                "split_rule": "by source (field split of scripts/l1_dlp/benign_docs_sources.json)",
                "metric": "every reported span and every flagged document is a false positive",
                "limits": {
                    "min_doc_chars": MIN_DOC_CHARS,
                    "max_doc_bytes": MAX_DOC_BYTES,
                    "source_budget_bytes": SOURCE_BUDGET_BYTES,
                },
                "sources": entries,
                "documents": sum(entry["documents"] for entry in entries),
                "bytes": sum(entry["bytes"] for entry in entries),
                **{table: dict(sorted(stats.items())) for table, stats in tables.items()},
            }
        )
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
    for source in manifest.get("sources", []):
        path = directory / source["file"]
        if not path.is_file():
            problems.append(f"{path} is missing")
        elif _sha256(path.read_bytes()) != source["sha256"]:
            problems.append(f"{path} does not match its SHA-256 in manifest.json")
    return problems


def default_source_dir(holdout_out: Path) -> Path:
    return holdout_out / ".sources" / "benign_docs"


def prepare(
    dev_out: Path,
    holdout_out: Path,
    source_dir: Path | None = None,
    sources_path: Path = SOURCES_PATH,
    offline: bool = False,
    force: bool = False,
) -> int:
    """Write both splits; 0 on success or an unchanged frozen split, 1 on any problem."""
    source_dir = default_source_dir(holdout_out) if source_dir is None else source_dir
    dev, holdout, cache = (path.resolve() for path in (dev_out, holdout_out, source_dir))
    try:
        if dev == holdout or dev.is_relative_to(holdout) or holdout.is_relative_to(dev):
            raise ValueError("--dev-out and --holdout-out must be separate, non-nested directories")
        if cache.is_relative_to(dev):
            raise ValueError("--sources must not be inside --dev-out: the caches hold holdout documents")
        outputs = build_splits(load_sources(sources_path), cache, offline)
    except (ValueError, OSError, KeyError) as error:
        print(f"benign_docs: {error}", file=sys.stderr)
        return 1

    pending = {}
    for split, directory in (("dev", dev), ("holdout", holdout)):
        if (directory / READY).exists():
            manifest = (directory / "manifest.json").read_bytes() if (directory / "manifest.json").is_file() else b""
            if not check_split(directory) and manifest == outputs[split]["manifest.json"]:
                continue
            if not force:
                print(
                    f"benign_docs: {split} split in {directory} is frozen and differs from this run "
                    "(or was modified); nothing written. Use --force to replace it.",
                    file=sys.stderr,
                )
                return 1
        pending[split] = directory
    for split, directory in pending.items():
        BENIGN_CODE._write(directory, outputs[split])

    dev_manifest = json.loads(outputs["dev"]["manifest.json"])
    for source in dev_manifest["sources"]:
        print(f"dev {source['id']}: {source['documents']} documents, {source['bytes']} bytes")
    for split, directory in (("dev", dev), ("holdout", holdout)):
        state = "written" if split in pending else "unchanged (frozen)"
        print(f"{split}: {state} in {directory}, manifest sha256 {_sha256(outputs[split]['manifest.json'])}")
    return 0


def pin(source_dir: Path, sources_path: Path = SOURCES_PATH, write: bool = False, offline: bool = False) -> int:
    """Build every source and report (or write) its SHA-256; prints no corpus content."""
    data = json.loads(sources_path.read_text(encoding="utf-8"))
    load_sources(sources_path)
    changed = 0
    for source in data["sources"]:
        _, entry = build_source(source, source_dir.resolve(), offline)
        state = "ok" if source.get("sha256") == entry["sha256"] else "changed"
        changed += state == "changed"
        print(f"{source['split']} {source['id']}: {entry['documents']} documents, {entry['sha256']} {state}")
        source["sha256"] = entry["sha256"]
    if write and changed:
        sources_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if write or not changed else 1


# ── FP report ────────────────────────────────────────────────────────────────


def load_corpus(directory: Path) -> dict[str, dict[str, Any]]:
    """``{document id: {source, lang, genre, bytes}}`` of a checked split directory."""
    problems = check_split(directory)
    if problems:
        raise ValueError("; ".join(problems))
    manifest = json.loads((directory / "manifest.json").read_bytes())
    documents = {}
    for source in manifest["sources"]:
        with (directory / source["file"]).open(encoding="utf-8") as handle:
            for line in handle:
                doc = json.loads(line)
                documents[doc["id"]] = {
                    "source": doc["source"],
                    "lang": doc["lang"],
                    "genre": doc["genre"],
                    "bytes": len(doc["text"].encode("utf-8")),
                }
    return documents


def _ratio(count: int, total: int) -> float:
    return round(count / total, 4) if total else 0.0


def fp_report(documents: dict[str, dict[str, Any]], predictions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """FP/MB of spans and the rate of flagged documents, in total and per rule, language, genre and source.

    ``predictions`` rows carry ``id``, ``evidence_spans`` (``start_char``, ``end_char`` and
    ``rule_id`` or ``label``) and optionally ``document_labels`` (document-level classes).
    A span counts once per document even if several rules report it; a document counts as
    flagged if it has a span or a document label. Repeated rows for the same document
    (concatenated detector outputs, retries) are merged: per rule, a span counts once per
    document and a document counts once.
    """
    spans: dict[str, set[tuple[int, int]]] = {}
    flagged: set[str] = set()
    rule_span_keys: set[tuple[str, str, tuple[int, int]]] = set()
    rule_doc_keys: set[tuple[str, str]] = set()
    for row in predictions:
        doc_id = row.get("id")
        if doc_id not in documents:
            raise ValueError(f"prediction for unknown document {doc_id!r}")
        rules: set[str] = {str(label) for label in row.get("document_labels") or []}
        for span in row.get("evidence_spans") or []:
            key = (int(span["start_char"]), int(span["end_char"]))
            rule = str(span.get("rule_id") or span.get("label") or "unknown")
            spans.setdefault(doc_id, set()).add(key)
            rule_span_keys.add((rule, doc_id, key))
            rules.add(rule)
        rule_doc_keys.update((rule, doc_id) for rule in rules)
        if rules:
            flagged.add(doc_id)
    rule_spans: Counter[str] = Counter(rule for rule, _, _ in rule_span_keys)
    rule_documents: Counter[str] = Counter(rule for rule, _ in rule_doc_keys)
    total_bytes = sum(doc["bytes"] for doc in documents.values())

    def stats(members: list[str]) -> dict[str, Any]:
        size = sum(documents[doc_id]["bytes"] for doc_id in members)
        fp = sum(len(spans.get(doc_id, ())) for doc_id in members)
        hits = len([doc_id for doc_id in members if doc_id in flagged])
        return {
            "bytes": size,
            "documents": len(members),
            "documents_flagged": hits,
            "flagged_rate": _ratio(hits, len(members)),
            "fp": fp,
            "fp_per_mb": BENIGN_CODE._rate(fp, size),
        }

    def table(field: str) -> dict[str, dict[str, Any]]:
        groups: dict[str, list[str]] = {}
        for doc_id, doc in documents.items():
            groups.setdefault(doc[field], []).append(doc_id)
        return {name: stats(members) for name, members in sorted(groups.items())}

    return {
        **stats(list(documents)),
        "by_lang": table("lang"),
        "by_genre": table("genre"),
        "by_source": table("source"),
        "by_rule": {
            rule: {
                "documents_flagged": rule_documents[rule],
                "flagged_rate": _ratio(rule_documents[rule], len(documents)),
                "fp": rule_spans[rule],
                "fp_per_mb": BENIGN_CODE._rate(rule_spans[rule], total_bytes),
            }
            for rule in sorted(rule_documents)
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="build and freeze the dev and holdout splits")
    prep.add_argument("--dev-out", type=Path, required=True, help="dev split directory (visible to agents)")
    prep.add_argument("--holdout-out", type=Path, required=True, help="holdout split directory (gate only)")
    prep.add_argument("--sources", type=Path, help="download cache (default: HOLDOUT/.sources/benign_docs)")
    prep.add_argument("--list", type=Path, default=SOURCES_PATH, help="pinned source list")
    prep.add_argument("--offline", action="store_true", help="never fetch; caches must be complete")
    prep.add_argument("--force", action="store_true", help="replace a frozen split that differs")
    check = commands.add_parser("check", help="verify a written split directory")
    check.add_argument("directory", type=Path)
    pins = commands.add_parser("pin", help="build every source and report its corpus SHA-256")
    pins.add_argument("--sources", type=Path, required=True, help="download cache")
    pins.add_argument("--list", type=Path, default=SOURCES_PATH, help="pinned source list")
    pins.add_argument("--offline", action="store_true", help="never fetch; caches must be complete")
    pins.add_argument("--write", action="store_true", help="write changed SHA-256 values into the list")
    score = commands.add_parser("fp-report", help="FP/MB and flagged-document rate of predictions on one split")
    score.add_argument("--corpus", type=Path, required=True, help="split directory written by prepare")
    score.add_argument("--predictions", type=Path, required=True, help="JSONL with id, evidence_spans, document_labels")
    score.add_argument("--output", type=Path, help="write the JSON report here instead of stdout")
    args = parser.parse_args(argv)

    if args.command == "prepare":
        return prepare(args.dev_out, args.holdout_out, args.sources, args.list, args.offline, args.force)
    if args.command == "check":
        problems = check_split(args.directory)
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(f"{args.directory}: split ok")
        return 1 if problems else 0
    try:
        if args.command == "pin":
            return pin(args.sources, args.list, args.write, args.offline)
        report = fp_report(load_corpus(args.corpus), BENIGN_CODE._read_jsonl(args.predictions))
    except (ValueError, OSError, KeyError) as error:
        print(f"benign_docs: {error}", file=sys.stderr)
        return 1
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
