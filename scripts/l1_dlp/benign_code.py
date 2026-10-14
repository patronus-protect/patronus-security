#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Benign-code corpus for the L1-DLP false-positive rate (FP/MB).

Permissively licensed repositories pinned to a commit in ``benign_code_repos.json`` are
fetched with git, their text files classified by kind (code, lockfile, minified_js, svg,
base64, plus the repository's ``git log`` as git_log) and written as one JSONL per
repository. The split is by repository: each entry names its split, so no repository
contributes to both. Each repository pins the SHA-256 of its JSONL; a build that does not
reproduce it is an error. Data stays on the VPS, never in the repo.

    python3 scripts/l1_dlp/benign_code.py prepare --dev-out DIR --holdout-out DIR
    python3 scripts/l1_dlp/benign_code.py check DIR
    python3 scripts/l1_dlp/benign_code.py fp-per-mb --corpus DIR --predictions FILE
    python3 scripts/l1_dlp/benign_code.py pin --sources DIR [--write]

``prepare`` follows ``scripts/l1_presidio/prepare_corpora.py``: each output directory gets
``<repo>.jsonl``, ``manifest.json`` (URL, commit, license, SHA-256, bytes and documents per
kind for every repository) and, written last, ``.ready``. A directory with ``.ready`` is
frozen: a rerun must reproduce it byte for byte, otherwise nothing is written and the exit
code is 1 (``--force`` replaces it). Git caches live in ``--sources`` (default
``HOLDOUT/.sources/benign_code``), never in the dev directory; stdout names only dev numbers.

FP/MB: the corpus is assumed to contain no secrets, so every distinct reported span is a
false positive. FP/MB = false positives / (UTF-8 bytes of the scanned text / 1,000,000).
Only the standard library and the git CLI are needed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
REPOS_PATH = HERE / "benign_code_repos.json"
SCHEMA = "ark-dlp-benign-code-v1"
LIST_SCHEMA = "ark-dlp-benign-code-repos-v1"
SPLITS = ("dev", "holdout")
KINDS = ("code", "lockfile", "minified_js", "svg", "base64", "git_log")
READY = ".ready"
MB = 1_000_000

# Selection limits (part of the pinned output: changing them changes every repo SHA-256).
MAX_FILE_BYTES = 2 * 1024 * 1024
KIND_BUDGET_BYTES = {
    "code": 4 * 1024 * 1024,
    "lockfile": 4 * 1024 * 1024,
    "minified_js": 4 * 1024 * 1024,
    "svg": 2 * 1024 * 1024,
    "base64": 4 * 1024 * 1024,
}
LOG_COMMITS = 1500
LOG_MAX_BYTES = 4 * 1024 * 1024
LOG_ID = "@git-log"

PERMISSIVE_LICENSES = frozenset(
    {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0", "Zlib"}
)
# Secret scanners and their rule/fixture repositories are excluded: their test data is
# made of secret look-alikes and would measure the baselines against their own fixtures.
SCANNER_KEYWORDS = (
    "secret", "leak", "credential", "trufflehog", "gitleaks", "kingfisher", "ggshield",
    "noseyparker", "nosey-parker", "talisman", "whispers", "shhgit", "repo-supervisor",
)  # fmt: skip
LOCKFILES = frozenset(
    {
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
        "Cargo.lock", "go.sum", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock",
        "Gemfile.lock", "composer.lock", "packages.lock.json", "gradle.lockfile", "mix.lock",
        "pubspec.lock", "Podfile.lock", "flake.lock",
    }
)  # fmt: skip
# Key material and credential files are skipped: a test key in a fixture is still key material.
EXCLUDED_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".crt", ".cer", ".der", ".csr",
    ".asc", ".gpg", ".pgp", ".kdbx", ".ppk",
)  # fmt: skip
EXCLUDED_NAMES = frozenset({".npmrc", ".pypirc", ".netrc", ".git-credentials", "credentials", ".htpasswd"})
EXCLUDED_NAME_PREFIXES = (".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
JS_SUFFIXES = (".js", ".mjs", ".cjs")
LICENSE_FILE = re.compile(r"^(?:LICEN[CS]E|COPYING|UNLICENSE)(?:[.-][A-Za-z0-9.-]+)?$", re.IGNORECASE)
BASE64_RUN = re.compile(r"base64,[A-Za-z0-9+/]{64,}|[A-Za-z0-9+/]{200,}={0,2}")

GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.devnull,
    "LC_ALL": "C",
    "TZ": "UTC",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
}
GIT_CONFIG = (
    "-c", "core.quotepath=on", "-c", "log.showsignature=false", "-c", "log.mailmap=false",
    "-c", "diff.renames=false", "-c", "color.ui=never", "-c", "protocol.file.allow=always",
)  # fmt: skip


# ── repository list ──────────────────────────────────────────────────────────


def is_permissive(expression: str) -> bool:
    """SPDX expression check: any ``OR`` alternative whose ``AND`` terms are all permissive."""
    alternatives = [part.strip("() ") for part in expression.split(" OR ")]
    return any(all(term.strip("() ") in PERMISSIVE_LICENSES for term in alt.split(" AND ")) for alt in alternatives)


def is_scanner_repo(url: str, repo_id: str) -> bool:
    text = f"{url} {repo_id}".lower()
    return any(keyword in text for keyword in SCANNER_KEYWORDS)


def load_repos(path: Path = REPOS_PATH) -> list[dict[str, Any]]:
    """Validated repository entries of the pinned list."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != LIST_SCHEMA:
        raise ValueError(f"{path}: schema is not {LIST_SCHEMA}")
    repos = data.get("repos")
    if not isinstance(repos, list) or not repos:
        raise ValueError(f"{path}: no repos")
    seen_ids, seen_urls = set(), set()
    for repo in repos:
        repo_id = repo.get("id", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", repo_id):
            raise ValueError(f"{path}: invalid repo id {repo_id!r}")
        if repo_id in seen_ids or repo.get("url") in seen_urls:
            raise ValueError(f"{path}: duplicate repo {repo_id!r}")
        seen_ids.add(repo_id)
        seen_urls.add(repo.get("url"))
        if repo.get("split") not in SPLITS:
            raise ValueError(f"{repo_id}: split must be one of {SPLITS}")
        if not re.fullmatch(r"[0-9a-f]{40}", repo.get("commit", "")):
            raise ValueError(f"{repo_id}: commit must be a full 40-hex SHA")
        if not is_permissive(repo.get("license", "")):
            raise ValueError(f"{repo_id}: license {repo.get('license')!r} is not permissive")
        if is_scanner_repo(repo.get("url", ""), repo_id):
            raise ValueError(f"{repo_id}: secret-scanner repositories are excluded")
        digest = repo.get("sha256")
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{repo_id}: sha256 must be 64 lowercase hex characters or null")
    return repos


# ── git ──────────────────────────────────────────────────────────────────────


def git(args: Iterable[str], git_dir: Path | None = None, stdin: bytes | None = None) -> bytes:
    command = ["git", *GIT_CONFIG]
    if git_dir is not None:
        command += ["--git-dir", str(git_dir)]
    result = subprocess.run([*command, *args], input=stdin, env=GIT_ENV, capture_output=True)
    if result.returncode:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {message}")
    return result.stdout


def _fetched(git_dir: Path, commit: str) -> bool:
    return (git_dir / "ark-complete").is_file() and (git_dir / "ark-complete").read_text() == commit


def fetch_repo(repo: dict[str, Any], cache: Path, offline: bool = False) -> tuple[Path, Path]:
    """Bare git dirs with the pinned tree (``files``) and its recent history (``log``)."""
    root = cache / repo["id"]
    dirs = {"files": root / "files.git", "log": root / "log.git"}
    options = {"files": ["--depth=1"], "log": [f"--depth={LOG_COMMITS + 1}", "--filter=blob:none"]}
    for name, git_dir in dirs.items():
        if _fetched(git_dir, repo["commit"]):
            continue
        if offline:
            raise ValueError(f"{repo['id']}: {git_dir} is not cached (--offline)")
        if git_dir.exists():
            shutil.rmtree(git_dir)
        git_dir.parent.mkdir(parents=True, exist_ok=True)
        git(["init", "--quiet", "--bare", str(git_dir)])
        git(["fetch", "--quiet", "--no-tags", *options[name], repo["url"], repo["commit"]], git_dir)
        git(["cat-file", "-e", f"{repo['commit']}^{{commit}}"], git_dir)
        (git_dir / "ark-complete").write_text(repo["commit"])
    return dirs["files"], dirs["log"]


def _blobs(git_dir: Path, oids: list[str]) -> list[bytes]:
    if not oids:
        return []
    out = git(["cat-file", "--batch"], git_dir, ("\n".join(oids) + "\n").encode())
    blobs, pos = [], 0
    for oid in oids:
        end = out.index(b"\n", pos)
        header = out[pos:end].split()
        if len(header) != 3 or header[0].decode() != oid or header[1] != b"blob":
            raise ValueError(f"unexpected git cat-file output for {oid}")
        size = int(header[2])
        blobs.append(out[end + 1 : end + 1 + size])
        pos = end + 2 + size
    return blobs


def tree_entries(git_dir: Path, commit: str) -> list[tuple[str, str, int]]:
    """``(path, blob oid, size)`` of regular files at ``commit``; symlinks and submodules skipped."""
    out = git(["ls-tree", "-r", "-z", "-l", "--full-tree", commit], git_dir)
    entries = []
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, kind, oid, size = meta.split()
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            continue
        entries.append((path.decode("utf-8", "surrogateescape"), oid.decode(), int(size)))
    return entries


def git_log(git_dir: Path, commit: str) -> str:
    out = git(
        [
            "log", f"-n{LOG_COMMITS}", "--no-decorate", "--no-mailmap", "--no-renames", "--no-color",
            "--encoding=UTF-8", "--format=fuller", "--date=iso-strict-local", "--name-status", commit,
        ],
        git_dir,
    )  # fmt: skip
    text = out.decode("utf-8", "replace")
    if len(text.encode("utf-8")) <= LOG_MAX_BYTES:
        return text
    kept, size = [], 0
    for block in re.split(r"(?m)^(?=commit [0-9a-f]{40}$)", text):
        size += len(block.encode("utf-8"))
        if size > LOG_MAX_BYTES:
            break
        kept.append(block)
    return "".join(kept)


# ── classification ───────────────────────────────────────────────────────────


def excluded(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if ".git" in parts or "node_modules" in parts:
        return True
    name = parts[-1]
    lower = name.lower()
    return (
        lower.endswith(EXCLUDED_SUFFIXES)
        or name in EXCLUDED_NAMES
        or lower.startswith(EXCLUDED_NAME_PREFIXES)
    )


def decode_text(data: bytes) -> str | None:
    """UTF-8 text without NUL bytes, else ``None`` (binary or other encodings are skipped)."""
    if b"\0" in data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text.removeprefix("﻿")


def _minified(text: str) -> bool:
    lines = text.splitlines() or [""]
    return max(map(len, lines)) >= 1000 and len(text) / len(lines) >= 200


def classify(path: str, text: str) -> str:
    name = PurePosixPath(path).name
    lower = name.lower()
    if name in LOCKFILES:
        return "lockfile"
    if lower.endswith(JS_SUFFIXES) and (".min." in lower or _minified(text)):
        return "minified_js"
    if lower.endswith(".svg"):
        return "svg"
    if BASE64_RUN.search(text):
        return "base64"
    return "code"


def _order(repo_id: str, path: str) -> str:
    return hashlib.sha256(f"{repo_id}:{path}".encode("utf-8", "surrogateescape")).hexdigest()


def repo_documents(repo: dict[str, Any], files_dir: Path, log_dir: Path) -> tuple[list[dict[str, Any]], str | None]:
    """Selected documents of one repository and its root license file."""
    entries = tree_entries(files_dir, repo["commit"])
    license_file = next(
        (path for path, _, _ in sorted(entries) if "/" not in path and LICENSE_FILE.match(path)), None
    )
    candidates = [
        (path, oid) for path, oid, size in entries if 0 < size <= MAX_FILE_BYTES and not excluded(path)
    ]
    candidates.sort(key=lambda item: _order(repo["id"], item[0]))
    used = Counter()
    documents = []
    for (path, _), blob in zip(candidates, _blobs(files_dir, [oid for _, oid in candidates])):
        text = decode_text(blob)
        try:
            path.encode("utf-8")
        except UnicodeEncodeError:
            continue
        if not text or not text.strip():
            continue
        kind = classify(path, text)
        size = len(text.encode("utf-8"))
        if used[kind] + size > KIND_BUDGET_BYTES[kind]:
            continue
        used[kind] += size
        documents.append({"id": f"{repo['id']}:{path}", "repo": repo["id"], "path": path, "kind": kind, "text": text})
    documents.sort(key=lambda doc: doc["path"])
    log = git_log(log_dir, repo["commit"])
    if log.strip():
        documents.append({"id": f"{repo['id']}:{LOG_ID}", "repo": repo["id"], "path": LOG_ID, "kind": "git_log", "text": log})
    return documents, license_file


# ── output ───────────────────────────────────────────────────────────────────


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonl(rows: list[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows).encode("utf-8")


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _kind_stats(documents: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    stats = {kind: {"documents": 0, "bytes": 0} for kind in KINDS}
    for doc in documents:
        stats[doc["kind"]]["documents"] += 1
        stats[doc["kind"]]["bytes"] += len(doc["text"].encode("utf-8"))
    return stats


def build_repo(repo: dict[str, Any], cache: Path, offline: bool = False) -> tuple[bytes, dict[str, Any]]:
    """JSONL bytes and manifest entry of one repository (not yet checked against the pin)."""
    files_dir, log_dir = fetch_repo(repo, cache, offline)
    documents, license_file = repo_documents(repo, files_dir, log_dir)
    if license_file is None:
        raise ValueError(f"{repo['id']}: no license file in the repository root at {repo['commit']}")
    data = _jsonl(documents)
    kinds = _kind_stats(documents)
    entry = {
        "id": repo["id"],
        "url": repo["url"],
        "commit": repo["commit"],
        "license": repo["license"],
        "license_file": license_file,
        "split": repo["split"],
        "file": f"{repo['id']}.jsonl",
        "sha256": _sha256(data),
        "documents": len(documents),
        "bytes": sum(stat["bytes"] for stat in kinds.values()),
        "kinds": kinds,
    }
    return data, entry


def build_splits(
    repos: list[dict[str, Any]], cache: Path, offline: bool = False, require_pins: bool = True
) -> dict[str, dict[str, bytes]]:
    """``{split: {file name: content}}`` including ``manifest.json`` and ``.ready``."""
    built: dict[str, list[tuple[bytes, dict[str, Any]]]] = {split: [] for split in SPLITS}
    for repo in repos:
        data, entry = build_repo(repo, cache, offline)
        if repo.get("sha256") is None:
            if require_pins:
                raise ValueError(f"{repo['id']}: no pinned sha256 (run the pin subcommand)")
        elif entry["sha256"] != repo["sha256"]:
            raise ValueError(f"{repo['id']}: corpus SHA-256 {entry['sha256']}, pinned {repo['sha256']}")
        built[repo["split"]].append((data, entry))
    outputs = {}
    for split in SPLITS:
        entries = [entry for _, entry in built[split]]
        totals = {kind: {"documents": 0, "bytes": 0} for kind in KINDS}
        for entry in entries:
            for kind, stat in entry["kinds"].items():
                totals[kind]["documents"] += stat["documents"]
                totals[kind]["bytes"] += stat["bytes"]
        missing = [kind for kind in KINDS if not totals[kind]["bytes"]]
        if missing:
            raise ValueError(f"{split} split has no {', '.join(missing)} documents")
        files = {entry["file"]: data for data, entry in built[split]}
        manifest = _manifest_bytes(
            {
                "schema": SCHEMA,
                "split": split,
                "split_rule": "by repository (field split of scripts/l1_dlp/benign_code_repos.json)",
                "metric": "FP/MB = distinct reported spans / (UTF-8 bytes of text / 1,000,000); every span is a FP",
                "limits": {
                    "max_file_bytes": MAX_FILE_BYTES,
                    "kind_budget_bytes": KIND_BUDGET_BYTES,
                    "log_commits": LOG_COMMITS,
                    "log_max_bytes": LOG_MAX_BYTES,
                },
                "repos": entries,
                "documents": sum(entry["documents"] for entry in entries),
                "bytes": sum(entry["bytes"] for entry in entries),
                "kinds": totals,
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
    for repo in manifest.get("repos", []):
        path = directory / repo["file"]
        if not path.is_file():
            problems.append(f"{path} is missing")
        elif _sha256(path.read_bytes()) != repo["sha256"]:
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
    return holdout_out / ".sources" / "benign_code"


def prepare(
    dev_out: Path,
    holdout_out: Path,
    source_dir: Path | None = None,
    repos_path: Path = REPOS_PATH,
    offline: bool = False,
    force: bool = False,
) -> int:
    """Write both splits; 0 on success or an unchanged frozen split, 1 on any problem."""
    source_dir = default_source_dir(holdout_out) if source_dir is None else source_dir
    dev, holdout, sources = (path.resolve() for path in (dev_out, holdout_out, source_dir))
    try:
        if dev == holdout or dev.is_relative_to(holdout) or holdout.is_relative_to(dev):
            raise ValueError("--dev-out and --holdout-out must be separate, non-nested directories")
        if sources.is_relative_to(dev):
            raise ValueError("--sources must not be inside --dev-out: the git caches hold holdout repositories")
        outputs = build_splits(load_repos(repos_path), sources, offline)
    except (ValueError, OSError, KeyError) as error:
        print(f"benign_code: {error}", file=sys.stderr)
        return 1

    pending = {}
    for split, directory in (("dev", dev), ("holdout", holdout)):
        if (directory / READY).exists():
            manifest = (directory / "manifest.json").read_bytes() if (directory / "manifest.json").is_file() else b""
            if not check_split(directory) and manifest == outputs[split]["manifest.json"]:
                continue
            if not force:
                print(
                    f"benign_code: {split} split in {directory} is frozen and differs from this run "
                    "(or was modified); nothing written. Use --force to replace it.",
                    file=sys.stderr,
                )
                return 1
        pending[split] = directory
    for split, directory in pending.items():
        _write(directory, outputs[split])

    dev_manifest = json.loads(outputs["dev"]["manifest.json"])
    for repo in dev_manifest["repos"]:
        print(f"dev {repo['id']}: {repo['documents']} documents, {repo['bytes']} bytes")
    for split, directory in (("dev", dev), ("holdout", holdout)):
        state = "written" if split in pending else "unchanged (frozen)"
        print(f"{split}: {state} in {directory}, manifest sha256 {_sha256(outputs[split]['manifest.json'])}")
    return 0


def pin(source_dir: Path, repos_path: Path = REPOS_PATH, write: bool = False, offline: bool = False) -> int:
    """Build every repository and report (or write) its SHA-256; prints no corpus content."""
    data = json.loads(repos_path.read_text(encoding="utf-8"))
    load_repos(repos_path)
    changed = 0
    for repo in data["repos"]:
        _, entry = build_repo(repo, source_dir.resolve(), offline)
        state = "ok" if repo.get("sha256") == entry["sha256"] else "changed"
        changed += state == "changed"
        print(f"{repo['split']} {repo['id']}: {entry['sha256']} {state}")
        repo["sha256"] = entry["sha256"]
    if write and changed:
        repos_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if write or not changed else 1


# ── FP/MB ────────────────────────────────────────────────────────────────────


def load_corpus(directory: Path) -> dict[str, dict[str, Any]]:
    """``{document id: {repo, kind, bytes}}`` of a checked split directory."""
    problems = check_split(directory)
    if problems:
        raise ValueError("; ".join(problems))
    manifest = json.loads((directory / "manifest.json").read_bytes())
    documents = {}
    for repo in manifest["repos"]:
        with (directory / repo["file"]).open(encoding="utf-8") as handle:
            for line in handle:
                doc = json.loads(line)
                documents[doc["id"]] = {
                    "repo": doc["repo"],
                    "kind": doc["kind"],
                    "bytes": len(doc["text"].encode("utf-8")),
                }
    return documents


def _rate(count: int, size: int) -> float:
    return round(count / (size / MB), 4) if size else 0.0


def fp_per_mb(documents: dict[str, dict[str, Any]], predictions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """FP/MB in total, per kind, per repository and per rule.

    ``predictions`` rows carry ``id`` and ``evidence_spans`` (``start_char``, ``end_char`` and
    ``rule_id`` or ``label``). A span counts once per document even if several rules report it;
    the per-rule numbers count each rule separately and are normalized by the total bytes.
    """
    spans: dict[str, set[tuple[int, int]]] = {}
    rules: Counter[str] = Counter()
    for row in predictions:
        doc_id = row.get("id")
        if doc_id not in documents:
            raise ValueError(f"prediction for unknown document {doc_id!r}")
        seen_rules = set()
        for span in row.get("evidence_spans") or []:
            key = (int(span["start_char"]), int(span["end_char"]))
            spans.setdefault(doc_id, set()).add(key)
            seen_rules.add((str(span.get("rule_id") or span.get("label") or "unknown"), key))
        rules.update(rule for rule, _ in seen_rules)
    total_bytes = sum(doc["bytes"] for doc in documents.values())
    groups: dict[str, dict[str, Counter[str]]] = {"kind": {}, "repo": {}}
    for field, counters in groups.items():
        for doc_id, doc in documents.items():
            counter = counters.setdefault(doc[field], Counter())
            counter["bytes"] += doc["bytes"]
            counter["documents"] += 1
            counter["fp"] += len(spans.get(doc_id, ()))
    total_fp = sum(len(found) for found in spans.values())

    def table(counters: dict[str, Counter[str]]) -> dict[str, dict[str, Any]]:
        return {
            name: {"bytes": c["bytes"], "documents": c["documents"], "fp": c["fp"], "fp_per_mb": _rate(c["fp"], c["bytes"])}
            for name, c in sorted(counters.items())
        }

    return {
        "bytes": total_bytes,
        "documents": len(documents),
        "documents_with_fp": len([found for found in spans.values() if found]),
        "fp": total_fp,
        "fp_per_mb": _rate(total_fp, total_bytes),
        "by_kind": table(groups["kind"]),
        "by_repo": table(groups["repo"]),
        "by_rule": {rule: {"fp": count, "fp_per_mb": _rate(count, total_bytes)} for rule, count in sorted(rules.items())},
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="build and freeze the dev and holdout splits")
    prep.add_argument("--dev-out", type=Path, required=True, help="dev split directory (visible to agents)")
    prep.add_argument("--holdout-out", type=Path, required=True, help="holdout split directory (gate only)")
    prep.add_argument("--sources", type=Path, help="git cache (default: HOLDOUT/.sources/benign_code)")
    prep.add_argument("--repos", type=Path, default=REPOS_PATH, help="pinned repository list")
    prep.add_argument("--offline", action="store_true", help="never fetch; git caches must be complete")
    prep.add_argument("--force", action="store_true", help="replace a frozen split that differs")
    check = commands.add_parser("check", help="verify a written split directory")
    check.add_argument("directory", type=Path)
    pins = commands.add_parser("pin", help="build every repository and report its corpus SHA-256")
    pins.add_argument("--sources", type=Path, required=True, help="git cache")
    pins.add_argument("--repos", type=Path, default=REPOS_PATH, help="pinned repository list")
    pins.add_argument("--offline", action="store_true", help="never fetch; git caches must be complete")
    pins.add_argument("--write", action="store_true", help="write changed SHA-256 values into the list")
    score = commands.add_parser("fp-per-mb", help="FP/MB of predictions on one split")
    score.add_argument("--corpus", type=Path, required=True, help="split directory written by prepare")
    score.add_argument("--predictions", type=Path, required=True, help="JSONL with id and evidence_spans")
    score.add_argument("--output", type=Path, help="write the JSON report here instead of stdout")
    args = parser.parse_args(argv)

    if args.command == "prepare":
        return prepare(args.dev_out, args.holdout_out, args.sources, args.repos, args.offline, args.force)
    if args.command == "check":
        problems = check_split(args.directory)
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(f"{args.directory}: split ok")
        return 1 if problems else 0
    try:
        if args.command == "pin":
            return pin(args.sources, args.repos, args.write, args.offline)
        report = fp_per_mb(load_corpus(args.corpus), _read_jsonl(args.predictions))
    except (ValueError, OSError, KeyError) as error:
        print(f"benign_code: {error}", file=sys.stderr)
        return 1
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
