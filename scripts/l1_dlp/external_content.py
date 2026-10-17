#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""External content goldens for the DLP scoreboard (gitleaks Go, SchemaPile SQL), dev only.

Builds the ``external/`` component of the dev split from the two admitted sources of
``python/patronus_ark/benchmark_data/external_dlp/manifest.json`` and scores predictions on it
under the document-label contract of ``docs/research/dlp-external-content-contract-0.1.8.md``:

* ``gitleaks-go.jsonl``: every UTF-8 ``.go`` file of gitleaks at the pinned commit is a
  ``content.source_code`` document and a ``content.sql`` negative; the Markdown files are
  ``content.source_code`` negatives. Document labels only, no span Gold.
* ``schemapile-sql.jsonl``: one row per SchemaPile-Perm SQL file holding the first 250
  terminated statements of the archive; each statement is an exact ``content.sql`` evidence
  span, and ``scope`` ends after the last selected statement of the file.

A predicted document label needs an in-scope evidence span of that class (attach); classes a
row does not list in ``judged`` / ``span_judged`` are not scored on it (scope).

    python3 scripts/l1_dlp/external_content.py prepare --out DEV/external   # [--sources DIR] [--offline] [--force]
    python3 scripts/l1_dlp/external_content.py check DIR
    python3 scripts/l1_dlp/external_content.py score --corpus DIR --predictions FILE   # [--output FILE]

The sources are public and never part of the holdout: gitleaks ships secret rules and test
values, so it is no neutral code corpus. Only the standard library and git are needed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ADAPTER_PATH = ROOT / "python" / "patronus_ark" / "external_dlp_eval.py"
CONTRACT = "docs/research/dlp-external-content-contract-0.1.8.md"


def _load_file(name: str, path: Path) -> ModuleType:
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


BENIGN_CODE = _load_file("_ark_l1_dlp_benign_code", HERE / "benign_code.py")
# Stdlib only; loaded by path so the native module is never imported.
ADAPTER = _load_file("_ark_external_dlp_eval", ADAPTER_PATH)

SCHEMA = "ark-dlp-external-content-v1"
READY = ".ready"
GITLEAKS = "gitleaks-go-source-v8"
SCHEMAPILE = "schemapile-perm-sql-v1"
SOURCE_CODE = "content.source_code"
SQL = "content.sql"
# Entity group of a class in research/dlp/entity_map.yaml (the ARK span label).
GROUPS = {SOURCE_CODE: "dlp.content.source_code", SQL: "dlp.content.sql"}
FILES = {GITLEAKS: "gitleaks-go.jsonl", SCHEMAPILE: "schemapile-sql.jsonl"}
ARCHIVE = "schemapile-perm-sqlfiles.tar.gz"
# Source pins of the adapter manifest copied into the component manifest.
SOURCE_PINS = ("revision", "license_file_sha256", "source_revision", "verified_sha256", "published_md5")
# SHA-256 of the normalized JSONL per corpus; a build that differs is not written.
PINNED_SHA256 = {
    GITLEAKS: "48c6b751e9e5ec8f43d20acc800c3ba71e757ae83bc42a3fc6ebc44330f57aa7",
    SCHEMAPILE: "bae052c704dd69c2005e3926d31b43e9e926e0b9761ccf626257255191a29137",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ready(manifest: bytes) -> bytes:
    return f"{_sha256(manifest)}  manifest.json\n".encode("utf-8")


# ── sources ──────────────────────────────────────────────────────────────────


def fetch_gitleaks(corpus: dict[str, Any], cache: Path, offline: bool = False) -> Path:
    """Checkout of the pinned gitleaks commit (a shallow fetch of that commit only)."""
    root = cache / "gitleaks"
    marker = root / ".git" / "ark-complete"
    if marker.is_file() and marker.read_text(encoding="utf-8") == corpus["revision"]:
        return root
    if offline:
        raise ValueError(f"{GITLEAKS}: {root} is not cached (--offline)")
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    git_dir = root / ".git"
    BENIGN_CODE.git(["init", "--quiet", str(root)])
    BENIGN_CODE.git(["fetch", "--quiet", "--no-tags", "--depth=1", corpus["source"], corpus["revision"]], git_dir)
    BENIGN_CODE.git(["--work-tree", str(root), "checkout", "--quiet", "--detach", corpus["revision"]], git_dir)
    marker.write_text(corpus["revision"], encoding="utf-8")
    return root


def fetch_schemapile(corpus: dict[str, Any], cache: Path, offline: bool = False) -> Path:
    """The pinned SchemaPile-Perm archive, verified by SHA-256 and the published MD5."""
    path = cache / ARCHIVE

    def verified() -> bool:
        if not path.is_file():
            return False
        sha, md5 = hashlib.sha256(), hashlib.md5()  # noqa: S324 - MD5 is the publisher's checksum
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                sha.update(block)
                md5.update(block)
        return sha.hexdigest() == corpus["verified_sha256"] and md5.hexdigest() == corpus["published_md5"]

    if verified():
        return path
    if offline:
        raise ValueError(f"{SCHEMAPILE}: {path} is not cached (--offline)")
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".part")
    request = urllib.request.Request(corpus["source"], headers={"User-Agent": "patronus-ark-l1-dlp-eval"})
    with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as handle:  # noqa: S310
        shutil.copyfileobj(response, handle, 1 << 20)
    partial.replace(path)
    if not verified():
        path.unlink()
        raise ValueError(f"{SCHEMAPILE}: downloaded archive does not match its SHA-256/MD5 pin")
    return path


# ── rows ─────────────────────────────────────────────────────────────────────


def gitleaks_rows(root: Path, manifest_path: Path = ADAPTER.MANIFEST_PATH) -> list[dict[str, Any]]:
    """Document rows: Go files are source code and no SQL, Markdown files are no source code."""
    rows = []
    for row in ADAPTER.normalize_git_tree(root, GITLEAKS, manifest_path):
        go = row["document_label"] is not None
        rows.append({
            "id": row["id"],
            "corpus": GITLEAKS,
            "path": row["source_path"],
            "kind": "go" if go else "markdown",
            "text": row["text"],
            "document_labels": [SOURCE_CODE] if go else [],
            "judged": [SOURCE_CODE, SQL] if go else [SOURCE_CODE],
            "span_judged": [],
            "scope": [0, len(row["text"])],
            "entities": [],
        })
    return rows


def schemapile_rows(archive: Path, manifest_path: Path = ADAPTER.MANIFEST_PATH) -> list[dict[str, Any]]:
    """One row per SQL file with its selected statements as exact evidence spans."""
    statements: dict[str, list[tuple[int, int]]] = defaultdict(list)
    texts: dict[str, str] = {}
    for row in ADAPTER.normalize_sql_archive(archive, SCHEMAPILE, manifest_path):
        entity = row["entities"][0]
        statements[row["source_path"]].append((int(entity["start"]), int(entity["end"])))
        texts[row["source_path"]] = row["text"]
    rows = []
    for path, spans in statements.items():  # archive order
        text = texts[path]
        # The cap may stop inside a file: its statements after the cap are not Gold.
        complete = len(ADAPTER._sql_statement_spans(text)) == len(spans)
        rows.append({
            "id": f"{SCHEMAPILE}:{path}",
            "corpus": SCHEMAPILE,
            "path": path,
            "kind": "sql",
            "text": text,
            "document_labels": [SQL],
            "judged": [SQL],
            "span_judged": [SQL],
            "scope": [0, len(text) if complete else spans[-1][1]],
            "entities": [{"start": start, "end": end, "entity": SQL, "label": GROUPS[SQL]} for start, end in spans],
        })
    return rows


def _stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = Counter(label for row in rows for label in row["document_labels"])
    return {
        "documents": len(rows),
        "bytes": sum(len(row["text"].encode("utf-8")) for row in rows),
        "kinds": dict(sorted(Counter(row["kind"] for row in rows).items())),
        "document_labels": dict(sorted(labels.items())),
        "evidence_spans": sum(len(row["entities"]) for row in rows),
    }


def build(
    gitleaks_root: Path,
    archive: Path,
    manifest_path: Path = ADAPTER.MANIFEST_PATH,
    pins: dict[str, str] | None = None,
) -> dict[str, bytes]:
    """``{file name: content}`` of the external component; refuses output that misses its pin."""
    pins = PINNED_SHA256 if pins is None else pins
    sources = ADAPTER.load_manifest(manifest_path)
    corpora, files = [], {}
    for corpus_id, rows in ((GITLEAKS, gitleaks_rows(gitleaks_root, manifest_path)),
                            (SCHEMAPILE, schemapile_rows(archive, manifest_path))):
        data = BENIGN_CODE._jsonl(rows)
        if pins.get(corpus_id) and _sha256(data) != pins[corpus_id]:
            raise ValueError(f"{corpus_id}: normalized rows do not match the pinned SHA-256")
        source = sources[corpus_id]
        files[FILES[corpus_id]] = data
        corpora.append({
            "id": corpus_id,
            "source": source["source"],
            "pins": {key: source[key] for key in SOURCE_PINS if key in source},
            "license": source["license"],
            "adapter": source["adapter"],
            "file": FILES[corpus_id],
            "sha256": _sha256(data),
            **_stats(rows),
        })
    manifest = BENIGN_CODE._manifest_bytes({
        "schema": SCHEMA,
        "split": "dev",
        "contract": CONTRACT,
        "offsets": "code points (Python str indices)",
        "corpora": corpora,
        "excluded": "dev only, never holdout: gitleaks ships secret rules and test values",
    })
    return {**files, "manifest.json": manifest, READY: _ready(manifest)}


def check(directory: Path) -> list[str]:
    """Problems of a written external component (empty list: ready and intact)."""
    ready, manifest_path = directory / READY, directory / "manifest.json"
    if not ready.is_file() or not manifest_path.is_file():
        return [f"{directory}: no {READY} or manifest.json"]
    manifest_bytes = manifest_path.read_bytes()
    problems = []
    if ready.read_bytes() != _ready(manifest_bytes):
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


def prepare(
    out: Path,
    sources: Path,
    offline: bool = False,
    force: bool = False,
    manifest_path: Path = ADAPTER.MANIFEST_PATH,
    pins: dict[str, str] | None = None,
) -> int:
    """Build and freeze the component: 0 on success or an unchanged frozen copy, 1 on any problem."""
    try:
        if sources.resolve().is_relative_to(out.resolve()):
            raise ValueError("--sources must not be inside --out")
        corpora = ADAPTER.load_manifest(manifest_path)
        files = build(
            fetch_gitleaks(corpora[GITLEAKS], sources, offline),
            fetch_schemapile(corpora[SCHEMAPILE], sources, offline),
            manifest_path,
            pins,
        )
    except (ValueError, OSError, KeyError) as error:
        print(f"external_content: {error}", file=sys.stderr)
        return 1
    if (out / READY).exists():
        current = (out / "manifest.json").read_bytes() if (out / "manifest.json").is_file() else b""
        if not check(out) and current == files["manifest.json"]:
            print(f"external: unchanged (frozen) in {out}")
            return 0
        if not force:
            print(f"external_content: {out} is frozen and differs from this run (or was modified); "
                  "nothing written. Use --force to replace it.", file=sys.stderr)
            return 1
    BENIGN_CODE._write(out, files)
    for corpus in json.loads(files["manifest.json"])["corpora"]:
        print(f"external {corpus['id']}: {corpus['documents']} documents, {corpus['evidence_spans']} evidence spans, "
              f"sha256 {corpus['sha256']}")
    print(f"external: written in {out}")
    return 0


def load(directory: Path, keep_text: bool = False) -> list[dict[str, Any]]:
    """Rows of a checked component; without ``text`` unless asked (scoring needs offsets only)."""
    problems = check(directory)
    if problems:
        raise ValueError("; ".join(problems))
    manifest = json.loads((directory / "manifest.json").read_bytes())
    rows = []
    for corpus in manifest["corpora"]:
        with (directory / corpus["file"]).open(encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                row["bytes"] = len(row["text"].encode("utf-8"))
                if not keep_text:
                    row.pop("text")
                rows.append(row)
    return rows


def files(directory: Path) -> list[Path]:
    manifest = json.loads((directory / "manifest.json").read_bytes())
    return [directory / corpus["file"] for corpus in manifest["corpora"]]


# ── scoring ──────────────────────────────────────────────────────────────────


def _ratio(count: int, total: int) -> float:
    return round(count / total, 6) if total else 0.0


def _prf(tp_precision: int, predicted: int, tp_recall: int, gold: int) -> dict[str, Any]:
    precision, recall = _ratio(tp_precision, predicted), _ratio(tp_recall, gold)
    f1 = round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0
    return {"tp": tp_recall, "precision": precision, "recall": recall, "f1": f1}


def span_classes(span: dict[str, Any]) -> set[str]:
    """Classes of a predicted span: its entity ids, else the class of its engine group."""
    entities = {str(entity) for entity in span.get("entities") or []}
    if entities:
        return entities
    groups = [span.get("group"), *(span.get("groups") or [])]
    return {cls for cls, group in GROUPS.items() if group in groups}


def _in_scope(start: int, end: int, scope: list[int]) -> bool:
    """A span belongs to the scored region if it intersects it (an empty span if it lies in it)."""
    if start == end:
        return scope[0] <= start < scope[1]
    return start < scope[1] and scope[0] < end


def _match(gold: set[tuple[str, int, int]], predicted: set[tuple[str, int, int]]) -> dict[str, Any]:
    def overlapping(spans, others) -> int:
        by_row: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for row, start, end in others:
            by_row[row].append((start, end))
        return sum(any(start < o_end and o_start < end for o_start, o_end in by_row.get(row, ()))
                   for row, start, end in spans)

    exact = len(gold & predicted)
    return {
        "gold": len(gold),
        "predicted": len(predicted),
        "exact": _prf(exact, len(predicted), exact, len(gold)),
        "overlap": _prf(overlapping(predicted, gold), len(predicted), overlapping(gold, predicted), len(gold)),
    }


def score(
    rows: list[dict[str, Any]], predictions: Iterable[dict[str, Any]], classes: Iterable[str] | None = None
) -> dict[str, Any]:
    """Document- and span-level report of predictions under the attach/scope contract.

    ``unjudged`` counts spans of a class a row does not judge, restricted to ``classes``
    (e.g. the content classes of the entity map) when given.
    """
    reported = None if classes is None else set(classes)
    by_id = {row["id"]: row for row in rows}
    evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    bare_labels: dict[str, set[str]] = defaultdict(set)
    for prediction in predictions:
        row_id = prediction.get("id")
        if row_id not in by_id:
            raise ValueError(f"prediction for unknown row {row_id!r}")
        evidence[row_id].extend(prediction.get("evidence_spans") or [])
        bare_labels[row_id].update(str(label) for label in prediction.get("document_labels") or [])

    docs: dict[str, dict[str, dict[str, set[str]]]] = {
        cls: {"gold": defaultdict(set), "predicted": defaultdict(set), "judged": defaultdict(set)}
        for cls in sorted({cls for row in rows for cls in row["judged"]})
    }
    gold_spans: dict[str, set[tuple[str, int, int]]] = defaultdict(set)
    pred_spans: dict[str, set[tuple[str, int, int]]] = defaultdict(set)
    out_of_scope: Counter[str] = Counter()
    unjudged: Counter[str] = Counter()
    without_evidence: Counter[str] = Counter()
    for row in rows:
        row_id, corpus, scope = row["id"], row["corpus"], row["scope"]
        attached: set[str] = set()
        for span in evidence.get(row_id, ()):
            start, end = int(span["start_char"]), int(span["end_char"])
            for cls in span_classes(span):
                if cls not in row["judged"] and cls not in row["span_judged"]:
                    if reported is None or cls in reported:
                        unjudged[cls] += 1
                elif not _in_scope(start, end, scope):
                    out_of_scope[cls] += 1
                else:
                    attached.add(cls)
                    if cls in row["span_judged"]:
                        pred_spans[cls].add((row_id, start, end))
        # A document label without an in-scope evidence span is not credited.
        for cls in bare_labels.get(row_id, set()) - attached:
            without_evidence[cls] += 1
        for cls in row["judged"]:
            docs[cls]["judged"][corpus].add(row_id)
            if cls in row["document_labels"]:
                docs[cls]["gold"][corpus].add(row_id)
            if cls in attached:
                docs[cls]["predicted"][corpus].add(row_id)
        for entity in row["entities"]:
            gold_spans[str(entity["entity"])].add((row_id, int(entity["start"]), int(entity["end"])))

    def document_entry(gold: set[str], predicted: set[str], judged: set[str]) -> dict[str, Any]:
        tp = len(gold & predicted)
        return {"documents": len(judged), "gold": len(gold), "predicted": len(predicted),
                **_prf(tp, len(predicted), tp, len(gold))}

    documents, by_corpus = {}, defaultdict(dict)
    for cls, table in docs.items():
        everything = [set().union(*table[key].values()) if table[key] else set() for key in ("gold", "predicted", "judged")]
        documents[cls] = document_entry(*everything)
        for corpus in sorted(table["judged"]):
            by_corpus[corpus][cls] = document_entry(
                table["gold"][corpus], table["predicted"][corpus], table["judged"][corpus])
    span_judged = sorted({cls for row in rows for cls in row["span_judged"]})
    return {
        "corpora": {corpus: {"documents": count, "bytes": sum(row["bytes"] for row in rows if row["corpus"] == corpus)}
                    for corpus, count in sorted(Counter(row["corpus"] for row in rows).items())},
        "documents": documents,
        "documents_by_corpus": dict(sorted(by_corpus.items())),
        "spans": {cls: {**_match(gold_spans[cls], pred_spans[cls]), "out_of_scope": out_of_scope[cls]}
                  for cls in span_judged},
        "unjudged": dict(sorted(unjudged.items())),
        "labels_without_evidence": dict(sorted(without_evidence.items())),
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare", help="build and freeze the external component of the dev split")
    p.add_argument("--out", type=Path, required=True, help="component directory, normally DEV/external")
    p.add_argument("--sources", type=Path, help="git checkout and archive cache (default: OUT/../.external-sources)")
    p.add_argument("--offline", action="store_true", help="never fetch; the cache must be complete")
    p.add_argument("--force", action="store_true", help="replace a frozen component that differs")
    c = commands.add_parser("check", help="verify a written component")
    c.add_argument("directory", type=Path)
    s = commands.add_parser("score", help="score predictions (JSONL with id and evidence_spans)")
    s.add_argument("--corpus", type=Path, required=True)
    s.add_argument("--predictions", type=Path, required=True)
    s.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        sources = args.sources if args.sources is not None else args.out.parent / ".external-sources"
        return prepare(args.out, sources, args.offline, args.force)
    if args.command == "check":
        problems = check(args.directory)
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(f"{args.directory}: external content ok")
        return 1 if problems else 0
    try:
        report = score(load(args.corpus), _read_jsonl(args.predictions))
    except (ValueError, OSError) as error:
        print(f"external_content: {error}", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
