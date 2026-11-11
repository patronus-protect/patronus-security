#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""L1 latency of threat, injection and all L1 categories combined on real German text.

The corpus is built from licensed German documents: the German dev sources of the DLP
benign-document corpus (``scripts/l1_dlp/benign_docs_sources.json``: Wikipedia articles,
federal laws, Wikimedia policies) and the long German Wikipedia articles of
``latency_sources.json``, all with pinned revisions and SHA-256. Documents are split into
paragraphs, every paragraph is used at most once in the whole corpus (case- and
whitespace-insensitive), and the stream is packed into windows of exactly 100 KiB UTF-8;
a window ends with the start of the paragraph that no longer fits (cut at a character
boundary, the rest is dropped). At least MIN_WINDOWS windows are required, at most
MAX_WINDOWS are kept. Data stays on the VPS, never in the repo.

    python3 scripts/l1_threat/latency.py prepare --out DIR [--sources CACHE] [--offline]
    python3 scripts/l1_threat/latency.py check DIR
    python3 scripts/l1_threat/latency.py run --corpus DIR --output latency.json \
        [--markdown latency.md] [--runs 3] [--profiles threat injection all] [--repo CHECKOUT]
    # a change against its base (gate criterion: 100 KiB p95 at most +5 % per profile)
    python3 scripts/l1_threat/latency.py compare --base base.json --head head.json [--profile threat]

``run`` builds the native timing worker (``rust/dev/l1_latency_workloads.rs``) in release mode
and times one scan per sample through the Rust gateway at L1: profile ``threat`` and
``injection`` with that category alone, ``all`` with every L1 category in one request. The
p95 is pooled over all windows. ``--runs N`` keeps, per profile, the run with the median p95.
``compare`` exits 1 if a profile's p95 (only ``--profile``'s, when given) grew by more than the
tolerance; every command exits 2 on setup errors (missing or modified corpus, differing corpora or machines).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXTRA_SOURCES_PATH = HERE / "latency_sources.json"


def _load_file(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


# Source fetching and pinning come from the DLP benign-document corpus, timing helpers
# (percentiles, machine info, native release build) from the PII latency benchmark.
BENIGN_DOCS = _load_file("_ark_l1_dlp_benign_docs", ROOT / "scripts" / "l1_dlp" / "benign_docs.py")
PII_LATENCY = _load_file("_ark_l1_pii_latency", ROOT / "scripts" / "l1_presidio" / "latency.py")
LatencyError = PII_LATENCY.LatencyError

CORPUS_SCHEMA = "ark-threat-latency-corpus-v1"
REPORT_SCHEMA = "ark-threat-latency-v1"
READY = ".ready"
WINDOWS_FILE = "windows.jsonl"
SOURCE_IDS = ("dewiki-dev", "gesetze-dev", "wmf-dev-de")
WINDOW_BYTES = 100 * 1024
MIN_WINDOWS = 50
MAX_WINDOWS = 64
MIN_PARAGRAPH_CHARS = 40
# Profile -> categories scanned in one request. ``all`` is every category with an L1 stage.
PROFILES: dict[str, tuple[str, ...]] = {
    "threat": ("threat",),
    "injection": ("injection",),
    "all": ("injection", "dlp", "pii", "threat", "shell_command"),
}
SAMPLES_PER_WINDOW = 5
WARMUP_PER_WINDOW = 1
BUDGET_S = 60.0
TOLERANCE_PCT = 5.0
_PARAGRAPH_BREAK = re.compile(r"\n[ \t]*\n+")
_SPACE = re.compile(r"\s+")


# ── corpus ───────────────────────────────────────────────────────────────────


def default_source_dir(out: Path) -> Path:
    return out.parent / f"{out.name}.sources"


def paragraphs(text: str) -> list[str]:
    """Blank-line separated paragraphs with at least MIN_PARAGRAPH_CHARS characters and a letter."""
    parts = (part.strip() for part in _PARAGRAPH_BREAK.split(text.replace("\r\n", "\n")))
    return [part for part in parts if len(part) >= MIN_PARAGRAPH_CHARS and any(ch.isalpha() for ch in part)]


def paragraph_key(paragraph: str) -> str:
    """Identity of a paragraph for the no-repeat rule: NFKC, case-folded, whitespace collapsed."""
    return _SPACE.sub(" ", unicodedata.normalize("NFKC", paragraph).casefold()).strip()


def unique_paragraphs(documents: Iterable[dict[str, Any]]) -> list[tuple[str, str]]:
    """(document id, paragraph) in document order; a paragraph seen before is skipped."""
    seen: set[str] = set()
    out = []
    for doc in documents:
        for paragraph in paragraphs(doc["text"]):
            key = paragraph_key(paragraph)
            if key not in seen:
                seen.add(key)
                out.append((doc["id"], paragraph))
    return out


def _cut(text: str, size: int) -> str:
    """The longest prefix of text with at most size UTF-8 bytes."""
    return text.encode("utf-8")[:size].decode("utf-8", "ignore")


def pack_windows(items: list[tuple[str, str]], size: int = WINDOW_BYTES,
                 limit: int = MAX_WINDOWS) -> list[dict[str, Any]]:
    """Windows of exactly size bytes: paragraphs joined by blank lines, the last one cut.

    The cut paragraph's rest is dropped, so no paragraph appears in two windows; a cut that
    ends inside a multi-byte character is padded with up to three spaces."""
    windows: list[dict[str, Any]] = []
    parts: list[str] = []
    docs: list[str] = []
    used = 0
    for doc_id, paragraph in items:
        if len(windows) == limit:
            break
        sep = "\n\n" if parts else ""
        cost = len((sep + paragraph).encode("utf-8"))
        if doc_id not in docs:
            docs.append(doc_id)
        if used + cost < size:
            parts.append(sep + paragraph)
            used += cost
            continue
        tail = _cut(sep + paragraph, size - used)
        text = "".join(parts) + tail
        text += " " * (size - len(text.encode("utf-8")))
        windows.append({"id": f"de-{len(windows):03d}", "documents": docs, "text": text})
        parts, docs, used = [], [], 0
    for window in windows:
        window["bytes"] = len(window["text"].encode("utf-8"))
        window["sha256"] = PII_LATENCY.sha256_bytes(window["text"].encode("utf-8"))
    return windows


def corpus_sources(sources_path: Path = BENIGN_DOCS.SOURCES_PATH,
                   extra_path: Path = EXTRA_SOURCES_PATH) -> list[dict[str, Any]]:
    """SOURCE_IDS from the DLP list, then every source of the extra list; all German dev sources."""
    by_id = {source["id"]: source for source in BENIGN_DOCS.load_sources(sources_path)}
    missing = [source_id for source_id in SOURCE_IDS if source_id not in by_id]
    if missing:
        raise LatencyError(f"{', '.join(missing)}: not in {sources_path}")
    sources = [by_id[source_id] for source_id in SOURCE_IDS] + BENIGN_DOCS.load_sources(extra_path)
    for source in sources:
        if source["id"] in by_id and by_id[source["id"]] is not source:
            raise LatencyError(f"{source['id']}: listed in both {sources_path} and {extra_path}")
        if source["lang"] != "de" or source["split"] != "dev":
            raise LatencyError(f"{source['id']}: not a German dev source")
    return sources


def build_corpus(cache: Path, offline: bool = False, sources_path: Path = BENIGN_DOCS.SOURCES_PATH,
                 extra_path: Path = EXTRA_SOURCES_PATH) -> dict[str, bytes]:
    """File name -> bytes of the corpus directory; every source must reproduce its pinned SHA-256."""
    documents: list[dict[str, Any]] = []
    entries = []
    for source in corpus_sources(sources_path, extra_path):
        data, entry = BENIGN_DOCS.build_source(source, cache, offline)
        if entry["sha256"] != source.get("sha256"):
            raise LatencyError(f"{source['id']}: built sha256 {entry['sha256']} differs from the pin")
        documents += [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]
        entries.append({key: entry[key] for key in ("id", "license", "genre", "sha256", "documents", "bytes")})
    items = unique_paragraphs(documents)
    windows = pack_windows(items)
    if len(windows) < MIN_WINDOWS:
        raise LatencyError(f"only {len(windows)} windows of {WINDOW_BYTES} bytes; at least {MIN_WINDOWS} needed")
    data = "".join(json.dumps(window, ensure_ascii=False, sort_keys=True) + "\n" for window in windows).encode()
    manifest = {
        "schema": CORPUS_SCHEMA,
        "window_bytes": WINDOW_BYTES,
        "min_paragraph_chars": MIN_PARAGRAPH_CHARS,
        "max_windows": MAX_WINDOWS,
        "sources": entries,
        "paragraphs": len(items),
        "windows": len(windows),
        "file": WINDOWS_FILE,
        "sha256": PII_LATENCY.sha256_bytes(data),
    }
    return {WINDOWS_FILE: data, "manifest.json": (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()}


def load_corpus(directory: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Manifest and windows of a frozen corpus directory; LatencyError when it is not intact."""
    if not (directory / READY).is_file():
        raise LatencyError(f"{directory}: no {READY}; run prepare first")
    try:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        data = (directory / WINDOWS_FILE).read_bytes()
    except (OSError, ValueError) as error:
        raise LatencyError(f"{directory}: unreadable corpus ({error})") from error
    if manifest.get("schema") != CORPUS_SCHEMA or manifest.get("sha256") != PII_LATENCY.sha256_bytes(data):
        raise LatencyError(f"{directory}: manifest schema or {WINDOWS_FILE} sha256 does not match")
    windows = [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]
    return manifest, windows


def check_corpus(directory: Path) -> list[str]:
    """Problems of a corpus directory (empty when it holds the promised windows)."""
    try:
        manifest, windows = load_corpus(directory)
    except LatencyError as error:
        return [str(error)]
    problems = []
    if not MIN_WINDOWS <= len(windows) == manifest["windows"]:
        problems.append(f"{len(windows)} windows (manifest {manifest['windows']}); at least {MIN_WINDOWS} needed")
    seen: dict[str, str] = {}
    for window in windows:
        raw = window["text"].encode("utf-8")
        if len(raw) != manifest["window_bytes"] or PII_LATENCY.sha256_bytes(raw) != window["sha256"]:
            problems.append(f"{window['id']}: not {manifest['window_bytes']} bytes or sha256 mismatch")
        for paragraph in paragraphs(window["text"]):
            key = paragraph_key(paragraph)
            if key in seen:
                problems.append(f"{window['id']}: paragraph repeated from {seen[key]}")
                break
            seen[key] = window["id"]
    return problems


def prepare(out: Path, cache: Path | None = None, offline: bool = False, force: bool = False) -> int:
    cache = default_source_dir(out) if cache is None else cache
    try:
        files = build_corpus(cache, offline)
    except (LatencyError, ValueError, OSError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if (out / READY).exists():
        if (out / "manifest.json").read_bytes() == files["manifest.json"] and not check_corpus(out):
            print(f"unchanged (frozen) in {out}")
            return 0
        if not force:
            print(f"error: {out} is frozen and differs from this build; use --force to replace it", file=sys.stderr)
            return 2
        (out / READY).unlink()
    out.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (out / name).write_bytes(data)
    (out / READY).write_text("", encoding="utf-8")
    manifest = json.loads(files["manifest.json"])
    print(f"{manifest['windows']} windows from {manifest['paragraphs']} paragraphs in {out}, "
          f"sha256 {manifest['sha256']}")
    return 0


# ── measurement ──────────────────────────────────────────────────────────────


def jobs(windows: list[dict[str, Any]], profile: str, samples: int, budget_s: float) -> list[dict[str, Any]]:
    return [
        {"id": f"{profile}:{window['id']}", "text": window["text"], "samples": samples,
         "warmup": WARMUP_PER_WINDOW, "min_samples": 1, "budget_ms": budget_s * 1000 / len(windows),
         "categories": list(PROFILES[profile])}
        for window in windows
    ]


def measure_profile(binary: Path, windows: list[dict[str, Any]], profile: str, samples: int,
                    budget_s: float = BUDGET_S) -> dict[str, Any]:
    """Run the native worker on every window with the profile's categories; pooled summary."""
    requested = jobs(windows, profile, samples, budget_s)
    with tempfile.TemporaryDirectory(prefix="ark-threat-latency-") as tmp:
        path = Path(tmp) / "jobs.jsonl"
        path.write_text("".join(json.dumps(job, ensure_ascii=False) + "\n" for job in requested), encoding="utf-8")
        load_before = os.getloadavg()[0]
        proc = subprocess.run([str(binary), str(path)], text=True, capture_output=True)
    if proc.returncode != 0:
        raise LatencyError(f"native worker failed for {profile} (exit {proc.returncode}):\n{proc.stderr.strip()[-3000:]}")
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    if [line["id"] for line in lines] != [job["id"] for job in requested]:
        raise LatencyError(f"native worker returned other windows than requested for {profile}")
    if any(not line["samples_ns"] for line in lines):
        raise LatencyError(f"native worker returned a window without samples for {profile}")
    return {
        "categories": list(PROFILES[profile]),
        "init_ms": round(lines[0]["init_ms"], 1),
        "loadavg_1m": [round(load_before, 2), round(os.getloadavg()[0], 2)],
        "spans": sum(line["spans"] for line in lines),
        "summary": PII_LATENCY.summarize([ns for line in lines for ns in line["samples_ns"]]),
    }


def combine(manifest: dict[str, Any], runs: list[dict[str, dict[str, Any]]], binary_sha256: str) -> dict[str, Any]:
    """Per profile the run with the (lower) median p95, plus every run's p95."""
    profiles = {}
    for profile in runs[0]:
        p95s = [run[profile]["summary"]["p95_ms"] for run in runs]
        profiles[profile] = {**runs[p95s.index(statistics.median_low(p95s))][profile], "runs_p95_ms": p95s}
    return {
        "schema": REPORT_SCHEMA,
        "corpus": {key: manifest[key] for key in ("sha256", "windows", "window_bytes")},
        "machine": PII_LATENCY.machine_info(),
        "binary_sha256": binary_sha256,
        "runs": len(runs),
        "samples_per_window": runs[0][next(iter(runs[0]))]["summary"]["samples"] // manifest["windows"],
        "profiles": profiles,
    }


def cmd_run(args: argparse.Namespace) -> dict[str, Any]:
    manifest, windows = load_corpus(args.corpus)
    samples = max(1, round(SAMPLES_PER_WINDOW * args.samples_scale))
    binary = PII_LATENCY.build_native(args.repo.resolve(), args.cargo)
    runs = []
    for run in range(1, args.runs + 1):
        runs.append({profile: measure_profile(binary, windows, profile, samples, args.budget_s)
                     for profile in args.profiles})
        print(f"run {run}/{args.runs}: done", file=sys.stderr)
    return combine(manifest, runs, PII_LATENCY.sha256_bytes(binary.read_bytes()))


def table(report: dict[str, Any]) -> list[str]:
    lines = ["| Profile | Categories | Init ms | p50 ms | p95 ms | p99 ms | max ms | p95 per run ms |",
             "|---|---|---:|---:|---:|---:|---:|---|"]
    for profile, data in report["profiles"].items():
        s = data["summary"]
        runs = ", ".join(f"{p95:.3f}" for p95 in data["runs_p95_ms"])
        lines.append(f"| {profile} | {', '.join(data['categories'])} | {data['init_ms']:.0f} | {s['p50_ms']:.3f} | "
                     f"{s['p95_ms']:.3f} | {s['p99_ms']:.3f} | {s['max_ms']:.3f} | {runs} |")
    return lines


def markdown(report: dict[str, Any]) -> str:
    machine, corpus = report["machine"], report["corpus"]
    return "\n".join([
        "# L1-Threat latency on real German text",
        "",
        f"Machine: {machine['cpu']}, {machine['cpus_usable']} usable CPUs, {machine['system']} {machine['machine']}. "
        f"Native Rust gateway at L1 (release build), one scan per sample, sequential.",
        f"Corpus: {corpus['windows']} distinct windows of {corpus['window_bytes']} bytes, sha256 "
        f"`{corpus['sha256'][:16]}`; {report['samples_per_window']} samples per window, p95 pooled over "
        f"all windows. Runs: {report['runs']}; per profile the run with the median p95.",
        "",
        *table(report),
        "",
    ])


def compare(base: dict[str, Any], head: dict[str, Any], tolerance_pct: float = TOLERANCE_PCT,
            profile: str | None = None) -> dict[str, Any]:
    """p95 of head vs. base per profile (only ``profile`` when given); a profile regresses above +tolerance_pct."""
    for side, report in (("base", base), ("head", head)):
        if report.get("schema") != REPORT_SCHEMA:
            raise LatencyError(f"{side} report is not {REPORT_SCHEMA}")
    if base["corpus"] != head["corpus"]:
        raise LatencyError("base and head measured different corpora")
    if base["machine"] != head["machine"]:
        raise LatencyError("base and head were measured on different machines")
    if profile is not None and profile not in base["profiles"]:
        raise LatencyError(f"base has no {profile} measurement")
    rows = []
    for name, data in base["profiles"].items():
        if profile not in (None, name):
            continue
        if name not in head["profiles"] or head["profiles"][name]["categories"] != data["categories"]:
            raise LatencyError(f"head has no {name} measurement with the base's categories")
        before = data["summary"]["p95_ms"]
        after = head["profiles"][name]["summary"]["p95_ms"]
        change = (after / before - 1) * 100 if before else float("inf")
        rows.append({"profile": name, "base_p95_ms": before, "head_p95_ms": after,
                     "change_pct": round(change, 1), "regression": change > tolerance_pct})
    return {"tolerance_pct": tolerance_pct, "rows": rows, "regression": any(row["regression"] for row in rows)}


def compare_lines(result: dict[str, Any]) -> list[str]:
    lines = [f"threat latency, real-DE 100 KiB p95 head vs. base (at most +{result['tolerance_pct']:g} %)"]
    for row in result["rows"]:
        mark = " REGRESSION" if row["regression"] else ""
        lines.append(f"  {row['profile']:<9} {row['base_p95_ms']:>9.3f} ms -> {row['head_p95_ms']:>9.3f} ms "
                     f"({row['change_pct']:+.1f} %){mark}")
    lines.append("RESULT: " + ("REGRESSION" if result["regression"] else "PASS"))
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare", help="build the frozen corpus directory")
    prepare_parser.add_argument("--out", type=Path, required=True)
    prepare_parser.add_argument("--sources", type=Path, help="source cache (default: <out>.sources)")
    prepare_parser.add_argument("--offline", action="store_true", help="use only the source cache")
    prepare_parser.add_argument("--force", action="store_true", help="replace a frozen corpus that differs")
    check_parser = sub.add_parser("check", help="validate a corpus directory")
    check_parser.add_argument("corpus", type=Path)
    run_parser = sub.add_parser("run", help="measure the profiles on the corpus")
    run_parser.add_argument("--corpus", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True, help="report JSON")
    run_parser.add_argument("--markdown", type=Path, help="report Markdown")
    run_parser.add_argument("--profiles", nargs="+", choices=list(PROFILES), default=list(PROFILES))
    run_parser.add_argument("--runs", type=int, default=1)
    run_parser.add_argument("--samples-scale", type=float, default=1.0)
    run_parser.add_argument("--budget-s", type=float, default=BUDGET_S,
                            help="per profile and run; after one sample per window, timing stops once spent")
    run_parser.add_argument("--repo", type=Path, default=ROOT, help="checkout to build and measure")
    run_parser.add_argument("--cargo", default="cargo")
    compare_parser = sub.add_parser("compare", help="head vs. base report (p95 tolerance)")
    compare_parser.add_argument("--base", type=Path, required=True)
    compare_parser.add_argument("--head", type=Path, required=True)
    compare_parser.add_argument("--tolerance-pct", type=float, default=TOLERANCE_PCT)
    compare_parser.add_argument("--profile", choices=list(PROFILES), help="compare only this profile")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            return prepare(args.out, args.sources, args.offline, args.force)
        if args.command == "check":
            problems = check_corpus(args.corpus)
            print("\n".join(problems) if problems else f"{args.corpus}: ok")
            return 1 if problems else 0
        if args.command == "run":
            if args.runs < 1 or args.samples_scale <= 0 or args.budget_s <= 0:
                raise LatencyError("--runs, --samples-scale and --budget-s must be positive")
            report = cmd_run(args)
            PII_LATENCY.write_json(args.output, report)
            if args.markdown:
                args.markdown.write_text(markdown(report), encoding="utf-8")
            print("\n".join(table(report)))
            return 0
        base = json.loads(args.base.read_text(encoding="utf-8"))
        head = json.loads(args.head.read_text(encoding="utf-8"))
        result = compare(base, head, args.tolerance_pct, args.profile)
        print("\n".join(compare_lines(result)))
        return 1 if result["regression"] else 0
    except LatencyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
