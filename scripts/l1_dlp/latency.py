#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""DLP latency and throughput: ARK vs. gitleaks, TruffleHog and detect-secrets.

Four workloads, built deterministically from a frozen dev split (``prepare_corpora.py``):

- ``short``: single carrier rows (``.env``, YAML, CLI, prose …), as they come;
- ``4k`` / ``100k``: documents of exactly 4 KiB / 100 KiB UTF-8, benign code with one
  carrier row per 4 KiB block;
- ``repo``: a 10 MiB repository of benign-code files with one carrier file per 64 KiB.

ARK is timed in process (``SecurityGateway.scan_category("dlp", text)``, default profile)
in a worker that loads the module of a build. The baselines are timed as their pinned
binaries / CLI: one invocation over all documents of a workload (throughput), one
invocation per document (latency including process start) and the start on an empty file.
Every process is pinned to the same CPUs (``--cpus``, default 1).

``bench`` writes the full report. The scoreboard gate calls ``gate_check`` to compare the
head build with its base (100 KiB p95 at most +10 %, H03 budget). Reports carry numbers
only, never document text.

    python3 scripts/l1_dlp/latency.py bench --dev DIR [--tools ark,gitleaks,trufflehog,detect-secrets]
        [--package DIR] [--sizes short,4k,100k,repo] [--rounds N] [--cpus N] [--output FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable, Iterator


HERE = Path(__file__).resolve().parent


def _load_file(name: str, path: Path) -> ModuleType:
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


CORPORA = _load_file("_ark_l1_dlp_prepare_corpora", HERE / "prepare_corpora.py")
BASELINES = _load_file("l1_dlp_run_baselines", HERE / "run_baselines.py")

SCHEMA = "ark-dlp-latency-v1"
WORKER = "_ark-worker"
DETECT_SECRETS_WORKER = "_detect-secrets-worker"
TOOLS = ("ark", *BASELINES.TOOLS)
SIZES = ("short", "4k", "100k", "repo")
SIZE_LABELS = {"short": "short", "4k": "4 KiB", "100k": "100 KiB", "repo": "10 MiB repo"}
DOC_BYTES = {"4k": 4 * 1024, "100k": 100 * 1024}
DOC_COUNTS = {"short": 256, "4k": 64, "100k": 32}
REPO_BYTES = 10 * 1024 * 1024
CARRIER_EVERY = 4 * 1024  # one carrier row per 4 KiB block of a document
REPO_CARRIER_EVERY = 64 * 1024  # one carrier file per 64 KiB of the repository
MIB = 1024 * 1024

# Gate: head vs. base on the dev workloads; only the 100 KiB p95 is gated.
GATED_SIZE = "100k"
TOLERANCE = 0.10  # head p95 may be 10 % above the base …
SLACK_MS = 0.25  # … plus timer and scheduler noise
BUDGET_MS = 10.0  # H03 / M4: 100 KiB p95 ≤ 10 ms
GATE_ROUNDS = {"short": 2, "4k": 3, "100k": 16, "repo": 2}
GATE_ATTEMPTS = 2  # a regression must show in every attempt
BENCH_ROUNDS = 5
INVOCATIONS = 8  # per-document invocations of a baseline per workload


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _order(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda row: sha256_bytes(str(row["id"]).encode()))


# ── workloads ────────────────────────────────────────────────────────────────


def load_sources(dev: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Carrier rows and benign-code documents of a frozen split, each in sha256(id) order."""
    problems = CORPORA.check(dev)
    if problems:
        raise ValueError("; ".join(problems))
    components = json.loads((dev / "manifest.json").read_bytes())["components"]

    def rows(name: str) -> list[dict[str, Any]]:
        entry = components[name]
        out = []
        for file in sorted(entry["files"]):
            with (dev / entry["dir"] / file).open(encoding="utf-8") as handle:
                out.extend(json.loads(line) for line in handle if line.strip())
        return [row for row in out if isinstance(row.get("text"), str) and row["text"]]

    return _order(rows("synthetic")), _order(rows("benign_code"))


def _carrier_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {"format": row.get("format"), "code_language": row.get("code_language")}


def _exact(data: bytes) -> str:
    """``data`` as text of exactly ``len(data)`` UTF-8 bytes (a cut code point becomes spaces)."""
    text = data.decode("utf-8", "ignore")
    return text + " " * (len(data) - len(text.encode("utf-8")))


class _CodeStream:
    """Endless byte stream over the benign-code documents (kind ``code``), in corpus order."""

    def __init__(self, code: list[dict[str, Any]]):
        texts = [row["text"] for row in code if row.get("kind") == "code"] or [row["text"] for row in code]
        self.data = "\n".join(texts).encode("utf-8") + b"\n"
        self.pos = 0

    def take(self, count: int) -> bytes:
        out = bytearray()
        while len(out) < count:
            chunk = self.data[self.pos:self.pos + count - len(out)]
            out += chunk
            self.pos = (self.pos + len(chunk)) % len(self.data)
        return bytes(out)


def build_workloads(
    dev: Path,
    doc_counts: dict[str, int] = DOC_COUNTS,
    doc_bytes: dict[str, int] = DOC_BYTES,
    repo_bytes: int = REPO_BYTES,
    carrier_every: int = CARRIER_EVERY,
    repo_carrier_every: int = REPO_CARRIER_EVERY,
) -> dict[str, list[dict[str, Any]]]:
    """``{size: rows}``; rows carry ``id``, ``text`` and the file-name fields of run_baselines."""
    carriers, code = load_sources(dev)
    if not carriers or not code:
        raise ValueError(f"{dev}: latency workloads need carrier rows and benign-code documents")
    workloads: dict[str, list[dict[str, Any]]] = {}
    workloads["short"] = [
        {"id": f"short:{index:05d}", "text": row["text"], **_carrier_fields(row)}
        for index, row in enumerate(carriers[:doc_counts["short"]])
    ]
    cycle = itertools.cycle(carriers)
    stream = _CodeStream(code)
    for size in ("4k", "100k"):
        rows = []
        for index in range(doc_counts[size]):
            data = bytearray()
            while len(data) < doc_bytes[size]:
                block = next(cycle)["text"].encode("utf-8") + b"\n"
                # per block, so a code point cut by the stream never shifts the next block
                data += _exact(block + stream.take(max(0, carrier_every - len(block)))).encode("utf-8")
            rows.append({"id": f"{size}:{index:05d}", "text": _exact(bytes(data[:doc_bytes[size]]))})
        workloads[size] = rows
    workloads["repo"] = _repo(carriers, code, repo_bytes, repo_carrier_every)
    return workloads


def _repo(
    carriers: list[dict[str, Any]], code: list[dict[str, Any]], total: int, carrier_every: int
) -> list[dict[str, Any]]:
    carrier_cycle, code_cycle = itertools.cycle(carriers), itertools.cycle(code)
    rows: list[dict[str, Any]] = []
    used, next_carrier = 0, 0
    while used < total:
        if used >= next_carrier:
            source = next(carrier_cycle)
            fields = _carrier_fields(source)
            next_carrier += carrier_every
        else:
            source = next(code_cycle)
            fields = {"path": source.get("path")}
        data = source["text"].encode("utf-8")[:total - used]
        rows.append({"id": f"repo:{len(rows):05d}", "text": _exact(data), **fields})
        used += len(data)
    return rows


def workload_stats(workloads: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """Documents, bytes and a digest per workload (no text)."""
    stats = {}
    for size, rows in workloads.items():
        encoded = [row["text"].encode("utf-8") for row in rows]
        stats[size] = {
            "docs": len(rows),
            "bytes": sum(len(data) for data in encoded),
            "sha256": sha256_bytes(b"".join(sha256_bytes(data).encode() for data in encoded)),
        }
    return stats


def write_workloads(workloads: dict[str, list[dict[str, Any]]], path: Path) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for size in SIZES:
            for row in workloads.get(size, []):
                handle.write(json.dumps({"size": size, **row}, ensure_ascii=False) + "\n")


def read_workloads(path: Path) -> dict[str, list[dict[str, Any]]]:
    workloads: dict[str, list[dict[str, Any]]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                workloads.setdefault(row.pop("size"), []).append(row)
    return workloads


# ── statistics ───────────────────────────────────────────────────────────────


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile."""
    if not values:
        raise ValueError("percentile of no values")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]


def summarize(ms: list[float], seconds: list[float], round_bytes: int) -> dict[str, Any]:
    """Per-document latency (``ms``) and scan throughput over whole rounds (``seconds`` per round)."""
    return {
        "samples": len(ms),
        "rounds": len(seconds),
        "p50_ms": round(percentile(ms, 0.50), 4),
        "p95_ms": round(percentile(ms, 0.95), 4),
        "p99_ms": round(percentile(ms, 0.99), 4),
        "mean_ms": round(statistics.fmean(ms), 4),
        "max_ms": round(max(ms), 4),
        "round_seconds_median": round(statistics.median(seconds), 4),
        "mib_per_s": _rate(round_bytes, statistics.median(seconds)),
    }


def _rate(size: int, seconds: float) -> float | None:
    return round(size / MIB / seconds, 3) if seconds > 0 else None


# ── CPU pinning ──────────────────────────────────────────────────────────────


def pinned_cpus(count: int) -> list[int] | None:
    """The last ``count`` CPUs this process may use; None for ``count`` 0 (no pinning)."""
    if count <= 0:
        return None
    available = sorted(os.sched_getaffinity(0))
    if count > len(available):
        raise ValueError(f"--cpus {count}: only {len(available)} CPUs available")
    return available[-count:]


def _preexec(cpus: list[int] | None) -> Callable[[], None] | None:
    if cpus is None:
        return None
    return lambda: os.sched_setaffinity(0, cpus)


# ── ARK worker ───────────────────────────────────────────────────────────────


def _ark_worker(package: Path | None, workloads_path: Path) -> int:
    """Load the module of ``package`` (else the installed one), then answer timing commands.

    stdin: one JSON command per line, ``{"size": "100k", "rounds": 1}``; stdout: one JSON line
    per command with the per-document ``ms`` and the ``seconds`` of every round.
    """
    started = time.perf_counter()
    if package is not None:
        sys.path.insert(0, str(package))
    import patronus_ark

    if package is not None and Path(patronus_ark.__file__).resolve().parent != (package / "patronus_ark").resolve():
        raise RuntimeError(f"patronus_ark resolved outside the build: {patronus_ark.__file__}")
    run_ark = _load_file("_ark_l1_dlp_run_ark", HERE / "run_ark.py")
    gateway = run_ark.build_gateway((), {})  # default profile; no entity map needed
    workloads = {size: [row["text"] for row in rows] for size, rows in read_workloads(workloads_path).items()}
    category = run_ark.CATEGORY

    def scan(text: str, size: str) -> float:
        begin = time.perf_counter_ns()
        results = gateway.scan_category(category, text)
        elapsed = (time.perf_counter_ns() - begin) / 1e6
        if any(result.get("class_name") == "error" for result in results):
            raise RuntimeError(f"ARK scanner failed during the {size} workload")
        return elapsed

    for size, texts in workloads.items():  # warm-up: first documents of every workload
        for text in texts[:4]:
            scan(text, size)
    try:
        build = run_ark.build_info()
    except Exception:  # noqa: BLE001 - only informative
        build = {}
    ready = {"ready": True, "startup_ms": round((time.perf_counter() - started) * 1000, 3), "build": build}
    print(json.dumps(ready), flush=True)
    for line in sys.stdin:
        command = json.loads(line)
        size, rounds = command["size"], int(command.get("rounds", 1))
        ms, seconds = [], []
        for _ in range(rounds):
            round_ms = [scan(text, size) for text in workloads[size]]
            ms.extend(round_ms)
            seconds.append(sum(round_ms) / 1000)
        print(json.dumps({"size": size, "ms": ms, "seconds": seconds}), flush=True)
    return 0


class ArkWorker:
    """A worker process for one build; ``run`` times rounds of one workload."""

    def __init__(self, package: Path | None, workloads_path: Path, cpus: list[int] | None):
        cmd = [sys.executable, str(HERE / "latency.py"), WORKER, "--workloads", str(workloads_path)]
        if package is not None:
            cmd += ["--package", str(package)]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("PYTHONPATH", None)
        self.process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, preexec_fn=_preexec(cpus)
        )
        self.info = self._read()

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            code = self.process.wait()
            raise RuntimeError(f"ARK latency worker exited {code}")
        return json.loads(line)

    def run(self, size: str, rounds: int = 1) -> dict[str, Any]:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps({"size": size, "rounds": rounds}) + "\n")
        self.process.stdin.flush()
        return self._read()

    def close(self) -> None:
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def __enter__(self) -> "ArkWorker":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def measure_ark(
    workers: dict[str, ArkWorker], workloads: dict[str, list[dict[str, Any]]], rounds: dict[str, int]
) -> dict[str, dict[str, dict[str, Any]]]:
    """``{worker: {size: summary}}``; with several workers the rounds alternate (ABBA …)."""
    stats = workload_stats(workloads)
    out: dict[str, dict[str, dict[str, Any]]] = {name: {} for name in workers}
    names = list(workers)
    for size in SIZES:
        if size not in workloads or not rounds.get(size):
            continue
        samples: dict[str, tuple[list[float], list[float]]] = {name: ([], []) for name in names}
        for index in range(rounds[size]):
            for name in names if index % 2 == 0 else reversed(names):
                result = workers[name].run(size)
                samples[name][0].extend(result["ms"])
                samples[name][1].extend(result["seconds"])
        for name in names:
            out[name][size] = {"docs": stats[size]["docs"], "bytes": stats[size]["bytes"],
                               **summarize(*samples[name], stats[size]["bytes"])}
    return out


# ── baselines ────────────────────────────────────────────────────────────────


def _detect_secrets_worker(root: Path) -> int:
    """``scan_file`` with all plugins and default filters on every file, in one process.

    The CLI (``detect-secrets scan --all-files``) aborts the whole scan when one file raises
    (e.g. a YAML date it cannot parse); here such a file counts as an error and the scan goes on.
    """
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import default_settings

    files = errors = 0
    with default_settings():
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            files += 1
            try:
                for _ in scan_file(str(path)):
                    pass
            except Exception:  # noqa: BLE001 - counted, like a file the CLI would fail on
                errors += 1
    print(json.dumps({"files": files, "errors": errors}))
    return 0


def baseline_command(tool: str, root: Path, work: Path, bin_dir: Path, detect_secrets_python: Path) -> list[str]:
    """The tool's default-profile scan of ``root`` as in run_baselines.py (no verification)."""
    if tool == "detect-secrets":
        return [str(detect_secrets_python), "-I", str(HERE / "latency.py"), DETECT_SECRETS_WORKER, str(root)]
    report = work / "report.json"
    return [str(bin_dir / tool)] + [part.format(root=root, report=report) for part in BASELINES.COMMANDS[tool]]


def _timed(command: list[str], work: Path, cpus: list[int] | None, tool: str) -> float:
    """Wall-clock seconds of one tool run; output goes to a file, a failure raises."""
    with (work / "stdout").open("wb") as out, (work / "stderr").open("wb") as err:
        begin = time.perf_counter()
        result = subprocess.run(command, cwd=work, env=BASELINES.tool_env(work), stdout=out, stderr=err,
                                stdin=subprocess.DEVNULL, preexec_fn=_preexec(cpus), check=False)
        elapsed = time.perf_counter() - begin
    if result.returncode != 0:
        tail = (work / "stderr").read_text(encoding="utf-8", errors="replace").strip()[-1000:]
        raise RuntimeError(f"{tool} exited {result.returncode}: {tail}")
    return elapsed


def measure_baseline(
    tool: str,
    workloads: dict[str, list[dict[str, Any]]],
    rounds: dict[str, int],
    invocations: int,
    cpus: list[int] | None,
    bin_dir: Path,
    detect_secrets_python: Path,
) -> dict[str, Any]:
    """Start-up, per-document invocations and one run over every workload."""
    stats = workload_stats(workloads)
    out: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix=f"ark-dlp-latency-{tool}-") as tmp:
        work = Path(tmp)

        def run_on(rows: list[dict[str, Any]], name: str) -> Callable[[], float]:
            root = work / name
            BASELINES.materialize(rows, root)
            command = baseline_command(tool, root, work, bin_dir, detect_secrets_python)
            return lambda: _timed(command, work, cpus, tool)

        empty = run_on([{"id": "empty", "text": ""}], "empty")
        out["startup_ms"] = round(statistics.median(empty() for _ in range(3)) * 1000, 3)
        for size in SIZES:
            rows = workloads.get(size)
            if not rows or not rounds.get(size):
                continue
            batch = run_on(rows, size)
            seconds = [batch() for _ in range(rounds[size])]
            median = statistics.median(seconds)
            entry: dict[str, Any] = {
                "docs": stats[size]["docs"],
                "bytes": stats[size]["bytes"],
                "rounds": len(seconds),
                "round_seconds_median": round(median, 4),
                # scan only: the run minus the median start on an empty file
                "mib_per_s": _rate(stats[size]["bytes"], median - out["startup_ms"] / 1000),
                "end_to_end_mib_per_s": _rate(stats[size]["bytes"], median),
                "per_doc_ms": round(median * 1000 / stats[size]["docs"], 4),
            }
            if tool == "detect-secrets":  # files the plugins raised on (the CLI would abort)
                entry["errors"] = json.loads((work / "stdout").read_text(encoding="utf-8"))["errors"]
            if size != "repo" and invocations > 0:
                ms = [run_on([row], f"{size}-{index}")() * 1000 for index, row in enumerate(rows[:invocations])]
                entry["invocation"] = {"samples": len(ms), "p50_ms": round(percentile(ms, 0.5), 3),
                                       "p95_ms": round(percentile(ms, 0.95), 3)}
            out[size] = entry
    return out


# ── bench ────────────────────────────────────────────────────────────────────


def host_info(cpus: list[int] | None) -> dict[str, Any]:
    model = ""
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {"cpu_model": model, "cpu_count": os.cpu_count(), "pinned_cpus": cpus,
            "kernel": platform.release(), "python": platform.python_version()}


def bench(
    dev: Path,
    tools: Iterable[str],
    sizes: Iterable[str],
    rounds: int,
    cpus: list[int] | None,
    package: Path | None = None,
    bin_dir: Path = BASELINES.BASELINES_DIR / "bin",
    detect_secrets_python: Path = BASELINES.DETECT_SECRETS_PYTHON,
    invocations: int = INVOCATIONS,
    check_pins: bool = True,
    workload_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tools, sizes = list(tools), [size for size in SIZES if size in set(sizes)]
    workloads = {size: rows for size, rows in build_workloads(dev, **(workload_options or {})).items()
                 if size in sizes}
    per_size = {size: rounds for size in sizes}
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "dev_manifest_sha256": sha256_bytes((dev / "manifest.json").read_bytes()),
        "host": host_info(cpus),
        "workloads": workload_stats(workloads),
        "tools": {},
    }
    baselines = [tool for tool in tools if tool != "ark"]
    if baselines and check_pins:
        installed, problems = BASELINES.check_pins(baselines, bin_dir, detect_secrets_python)
        if problems:
            raise RuntimeError("installed baselines differ from the pins: " + "; ".join(problems))
        report["installed"] = installed
    for tool in tools:
        if tool == "ark":
            with tempfile.TemporaryDirectory(prefix="ark-dlp-latency-ark-") as tmp:
                path = Path(tmp) / "workloads.jsonl"
                write_workloads(workloads, path)
                with ArkWorker(package, path, cpus) as worker:
                    entry = measure_ark({"ark": worker}, workloads, per_size)["ark"]
                    entry["startup_ms"] = worker.info["startup_ms"]
                    for size in sizes:  # one process start (import + rule compilation) per run
                        entry[size]["end_to_end_mib_per_s"] = _rate(
                            entry[size]["bytes"], entry[size]["round_seconds_median"] + entry["startup_ms"] / 1000
                        )
                    report["build"] = worker.info.get("build", {})
            report["tools"]["ark"] = entry
        else:
            report["tools"][tool] = measure_baseline(
                tool, workloads, per_size, invocations, cpus, bin_dir, detect_secrets_python
            )
    return report


def _fmt(value: Any, digits: int = 2) -> str:
    return "–" if value is None else f"{value:.{digits}f}"


def table_lines(report: dict[str, Any]) -> list[str]:
    """Markdown table: ARK p50/p95 in process, baselines per invocation (incl. process start)."""
    lines = [
        "| tool | workload | docs | MiB | p50 ms | p95 ms | scan MiB/s | end-to-end MiB/s | start ms |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for tool, entry in report["tools"].items():
        for size in SIZES:
            if size not in entry:
                continue
            item = entry[size]
            latency = item if tool == "ark" else item.get("invocation", {})
            lines.append(
                f"| {tool} | {SIZE_LABELS[size]} | {item['docs']} | {item['bytes'] / MIB:.2f} | "
                f"{_fmt(latency.get('p50_ms'), 3)} | {_fmt(latency.get('p95_ms'), 3)} | "
                f"{_fmt(item.get('mib_per_s'))} | {_fmt(item.get('end_to_end_mib_per_s'))} | "
                f"{_fmt(entry.get('startup_ms'), 1)} |"
            )
    return lines


# ── gate ─────────────────────────────────────────────────────────────────────


def latency_checks(base: dict[str, Any], head: dict[str, Any]) -> list[dict[str, Any]]:
    """Gated checks on the 100 KiB p95: +10 % (plus slack) over the base, and the H03 budget."""
    b, h = base[GATED_SIZE]["p95_ms"], head[GATED_SIZE]["p95_ms"]
    limit = round(b * (1 + TOLERANCE) + SLACK_MS, 4)
    return [
        {"check": f"latency:{GATED_SIZE}_p95_ms", "base": b, "head": h, "limit": limit, "ok": h <= limit},
        # Once the base is within the budget, no head may leave it.
        {"check": f"latency:budget_{GATED_SIZE}_p95_ms", "base": b, "head": h, "budget": BUDGET_MS,
         "ok": h <= BUDGET_MS or b > BUDGET_MS},
    ]


def gate_check(
    base: Any,
    head: Any,
    dev: Path,
    workdir: Path,
    cpus: int = 1,
    rounds: dict[str, int] = GATE_ROUNDS,
    attempts: int = GATE_ATTEMPTS,
    workload_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Time the base and the head build (``package``, ``key``) on the dev workloads.

    Rounds alternate between both workers on the same CPUs. A failed check is measured again
    (``attempts``) and only fails when it fails every time.
    """
    if base.key == head.key:
        return {"schema": SCHEMA, "skipped": "head and base share one build", "checks": []}
    pinned = pinned_cpus(cpus)
    workloads = build_workloads(dev, **(workload_options or {}))
    workdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="latency-", dir=workdir) as tmp:
        path = Path(tmp) / "workloads.jsonl"
        write_workloads(workloads, path)
        with ArkWorker(base.package, path, pinned) as base_worker, ArkWorker(head.package, path, pinned) as head_worker:
            workers = {"base": base_worker, "head": head_worker}
            measurements, checks = [], []
            for _ in range(max(1, attempts)):
                measured = measure_ark(workers, workloads, rounds)
                measurements.append(measured)
                current = latency_checks(measured["base"], measured["head"])
                # A check passes when any attempt passed it.
                checks = current if not checks else [
                    {**now, "ok": before["ok"] or now["ok"]} for before, now in zip(checks, current)
                ]
                if all(check["ok"] for check in checks):
                    break
    last = measurements[-1]
    return {
        "schema": SCHEMA,
        "workloads": workload_stats(workloads),
        "pinned_cpus": pinned,
        "attempts": len(measurements),
        "base": last["base"],
        "head": last["head"],
        "measurements": measurements,
        "checks": checks,
    }


def gate_lines(result: dict[str, Any]) -> list[str]:
    if result.get("skipped"):
        return [f"dev latency: not measured ({result['skipped']})"]
    b, h = result["base"], result["head"]
    b95, h95 = b[GATED_SIZE]["p95_ms"], h[GATED_SIZE]["p95_ms"]
    delta = (h95 / b95 - 1) * 100 if b95 else 0.0
    line = (f"dev latency: 100 KiB p95 {b95:.2f} → {h95:.2f} ms ({delta:+.1f} %, budget {BUDGET_MS:g} ms)")
    if "repo" in b and "repo" in h:
        line += f", 10 MiB repo {_fmt(b['repo']['mib_per_s'])} → {_fmt(h['repo']['mib_per_s'])} MiB/s"
    return [line + (f", {result['attempts']} attempts" if result["attempts"] > 1 else "")]


# ── CLI ──────────────────────────────────────────────────────────────────────


def _names(value: str, allowed: tuple[str, ...]) -> list[str]:
    names = [name.strip() for name in value.split(",") if name.strip()]
    unknown = [name for name in names if name not in allowed]
    if unknown or not names:
        raise argparse.ArgumentTypeError(f"choose from {', '.join(allowed)}")
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    b = commands.add_parser("bench", help="time ARK and the baselines on the dev workloads")
    b.add_argument("--dev", type=Path, required=True, help="frozen dev split (prepare_corpora.py)")
    b.add_argument("--tools", type=lambda v: _names(v, TOOLS), default=list(TOOLS))
    b.add_argument("--sizes", type=lambda v: _names(v, SIZES), default=list(SIZES))
    b.add_argument("--rounds", type=int, default=BENCH_ROUNDS, help=f"rounds per workload (default {BENCH_ROUNDS})")
    b.add_argument("--invocations", type=int, default=INVOCATIONS,
                   help=f"per-document baseline runs per workload (default {INVOCATIONS})")
    b.add_argument("--cpus", type=int, default=1, help="pin every process to N CPUs (0 = no pinning)")
    b.add_argument("--package", type=Path, help="ARK build directory with patronus_ark/ (default: installed)")
    b.add_argument("--bin-dir", type=Path, default=BASELINES.BASELINES_DIR / "bin")
    b.add_argument("--detect-secrets-python", type=Path, default=BASELINES.DETECT_SECRETS_PYTHON)
    b.add_argument("--output", type=Path, help="write the JSON report here")
    w = commands.add_parser(WORKER, help=argparse.SUPPRESS)
    w.add_argument("--workloads", type=Path, required=True)
    w.add_argument("--package", type=Path)
    d = commands.add_parser(DETECT_SECRETS_WORKER, help=argparse.SUPPRESS)
    d.add_argument("root", type=Path)
    args = parser.parse_args(argv)

    if args.command == WORKER:
        return _ark_worker(args.package, args.workloads)
    if args.command == DETECT_SECRETS_WORKER:
        return _detect_secrets_worker(args.root)
    try:
        report = bench(args.dev, args.tools, args.sizes, max(1, args.rounds), pinned_cpus(args.cpus),
                       args.package, args.bin_dir, args.detect_secrets_python, max(0, args.invocations))
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"latency: error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n".join(table_lines(report)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
