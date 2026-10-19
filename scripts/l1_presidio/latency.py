#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Latency benchmark Ark PII-L1 vs. Presidio on short, 4 KiB and 100 KiB inputs.

All engines run on the same machine and the same fixed workloads: a short sentence,
exactly 4096 and exactly 102400 UTF-8 bytes of DE and EN business prose with PII in
two of three paragraphs. Each engine is measured in its own process, one call per
sample, after warmup: ``ark`` through the Python bindings of a release build of the
checkout, ``ark-native`` through the Rust gateway (``rust/dev/l1_latency_workloads.rs``),
Presidio ``default``/``tuned`` from its pinned venv. Python pauses the garbage collector
while timing. The L1 pipeline has no result cache, so repeating a text measures the
scan itself. After MIN_SAMPLES samples a workload stops once BUDGET_S is spent.

    # on the VPS: release build of the checkout, Ark + Presidio default/tuned
    python3 scripts/l1_presidio/latency.py run --ark-python .venv/bin/python \
        --presidio-python ~/ark-l1/presidio-venv/bin/python \
        --output latency.json --markdown latency.md [--check-m4]
    # a change against its base (gate criterion: 100 KiB p95 at most +10 %)
    python3 scripts/l1_presidio/latency.py compare --base base.json --head head.json

``measure`` is the worker that ``run`` starts once per Python engine. ``run`` exits 1
with ``--check-m4`` if an Ark engine's 100 KiB p95 exceeds 10 ms (milestone M4); ``compare`` exits 1
if a gated p95 grew by more than the tolerance; both exit 2 on setup errors (debug
build, Presidio pins, differing workloads).
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "ark-l1-latency-v1"
WORKLOAD_VERSION = "1"
LANGUAGES = ("de", "en")
# Size class -> exact UTF-8 bytes (None: the first paragraph alone).
SIZES: dict[str, int | None] = {"short": None, "4kib": 4 * 1024, "100kib": 100 * 1024}
SAMPLES = {"short": 500, "4kib": 200, "100kib": 50}
WARMUP = {"short": 20, "4kib": 10, "100kib": 3}
# Presidio needs about 10 s per 100 KiB call: after MIN_SAMPLES, stop once BUDGET_S is spent.
MIN_SAMPLES = 10
BUDGET_S = 60.0
ENGINES = ("ark", "ark-native", "presidio-default", "presidio-tuned")
ARK_ENGINES = ("ark", "ark-native")
M4_SIZE = "100kib"
M4_P95_MS = 10.0
TOLERANCE_PCT = 10.0
NATIVE_LIBRARY = "lib_patronus_ark.so"
NATIVE_MODULE = "_patronus_ark.abi3.so"
NATIVE_EXAMPLE = "l1_latency_workloads"
DEFAULT_PRESIDIO_PYTHON = Path.home() / "ark-l1" / "presidio-venv" / "bin" / "python"

# Every third paragraph is benign; the PII paragraphs cover the shared entities.
PARAGRAPHS = {
    "en": [
        "Please send the signed contract to jane.miller@contoso-mail.com or call +1 415 867 5309 by Friday.",
        "The quarterly review covers the logistics budget, the warehouse expansion and the supplier "
        "contracts that were renegotiated in spring.",
        "Payment goes to IBAN GB82 WEST 1234 5698 7654 32; the card on file is 4111 1111 1111 1111.",
        "The VPN gateway at 10.24.8.17 recorded a login from 198.51.100.23 shortly after midnight, "
        "which the on-call engineer confirmed.",
        "Our team will review the open items in the next planning meeting and report back to the "
        "steering committee with a recommendation.",
        "Employee Daniel Brooks, SSN 219-09-9999, date of birth 04/12/1986, moved to the Denver office.",
        "Customer support reached Maria Lopez at maria.lopez@fabrikam-shop.net about order 58213.",
        "The facility team replaced the ventilation filters on all floors and updated the maintenance "
        "schedule for the coming year.",
        "Passport number 533380006 and driver license D1234567 were checked at the front desk.",
    ],
    "de": [
        "Bitte senden Sie den unterschriebenen Vertrag an juergen.weiss@beispiel-firma.de oder rufen Sie "
        "+49 30 12345678 an.",
        "Der Quartalsbericht umfasst das Logistikbudget, die Erweiterung des Lagers und die im Frühjahr "
        "neu verhandelten Lieferverträge.",
        "Die Zahlung erfolgt auf IBAN DE89 3704 0044 0532 0130 00 (BIC COBADEFFXXX), Kreditkarte "
        "5500 0000 0000 0004.",
        "Das VPN-Gateway 10.24.8.17 verzeichnete kurz nach Mitternacht eine Anmeldung von 198.51.100.23, "
        "die der Bereitschaftsdienst bestätigt hat.",
        "Unser Team prüft die offenen Punkte in der nächsten Planungsrunde und berichtet dem "
        "Lenkungskreis mit einer Empfehlung.",
        "Frau Müller, geboren am 12.04.1986, Steuer-ID 65 929 970 489, ist in die Münchner Niederlassung "
        "gewechselt.",
        "Der Kundendienst erreichte Herrn Schäfer unter s.schaefer@kundenportal-test.de wegen Auftrag 58213.",
        "Das Facility-Team hat die Lüftungsfilter auf allen Etagen getauscht und den Wartungsplan für das "
        "kommende Jahr aktualisiert.",
        "Personalausweis T22000129 und Führerschein B072RRE2I55 wurden am Empfang geprüft.",
    ],
}


class LatencyError(Exception):
    """Setup or input problem (exit 2)."""


class Workload(NamedTuple):
    id: str
    size: str
    language: str
    text: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_text(language: str, size: int | None) -> str:
    """The first paragraph, or whole paragraphs cycled and space-padded to exactly size bytes."""
    paragraphs = PARAGRAPHS[language]
    if size is None:
        return paragraphs[0]
    parts: list[str] = []
    used = 0
    index = 0
    while True:
        paragraph = paragraphs[index % len(paragraphs)]
        cost = len(paragraph.encode("utf-8")) + (2 if parts else 0)
        if used + cost > size:
            break
        parts.append(paragraph)
        used += cost
        index += 1
    text = "\n\n".join(parts)
    return text + " " * (size - len(text.encode("utf-8")))


def workloads() -> list[Workload]:
    return [
        Workload(f"{size}-{language}", size, language, build_text(language, nbytes))
        for size, nbytes in SIZES.items()
        for language in LANGUAGES
    ]


def describe_workloads(items: Iterable[Workload]) -> list[dict[str, Any]]:
    return [
        {
            "id": item.id,
            "size": item.size,
            "language": item.language,
            "bytes": len(item.text.encode("utf-8")),
            "chars": len(item.text),
            "sha256": sha256_bytes(item.text.encode("utf-8")),
        }
        for item in items
    ]


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile."""
    if not values:
        raise ValueError("percentile of no samples")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def summarize(samples_ns: list[int]) -> dict[str, Any]:
    ms = [value / 1e6 for value in samples_ns]
    return {
        "samples": len(ms),
        "p50_ms": round(percentile(ms, 0.50), 4),
        "p95_ms": round(percentile(ms, 0.95), 4),
        "p99_ms": round(percentile(ms, 0.99), 4),
        "mean_ms": round(sum(ms) / len(ms), 4),
        "max_ms": round(max(ms), 4),
    }


def sample_counts(scale: float) -> dict[str, int]:
    return {size: max(1, round(count * scale)) for size, count in SAMPLES.items()}


def time_workload(
    analyze: Callable[[str, str], int],
    item: Workload,
    samples: int,
    warmup: int,
    clock: Callable[[], int] = time.perf_counter_ns,
    min_samples: int = MIN_SAMPLES,
    budget_s: float = BUDGET_S,
) -> tuple[int, list[int]]:
    """Return (spans, sample durations in ns); stop after min_samples once budget_s is spent."""
    for _ in range(warmup):
        analyze(item.text, item.language)
    spans = analyze(item.text, item.language)
    times: list[int] = []
    gc.collect()
    gc.disable()
    try:
        begin = clock()
        while len(times) < samples:
            if len(times) >= min_samples and clock() - begin > budget_s * 1e9:
                break
            started = clock()
            analyze(item.text, item.language)
            times.append(clock() - started)
    finally:
        gc.enable()
    return spans, times


def aggregate(items: list[Workload], timings: dict[str, tuple[int, list[int]]]) -> dict[str, Any]:
    """Summaries per workload and per size class (DE + EN samples pooled)."""
    per_workload = {}
    pooled: dict[str, list[int]] = {}
    for item in items:
        spans, times = timings[item.id]
        per_workload[item.id] = {**summarize(times), "spans": spans}
        pooled.setdefault(item.size, []).extend(times)
    return {
        "results": per_workload,
        "sizes": {size: summarize(times) for size, times in pooled.items()},
    }


def measure(
    analyze: Callable[[str, str], int],
    items: list[Workload],
    samples: dict[str, int],
    warmup: dict[str, int] = WARMUP,
    clock: Callable[[], int] = time.perf_counter_ns,
    budget_s: float = BUDGET_S,
) -> dict[str, Any]:
    """Time analyze(text, language) per workload; analyze returns the number of spans."""
    return aggregate(items, {
        item.id: time_workload(analyze, item, samples[item.size], warmup.get(item.size, 0), clock,
                               budget_s=budget_s)
        for item in items
    })


# ── ELF check: the dev profile keeps line tables, release strips debug info ──


def elf_section_names(path: Path) -> list[str] | None:
    """Section names of a 64-bit little-endian ELF file; None for other formats."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if not shoff or shstrndx >= shnum:
        return []

    def header(index: int) -> tuple[int, int, int]:
        base = shoff + index * shentsize
        name = struct.unpack_from("<I", data, base)[0]
        offset, size = struct.unpack_from("<QQ", data, base + 0x18)
        return name, offset, size

    _, strtab, strsize = header(shstrndx)
    names = []
    for index in range(shnum):
        name = header(index)[0]
        end = data.index(b"\0", strtab + name, strtab + strsize)
        names.append(data[strtab + name : end].decode("ascii", "replace"))
    return names


def is_debug_build(path: Path) -> bool | None:
    names = elf_section_names(path)
    if names is None:
        return None
    return any(name.startswith(".debug_") for name in names)


# ── engines (run inside the engine's own interpreter) ─────────────────────


def ark_engine(allow_debug: bool) -> tuple[Callable[[str, str], int], dict[str, Any]]:
    from patronus_ark import SecurityGateway, _patronus_ark

    module = Path(_patronus_ark.__file__).resolve()
    debug = is_debug_build(module)
    if debug and not allow_debug:
        raise LatencyError(f"{module} is a debug build; measure a release build (run builds one)")
    gateway = SecurityGateway(categories=["pii"], max_level="l1", download_files=False)

    def analyze(text: str, language: str) -> int:
        return sum(len(result.get("evidence_spans", [])) for result in gateway.scan_category("pii", text))

    info = {
        "native_module": str(module),
        "native_sha256": sha256_bytes(module.read_bytes()),
        "debug_build": debug,
    }
    return analyze, info


def presidio_engine(profile_name: str) -> tuple[Callable[[str, str], int], dict[str, Any]]:
    sys.path.insert(0, str(HERE))
    import run_presidio

    pins = run_presidio.parse_requirements(run_presidio.REQUIREMENTS_PATH)
    problems = run_presidio.check_pins(pins)
    if problems:
        raise LatencyError("installed packages differ from requirements.txt: " + "; ".join(problems))
    profile = run_presidio.load_profile(profile_name)
    analyzer = run_presidio.build_analyzer(profile)
    threshold = profile["score_threshold"]

    def analyze(text: str, language: str) -> int:
        target = run_presidio.analysis_language(language, profile)
        return len(analyzer.analyze(text=text, language=target, score_threshold=threshold))

    info = {
        "profile": profile_name,
        "score_threshold": threshold,
        "versions": {name: run_presidio._installed_version(name) or "none"
                     for name in ("presidio-analyzer", "spacy")},
    }
    return analyze, info


def machine_info() -> dict[str, Any]:
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    try:
        usable = len(os.sched_getaffinity(0))
    except AttributeError:
        usable = os.cpu_count()
    return {
        "cpu": cpu,
        "cpus": os.cpu_count(),
        "cpus_usable": usable,
        "machine": platform.machine(),
        "system": platform.system(),
    }


def cmd_measure(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    if args.engine == "ark":
        analyze, info = ark_engine(args.allow_debug)
    else:
        analyze, info = presidio_engine(args.engine.removeprefix("presidio-"))
    init_ms = (time.perf_counter() - started) * 1000
    items = workloads()
    load_before = os.getloadavg()[0]
    result = measure(analyze, items, sample_counts(args.samples_scale), budget_s=args.budget_s)
    return {
        "engine": args.engine,
        "init_ms": round(init_ms, 1),
        "info": {**info, "python": platform.python_version()},
        "machine": machine_info(),
        "loadavg_1m": [round(load_before, 2), round(os.getloadavg()[0], 2)],
        "workloads": describe_workloads(items),
        **result,
    }


# ── orchestration ─────────────────────────────────────────────────────────


def build_release(repo: Path, stage: Path, cargo: str = "cargo") -> Path:
    """cargo build --release of the Python crate; stage the package with the native module."""
    target = Path(os.environ.get("CARGO_TARGET_DIR") or repo / "target")
    proc = subprocess.run(
        [cargo, "build", "--release", "--locked", "--lib", "--manifest-path", str(repo / "python" / "Cargo.toml")],
        cwd=repo, text=True, capture_output=True,
    )
    if proc.returncode != 0:
        raise LatencyError(f"release build failed:\n{proc.stderr.strip()[-3000:]}")
    library = target / "release" / NATIVE_LIBRARY
    if not library.is_file():
        raise LatencyError(f"release build produced no {library}")
    package = stage / "patronus_ark"
    shutil.rmtree(package, ignore_errors=True)
    shutil.copytree(repo / "python" / "patronus_ark", package,
                    ignore=shutil.ignore_patterns("benchmark_data", "__pycache__", "*.so"))
    shutil.copy2(library, package / NATIVE_MODULE)
    return package / NATIVE_MODULE


def build_native(repo: Path, cargo: str = "cargo") -> Path:
    """cargo build --release of the native timing worker (rust/dev/l1_latency_workloads.rs)."""
    target = Path(os.environ.get("CARGO_TARGET_DIR") or repo / "target")
    proc = subprocess.run(
        [cargo, "build", "--release", "--locked", "--example", NATIVE_EXAMPLE,
         "--manifest-path", str(repo / "rust" / "Cargo.toml")],
        cwd=repo, text=True, capture_output=True,
    )
    if proc.returncode != 0:
        raise LatencyError(f"native release build failed:\n{proc.stderr.strip()[-3000:]}")
    binary = target / "release" / "examples" / NATIVE_EXAMPLE
    if not binary.is_file():
        raise LatencyError(f"native release build produced no {binary}")
    return binary


def measure_native(binary: Path, samples: dict[str, int], budget_s: float = BUDGET_S) -> dict[str, Any]:
    """Run the native worker on the same workloads; summarize like the Python engines."""
    items = workloads()
    jobs = "".join(
        json.dumps({"id": item.id, "text": item.text, "samples": samples[item.size],
                    "warmup": WARMUP[item.size], "min_samples": MIN_SAMPLES,
                    "budget_ms": budget_s * 1000}, ensure_ascii=False) + "\n"
        for item in items
    )
    load_before = os.getloadavg()[0]
    with tempfile.TemporaryDirectory(prefix="ark-l1-latency-") as tmp:
        path = Path(tmp) / "jobs.jsonl"
        path.write_text(jobs, encoding="utf-8")
        proc = subprocess.run([str(binary), str(path)], text=True, capture_output=True)
    if proc.returncode != 0:
        raise LatencyError(f"ark-native worker failed (exit {proc.returncode}):\n{proc.stderr.strip()[-3000:]}")
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    if [line["id"] for line in lines] != [item.id for item in items]:
        raise LatencyError("ark-native worker returned other workloads than requested")
    if any(not line["samples_ns"] for line in lines):
        raise LatencyError("ark-native worker returned a workload without samples")
    return {
        "engine": "ark-native",
        "init_ms": round(lines[0]["init_ms"], 1),
        "info": {"binary_sha256": sha256_bytes(binary.read_bytes())},
        "machine": machine_info(),
        "loadavg_1m": [round(load_before, 2), round(os.getloadavg()[0], 2)],
        "workloads": describe_workloads(items),
        **aggregate(items, {line["id"]: (line["spans"], line["samples_ns"]) for line in lines}),
    }


def run_worker(python: str, engine: str, args: argparse.Namespace, env: dict[str, str]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ark-l1-latency-") as tmp:
        output = Path(tmp) / f"{engine}.json"
        cmd = [python, str(Path(__file__).resolve()), "measure", "--engine", engine,
               "--output", str(output), "--samples-scale", str(args.samples_scale),
               "--budget-s", str(args.budget_s)]
        if args.allow_debug:
            cmd.append("--allow-debug")
        proc = subprocess.run(cmd, env={**os.environ, **env}, text=True, capture_output=True)
        if proc.returncode != 0:
            raise LatencyError(f"{engine} worker failed (exit {proc.returncode}):\n{proc.stderr.strip()[-3000:]}")
        return json.loads(output.read_text(encoding="utf-8"))


def m4_check(report: dict[str, Any]) -> dict[str, Any]:
    """M4 for every measured Ark engine (Python binding and native)."""
    checks = {}
    for engine in ARK_ENGINES:
        if engine in report["engines"]:
            p95 = report["engines"][engine]["sizes"][M4_SIZE]["p95_ms"]
            checks[engine] = {"p95_ms": p95, "pass": p95 <= M4_P95_MS}
    return {"size": M4_SIZE, "limit_ms": M4_P95_MS, "engines": checks,
            "pass": all(check["pass"] for check in checks.values())}


def assemble(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge worker results; every engine must have measured the same workloads."""
    if not results:
        raise LatencyError("no engine measured")
    reference = results[0]["workloads"]
    for result in results[1:]:
        if result["workloads"] != reference:
            raise LatencyError(f"{result['engine']} measured different workloads than {results[0]['engine']}")
        if result["machine"] != results[0]["machine"]:
            raise LatencyError(f"{result['engine']} ran on a different machine than {results[0]['engine']}")
    report = {
        "schema": SCHEMA,
        "workload_version": WORKLOAD_VERSION,
        "machine": results[0]["machine"],
        "workloads": reference,
        "engines": {
            result["engine"]: {key: result[key] for key in ("init_ms", "info", "loadavg_1m", "sizes", "results")}
            for result in results
        },
    }
    if any(engine in report["engines"] for engine in ARK_ENGINES):
        report["m4"] = m4_check(report)
    return report


def table(report: dict[str, Any]) -> list[str]:
    engines = list(report["engines"])
    lines = [
        "| Engine | Init ms | " + " | ".join(f"{size} p50 / p95 / p99 ms" for size in SIZES) + " |",
        "|---|---:|" + "---:|" * len(SIZES),
    ]
    for engine in engines:
        data = report["engines"][engine]
        cells = [
            "{p50_ms:.3f} / {p95_ms:.3f} / {p99_ms:.3f}".format(**data["sizes"][size]) for size in SIZES
        ]
        lines.append(f"| {engine} | {data['init_ms']:.0f} | " + " | ".join(cells) + " |")
    if "ark" in engines and len(engines) > 1:
        # Presidio runs in Python too, so the Python binding is the like-for-like reference.
        lines += ["", "| p95 / Ark (Python) | " + " | ".join(SIZES) + " |", "|---|" + "---:|" * len(SIZES)]
        ark = report["engines"]["ark"]["sizes"]
        for engine in engines:
            if engine != "ark":
                other = report["engines"][engine]["sizes"]
                ratios = [other[size]["p95_ms"] / ark[size]["p95_ms"] for size in SIZES]
                lines.append(f"| {engine} | " + " | ".join(
                    f"{ratio:.0f}×" if ratio >= 10 else f"{ratio:.2f}×" for ratio in ratios) + " |")
    return lines


def m4_lines(m4: dict[str, Any]) -> list[str]:
    return [
        f"M4 ({engine} {m4['size']} p95 ≤ {m4['limit_ms']:g} ms): {check['p95_ms']:.3f} ms, "
        + ("pass." if check["pass"] else "FAIL.")
        for engine, check in m4["engines"].items()
    ]


def markdown(report: dict[str, Any]) -> str:
    machine = report["machine"]
    lines = [
        "# L1-PII latency: Ark vs. Presidio",
        "",
        f"Machine: {machine['cpu']}, {machine['cpus_usable']} usable CPUs, {machine['system']} "
        f"{machine['machine']}. One call per sample, sequential, each engine in its own process. "
        f"Workloads v{report['workload_version']}: DE + EN pooled per size class.",
        "",
        *table(report),
        "",
        "| Workload | Bytes | Chars | " + " | ".join(f"{engine} spans" for engine in report["engines"]) + " |",
        "|---|---:|---:|" + "---:|" * len(report["engines"]),
    ]
    for item in report["workloads"]:
        spans = [str(data["results"][item["id"]]["spans"]) for data in report["engines"].values()]
        lines.append(f"| {item['id']} | {item['bytes']} | {item['chars']} | " + " | ".join(spans) + " |")
    if "m4" in report:
        lines += ["", *m4_lines(report["m4"])]
    return "\n".join(lines) + "\n"


def cmd_run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    results = []
    engines = [engine for engine in ENGINES if engine in (args.engines or ENGINES)]
    with tempfile.TemporaryDirectory(prefix="ark-l1-latency-stage-") as stage:
        for engine in engines:
            if engine == "ark-native":
                result = measure_native(build_native(ROOT, args.cargo), sample_counts(args.samples_scale),
                                        args.budget_s)
            elif engine == "ark":
                env = {}
                if not args.installed_ark:
                    module = build_release(ROOT, Path(stage), args.cargo)
                    env = {"PYTHONPATH": stage}
                result = run_worker(args.ark_python, engine, args, env)
                loaded = result["info"].pop("native_module")
                if not args.installed_ark and Path(loaded) != module.resolve():
                    raise LatencyError(f"ark worker loaded {loaded}, not {module}")
            else:
                result = run_worker(args.presidio_python, engine, args, {})
            results.append(result)
            print(f"{engine}: done", file=sys.stderr)
    report = assemble(results)
    failed = args.check_m4 and not report.get("m4", {}).get("pass", False)
    return report, 1 if failed else 0


def compare(base: dict[str, Any], head: dict[str, Any], engine: str = "ark",
            sizes: Iterable[str] = (M4_SIZE,), tolerance_pct: float = TOLERANCE_PCT) -> dict[str, Any]:
    """p95 of head vs. base per size class; a gated size regresses above +tolerance_pct."""
    if base.get("workloads") != head.get("workloads"):
        raise LatencyError("base and head measured different workloads")
    if base.get("machine") != head.get("machine"):
        raise LatencyError("base and head were measured on different machines")
    for side, report in (("base", base), ("head", head)):
        if engine not in report.get("engines", {}):
            raise LatencyError(f"{side} report has no {engine} measurement")
    gated = set(sizes)
    rows = []
    for size in SIZES:
        before = base["engines"][engine]["sizes"][size]["p95_ms"]
        after = head["engines"][engine]["sizes"][size]["p95_ms"]
        change = (after / before - 1) * 100 if before else math.inf
        rows.append({"size": size, "base_p95_ms": before, "head_p95_ms": after,
                     "change_pct": round(change, 1), "gated": size in gated,
                     "regression": size in gated and change > tolerance_pct})
    return {"engine": engine, "tolerance_pct": tolerance_pct, "rows": rows,
            "regression": any(row["regression"] for row in rows)}


def compare_lines(result: dict[str, Any]) -> list[str]:
    lines = [f"{result['engine']} p95 head vs. base (gated sizes: at most +{result['tolerance_pct']:g} %)"]
    for row in result["rows"]:
        mark = "REGRESSION" if row["regression"] else ("gated" if row["gated"] else "")
        lines.append(f"  {row['size']:<7} {row['base_p95_ms']:>9.3f} ms -> {row['head_p95_ms']:>9.3f} ms "
                     f"({row['change_pct']:+.1f} %) {mark}".rstrip())
    lines.append("RESULT: " + ("REGRESSION" if result["regression"] else "PASS"))
    return lines


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    measure_parser = sub.add_parser("measure", help="measure one engine in this interpreter")
    measure_parser.add_argument("--engine", choices=[e for e in ENGINES if e != "ark-native"], required=True)
    measure_parser.add_argument("--output", type=Path, required=True)

    run_parser = sub.add_parser("run", help="measure every engine in its own interpreter")
    run_parser.add_argument("--engines", nargs="+", choices=ENGINES)
    run_parser.add_argument("--ark-python", default=str(Path(os.environ["VIRTUAL_ENV"]) / "bin" / "python")
                            if os.environ.get("VIRTUAL_ENV") else sys.executable)
    run_parser.add_argument("--presidio-python", default=str(DEFAULT_PRESIDIO_PYTHON))
    run_parser.add_argument("--installed-ark", action="store_true",
                            help="measure the patronus_ark of --ark-python instead of a fresh release build")
    run_parser.add_argument("--cargo", default="cargo")
    run_parser.add_argument("--output", type=Path, required=True, help="report JSON")
    run_parser.add_argument("--markdown", type=Path, help="report Markdown")
    run_parser.add_argument("--check-m4", action="store_true",
                            help=f"exit 1 if an Ark engine's {M4_SIZE} p95 exceeds {M4_P95_MS:g} ms")

    for each in (measure_parser, run_parser):
        each.add_argument("--samples-scale", type=float, default=1.0, help="scale the sample counts")
        each.add_argument("--allow-debug", action="store_true", help="accept a debug build of Ark")
        each.add_argument("--budget-s", type=float, default=BUDGET_S,
                          help=f"stop a workload after {MIN_SAMPLES} samples once this many seconds are spent")

    compare_parser = sub.add_parser("compare", help="head vs. base report (p95 tolerance)")
    compare_parser.add_argument("--base", type=Path, required=True)
    compare_parser.add_argument("--head", type=Path, required=True)
    compare_parser.add_argument("--engine", choices=ENGINES, default="ark")
    compare_parser.add_argument("--sizes", nargs="+", choices=list(SIZES), default=[M4_SIZE])
    compare_parser.add_argument("--tolerance-pct", type=float, default=TOLERANCE_PCT)

    args = parser.parse_args(argv)
    try:
        if args.command != "compare" and (args.samples_scale <= 0 or args.budget_s <= 0):
            raise LatencyError("--samples-scale and --budget-s must be positive")
        if args.command == "measure":
            write_json(args.output, cmd_measure(args))
            return 0
        if args.command == "run":
            report, code = cmd_run(args)
            write_json(args.output, report)
            if args.markdown:
                args.markdown.write_text(markdown(report), encoding="utf-8")
            print("\n".join(table(report)))
            if "m4" in report:
                print("\n".join(m4_lines(report["m4"])))
            return code
        base = json.loads(args.base.read_text(encoding="utf-8"))
        head = json.loads(args.head.read_text(encoding="utf-8"))
        result = compare(base, head, args.engine, args.sizes, args.tolerance_pct)
        print("\n".join(compare_lines(result)))
        return 1 if result["regression"] else 0
    except LatencyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
