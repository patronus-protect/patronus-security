#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure Patronus Ark peak RSS for large-text scan scenarios.

The parent process starts one child process per scenario and polls child RSS.
The child imports patronus_ark, builds one SecurityGateway, optionally warms it
from local assets, enqueues the configured number of requests, and consumes
events until every request finishes.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ("l1_l2", "l1_l2_l3", "l1_dynamic_pii", "dynamic_pii_only")
MOBY_DICK_PLAINTEXT_MIB = 1.2
PRODUCT_CATEGORIES = [
    "injection",
    "dlp",
    "pii",
    "sensitive_document",
    "tool_class",
    "tool_action",
    "tool_tags",
    "routing",
    "threat",
    "dynamic-pii",
]


@dataclass(frozen=True)
class SurfaceRequest:
    name: str
    categories: list[str]
    gates: dict[str, Any]
    ntdb_operating_point: str
    text_bytes: int | None = None
    use_full_text: bool = False


@dataclass(frozen=True)
class Scenario:
    name: str
    categories: list[str]
    max_level: str
    execution_gates: dict[str, Any]


SCENARIOS: dict[str, Scenario] = {
    "l1_l2": Scenario(
        name="l1_l2",
        categories=["injection"],
        max_level="l2",
        execution_gates={"levels": {"l1": True, "l2": True, "l3": False}},
    ),
    "l1_l2_l3": Scenario(
        name="l1_l2_l3",
        categories=["injection"],
        max_level="l3",
        execution_gates={"levels": {"l1": True, "l2": True, "l3": True}},
    ),
    "l1_dynamic_pii": Scenario(
        name="l1_dynamic_pii",
        categories=["dynamic-pii"],
        max_level="l3",
        execution_gates={"levels": {"l1": True, "l2": False, "l3": True}},
    ),
    "dynamic_pii_only": Scenario(
        name="dynamic_pii_only",
        categories=["dynamic-pii"],
        max_level="l3",
        execution_gates={"levels": {"l1": False, "l2": False, "l3": True}},
    ),
    "desktop_inventory_l2": Scenario(
        name="desktop_inventory_l2",
        categories=PRODUCT_CATEGORIES,
        max_level="l3",
        execution_gates={"levels": {"l1": True, "l2": True, "l3": False}},
    ),
    "desktop_response_mix_l2": Scenario(
        name="desktop_response_mix_l2",
        categories=PRODUCT_CATEGORIES,
        max_level="l3",
        execution_gates={"levels": {"l1": True, "l2": True, "l3": False}},
    ),
    "all_pipelines_unified_dynamic_pii": Scenario(
        name="all_pipelines_unified_dynamic_pii",
        categories=PRODUCT_CATEGORIES,
        max_level="l3",
        execution_gates={"levels": {"l1": True, "l2": True, "l3": True}},
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run isolated peak-RSS benchmarks for large-text Patronus Ark scans. "
            f"Plaintext Moby Dick is roughly {MOBY_DICK_PLAINTEXT_MIB:.1f} MiB, "
            "depending on edition and encoding; use --target-mb 10 to repeat it."
        )
    )
    parser.add_argument("--text-file", type=Path, help="UTF-8 text file to benchmark.")
    parser.add_argument(
        "--target-mb",
        type=float,
        default=None,
        help="Repeat/truncate the input to this many MiB before scanning.",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=1,
        help=(
            "Concurrent benchmark units inside each child process. For desktop_* cases, "
            "one request means one desktop-like audit fanout with many Ark requests."
        ),
    )
    parser.add_argument(
        "--cases",
        default=",".join(DEFAULT_CASES),
        help=f"Comma-separated cases. Known: {', '.join(SCENARIOS)}.",
    )
    parser.add_argument("--model-dir", type=Path, help="Asset root used by patronus_ark.")
    parser.add_argument(
        "--download-files",
        action="store_true",
        help="Allow child gateways to download missing assets. Default is offline.",
    )
    parser.add_argument(
        "--no-warmup",
        action="store_true",
        help="Do not call gateway.warmup() before measuring request RAM.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=180.0,
        help="Maximum wall time per child scenario.",
    )
    parser.add_argument(
        "--poll-interval-ms",
        type=int,
        default=100,
        help="Parent RSS polling interval.",
    )
    parser.add_argument(
        "--cache-memory-max-entries",
        type=int,
        default=0,
        help="Ark hot-cache entry limit. Default 0 preserves the old no-hot-cache benchmark.",
    )
    parser.add_argument(
        "--cache-memory-max-bytes",
        type=int,
        default=0,
        help="Ark hot-cache byte limit. Desktop default is 134217728.",
    )
    parser.add_argument(
        "--cache-storage-location",
        type=Path,
        help="Optional persistent exact-cache file used by the child gateway.",
    )
    parser.add_argument("--json-output", type=Path, help="Write full JSON results.")
    parser.add_argument("--child-case", choices=tuple(SCENARIOS), help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.child_case:
        return run_child(args)
    return run_parent(args)


def run_parent(args: argparse.Namespace) -> int:
    cases = parse_cases(args.cases)
    results = []
    for case in cases:
        result = run_case_process(args, case)
        results.append(result)
        print_case_result(result)

    if args.json_output:
        args.json_output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    failed = [result for result in results if result["returncode"] != 0]
    return 1 if failed else 0


def parse_cases(value: str) -> list[str]:
    cases = [case.strip() for case in value.split(",") if case.strip()]
    unknown = [case for case in cases if case not in SCENARIOS]
    if unknown:
        raise SystemExit(f"unknown case(s): {', '.join(unknown)}")
    return cases


def run_case_process(args: argparse.Namespace, case: str) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--child-case",
        case,
        "--requests",
        str(args.requests),
        "--timeout-seconds",
        str(args.timeout_seconds),
    ]
    if args.text_file:
        command.extend(["--text-file", str(args.text_file)])
    if args.target_mb is not None:
        command.extend(["--target-mb", str(args.target_mb)])
    if args.model_dir:
        command.extend(["--model-dir", str(args.model_dir)])
    if args.download_files:
        command.append("--download-files")
    if args.no_warmup:
        command.append("--no-warmup")
    command.extend(["--cache-memory-max-entries", str(args.cache_memory_max_entries)])
    command.extend(["--cache-memory-max-bytes", str(args.cache_memory_max_bytes)])
    if args.cache_storage_location:
        command.extend(["--cache-storage-location", str(args.cache_storage_location)])

    env = os.environ.copy()
    env["PYTHONPATH"] = prepend_path(env.get("PYTHONPATH"), str(REPO_ROOT / "python"))
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    peak_rss_kb = 0
    timed_out = False
    poll_interval = max(args.poll_interval_ms, 10) / 1000.0
    while process.poll() is None:
        peak_rss_kb = max(peak_rss_kb, process_rss_kb(process.pid))
        if time.monotonic() - started > args.timeout_seconds:
            timed_out = True
            process.kill()
            break
        time.sleep(poll_interval)
    stdout, stderr = process.communicate()
    peak_rss_kb = max(peak_rss_kb, process_rss_kb(process.pid))

    payload = parse_child_json(stdout)
    return {
        "case": case,
        "returncode": process.returncode,
        "timed_out": timed_out,
        "parent_peak_rss_mb": peak_rss_from_parent_or_child(peak_rss_kb, payload),
        "elapsed_s": round(time.monotonic() - started, 3),
        "child": payload,
        "stderr": stderr.strip(),
    }


def parse_child_json(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def run_child(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(REPO_ROOT / "python"))
    from patronus_ark import SecurityGateway

    scenario = SCENARIOS[args.child_case]
    text = load_text(args.text_file, args.target_mb)
    dynamic_pii_config = {
        "labels": ["person", "organization", "location", "date", "email"],
        "threshold": 0.5,
        "max_text_bytes": len(text.encode("utf-8")) + 1024,
        "chunk_size_words": 256,
        "chunk_overlap_words": 32,
        "timeout_ms": 5_000,
        "queue_timeout_ms": int(max(args.timeout_seconds * 1000, 1_000)),
        "timeout_per_chunk_ms": 500,
        "max_timeout_ms": int(max(args.timeout_seconds * 1000, 5_000)),
    }

    started = time.monotonic()
    output: dict[str, Any] = {
        "case": args.child_case,
        "categories": scenario.categories,
        "max_level": scenario.max_level,
        "requests": args.requests,
        "input_bytes": len(text.encode("utf-8")),
        "input_mib": round(len(text.encode("utf-8")) / (1024 * 1024), 3),
        "warmup": not args.no_warmup,
        "cache_memory_max_entries": args.cache_memory_max_entries,
        "cache_memory_max_bytes": args.cache_memory_max_bytes,
        "cache_storage_location": None
        if args.cache_storage_location is None
        else str(args.cache_storage_location),
    }
    try:
        gateway = SecurityGateway(
            categories=scenario.categories,
            max_level=scenario.max_level,
            model_dir=None if args.model_dir is None else str(args.model_dir),
            download_files=args.download_files,
            execution_gates=scenario.execution_gates,
            l3_strategy=(
                "multi"
                if args.child_case == "all_pipelines_unified_dynamic_pii"
                else "dedicated"
            ),
            dynamic_pii_config=dynamic_pii_config,
            cache_storage_location=None
            if args.cache_storage_location is None
            else str(args.cache_storage_location),
            cache_memory_max_entries=args.cache_memory_max_entries,
            cache_memory_max_bytes=args.cache_memory_max_bytes,
        )
        if not args.no_warmup:
            gateway.warmup()
        baseline_rss_mb = current_rss_mb()
        surface_requests = desktop_surface_requests(scenario.name, text)
        if surface_requests:
            request_ids = enqueue_desktop_fanout(gateway, surface_requests, args.requests, text)
            expected_finished = len(request_ids)
        else:
            request_ids = [
                gateway.enqueue(
                    text,
                    categories=scenario.categories,
                    execution_gates=scenario.execution_gates,
                )
                for _ in range(args.requests)
            ]
            expected_finished = args.requests
        completed, result_events, failure_count, failure_messages = consume_until_finished(
            gateway,
            expected_finished,
            args.timeout_seconds,
        )
        output.update(
            {
                "ok": completed == expected_finished,
                "completed_requests": completed,
                "ark_requests": expected_finished,
                "audit_fanout": len(surface_requests),
                "result_events": result_events,
                "failure_count": failure_count,
                "failure_messages": failure_messages,
                "baseline_rss_mb": baseline_rss_mb,
                "self_max_rss_mb": process_peak_rss_mb(),
                "elapsed_s": round(time.monotonic() - started, 3),
                "request_ids": request_ids,
            }
        )
    except Exception as exc:  # noqa: BLE001 - benchmark output should preserve failures.
        output.update(
            {
                "ok": False,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "self_max_rss_mb": process_peak_rss_mb(),
                "elapsed_s": round(time.monotonic() - started, 3),
            }
        )
        print(json.dumps(output, sort_keys=True), flush=True)
        return 1

    print(json.dumps(output, sort_keys=True), flush=True)
    return 0 if output["ok"] else 1


def load_text(path: Path | None, target_mb: float | None) -> str:
    if path is None:
        base = (
            "Call me Ishmael. Some years ago never mind how long precisely "
            "having little or no money in my purse, and nothing particular "
            "to interest me on shore, I thought I would sail about a little "
            "and see the watery part of the world.\n"
        )
    else:
        base = path.read_text(encoding="utf-8")
    if target_mb is None:
        return base
    target_bytes = max(int(target_mb * 1024 * 1024), 1)
    encoded = base.encode("utf-8")
    if not encoded:
        raise ValueError("benchmark text is empty")
    repeated = encoded * ((target_bytes // len(encoded)) + 1)
    return repeated[:target_bytes].decode("utf-8", errors="ignore")


def desktop_surface_requests(case: str, text: str) -> list[SurfaceRequest]:
    if case == "desktop_inventory_l2":
        return desktop_inventory_surfaces()
    if case == "desktop_response_mix_l2":
        return desktop_response_mix_surfaces(text)
    return []


def desktop_inventory_surfaces() -> list[SurfaceRequest]:
    sizes = [
        ("tool_description", 16),
        ("tool_schema", 315),
        ("tool_description", 16),
        ("tool_description", 83),
        ("tool_schema", 351),
        ("tool_description", 16),
        ("tool_description", 157),
        ("tool_schema", 487),
        ("tool_description", 16),
        ("tool_description", 350),
        ("tool_schema", 1579),
        ("tool_description", 16),
        ("tool_description", 625),
        ("tool_schema", 354),
        ("tool_description", 16),
        ("tool_description", 108),
        ("tool_description", 124),
        ("tool_schema", 317),
        ("tool_description", 16),
        ("tool_description", 122),
        ("tool_schema", 76),
        ("tool_description", 16),
        ("tool_description", 265),
        ("tool_schema", 408),
        ("tool_description", 16),
        ("tool_description", 1362),
        ("tool_schema", 483),
        ("tool_description", 16),
        ("tool_description", 33),
        ("tool_description", 32),
        ("tool_schema", 315),
        ("tool_description", 16),
        ("tool_description", 83),
        ("tool_schema", 351),
        ("tool_description", 16),
        ("tool_description", 157),
        ("tool_schema", 487),
        ("tool_description", 16),
        ("tool_description", 350),
    ]
    return [
        SurfaceRequest(
            name=name,
            categories=categories_for_surface(name),
            gates=l2_only_gates(),
            ntdb_operating_point="best_fpr_in_f1",
            text_bytes=size,
        )
        for name, size in sizes
    ]


def desktop_response_mix_surfaces(text: str) -> list[SurfaceRequest]:
    return [
        SurfaceRequest(
            name="tool_result",
            categories=categories_for_surface("tool_result"),
            gates=l2_only_gates(),
            ntdb_operating_point="best_promote",
            use_full_text=True,
        ),
        SurfaceRequest(
            name="model_output",
            categories=categories_for_surface("model_output"),
            gates=l2_only_gates(),
            ntdb_operating_point="best_fpr_in_f1",
            text_bytes=min(len(text.encode("utf-8")), 21_347),
        ),
        *desktop_inventory_surfaces(),
    ]


def categories_for_surface(surface: str) -> list[str]:
    return {
        "general_text": [
            "injection",
            "dlp",
            "pii",
            "dynamic-pii",
            "sensitive_document",
            "threat",
            "routing",
        ],
        "tool_description": [
            "injection",
            "dlp",
            "threat",
            "tool_class",
            "tool_action",
            "tool_tags",
        ],
        "tool_schema": ["injection", "threat"],
        "tool_result": [
            "injection",
            "dlp",
            "pii",
            "dynamic-pii",
            "sensitive_document",
            "routing",
            "threat",
        ],
        "model_output": ["pii", "routing", "sensitive_document"],
        "mcp_server_config": ["injection", "dlp"],
        "log_or_audit_payload": ["injection", "dlp"],
    }[surface]


def l2_only_gates() -> dict[str, Any]:
    return {"levels": {"l1": True, "l2": True, "l3": False}}


def enqueue_desktop_fanout(
    gateway: Any,
    surface_requests: list[SurfaceRequest],
    audit_count: int,
    source_text: str,
) -> list[str]:
    request_ids: list[str] = []
    for audit_index in range(audit_count):
        for surface_index, surface in enumerate(surface_requests):
            text = text_for_surface(surface, audit_index, surface_index, source_text)
            request_ids.append(
                gateway.enqueue(
                    text,
                    categories=surface.categories,
                    execution_gates=surface.gates,
                    metadata={
                        "desktop_benchmark": True,
                        "audit_index": audit_index,
                        "surface_index": surface_index,
                        "surface": surface.name,
                    },
                    ntdb_operating_point=surface.ntdb_operating_point,
                )
            )
    return request_ids


def text_for_surface(
    surface: SurfaceRequest,
    audit_index: int,
    surface_index: int,
    source_text: str,
) -> str:
    if surface.use_full_text:
        return source_text
    size = max(surface.text_bytes or 1, 1)
    prefix = f"{surface.name} audit={audit_index} surface={surface_index} "
    return sized_text(prefix, size)


def sized_text(prefix: str, target_bytes: int) -> str:
    seed = (
        prefix
        + "describe available tool behavior, accepted parameters, output shape, "
        + "security relevant side effects, and runtime constraints. "
    )
    encoded = seed.encode("utf-8")
    repeated = encoded * ((target_bytes // len(encoded)) + 1)
    return repeated[:target_bytes].decode("utf-8", errors="ignore")


def consume_until_finished(
    gateway: Any,
    expected: int,
    timeout_seconds: float,
) -> tuple[int, int, int, list[str]]:
    deadline = time.monotonic() + timeout_seconds
    completed = 0
    result_events = 0
    failure_count = 0
    failure_messages: list[str] = []
    while completed < expected and time.monotonic() < deadline:
        event = gateway.consume_next_event(timeout=1.0)
        if event is None:
            continue
        if event["event_type"] in ("result", "provisional"):
            result_events += 1
        elif event["event_type"] == "finished":
            completed += 1
            failures = event.get("failures", [])
            failure_count += len(failures)
            for failure in failures:
                message = failure.get("message")
                if message and message not in failure_messages:
                    failure_messages.append(message)
    return completed, result_events, failure_count, failure_messages


def current_rss_mb() -> float:
    current = process_rss_kb(os.getpid())
    if current > 0:
        return kb_to_mib(current)
    return process_peak_rss_mb()


def process_peak_rss_mb() -> float:
    import resource

    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return round(value / (1024 * 1024), 3)
    return kb_to_mib(value)


def process_rss_kb(pid: int) -> int:
    try:
        output = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(pid)],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (PermissionError, subprocess.CalledProcessError, FileNotFoundError):
        return 0
    return int(output or "0")


def peak_rss_from_parent_or_child(peak_rss_kb: int, payload: dict[str, Any] | None) -> float:
    if peak_rss_kb > 0:
        return kb_to_mib(peak_rss_kb)
    if payload and payload.get("self_max_rss_mb") is not None:
        return payload["self_max_rss_mb"]
    return 0.0


def kb_to_mib(value: int) -> float:
    return round(value / 1024, 3)


def prepend_path(existing: str | None, path: str) -> str:
    return path if not existing else f"{path}{os.pathsep}{existing}"


def print_case_result(result: dict[str, Any]) -> None:
    child = result.get("child") or {}
    baseline = child.get("baseline_rss_mb")
    peak = result["parent_peak_rss_mb"]
    delta = None if baseline is None else round(peak - baseline, 3)
    status = "ok" if result["returncode"] == 0 and not result["timed_out"] else "failed"
    print(
        "\t".join(
            [
                result["case"],
                status,
                f"input_mib={child.get('input_mib', 'n/a')}",
                f"requests={child.get('requests', 'n/a')}",
                f"ark_requests={child.get('ark_requests', 'n/a')}",
                f"fanout={child.get('audit_fanout', 'n/a')}",
                f"baseline_mb={baseline if baseline is not None else 'n/a'}",
                f"peak_mb={peak}",
                f"delta_mb={delta if delta is not None else 'n/a'}",
                f"failures={child.get('failure_count', 'n/a')}",
                f"elapsed_s={result['elapsed_s']}",
            ]
        ),
        flush=True,
    )
    if result["returncode"] != 0 and child.get("error"):
        print(f"  error: {child['error_type']}: {child['error']}", flush=True)
    if result.get("stderr"):
        print(f"  stderr: {result['stderr']}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
