"""Local benchmark for a configured `SecurityGateway`.

Runs three phases against sample data shipped with the package
(`patronus_security/benchmark_data/*.jsonl`, copied from the Patronus
validation splits) and writes one JSON file per phase into `output_dir`:

- `benign_result.json` — 100 benign prompts through the joint `scan_all`
  decision: class distribution, false-positive rate, latency.
- `classifier_result.json` — labelled validation samples per pipeline
  (up to 100 per class): accuracy, macro-F1, class distribution, latency.
  Runs once L2-only and, when `max_level` is `l3`, once more with L3
  promotions/executions enabled.
- `load_result.json` — one producer submits many texts through `enqueue`
  while one consumer worker drains the shared result queue, covering short L2
  texts, L3-promoting texts, >16-chunk long texts, and cache hits.
- `example_result.json` — one real queued sample and every result returned by
  the shared consume queue, preserving L2/L3 response order and shape.
- `BENCHMARK.md` — readable summary plus L2/L3 queue diagnostics.

Results contain the real prompts so mispredictions can be inspected directly.
"""

import json
import platform
import statistics
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from threading import Thread

DATA_DIR = Path(__file__).resolve().parent / "benchmark_data"
QUEUE_EXAMPLE_SAMPLE_ID = "attack-0003"

# Only threat categories count toward the benign false-positive rate;
# classification categories (tool_classifier, user_intent, sensitive_documents)
# always assign a content class and are reported informationally.
FLAG_CATEGORIES = {"injection", "dlp", "pii"}

# Classes that count as "not flagged" per category.
NEUTRAL_CLASSES = {
    "injection": {"benign", "safe"},
    "pii": {"safe", "benign"},
    "dlp": {"safe", "benign"},
    "tool_classifier": {"safe", "benign", "none", "missing", "tool_class.unknown"},
    "user_intent": {"safe", "benign", "none", "missing", "benign_conv"},
    "sensitive_documents": {"safe", "benign", "none", "missing", "other"},
}

# (data file stem, gateway category, tool_classifier area gates, result model)
CLASSIFIER_PIPELINES = [
    ("injection", "injection", None, "wolf-defender-small"),
    ("sensitive_documents", "sensitive_documents", None, "orca-sonar-document-classifier"),
    (
        "tool_prompts",
        "tool_classifier",
        {"prompt": True, "execution": False, "description": False},
        "tool-prompts-model",
    ),
    (
        "tool_executions",
        "tool_classifier",
        {"prompt": False, "execution": True, "description": False},
        "tool-executions-model",
    ),
    (
        "tool_descriptions",
        "tool_classifier",
        {"prompt": False, "execution": False, "description": True},
        "tool-classifier-descriptions-model",
    ),
    ("user_intent", "user_intent", None, "user-intent-model"),
]


def _round_robin_by_class(samples, limit):
    """Limit samples while keeping every class represented."""
    by_class = {}
    for sample in samples:
        by_class.setdefault(sample["expected_class"], []).append(sample)
    picked, index = [], 0
    while len(picked) < limit:
        added = False
        for group in by_class.values():
            if index < len(group) and len(picked) < limit:
                picked.append(group[index])
                added = True
        if not added:
            break
        index += 1
    return picked


def _load_samples(name):
    path = DATA_DIR / f"{name}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * pct)]


def _latency_stats(values):
    if not values:
        return {"avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
    return {
        "avg_ms": round(statistics.mean(values), 3),
        "p50_ms": round(_percentile(values, 0.50), 3),
        "p95_ms": round(_percentile(values, 0.95), 3),
        "p99_ms": round(_percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def _host_info():
    import os

    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def _gateway_info(gateway):
    return {
        "categories": list(gateway.categories),
        "max_level": gateway.max_level,
    }


def _macro_f1(expected, predicted):
    labels = sorted(set(expected) | set(predicted))
    scores = []
    for label in labels:
        tp = sum(e == label and p == label for e, p in zip(expected, predicted))
        fp = sum(e != label and p == label for e, p in zip(expected, predicted))
        fn = sum(e == label and p != label for e, p in zip(expected, predicted))
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        scores.append(2 * precision * recall / (precision + recall) if (precision + recall) else 0.0)
    return sum(scores) / len(scores) if scores else 0.0


def _run_benign(gateway):
    samples = _load_samples("benign")
    rows, latencies = [], []
    distribution = {}
    for sample in samples:
        started = time.perf_counter()
        results = gateway.scan_all(sample["text"])
        latency_ms = (time.perf_counter() - started) * 1000.0
        latencies.append(latency_ms)

        decisions = {}
        flagged = []
        for result in results:
            category = result["category"]
            class_name = result["class_name"]
            previous = decisions.get(category)
            neutral = NEUTRAL_CLASSES.get(category, {"safe", "benign"})
            if previous is None or (previous in neutral and class_name not in neutral):
                decisions[category] = class_name
        for category, class_name in decisions.items():
            neutral = NEUTRAL_CLASSES.get(category, {"safe", "benign"})
            distribution.setdefault(category, {})
            distribution[category][class_name] = distribution[category].get(class_name, 0) + 1
            if category in FLAG_CATEGORIES and class_name not in neutral:
                flagged.append({"category": category, "class_name": class_name})
        rows.append(
            {
                "id": sample["id"],
                "text": sample["text"],
                "source": sample.get("source"),
                "decisions": decisions,
                "flagged": flagged,
                "latency_ms": round(latency_ms, 3),
            }
        )

    flagged_rows = [row for row in rows if row["flagged"]]
    return {
        "samples": len(rows),
        "false_positive_categories": sorted(FLAG_CATEGORIES),
        "false_positives": len(flagged_rows),
        "false_positive_rate": round(len(flagged_rows) / len(rows), 4) if rows else 0.0,
        "class_distribution": distribution,
        "latency": _latency_stats(latencies),
        "rows": rows,
    }


def _classifier_modes(gateway):
    modes = [("l2_only", {"levels": {"l3": False}})]
    if gateway.max_level == "l3":
        modes.append(("with_l3", {}))
    return modes


def _run_classifier_mode(gateway, samples, category, tool_gates, model, mode_gates):
    gates = dict(mode_gates)
    if tool_gates is not None:
        gates["tool_classifier"] = tool_gates
    gateway.set_execution_gates(gates or None)

    expected, predicted, latencies, rows = [], [], [], []
    l3_scans = 0
    for sample in samples:
        started = time.perf_counter()
        results = gateway.scan_categories([category], sample["text"])
        latency_ms = (time.perf_counter() - started) * 1000.0
        latencies.append(latency_ms)

        # Prefer the deepest result the model produced (L3 over its L2 fallback).
        model_results = [result for result in results if result["model"] == model]
        model_results.sort(key=lambda result: result["level"])
        chosen = model_results[-1] if model_results else None
        prediction = chosen["class_name"] if chosen else "missing"
        level = chosen["level"] if chosen else "none"
        if level == "L3":
            l3_scans += 1
        expected.append(sample["expected_class"])
        predicted.append(prediction)
        rows.append(
            {
                "id": sample["id"],
                "text": sample["text"],
                "expected_class": sample["expected_class"],
                "predicted_class": prediction,
                "correct": prediction == sample["expected_class"],
                "level": level,
                "latency_ms": round(latency_ms, 3),
            }
        )

    per_class = {}
    for label in sorted(set(expected) | set(predicted)):
        per_class[label] = {
            "expected": expected.count(label),
            "predicted": predicted.count(label),
            "correct": sum(e == label and p == label for e, p in zip(expected, predicted)),
        }
    correct = sum(e == p for e, p in zip(expected, predicted))
    return {
        "samples": len(rows),
        "accuracy": round(correct / len(rows), 4) if rows else 0.0,
        "macro_f1": round(_macro_f1(expected, predicted), 4),
        "l3_scans": l3_scans,
        "class_distribution": per_class,
        "latency": _latency_stats(latencies),
        "rows": rows,
    }


def _run_classifier(gateway, limit_per_pipeline):
    configured = set(gateway.categories)
    pipelines = {}
    for name, category, tool_gates, model in CLASSIFIER_PIPELINES:
        if category not in configured:
            continue
        samples = _load_samples(name)
        if limit_per_pipeline:
            samples = _round_robin_by_class(samples, limit_per_pipeline)

        modes = {}
        for mode_name, mode_gates in _classifier_modes(gateway):
            modes[mode_name] = _run_classifier_mode(
                gateway, samples, category, tool_gates, model, mode_gates
            )
        pipelines[name] = {"model": model, "modes": modes}

    gateway.set_execution_gates(None)
    return {"pipelines": pipelines}


def _final_level(results):
    levels = [result["level"] for result in results]
    for level in ("L3", "L2", "L1"):
        if level in levels:
            return level
    return levels[0] if levels else "none"


def _load_scenario_texts(gateway):
    benign = [s["text"] for s in _load_samples("benign")]
    injection = _load_samples("injection")
    attacks = [s["text"] for s in injection if s["expected_class"] == "attack"]

    # >16 chunks at the 256-byte local chunk size, with one attack snippet
    # buried mid-document so the chunked path has non-benign work to verify.
    filler = " ".join(benign[:6])
    long_texts = []
    for attack in attacks[:10]:
        body = (filler + " ") * max(1, (8192 // max(1, len(filler))) + 1)
        middle = len(body) // 2
        long_texts.append(body[:middle] + " " + attack + " " + body[middle:])

    scenarios = {
        "l2_short": benign[:50],
        "long_text_over_16_chunks": long_texts,
        "cache_hits": benign[:5],
    }
    if gateway.max_level == "l3":
        scenarios["l3_promote"] = attacks[:50]
    return scenarios


def _run_load(gateway, requests_per_scenario):
    scenarios = _load_scenario_texts(gateway)
    results = {}
    for name, texts in scenarios.items():
        outcomes = [None] * requests_per_scenario
        pending = Queue()

        def consume_requests():
            active = {}
            early_results = defaultdict(list)
            producer_done = False
            while active or not producer_done:
                while True:
                    try:
                        item = pending.get_nowait()
                    except Empty:
                        break
                    pending.task_done()
                    if item is None:
                        producer_done = True
                    else:
                        index, request_id, started, enqueue_ms = item
                        active[request_id] = {
                            "index": index,
                            "request_id": request_id,
                            "started": started,
                            "enqueue_ms": enqueue_ms,
                            "first_result_ms": None,
                            "levels": [],
                            "l2_chunks": [],
                            "candidate_spans": [],
                            "l3_chunks": [],
                            "l3_queue_wait_ms": [],
                            "l3_execution_ms": [],
                        }
                        for result in early_results.pop(request_id, []):
                            _record_consumed_load_result(active[request_id], result)

                if not active:
                    if not producer_done:
                        try:
                            item = pending.get(timeout=0.1)
                        except Empty:
                            continue
                        pending.task_done()
                        if item is None:
                            producer_done = True
                        else:
                            index, request_id, started, enqueue_ms = item
                            active[request_id] = _new_load_request(
                                index, request_id, started, enqueue_ms
                            )
                    continue
                try:
                    result = gateway.consume_next_result(timeout=0.001)
                    if result is not None:
                        request_id = result["request_id"]
                        request = active.get(request_id)
                        if request is None:
                            early_results[request_id].append(result)
                        else:
                            _record_consumed_load_result(request, result)
                            if not gateway.has_request(request_id):
                                outcomes[request["index"]] = _completed_load_outcome(request)
                                del active[request_id]
                    for request_id in list(active):
                        if not gateway.has_request(request_id):
                            request = active.pop(request_id)
                            outcomes[request["index"]] = _completed_load_outcome(request)
                except Exception as exc:  # noqa: BLE001 - report, don't crash the run
                    for request in active.values():
                        outcomes[request["index"]] = {"error": f"{type(exc).__name__}: {exc}"}
                    active.clear()

        wall_start = time.perf_counter()
        consumer = Thread(target=consume_requests, name="patronus-benchmark-consumer")
        consumer.start()
        for index in range(requests_per_scenario):
            started = time.perf_counter()
            try:
                request_id = gateway.enqueue(texts[index % len(texts)])
                enqueue_ms = (time.perf_counter() - started) * 1000.0
                pending.put((index, request_id, started, enqueue_ms))
            except Exception as exc:  # noqa: BLE001 - report, don't crash the run
                outcomes[index] = {"error": f"{type(exc).__name__}: {exc}"}
        pending.put(None)
        pending.join()
        consumer.join()
        wall_seconds = time.perf_counter() - wall_start

        completed = [outcome for outcome in outcomes if outcome is not None]
        ok = [outcome for outcome in completed if outcome["error"] is None]
        errors = [outcome["error"] for outcome in completed if outcome["error"] is not None]
        errors.extend(["consumer produced no outcome"] * (requests_per_scenario - len(completed)))
        level_counts = {}
        for outcome in ok:
            level = outcome["final_level"]
            level_counts[level] = level_counts.get(level, 0) + 1
        results[name] = {
            "requests": requests_per_scenario,
            "producer_workers": 1,
            "consumer_workers": 1,
            "errors": len(errors),
            "error_messages": errors[:10],
            "throughput_rps": round(requests_per_scenario / wall_seconds, 2) if wall_seconds else 0.0,
            "enqueue_latency": _latency_stats([outcome["enqueue_ms"] for outcome in ok]),
            "first_result_latency": _latency_stats(
                [outcome["first_result_ms"] for outcome in ok if outcome["first_result_ms"] is not None]
            ),
            "total_latency": _latency_stats([outcome["total_ms"] for outcome in ok]),
            "final_levels": level_counts,
            "ntdb_l2_chunks": _latency_stats(
                [value for outcome in ok for value in outcome["l2_chunks"]]
            ),
            "l3_candidate_spans": _latency_stats(
                [value for outcome in ok for value in outcome["candidate_spans"]]
            ),
            "l3_chunks": _latency_stats(
                [value for outcome in ok for value in outcome["l3_chunks"]]
            ),
            "l3_queue_wait": _latency_stats(
                [value for outcome in ok for value in outcome["l3_queue_wait_ms"]]
            ),
            "l3_execution": _latency_stats(
                [value for outcome in ok for value in outcome["l3_execution_ms"]]
            ),
        }
    return {"scenarios": results}


def _run_queue_example(gateway):
    sample = next(
        sample
        for sample in _load_samples("injection")
        if sample["id"] == QUEUE_EXAMPLE_SAMPLE_ID
    )
    request_id = gateway.enqueue(sample["text"])
    results = []
    deadline = time.monotonic() + 60.0
    while gateway.has_request(request_id):
        result = gateway.consume_next_result(timeout=1.0)
        if result is None:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for example request {request_id}")
            continue
        if result["request_id"] != request_id:
            raise RuntimeError(
                f"expected example request {request_id}, got {result['request_id']}"
            )
        results.append(result)

    levels = sorted({result["level"] for result in results})
    return {
        "sample_id": sample["id"],
        "input": sample["text"],
        "request_id": request_id,
        "configured_categories": list(gateway.categories),
        "observed_levels": levels,
        "l2_and_l3_observed": "L2" in levels and "L3" in levels,
        "results": results,
    }


def _new_load_request(index, request_id, started, enqueue_ms):
    return {
        "index": index,
        "request_id": request_id,
        "started": started,
        "enqueue_ms": enqueue_ms,
        "first_result_ms": None,
        "levels": [],
        "l2_chunks": [],
        "candidate_spans": [],
        "l3_chunks": [],
        "l3_queue_wait_ms": [],
        "l3_execution_ms": [],
    }


def _record_consumed_load_result(request, result):
    if request["first_result_ms"] is None:
        request["first_result_ms"] = (time.perf_counter() - request["started"]) * 1000.0
    request["levels"].append(result["level"])
    _record_load_result_metrics(request, result)


def _record_load_result_metrics(request, result):
    l3_duration_ms = 0.0
    l3_chunk_count = None
    l3_queue_wait_ms = None
    for layer in result["layers"]:
        details = layer["details"]
        if layer["layer_type"] == "ntdb_l2":
            if isinstance(details.get("chunks"), int):
                request["l2_chunks"].append(details["chunks"])
            spans = details.get("l3_candidate_spans")
            if isinstance(spans, list):
                request["candidate_spans"].append(len(spans))
        if layer["level"] == "L3":
            l3_duration_ms += layer["duration_ms"]
            if isinstance(details.get("chunk_count"), int):
                l3_chunk_count = details["chunk_count"]
            if isinstance(details.get("l3_queue_wait_ms"), (int, float)):
                l3_queue_wait_ms = details["l3_queue_wait_ms"]
    if l3_chunk_count is not None:
        request["l3_chunks"].append(l3_chunk_count)
        request["l3_execution_ms"].append(l3_duration_ms)
    if l3_queue_wait_ms is not None:
        request["l3_queue_wait_ms"].append(l3_queue_wait_ms)


def _completed_load_outcome(request):
    return {
        "error": None,
        "enqueue_ms": request["enqueue_ms"],
        "first_result_ms": request["first_result_ms"],
        "total_ms": (time.perf_counter() - request["started"]) * 1000.0,
        "final_level": max(request["levels"], default="none"),
        "results": len(request["levels"]),
        "l2_chunks": request["l2_chunks"],
        "candidate_spans": request["candidate_spans"],
        "l3_chunks": request["l3_chunks"],
        "l3_queue_wait_ms": request["l3_queue_wait_ms"],
        "l3_execution_ms": request["l3_execution_ms"],
    }


def _print_summary(benign, classifier, load):
    print("== benign ==")
    print(
        f"  {benign['samples']} samples, "
        f"{benign['false_positives']} false positives "
        f"({benign['false_positive_rate']:.1%}), "
        f"avg {benign['latency']['avg_ms']:.1f} ms, "
        f"p95 {benign['latency']['p95_ms']:.1f} ms"
    )
    print("== classifier ==")
    for name, entry in classifier["pipelines"].items():
        for mode, stats in entry["modes"].items():
            l3_note = f", {stats['l3_scans']} via L3" if mode == "with_l3" else ""
            print(
                f"  {name} [{mode}]: {stats['samples']} samples, "
                f"accuracy {stats['accuracy']:.1%}, macro-F1 {stats['macro_f1']:.3f}, "
                f"avg {stats['latency']['avg_ms']:.1f} ms{l3_note}"
            )
    print("== load ==")
    for name, stats in load["scenarios"].items():
        print(
            f"  {name}: {stats['requests']} requests, 1 producer + 1 consumer, "
            f"{stats['errors']} errors, {stats['throughput_rps']} req/s, "
            f"total avg {stats['total_latency']['avg_ms']:.1f} ms, "
            f"p95 {stats['total_latency']['p95_ms']:.1f} ms, "
            f"levels {stats['final_levels']}"
        )


def _benchmark_markdown(meta, example, benign, classifier, load):
    def value(stats, key="avg_ms"):
        return f"{stats.get(key, 0.0):.1f}"

    lines = [
        "# Benchmark",
        "",
        f"Generated: `{meta['generated_at']}`  ",
        f"Platform: `{meta['host']['platform']}` / `{meta['host']['machine']}`  ",
        f"Gateway: `{', '.join(meta['gateway']['categories'])}`; max level "
        f"`{meta['gateway']['max_level']}`",
        "",
        "## Benign prompts",
        "",
        "| Samples | False positives | FP rate | Avg | p95 |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {benign['samples']} | {benign['false_positives']} | "
        f"{benign['false_positive_rate']:.1%} | {value(benign['latency'])} ms | "
        f"{value(benign['latency'], 'p95_ms')} ms |",
        "",
        "## Classifiers",
        "",
        "| Pipeline | Mode | Samples | Accuracy | Macro-F1 | L3 scans | Avg | p95 |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, entry in classifier["pipelines"].items():
        for mode, stats in entry["modes"].items():
            lines.append(
                f"| {name} | {mode} | {stats['samples']} | {stats['accuracy']:.1%} | "
                f"{stats['macro_f1']:.3f} | {stats['l3_scans']} | "
                f"{value(stats['latency'])} ms | {value(stats['latency'], 'p95_ms')} ms |"
            )

    lines.extend(
        [
            "",
            "## Queue load",
            "",
            "One producer enqueues all texts. One consumer drains the shared result queue, "
            "so an L3 request cannot hide an already available L2 result.",
            "",
            "| Scenario | Requests | Errors | req/s | Enqueue avg | First avg | Total avg | Total p95 | Final levels |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for name, stats in load["scenarios"].items():
        levels = ", ".join(f"{level}: {count}" for level, count in stats["final_levels"].items())
        lines.append(
            f"| {name} | {stats['requests']} | {stats['errors']} | "
            f"{stats['throughput_rps']:.2f} | {value(stats['enqueue_latency'])} ms | "
            f"{value(stats['first_result_latency'])} ms | {value(stats['total_latency'])} ms | "
            f"{value(stats['total_latency'], 'p95_ms')} ms | {levels or 'none'} |"
        )

    lines.extend(
        [
            "",
            "## L2/L3 diagnostics",
            "",
            "`L3 queue wait` is time spent behind higher-priority or earlier L3 jobs. "
            "`L3 execution` is ONNX layer time and excludes that wait.",
            "",
            "| Scenario | L2 chunks avg/max | Candidate spans avg/max | L3 chunks avg/max | L3 queue wait avg/p95 | L3 execution avg/p95 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, stats in load["scenarios"].items():
        lines.append(
            f"| {name} | {value(stats['ntdb_l2_chunks'])}/{value(stats['ntdb_l2_chunks'], 'max_ms')} | "
            f"{value(stats['l3_candidate_spans'])}/{value(stats['l3_candidate_spans'], 'max_ms')} | "
            f"{value(stats['l3_chunks'])}/{value(stats['l3_chunks'], 'max_ms')} | "
            f"{value(stats['l3_queue_wait'])}/{value(stats['l3_queue_wait'], 'p95_ms')} ms | "
            f"{value(stats['l3_execution'])}/{value(stats['l3_execution'], 'p95_ms')} ms |"
        )
    lines.extend(
        [
            "",
            "## One complete queued response",
            "",
            "This is one real `enqueue()` call with every configured pipeline active. "
            "The JSON below is the complete sequence returned by `consume_next_result()`.",
            "",
            f"Sample: `{example['sample_id']}`  ",
            f"Request: `{example['request_id']}`  ",
            f"Observed levels: `{', '.join(example['observed_levels'])}`  ",
            f"L2 and L3 observed: `{'yes' if example['l2_and_l3_observed'] else 'no'}`",
            "",
            "Input:",
            "",
            "```text",
            example["input"],
            "```",
            "",
            "Complete consume response:",
            "",
            "```json",
            json.dumps(example["results"], ensure_ascii=False, indent=2),
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


def _warm_l3_sessions(gateway):
    """Exercise the lazy L3 ONNX sessions once so session build time does not
    count as scan latency (first L3 inference loads the transformer)."""
    if gateway.max_level != "l3":
        return
    attack = next(
        (s["text"] for s in _load_samples("injection") if s["expected_class"] == "attack"),
        None,
    )
    document = _load_samples("sensitive_documents")[0]["text"]
    for text in (attack, document):
        if not text:
            continue
        for _ in range(2):
            gateway.scan_all(text)


def run_local_benchmark(
    gateway,
    output_dir="benchmark",
    limit_per_pipeline=None,
    load_requests=200,
    print_summary=True,
):
    """Run benchmark phases and write JSON details plus `BENCHMARK.md`."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gateway": _gateway_info(gateway),
        "host": _host_info(),
    }

    _warm_l3_sessions(gateway)
    example = _run_queue_example(gateway)
    benign = _run_benign(gateway)
    classifier = _run_classifier(gateway, limit_per_pipeline)
    load = _run_load(gateway, load_requests)

    outputs = {
        "example_result.json": {**meta, **example},
        "benign_result.json": {**meta, **benign},
        "classifier_result.json": {**meta, **classifier},
        "load_result.json": {**meta, **load},
    }
    for name, payload in outputs.items():
        (output / name).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    (output / "BENCHMARK.md").write_text(
        _benchmark_markdown(meta, example, benign, classifier, load), encoding="utf-8"
    )

    if print_summary:
        _print_summary(benign, classifier, load)
        print(f"results written to {output}/")

    return {"example": example, "benign": benign, "classifier": classifier, "load": load}
