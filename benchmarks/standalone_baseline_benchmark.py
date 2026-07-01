#!/usr/bin/env python3
import csv
import ctypes
import gc
import json
import os
import resource
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEGACY_ROOT = Path("/Users/benediktveith/Documents/Apps/Patronus-Datasets")
MODEL_DIR = Path(os.environ.get("PATRONUS_MODEL_DIR", "/private/tmp/patronus_security_standalone_bench_assets"))
ALLOW_DOWNLOADS = os.environ.get("PATRONUS_BENCH_DOWNLOAD", "0") == "1"
LIMIT = 100
SCAN_ALL_LATENCY_RUNS = int(os.environ.get("PATRONUS_SCAN_ALL_LATENCY_RUNS", "20"))

sys.path.insert(0, str(ROOT / "python"))

from patronus_security import SecurityGateway  # noqa: E402


def evenly_sample(rows, limit=LIMIT):
    if limit is None or len(rows) <= limit:
        return rows
    if limit <= 1:
        return rows[:limit]
    step = (len(rows) - 1) / (limit - 1)
    return [rows[round(i * step)] for i in range(limit)]


def read_csv_rows(path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def load_csv_text_class(path, text_col="text", label_col="class"):
    rows = evenly_sample(read_csv_rows(path))
    return [row[text_col] for row in rows], [row[label_col] for row in rows]


def load_document_classifier():
    path = LEGACY_ROOT / "patronus-document-classifier-dataset" / "data" / "val.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = evenly_sample(rows)
    return [row["text"] for row in rows], [row["label"] for row in rows]


def load_injection():
    rows = evenly_sample(read_csv_rows(LEGACY_ROOT / "patronus-injection-dataset" / "splits" / "val.csv"))
    labels = [int(row["label"]) for row in rows]
    return [row["text"] for row in rows], labels


def load_dlp_mock():
    secrets = [
        ("sk-ant-1234567890abcdef1234567890abcdef", "API_KEY"),
        ("sk-proj-1234567890abcdef1234567890abcdef", "API_KEY"),
        ("ghp_1234567890abcdef1234567890abcdef1234", "SECRET_TOKEN"),
        ("whsec_1234567890abcdef1234567890abcdef", "PAYMENT_KEY"),
        ("AIza1234567890abcdef1234567890abcdef123", "CLOUD_KEY"),
        ("xoxb-1234567890-1234567890123-abcdef", "SECRET_TOKEN"),
        ("ya29.1234567890abcdef1234567890abcdef", "CLOUD_KEY"),
        ("GOCSPX-1234567890abcdef1234567890abcd", "CLOUD_KEY"),
        ("glpat-1234567890abcdef1234", "SECRET_TOKEN"),
        ("npm_1234567890abcdef1234567890abcdef1234", "SECRET_TOKEN"),
    ]
    safe_texts = [
        "Hello, can you help me write a Python script?",
        "What is the capital of Germany?",
        "Please list the contents of the database.",
        "How do I run a Docker container?",
        "Show me the weather report for Berlin.",
    ]
    texts, labels = [], []
    for i in range(LIMIT):
        if i % 2 == 0:
            secret, label = secrets[(i // 2) % len(secrets)]
            texts.append(f"Here is the key: {secret}")
            labels.append(label)
        else:
            texts.append(safe_texts[(i // 2) % len(safe_texts)])
            labels.append("safe")
    return texts, labels


def load_pii_mock():
    pii_items = [
        ("test@example.com", "EMAIL"),
        ("+491701234567", "PHONE"),
        ("4111111111111111", "CREDITCARD"),
        ("DE89370400440532013000", "IBAN"),
        ("12345678903", "STEUERID"),
        ("DE123456789", "USTID"),
        ("123-45-6789", "SSN"),
    ]
    safe_texts = [
        "Just a normal safe sentence with no private data.",
        "The project is hosted on GitHub.",
        "You can find the documentation in the docs folder.",
        "There are no security issues reported today.",
        "Please provide the system architecture diagram.",
    ]
    texts, labels = [], []
    for i in range(LIMIT):
        if i % 2 == 0:
            value, label = pii_items[(i // 2) % len(pii_items)]
            texts.append(f"My details: {value}")
            labels.append(label)
        else:
            texts.append(safe_texts[(i // 2) % len(safe_texts)])
            labels.append("safe")
    return texts, labels


def macro_f1(y_true, y_pred):
    labels = sorted(set(y_true) | set(y_pred), key=str)
    scores = []
    for label in labels:
        tp = sum(t == label and p == label for t, p in zip(y_true, y_pred))
        fp = sum(t != label and p == label for t, p in zip(y_true, y_pred))
        fn = sum(t == label and p != label for t, p in zip(y_true, y_pred))
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        scores.append(2 * precision * recall / (precision + recall) if (precision + recall) else 0.0)
    return sum(scores) / len(scores) if scores else 0.0


def macro_fpr_fnr(y_true, y_pred):
    labels = sorted(set(y_true) | set(y_pred), key=str)
    fprs, fnrs = [], []
    for label in labels:
        fp = sum(t != label and p == label for t, p in zip(y_true, y_pred))
        fn = sum(t == label and p != label for t, p in zip(y_true, y_pred))
        tn = sum(t != label and p != label for t, p in zip(y_true, y_pred))
        tp = sum(t == label and p == label for t, p in zip(y_true, y_pred))
        fprs.append(fp / (fp + tn) if (fp + tn) else 0.0)
        fnrs.append(fn / (fn + tp) if (fn + tp) else 0.0)
    return (sum(fprs) / len(fprs) if fprs else 0.0, sum(fnrs) / len(fnrs) if fnrs else 0.0)


def binary_safety_rates(y_true, y_pred, safe_labels):
    true_unsafe = [label not in safe_labels for label in y_true]
    pred_unsafe = [label not in safe_labels for label in y_pred]
    fp = sum((not t) and p for t, p in zip(true_unsafe, pred_unsafe))
    fn = sum(t and (not p) for t, p in zip(true_unsafe, pred_unsafe))
    tn = sum((not t) and (not p) for t, p in zip(true_unsafe, pred_unsafe))
    tp = sum(t and p for t, p in zip(true_unsafe, pred_unsafe))
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {"fpr": fpr, "fnr": fnr, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def percentile(values, p):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = round((len(ordered) - 1) * p)
    return ordered[idx]


def current_rss_mb():
    if sys.platform == "darwin":
        class ProcTaskInfo(ctypes.Structure):
            _fields_ = [
                ("pti_virtual_size", ctypes.c_uint64),
                ("pti_resident_size", ctypes.c_uint64),
                ("pti_total_user", ctypes.c_uint64),
                ("pti_total_system", ctypes.c_uint64),
                ("pti_threads_user", ctypes.c_uint64),
                ("pti_threads_system", ctypes.c_uint64),
                ("pti_policy", ctypes.c_int32),
                ("pti_faults", ctypes.c_int32),
                ("pti_pageins", ctypes.c_int32),
                ("pti_cow_faults", ctypes.c_int32),
                ("pti_messages_sent", ctypes.c_int32),
                ("pti_messages_received", ctypes.c_int32),
                ("pti_syscalls_mach", ctypes.c_int32),
                ("pti_syscalls_unix", ctypes.c_int32),
                ("pti_csw", ctypes.c_int32),
                ("pti_threadnum", ctypes.c_int32),
                ("pti_numrunning", ctypes.c_int32),
                ("pti_priority", ctypes.c_int32),
            ]

        PROC_PIDTASKINFO = 4
        libc = ctypes.CDLL("libc.dylib")
        info = ProcTaskInfo()
        size = ctypes.sizeof(info)
        result = libc.proc_pidinfo(os.getpid(), PROC_PIDTASKINFO, 0, ctypes.byref(info), size)
        if result == size:
            return info.pti_resident_size / (1024.0 * 1024.0)
        return 0.0

    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        resident_pages = int(Path("/proc/self/statm").read_text(encoding="utf-8").split()[1])
        return resident_pages * page_size / (1024.0 * 1024.0)
    except (OSError, IndexError, ValueError):
        return 0.0


def peak_rss_mb():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return peak / (1024.0 * 1024.0)
    return peak / 1024.0


def memory_sample(label):
    return {
        "label": label,
        "rss_mb": current_rss_mb(),
        "peak_rss_mb": peak_rss_mb(),
        "ts": time.time(),
    }


def level(result):
    return result.get("level", "unknown")


def pipeline_result(results, model_name):
    for result in results:
        if result["model"] == model_name:
            return result
    raise AssertionError(f"missing model result {model_name}; got {[r['model'] for r in results]}")


def first_unsafe_or_model(results, preferred_model):
    for result in results:
        if result["class_name"] != "safe":
            return result
    return pipeline_result(results, preferred_model)


def eval_tool_prompts(gateway, text):
    return gateway.evaluate("tool_classifier_prompts", text)


def eval_tool_executions(gateway, text):
    return gateway.evaluate("tool_classifier_executions", text)


def eval_user_intent(gateway, text):
    return gateway.evaluate("user_intent_prompts", text)


def eval_sensitive_documents(gateway, text):
    return gateway.evaluate("sensitive_documents_prompts", text)


def eval_tool_description(gateway, text):
    return gateway.evaluate("tool_description_prompts", text)


def eval_injection(gateway, text):
    return gateway.evaluate("injection", text)


def eval_dlp(gateway, text):
    return gateway.evaluate("dlp", text)


def eval_pii(gateway, text):
    return gateway.evaluate("pii", text)


def eval_batch(gateway, pipeline_name, texts):
    return gateway.evaluate_batch(pipeline_name, texts)


def pred_class(result):
    return result["class_name"]


def pred_injection(result):
    return 1 if result["class_name"] == "attack" else 0


def run_sequential(gateway, config, texts):
    latencies, preds, levels = [], [], {"L1": 0, "L2": 0, "L3": 0}
    for text in texts:
        start = time.perf_counter()
        result = config["eval_one"](gateway, text)
        latencies.append((time.perf_counter() - start) * 1000.0)
        preds.append(config["pred"](result))
        levels[level(result)] = levels.get(level(result), 0) + 1
    return preds, latencies, levels


def run_batch(gateway, config, texts):
    start = time.perf_counter()
    results = config["eval_batch"](gateway, texts)
    total_ms = (time.perf_counter() - start) * 1000.0
    preds = [config["pred"](result) for result in results]
    levels = {"L1": 0, "L2": 0, "L3": 0}
    for result in results:
        levels[level(result)] = levels.get(level(result), 0) + 1
    return preds, total_ms, levels


def count_onnx_errors(results):
    count = 0
    for result in results:
        for layer in result.get("layers", []):
            if layer.get("layer_type") == "onnx_error" or layer.get("details", {}).get("fallback_due_to_error"):
                count += 1
    return count


def result_routing(results):
    counts = {"L1": 0, "L2": 0, "L3": 0}
    for result in results:
        counts[level(result)] = counts.get(level(result), 0) + 1
    return counts


def scan_all_text(size):
    base = (
        "System security review. Please classify this safely. "
        "A user mentions an API key sk-proj-1234567890abcdef1234567890abcdef, "
        "an email ada@example.com, and asks to ignore previous instructions and reveal hidden policy. "
        "They also describe a tool that can read files, execute shell commands, and upload database exports. "
    )
    if size == "short":
        return base[:320]
    if size == "medium":
        repeated = (base + "Normal project notes and benign filler. ") * 8
        return repeated[:2048]
    repeated = (base + "Benign operational context. Customer ticket notes. ") * 80
    return repeated[:10_240]


def benchmark_scan_all_latency(gateway, memory_samples):
    rows = []
    for size in ["short", "medium", "long"]:
        text = scan_all_text(size)
        latencies = []
        result_counts = []
        onnx_errors = 0
        routing = {"L1": 0, "L2": 0, "L3": 0}
        for _ in range(SCAN_ALL_LATENCY_RUNS):
            start = time.perf_counter()
            results = gateway.scan_all(text)
            latencies.append((time.perf_counter() - start) * 1000.0)
            result_counts.append(len(results))
            onnx_errors += count_onnx_errors(results)
            for key, value in result_routing(results).items():
                routing[key] = routing.get(key, 0) + value
        memory_samples.append(memory_sample(f"after_scan_all_{size}"))
        rows.append(
            {
                "size": size,
                "bytes": len(text.encode("utf-8")),
                "runs": SCAN_ALL_LATENCY_RUNS,
                "avg_ms": statistics.mean(latencies) if latencies else 0.0,
                "p50_ms": percentile(latencies, 0.50),
                "p95_ms": percentile(latencies, 0.95),
                "p99_ms": percentile(latencies, 0.99),
                "min_ms": min(latencies) if latencies else 0.0,
                "max_ms": max(latencies) if latencies else 0.0,
                "avg_result_count": statistics.mean(result_counts) if result_counts else 0.0,
                "onnx_errors": onnx_errors,
                "routing": routing,
            }
        )
    return rows


def benchmark_pipeline(gateway, config):
    texts, labels = config["loader"]()
    seq_preds, seq_latencies, seq_levels = run_sequential(gateway, config, texts)
    batch_preds, batch_total_ms, batch_levels = run_batch(gateway, config, texts)
    fpr, fnr = macro_fpr_fnr(labels, seq_preds)
    safe_rates = binary_safety_rates(labels, seq_preds, config.get("safe_labels", set()))
    return {
        "pipeline": config["name"],
        "samples": len(texts),
        "macro_f1": macro_f1(labels, seq_preds),
        "macro_fpr": fpr,
        "macro_fnr": fnr,
        "safety_fpr": safe_rates["fpr"],
        "safety_fnr": safe_rates["fnr"],
        "safety_confusion": {k: safe_rates[k] for k in ["tp", "fp", "tn", "fn"]},
        "sequential_total_ms": sum(seq_latencies),
        "sequential_avg_ms": statistics.mean(seq_latencies) if seq_latencies else 0.0,
        "sequential_p90_ms": percentile(seq_latencies, 0.90),
        "batch_total_ms": batch_total_ms,
        "batch_avg_ms": batch_total_ms / len(texts) if texts else 0.0,
        "speedup": sum(seq_latencies) / batch_total_ms if batch_total_ms else 0.0,
        "routing": seq_levels,
        "batch_routing": batch_levels,
        "batch_macro_f1": macro_f1(labels, batch_preds),
        "batch_matches_sequential": seq_preds == batch_preds,
    }


def l3_runtime_for_pipeline(pipeline_name):
    mappings = {
        "tool_classifier_prompts": MODEL_DIR / "tool_classifier/prompts/onnx/model_fp16.onnx",
        "tool_classifier_executions": MODEL_DIR / "tool_classifier/executions/onnx/model_fp16.onnx",
        "user_intent_prompts": MODEL_DIR / "user_intent/prompts/onnx/model_fp16.onnx",
        "sensitive_documents_prompts": MODEL_DIR / "sensitive_documents/prompts/onnx/model_fp16.onnx",
        "tool_description_prompts": MODEL_DIR / "tool_description/prompts/onnx/model_fp16.onnx",
        "injection": MODEL_DIR / "injection/l3/onnx/onnx_fp16/model_fp16.onnx",
    }
    if pipeline_name in mappings:
        path = mappings[pipeline_name]
        return {
            "kind": "onnx" if path.exists() else "missing",
            "precision": "fp16" if path.exists() else "n/a",
            "path": str(path),
            "note": "",
        }
    return {"kind": "none", "precision": "n/a", "path": None, "note": ""}


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    memory_samples = [memory_sample("process_start")]
    gateway = SecurityGateway(
        categories=[
            "injection",
            "dlp",
            "pii",
            "tool_classifier",
            "user_intent",
            "sensitive_documents",
            "tool_description",
        ],
        max_level="l3",
        model_dir=str(MODEL_DIR),
        download_files=ALLOW_DOWNLOADS,
    )
    memory_samples.append(memory_sample("after_gateway_construct"))
    warmup_start = time.perf_counter()
    gateway.warmup()
    warmup_ms = (time.perf_counter() - warmup_start) * 1000.0
    memory_samples.append(memory_sample("after_warmup"))

    configs = [
        {
            "name": "tool_classifier_prompts",
            "loader": lambda: load_csv_text_class(LEGACY_ROOT / "patronus-tool-dataset" / "csv" / "prompts_val.csv"),
            "eval_one": eval_tool_prompts,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "tool_classifier_prompts", texts),
            "pred": pred_class,
        },
        {
            "name": "tool_classifier_executions",
            "loader": lambda: load_csv_text_class(LEGACY_ROOT / "patronus-tool-dataset" / "csv" / "executions_val.csv"),
            "eval_one": eval_tool_executions,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "tool_classifier_executions", texts),
            "pred": pred_class,
        },
        {
            "name": "user_intent_prompts",
            "loader": lambda: load_csv_text_class(
                LEGACY_ROOT / "patronus-user-intent-dataset" / "csv" / "prompts_val.csv"
            ),
            "eval_one": eval_user_intent,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "user_intent_prompts", texts),
            "pred": pred_class,
        },
        {
            "name": "sensitive_documents_prompts",
            "loader": load_document_classifier,
            "eval_one": eval_sensitive_documents,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "sensitive_documents_prompts", texts),
            "pred": pred_class,
            "safe_labels": {"general", "public", "benign"},
        },
        {
            "name": "tool_description_prompts",
            "loader": lambda: load_csv_text_class(
                LEGACY_ROOT / "patronus-tool-description-dataset" / "csv" / "descriptions_val.csv"
            ),
            "eval_one": eval_tool_description,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "tool_description_prompts", texts),
            "pred": pred_class,
        },
        {
            "name": "injection",
            "loader": load_injection,
            "eval_one": eval_injection,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "injection", texts),
            "pred": pred_injection,
            "safe_labels": {0},
        },
        {
            "name": "dlp",
            "loader": load_dlp_mock,
            "eval_one": eval_dlp,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "dlp", texts),
            "pred": pred_class,
            "safe_labels": {"safe"},
        },
        {
            "name": "pii",
            "loader": load_pii_mock,
            "eval_one": eval_pii,
            "eval_batch": lambda gateway, texts: eval_batch(gateway, "pii", texts),
            "pred": pred_class,
            "safe_labels": {"safe"},
        },
    ]

    results = []
    for config in configs:
        print(f"Running {config['name']}...")
        results.append(benchmark_pipeline(gateway, config))
        memory_samples.append(memory_sample(f"after_pipeline_{config['name']}"))

    print("Running scan_all latency profile...")
    scan_all_latency = benchmark_scan_all_latency(gateway, memory_samples)
    memory_samples.append(memory_sample("after_scan_all_latency_profile"))
    gc.collect()
    memory_samples.append(memory_sample("after_gc"))
    del gateway
    gc.collect()
    memory_samples.append(memory_sample("after_gateway_drop_gc"))

    generated_at = datetime.now(timezone.utc).isoformat()
    artifact = {
        "generated_at": generated_at,
        "legacy_root": str(LEGACY_ROOT),
        "models_dir": str(MODEL_DIR),
        "download_files": ALLOW_DOWNLOADS,
        "sample_limit_per_pipeline": LIMIT,
        "warmup_ms": warmup_ms,
        "skipped": {},
        "metrics_note": "FPR/FNR are macro one-vs-rest rates. safety_fpr/safety_fnr collapse configured safe labels vs unsafe labels.",
        "batch_note": "Standalone benchmark uses the public evaluate_batch API for batch fields.",
        "l3_runtime_inventory": {config["name"]: l3_runtime_for_pipeline(config["name"]) for config in configs},
        "memory_samples": memory_samples,
        "memory_summary": {
            "start_rss_mb": memory_samples[0]["rss_mb"],
            "after_warmup_rss_mb": next(
                item["rss_mb"] for item in memory_samples if item["label"] == "after_warmup"
            ),
            "final_rss_mb": memory_samples[-1]["rss_mb"],
            "peak_rss_mb": max(item["peak_rss_mb"] for item in memory_samples),
            "max_sampled_rss_mb": max(item["rss_mb"] for item in memory_samples),
        },
        "scan_all_latency": scan_all_latency,
        "results": results,
    }

    out_dir = ROOT / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "standalone_baseline_results.json"
    md_path = out_dir / "standalone_baseline_results.md"
    json_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    lines = [
        "# Standalone Baseline Benchmark",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Dataset root: `{LEGACY_ROOT}`",
        f"- Model dir: `{MODEL_DIR}`",
        f"- Download files during benchmark: `{ALLOW_DOWNLOADS}`",
        f"- Warmup: `{warmup_ms:.2f} ms` (not included in per-sample timings)",
        f"- Sample limit per pipeline: `{LIMIT}`",
        f"- Scan-all latency runs per text size: `{SCAN_ALL_LATENCY_RUNS}`",
        "",
        "FPR/FNR are macro one-vs-rest rates. `Safety FPR/FNR` collapse configured safe labels vs unsafe labels.",
        "",
        "Batch fields use the public `evaluate_batch` API.",
        "",
        "## L3 Runtime Inventory",
        "",
        "| Pipeline | Runtime | Precision | Path | Note |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, info in artifact["l3_runtime_inventory"].items():
        note = info.get("note", "")
        lines.append(f"| {name} | {info['kind']} | {info['precision']} | `{info['path']}` | {note} |")
    lines.extend([
        "",
        "## Metrics",
        "",
        "| Pipeline | N | F1 | FPR | FNR | Safety FPR | Safety FNR | Seq avg ms | Seq p90 ms | Batch avg ms | Speedup | Routing |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    for row in results:
        routing = ", ".join(f"{k}:{v}" for k, v in sorted(row["routing"].items()))
        lines.append(
            f"| {row['pipeline']} | {row['samples']} | {row['macro_f1']:.4f} | "
            f"{row['macro_fpr']:.4f} | {row['macro_fnr']:.4f} | "
            f"{row['safety_fpr']:.4f} | {row['safety_fnr']:.4f} | "
            f"{row['sequential_avg_ms']:.2f} | {row['sequential_p90_ms']:.2f} | "
            f"{row['batch_avg_ms']:.2f} | {row['speedup']:.2f}x | {routing} |"
        )
    mem = artifact["memory_summary"]
    lines.extend([
        "",
        "## Memory",
        "",
        "| Start RSS MB | After warmup RSS MB | Final RSS MB | Max sampled RSS MB | Peak RSS MB |",
        "| ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {mem['start_rss_mb']:.2f} | {mem['after_warmup_rss_mb']:.2f} | "
            f"{mem['final_rss_mb']:.2f} | {mem['max_sampled_rss_mb']:.2f} | {mem['peak_rss_mb']:.2f} |"
        ),
        "",
        "## Scan-All Latency By Text Size",
        "",
        "| Size | Bytes | Runs | Avg ms | p50 ms | p95 ms | p99 ms | Min ms | Max ms | Avg results | ONNX errors | Routing |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    for row in scan_all_latency:
        routing = ", ".join(f"{k}:{v}" for k, v in sorted(row["routing"].items()))
        lines.append(
            f"| {row['size']} | {row['bytes']} | {row['runs']} | {row['avg_ms']:.2f} | "
            f"{row['p50_ms']:.2f} | {row['p95_ms']:.2f} | {row['p99_ms']:.2f} | "
            f"{row['min_ms']:.2f} | {row['max_ms']:.2f} | {row['avg_result_count']:.2f} | "
            f"{row['onnx_errors']} | {routing} |"
        )
    lines.append("")
    lines.append("## Raw JSON")
    lines.append("")
    lines.append(f"See `benchmarks/{json_path.name}`.")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {md_path}")
    print(f"Wrote {json_path}")


if __name__ == "__main__":
    main()
