# SPDX-License-Identifier: GPL-3.0-only
"""Markdown rendering for local benchmark results."""

import json


def _benchmark_markdown(
    meta, example, benign, classifier, load, native_l1=None, dynamic_pii=None
):
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

    if dynamic_pii and dynamic_pii["enabled"]:
        quality = dynamic_pii["quality"]
        lines.extend(
            [
                "",
                "## GLiNER NER",
                "",
                "Entity matches require the same label and exact character offsets.",
                "",
                "| Samples | Executed | Gold entities | Predicted | True positives | Precision | Recall | F1 | Exact samples | Avg | p95 |",
                "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
                f"| {quality['samples']} | {quality['executed_samples']} | {quality['gold']} | "
                f"{quality['predicted']} | {quality['true_positives']} | "
                f"{quality['precision']:.3f} | {quality['recall']:.3f} | "
                f"{quality['f1']:.3f} | {quality['exact_samples']} | "
                f"{value(quality['latency'])} ms | "
                f"{value(quality['latency'], 'p95_ms')} ms |",
                "",
                "| Source classification | Gold entities | Precision | Recall | F1 |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for source, stats in quality["per_source_class"].items():
            lines.append(
                f"| {source} | {stats['gold']} | {stats['precision']:.3f} | "
                f"{stats['recall']:.3f} | {stats['f1']:.3f} |"
            )
        if quality.get("per_tool_class"):
            lines.extend(
                [
                    "",
                    "| Tool classification | Gold entities | Precision | Recall | F1 |",
                    "| --- | ---: | ---: | ---: | ---: |",
                ]
            )
            for source, stats in quality["per_tool_class"].items():
                lines.append(
                    f"| {source} | {stats['gold']} | {stats['precision']:.3f} | "
                    f"{stats['recall']:.3f} | {stats['f1']:.3f} |"
                )
        if quality.get("per_context_pair"):
            lines.extend(
                [
                    "",
                    "| Sensitive-document + tool context | Gold entities | Precision | Recall | F1 |",
                    "| --- | ---: | ---: | ---: | ---: |",
                ]
            )
            for source, stats in quality["per_context_pair"].items():
                lines.append(
                    f"| {source} | {stats['gold']} | {stats['precision']:.3f} | "
                    f"{stats['recall']:.3f} | {stats['f1']:.3f} |"
                )
        lines.extend(
            [
                "",
                "| Label | Gold | Predicted | Precision | Recall | F1 |",
                "| --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for label, stats in quality["per_label"].items():
            lines.append(
                f"| {label} | {stats['gold']} | {stats['predicted']} | "
                f"{stats['precision']:.3f} | {stats['recall']:.3f} | {stats['f1']:.3f} |"
            )

        combined = dynamic_pii["combined_latency"]
        if combined["enabled"]:
            memory = combined.get(
                "memory",
                {"after_mb": None, "delta_mb": None},
            )
            lines.extend(
                [
                    "",
                    "### L2 + L3 + GLiNER latency",
                    "",
                    "Only requests that produced an injection L2 fallback, an injection L3 "
                    "result, and a GLiNER result contribute to these latency values.",
                    "RAM is measured in a fresh process configured only for `injection` and "
                    "`dynamic-pii`. `From start` uses that process before its gateway is built; "
                    "`joint delta` starts after both model sessions are warmed.",
                    "",
                    "| Samples | Joint samples | Total avg/p95 | L2 avg/p95 | L3 avg/p95 | GLiNER avg/p95 | GLiNER queue avg/p95 | Peak RSS | From start | Joint delta |",
                    "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
                    f"| {combined['samples']} | {combined['l2_l3_gliner_samples']} | "
                    f"{value(combined['total_latency'])}/{value(combined['total_latency'], 'p95_ms')} ms | "
                    f"{value(combined['l2_execution'])}/{value(combined['l2_execution'], 'p95_ms')} ms | "
                    f"{value(combined['l3_execution'])}/{value(combined['l3_execution'], 'p95_ms')} ms | "
                    f"{value(combined['gliner_execution'])}/{value(combined['gliner_execution'], 'p95_ms')} ms | "
                    f"{value(combined['gliner_queue_wait'])}/{value(combined['gliner_queue_wait'], 'p95_ms')} ms | "
                    f"{memory['after_mb'] or 0.0:.1f} MiB | "
                    f"{memory['delta_mb'] or 0.0:.1f} MiB | "
                    f"{memory.get('phase_delta_mb') or 0.0:.1f} MiB |",
                ]
            )

    if native_l1 and native_l1["profiles"]:
        lines.extend(
            [
                "",
                "## Native L1 on 10 KiB",
                "",
                "Each measured scan uses a unique, exact 10 KiB input so decision-cache "
                "hits cannot replace detector execution. DLP and MCP policy are isolated "
                "with model gates; `all_native_l1` enables every native L1 detector for "
                "the configured injection, DLP, and PII categories.",
                "",
                "| Profile | Categories | Case | Iterations | Results/scan | Findings/scan | Avg | p50 | p95 | p99 |",
                "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for name, profile in native_l1["profiles"].items():
            categories = ", ".join(profile["categories"])
            for case_name in ("benign", "match_at_end"):
                stats = profile[case_name]
                latency = stats["latency"]
                lines.append(
                    f"| {name} | {categories} | {case_name} | {stats['iterations']} | "
                    f"{stats['results_per_scan']:.3f} | {stats['findings_per_scan']:.3f} | "
                    f"{latency['avg_ms']:.3f} ms | {latency['p50_ms']:.3f} ms | "
                    f"{latency['p95_ms']:.3f} ms | {latency['p99_ms']:.3f} ms |"
                )

    lines.extend(
        [
            "",
            "## Burst queue load",
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

    paced = load.get("steady_10_rps")
    if paced:
        lines.extend(
            [
                "",
                "## Sustained queue load at 10 req/s",
                "",
                "One producer submits requests at 100 ms intervals. One consumer drains "
                "the shared result queue concurrently.",
                "",
                "| Scenario | Requests | Errors | Submitted req/s | Completed req/s | First avg | Total avg | Total p95 | Final levels |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for name, stats in paced["scenarios"].items():
            levels = ", ".join(
                f"{level}: {count}" for level, count in stats["final_levels"].items()
            )
            lines.append(
                f"| {name} | {stats['requests']} | {stats['errors']} | "
                f"{stats['submission_rate_rps']:.2f} | {stats['throughput_rps']:.2f} | "
                f"{value(stats['first_result_latency'])} ms | "
                f"{value(stats['total_latency'])} ms | "
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
    diagnostic_scenarios = [(f"burst/{name}", stats) for name, stats in load["scenarios"].items()]
    if paced:
        diagnostic_scenarios.extend(
            (f"10rps/{name}", stats) for name, stats in paced["scenarios"].items()
        )
    for name, stats in diagnostic_scenarios:
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
            "| Scenario | L3 inferred avg/max | L3 propagated avg/max | L3 resolved avg/max | L3 early exits | L3 timeouts | L3 cache hits | L3 clustering |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for name, stats in diagnostic_scenarios:
        inferred = stats.get("l3_inferred_chunks") or {}
        propagated = stats.get("l3_propagated_chunks") or {}
        resolved = stats.get("l3_resolved_chunks") or {}
        lines.append(
            f"| {name} | "
            f"{value(inferred)}/{value(inferred, 'max_ms')} | "
            f"{value(propagated)}/{value(propagated, 'max_ms')} | "
            f"{value(resolved)}/{value(resolved, 'max_ms')} | "
            f"{stats.get('l3_early_exits', 0)} | "
            f"{stats.get('l3_timeouts', 0)} | "
            f"{stats.get('l3_cache_hits', 0)} | "
            f"{json.dumps(stats.get('l3_clustering_strategies', {}), sort_keys=True)} |"
        )
    lines.extend(
        [
            "",
            "## One complete queued response",
            "",
            "This is one real `enqueue()` call with every configured pipeline active. "
            "The JSON below is the complete result sequence returned by `consume_next_event()`.",
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
