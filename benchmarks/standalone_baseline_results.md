# Standalone Baseline Benchmark

- Generated at: `2026-07-01T20:06:30.042519+00:00`
- Dataset root: `/Users/benediktveith/Documents/Apps/Patronus-Datasets`
- Model dir: `/private/tmp/patronus_security_standalone_bench_assets`
- Download files during benchmark: `False`
- Warmup: `17967.42 ms` (not included in per-sample timings)
- Sample limit per pipeline: `100`
- Scan-all latency runs per text size: `20`

FPR/FNR are macro one-vs-rest rates. `Safety FPR/FNR` collapse configured safe labels vs unsafe labels.

Batch fields use the public `evaluate_batch` API.

## L3 Runtime Inventory

| Pipeline | Runtime | Precision | Path | Note |
| --- | --- | --- | --- | --- |
| tool_classifier_prompts | onnx | fp16 | `/private/tmp/patronus_security_standalone_bench_assets/tool_classifier/prompts/onnx/model_fp16.onnx` |  |
| tool_classifier_executions | onnx | fp16 | `/private/tmp/patronus_security_standalone_bench_assets/tool_classifier/executions/onnx/model_fp16.onnx` |  |
| user_intent_prompts | onnx | fp16 | `/private/tmp/patronus_security_standalone_bench_assets/user_intent/prompts/onnx/model_fp16.onnx` |  |
| sensitive_documents_prompts | onnx | fp16 | `/private/tmp/patronus_security_standalone_bench_assets/sensitive_documents/prompts/onnx/model_fp16.onnx` |  |
| tool_description_prompts | onnx | fp16 | `/private/tmp/patronus_security_standalone_bench_assets/tool_description/prompts/onnx/model_fp16.onnx` |  |
| injection | onnx | fp16 | `/private/tmp/patronus_security_standalone_bench_assets/injection/l3/onnx/onnx_fp16/model_fp16.onnx` |  |
| dlp | none | n/a | `None` |  |
| pii | none | n/a | `None` |  |

## Metrics

| Pipeline | N | F1 | FPR | FNR | Safety FPR | Safety FNR | Seq avg ms | Seq p90 ms | Batch avg ms | Speedup | Routing |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| tool_classifier_prompts | 100 | 0.9660 | 0.0017 | 0.0351 | 0.0000 | 0.0000 | 57.82 | 1.40 | 1.04 | 55.60x | L1:83, L2:16, L3:1 |
| tool_classifier_executions | 100 | 0.9804 | 0.0012 | 0.0208 | 0.0000 | 0.0000 | 0.18 | 0.25 | 0.12 | 1.48x | L1:35, L2:65, L3:0 |
| user_intent_prompts | 100 | 0.9689 | 0.0030 | 0.0303 | 0.0000 | 0.0000 | 56.85 | 2.51 | 0.99 | 57.14x | L1:32, L2:67, L3:1 |
| sensitive_documents_prompts | 100 | 0.9720 | 0.0051 | 0.0280 | 0.0000 | 0.0000 | 80.45 | 28.44 | 6.59 | 12.21x | L1:34, L2:65, L3:1 |
| tool_description_prompts | 100 | 0.9509 | 0.0028 | 0.0391 | 0.0000 | 0.0000 | 60.69 | 3.92 | 2.32 | 26.11x | L1:46, L2:52, L3:2 |
| injection | 100 | 0.9322 | 0.0833 | 0.0833 | 0.0000 | 0.1667 | 153.18 | 541.20 | 94.03 | 1.63x | L1:0, L2:88, L3:12 |
| dlp | 100 | 1.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.73 | 1.41 | 0.39 | 1.88x | L1:100, L2:0, L3:0 |
| pii | 100 | 0.7333 | 0.0400 | 0.0800 | 0.8000 | 0.0000 | 0.67 | 1.17 | 0.33 | 2.03x | L1:50, L2:50, L3:0 |

## Memory

| Start RSS MB | After warmup RSS MB | Final RSS MB | Max sampled RSS MB | Peak RSS MB |
| ---: | ---: | ---: | ---: | ---: |
| 22.17 | 521.20 | 949.30 | 1781.61 | 2050.73 |

## Scan-All Latency By Text Size

| Size | Bytes | Runs | Avg ms | p50 ms | p95 ms | p99 ms | Min ms | Max ms | Avg results | ONNX errors | Routing |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| short | 315 | 20 | 179.35 | 171.18 | 231.19 | 246.64 | 163.19 | 246.64 | 24.00 | 0 | L1:400, L2:60, L3:20 |
| medium | 2048 | 20 | 239.09 | 237.39 | 276.61 | 293.22 | 193.73 | 293.22 | 24.00 | 0 | L1:400, L2:60, L3:20 |
| long | 10240 | 20 | 493.14 | 483.89 | 562.05 | 572.68 | 471.96 | 572.68 | 24.00 | 0 | L1:400, L2:60, L3:20 |

## Raw JSON

See `benchmarks/standalone_baseline_results.json`.
