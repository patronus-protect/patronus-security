# NTDB V3 Runtime TODO

## Current State

- V3 L2 inference runs as a sub-runtime behind the existing NTDB package API.
- Rules, gates, aggregation, L3 scheduling, and security decision code remain on the existing `ScoreOutput` / `NtdbDecision` contract.
- V3 now computes one per-chunk batch and derives the document-level `ScoreOutput` from chunk outputs.
- V2 and V3 can share `PreparedDocument` when manifest key fields match:
  - `tokenizer_dir`
  - `minilm.model` / `minilm.source_model_path`
  - `minilm.tokenizer_family`
  - `minilm.embedding_dim`
  - `minilm.content_tokens_per_chunk`
  - `feature_contract.local_feature_order`

## Measured Baseline

Bench command:

```bash
PATRONUS_NTDB_PROFILE=1 cargo run -q --example ntdb_v2_v3_benchmark -- \
  /Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/export/injection_current \
  /Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/export/injection_v3 \
  10
```

Multi-chunk command:

```bash
PATRONUS_NTDB_PROFILE=1 PATRONUS_NTDB_BENCH_REPEAT=120 cargo run -q --example ntdb_v2_v3_benchmark -- \
  /Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/export/injection_current \
  /Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/export/injection_v3 \
  10
```

Latest measurements with shared preparation:

```text
1 chunk:
V2       avg 1.18 ms
V3       avg 3.79 ms
V2+V3    avg 4.55 ms

9 chunks:
V2       avg 46.86 ms
V3       avg 42.30 ms
V2+V3    avg 47.90 ms
```

Previous 9-chunk V2+V3 measurement before shared preparation was about `76.64 ms`.

## TODO

1. Keep V3 chunk-first.
   - Do not reintroduce a separate V3 document inference pass.
   - Document-level `promote_score` should remain derived from per-chunk promote scores.
   - For `binary_promote`, keep document attack score derived from the max chunk attack score unless product semantics require another reducer.

2. Make preparation sharing explicit and test-covered.
   - Add a unit/integration assertion that V2 and V3 with matching manifest key fields share a single `PreparedDocument`.
   - Add a diagnostic for key mismatches, so future manifest regressions are visible.
   - Consider excluding fields from `PreparationKey` that are not actually required for shared tokenization/embedding.

3. Improve V3 profiling.
   - Keep `PATRONUS_NTDB_PROFILE=1` for component timing.
   - Add preparation timing: tokenization, embedding, local features.
   - Add package-level timing around `score_prepared`, so request latency can be split into preparation vs V2/V3 inference.
   - Keep `*_cpu_ms` labels for accumulated parallel CPU time; use `*_ms` only for wall time.

4. Reduce remaining V3 inference overhead.
   - Conditional LightGBM branch evaluation is the dominant V3-specific cost.
   - Group rows by selected L2 class and evaluate branch 0 / branch 1 in batches where possible.
   - Avoid per-row allocations in `promoter_features`.
   - Reuse buffers for frozen LGBM probabilities, neural outputs, promoter features, and branch probabilities.

5. Move toward a shared pipeline DAG.
   - Treat tokenization, embeddings, local features, V2 heads, V3 frozen heads, V3 ONNX, surrogate, and conditional branches as stages over shared chunk buffers.
   - Schedule independent stages across chunks and pipelines.
   - Keep the existing `ScoreOutput` / `NtdbDecision` surface stable while introducing the internal DAG.

6. Validate coexistence behavior.
   - Keep the real export test for `injection_current` + `injection_v3`.
   - Measure V2-only, V3-only, and V2+V3 request latency after each runtime change.
   - Verify decisions and promoted chunks remain stable across shared vs non-shared preparation.

7. Revisit load-time cost separately.
   - Request latency is now close to `max(V2, V3) + overhead`, but load time remains roughly additive.
   - Investigate lazy loading or shared mmap/session setup only if startup time becomes relevant.
