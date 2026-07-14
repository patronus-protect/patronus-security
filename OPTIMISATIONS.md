# Runtime and Memory Optimizations

Last updated: July 14, 2026

## Purpose

This document describes the production runtime architecture of the Patronus Security Lib and explains the memory and latency optimizations behind it. It covers the implemented paths for:

- NTDB L2 with static Granite embeddings;
- Injection L3 with Wolf Defender Small;
- `dynamic-pii` L3 with `gliner_small-v2.5-edge`;
- the compact `.kit` and `.mmbpe` tokenizer formats;
- INT8 MatMul and INT4 embedding quantization.

The central finding is that model file size is not a reliable estimate of process RSS. Tokenizer object graphs, expanded weights, ORT initializer tensors, prepacking, and temporary activations can consume more memory than the file on disk. Model representation, tokenization, and execution lifecycle were therefore optimized independently and verified for result parity.

## Final execution path

| Level | Runtime | Memory-relevant representation |
|---|---|---|
| L2 | NTDB static encoder and ONNX heads | shared, memory-mapped FP16 embedding matrix; local `.kit` tokenizer |
| Injection L3 | Wolf Defender Small in the shared L3 worker | mixed/quantized ONNX graph; `.mmbpe` when present, otherwise Hugging Face JSON |
| `dynamic-pii` L3 | GLiNER small v2.5 in the same worker | UINT4 word embeddings, QINT8 MatMuls, native SentencePiece |

L3 inference is sequential, so the large Wolf and GLiNER activation buffers are never active at the same time. Both sessions may remain resident together; unloading them per request would be counterproductive because of model load latency. The worker evicts unused sessions after `PATRONUS_L3_TTL_SECS` seconds of inactivity, with a default of 300 seconds. An idle sweep runs every 30 seconds and uses `try_lock`, preventing an inference that outlives its timeout from blocking the worker.

The shared L3 scheduler distributes compute time rather than job count. Deficit Round Robin starts with cost estimates of 200 ms for Injection and 240 ms for `dynamic-pii`, a 50 ms quantum, and a 2,000 ms aging limit. An exponentially weighted moving average gradually replaces these bootstrap values with observed execution time. This prevents either a long Injection backlog or a series of expensive GLiNER jobs from starving the other pipeline.

## 1. NTDB L2: static embeddings

### Why static embeddings

NTDB L2 does not require a full transformer for its fast preliminary decision. The encoder maps tokens through a fixed embedding table, accumulates only the rows required by the input, and then executes trained heads and aggregators as small ONNX graphs. Multiple L2 packages with the same encoder identity share one `StaticEncoder` instance within the process.

This avoids repeated model initialization and keeps L2 latency low. Model heads remain independent, while tokenization and the embedding table are shared for each encoder identity.

### FP16 remains FP16

The Granite embedding matrix is stored as an FP16 file. An earlier runtime converted the entire table to FP32 while loading it. A roughly 132 MiB file therefore created a second full-size buffer of roughly 264 MiB.

The current runtime maps the unchanged file read-only with `mmap`:

- the complete FP16 table is neither copied nor expanded;
- the operating system pages in only the regions that are accessed;
- only selected token rows are converted to FP32 during accumulation;
- the numerical accumulator remains FP32;
- existing F32 embedding packages use the same path without a format conversion.

The matrix is cached by model identity, vocabulary size, and embedding dimension. Symlink and package paths are canonicalized so that multiple NTDB packages genuinely share the same table.

### Metric sweeps remain on disk

An NTDB manifest may contain a large calibration sweep. One measured package contained 16,562 sweep points and roughly 21 MiB of JSON. The runtime only requires named operating points and their thresholds. The `sweep` field remains part of the file format but uses `skip_deserializing`, so it is not materialized as a generic `serde_json::Value` tree.

This preserves package compatibility without allocating tens of thousands of maps, strings, and JSON values on the heap.

## 2. Tokenizers

### Granite/ModernBERT: `.kit`

A Hugging Face `tokenizer.json` is a portable interchange representation, not a memory-efficient runtime structure. Loading it creates vocabulary strings, hash maps, normalizer objects, and search structures. For supported Granite/ModernBERT packages, the Security Lib therefore creates its own compact Kitoken cache.

This conversion is part of the regular asset path:

1. `tokenizer.json` is downloaded as the canonical source or read from an official cache.
2. The library converts it locally to `tokenizer.kit`.
3. Metadata binds the cache to the source model, BLAKE3 source hash, BLAKE3 compact hash, converter version, Kitoken version, and format version.
4. A temporary file, `fsync`, atomic rename, and a per-cache process lock prevent partial or concurrent artifacts.
5. If the `.kit` file is missing, stale, or corrupt, `tokenizer.json` remains the safe fallback.

Local model overrides are never rewritten. Existing official caches are prepared under the same contract during warmup.

Kitoken does not implicitly apply the Hugging Face template. BOS and EOS are therefore added deterministically from the model contract. Byte offsets are reconstructed by monotonically aligning decoded token bytes with the original text. Removed control characters may be skipped; evidence follows the stronger original-text invariant that the returned range must slice to the reported evidence text.

Parity was verified on 5,439 versioned repository texts and 61 adversarial Unicode, whitespace, added-token, and control-character cases, both with and without special tokens. Model IDs, templates, and decoded output are identical. Existing L2 datasets produce the same labels, routing decisions, chunk counts, and L3 candidate spans.

Measured effect in an isolated package run:

| Metric | Hugging Face JSON | `.kit` |
|---|---:|---:|
| Tokenizer file | 24.13 MiB | 1.82 MiB |
| Additional package RSS | 170.52 MiB | 82.25 MiB |
| Median package load time | 1.11 s | 277 ms |
| Warm single inference | 1.35 ms | 1.47 ms |

The small warm-inference difference is negligible compared with the reduced load time and approximately 88 MiB of saved RSS.

### Wolf/mmBERT: `.mmbpe`

Wolf uses an mmBERT BPE tokenizer with 256,000 vocabulary entries and 580,604 explicit merge rules. A direct Kitoken conversion is not parity-safe for this tokenizer: 580,604 `(left_id, right_id)` rules collapse to only 234,865 distinct byte concatenations. Pair identity is part of the model contract and cannot be replaced by heuristic preprocessing.

The specialized `.mmbpe` format therefore stores:

- BOS, EOS, and unknown IDs;
- character and byte-fallback mappings;
- every merge rule as `(left_id, right_id, output_id, rank)`;
- added tokens, including `lstrip`;
- no generic JSON structure.

The Wolf runtime looks for `tokenizer.mmbpe` next to `tokenizer.json` and prefers the compact file when it is part of the installed assets. Without `.mmbpe`, it loads the Hugging Face tokenizer. This keeps the regular asset contract backward compatible and does not change the model format or classification output.

Across 5,439 repository texts and 61 adversarial cases, 11,000 encodings with and without special tokens produced no ID differences. Wolf does not require evidence offsets in this classification path; padding and truncation occur after the parity-safe ID sequence in the shared ONNX input path.

Measured effect in an isolated tokenizer run:

| Metric | Hugging Face JSON | `.mmbpe` |
|---|---:|---:|
| File | 32.77 MiB | 9.03 MiB |
| Load time | 1,169.84 ms | 48.96 ms |
| Encode time for 5,439 texts | 797.69 ms | 439.94 ms |
| Peak footprint | 335.33 MiB | 22.17 MiB |

### GLiNER: native SentencePiece

At runtime, GLiNER uses the original `spm.model` through `sentencepiece-rust`, not the roughly 15 MiB Hugging Face JSON tokenizer. The JSON path produced a disproportionately large heap through duplicate token strings, hash maps, and a prefix trie containing more than 500,000 nodes.

The native SentencePiece model is roughly 4 MiB and implements the tokenizer contract of the base model directly. The `dynamic-pii` engine then reconstructs evidence spans from word boundaries in the original text and returns UTF-8-safe byte and character offsets.

## 3. Quantized ONNX models

### What INT8 and INT4 mean here

Quantization is validated from the graph rather than inferred from filenames:

- QINT8 MatMul weights execute through `MatMulInteger`;
- word embeddings are stored in block-quantized UINT4 and read through `GatherBlockQuantized`;
- hidden states, LayerNorm, activation functions, Softmax, and residual paths remain predominantly FP32;
- temporary activations and ORT work buffers therefore remain significant contributors to peak RSS.

“INT4 embeddings” refers to an unsigned 4-bit word embedding in these ONNX graphs. It is independent of the INT8 transformer weights.

### Wolf Defender Small

The production asset path loads `onnx/onnx_mixed/model_mixed.onnx`. The runtime treats the graph's stored data types as authoritative and does not maintain a second FP32 copy in application code. The documented combined memory baseline used the verified Wolf variant with INT8 MatMul weights and an INT4 word embedding.

Its quality baseline is:

| Dataset | F1 | Precision | Recall |
|---|---:|---:|---:|
| Qualifire, 5,000 texts | 0.9111 | 0.9024 | 0.9200 |
| Jajavibhav, 10,000 texts | 0.9391 | 0.9099 | 0.9702 |

Wolf remains in raw ONNX format. A controlled comparison under ORT rc.12 produced:

| Format | Load RSS delta | Load time |
|---|---:|---:|
| Raw ONNX | 209 MiB | 0.71 s |
| Fixed ORT | 293 MiB | 0.46 s |
| Fixed ORT without arena, memory pattern, or prepacking | 267 MiB | 0.42 s |

The ORT format loads faster but consumes more memory for this graph. Memory takes priority over one-time load latency for the resident L3 path. `commit_from_memory_directly` is not used because its initializer lifetime and ownership contract introduces unnecessary failure risk.

### GLiNER small v2.5 Edge

`dynamic-pii` uses the revision-pinned `patronus-studio/gliner_small-v2.5-edge` bundle. Its runtime graph, `model_int4_embeddings_int8.onnx`, is 127.492 MiB and contains:

- exactly one UINT4 `GatherBlockQuantized` node for the word embedding matrix;
- 56 `MatMulInteger` nodes for QINT8 weights;
- approximately 47.242 MiB of UINT4, 60.750 MiB of INT8, and 18.252 MiB of FLOAT initializers.

The export includes the model configuration, `spm.model`, tokenizer metadata, and special tokens, and produces a quantization manifest. The asset downloader verifies an immutable Hub revision and expects the complete bundle under the regular `model_dir` root.

INT4 was selected over an 8-bit embedding variant because the larger embedding matrix provided no measurable latency benefit. Encoder work is dominated by quantized MatMuls and non-quantized activation paths, not the embedding gather.

The GLiNER session disables the CPU arena, memory pattern, and prepacking. This reduces additional ORT buffers and prepacked weight copies. ORT still materializes runtime tensors from the ONNX graph, so quantized disk size cannot be treated as expected RSS.

`dynamic-pii` is a span-only pipeline. It returns label, text, score, and byte and character offsets. Global classification and relations are not part of this runtime path.

## 4. Chunking, scheduling, and model lifecycle

Wolf processes at most 256 model tokens with 32 tokens of overlap. Candidate spans from L2 limit which L3 windows are executed. `dynamic-pii` uses 256 words with 32 words of overlap by default and executes chunks sequentially. Overlapping GLiNER matches are merged by score, and final offsets always refer to the complete original text.

Chunking bounds hidden states, span matrices, and ORT work buffers. An earlier full-text process exceeded 1 GiB RSS on long samples. The bounded sequential path keeps only one chunk's and one L3 model's activations live at a time.

GLiNER is not loaded and removed per request. The complete Edge graph takes approximately 0.85 to 0.92 seconds to load in a release profile. Releasing an ORT session also does not immediately and deterministically reduce visible macOS RSS because allocator and file-backed pages may remain within the process. Shared residency with a long idle TTL therefore provides more stable latency without concurrent activation peaks.

## 5. Verified end-to-end measurements

The final release benchmark ran on Apple arm64 with Rust, `ort = 2.0.0-rc.12`, and ONNX Runtime 1.24.2. It used:

- Granite L2 with a memory-mapped FP16 table and `.kit`;
- optional Wolf L3 with `.mmbpe` and the INT8/INT4-embedding variant;
- GLiNER small v2.5 Edge;
- eight production `dynamic-pii` classes;
- 200 balanced Injection texts.

| Metric | Result |
|---|---:|
| Peak RSS | 626.64 MiB |
| Injection F1 | 0.9592 |
| Wolf L3 promotions | 54 / 200 |
| L2 plus optional Wolf L3, mean | 56.58 ms |
| GLiNER, mean / p50 / p95 | 245.63 / 130.62 / 919.90 ms |
| End-to-end, mean / p95 | 302.21 / 1,038.35 ms |
| GLiNER load / first inference | 846.68 / 60.14 ms |
| GLiNER chunks / entities | 237 / 288 |

A separate fresh-process smoke test with L2, Wolf, and GLiNER loaded simultaneously reached 531.30 MiB RSS. The production eight-class configuration therefore remains below the 800 MiB process target. Peak RSS includes models and temporary activations and is more useful for capacity planning than a snapshot immediately after loading.

The NER quality baseline on the checked-in 100-sample, 195-entity fixture at threshold 0.5 is:

| Metric | Result |
|---|---:|
| Micro F1 | 0.7407 |
| Precision | 0.7143 |
| Recall | 0.7692 |
| Exact sample matches | 57% |

Threshold 0.7 reaches F1 0.7737 on this fixture. The production default remains 0.5 because thresholds are configurable per pipeline and label, and this dataset does not represent every dynamic class.

## 6. Parity and safety contract

These optimizations do not change public result shapes:

- `.kit` and `.mmbpe` must produce the same model token IDs as their Hugging Face sources;
- an invalid compact Granite cache is removed and falls back to `tokenizer.json`;
- cache files are bound to source hashes, versions, and formats and are created atomically;
- FP16 rows are converted to FP32 only while accumulating selected embeddings;
- quantized graphs are validated from their ONNX operators and quantization manifest;
- L3 remains sequential, cost-fair, and bounded by timeouts;
- evidence spans slice to the reported text in the original input;
- model assets use the existing revision-pinned Hugging Face asset path, without a Git clone or second downloader.

## Relevant implementations and measurements

| Subject | Path |
|---|---|
| FP16 memory map and shared static encoder | `rust/src/ml/ntdb_executor/encoder.rs` |
| Metric sweep deserialization | `rust/src/ml/ntdb_executor/manifest.rs` |
| `.kit` runtime and offset reconstruction | `rust/src/ml/ntdb_executor/tokenizer.rs` |
| Atomic `.kit` generation in the asset path | `rust/src/assets/compact_tokenizer.rs` |
| `.mmbpe` runtime | `rust/src/ml/mmbert_tokenizer.rs` |
| Wolf tokenizer selection and ONNX lifecycle | `rust/src/ml/onnx.rs` |
| GLiNER export and quantization | `scripts/export_quantize_gliner_onnx.py` |
| GLiNER ONNX engine | `rust/gliner-onnx-engine/` |
| `dynamic-pii` runtime | `rust/src/ml/dynamic_pii.rs` |
| Shared L3 scheduler | `rust/src/pipeline/l3_worker.rs` |
| Combined release benchmark | `rust/examples/injection_pair_gliner_benchmark.rs` |
| NER benchmark | `rust/examples/gliner_onnx_ner_benchmark.rs` |
| NER fixture | `rust/tests/fixtures/gliner_eval_quant_pii.json` |
| GLiNER A/B measurements | `benchmark/gliner_ab_2026-07-14.json` |
| CoNLL NER measurements | `benchmark/gliner_conll2003_ner_ab_2026-07-14.json` |
