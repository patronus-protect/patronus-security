# Models & the NTDB format

Patronus Ark's L2 and L3 layers are backed by Patronus-trained models. This page explains
the two model formats (NTDB for L2, ONNX transformers for L3), the model families, and how
assets are organized.

## NTDB — the L2 format

**NTDB** (Neural Text DataBase) is the Patronus export format for lightweight text
classifiers. An NTDB model package contains:

- a **static token-embedding encoder** (no attention, no per-token transformer pass);
- one or more small **ONNX heads** and **aggregators**;
- a `manifest.json` with `format: ntdb_model_package` describing operating points and metadata.

The key property is that **all L2 packages in a process share a single static encoder
instance**. Embedding is done once per token lookup, so running seven L2 categories costs
barely more than running one. This is what makes L2 fast enough to sit on the request path.

### Operating points

Each NTDB package ships several **operating points** — precomputed threshold configurations
that trade off recall, precision, latency, and promotion rate. You select one globally with
[`ntdb_operating_point`](../reference/configuration.md#ntdb-operating-point):

| Operating point | Optimizes for |
| --- | --- |
| `best_f1` | Overall balanced F1 |
| `best_promote` | Promotion quality (what L2 hands to L3) |
| `best_fpr_in_f1` | Low false-positive rate within an F1 band |
| `best_fnr_in_f1` | Low false-negative rate within an F1 band |
| `best_latency_in_f1` | Lowest latency within an F1 band |

The metric sweeps that back these points stay on disk and are loaded only as needed.

### Compact tokenizers

For supported packages, asset preparation converts the downloaded Hugging Face
`tokenizer.json` **once** into a compact `tokenizer.kit` in the shared encoder cache. The
source JSON remains canonical and is used automatically if conversion, validation, or compact
loading fails. Source/content hashes and converter versions invalidate stale generated files;
local model overrides are never rewritten. Details are in
[Performance & memory](performance.md).

## ONNX transformers — the L3 format

L3 models are full transformers (the ModernBERT / mmBERT family) exported to ONNX and
quantized (typically FP16 / INT8 / INT4-embedding variants). They are loaded **lazily** — the
ONNX Runtime session is created only when a scan first reaches L3 — and executed by the
background worker. Only required assets are downloaded by default; optional full ONNX assets
are fetched only when `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS=1`.

## The model families

| Family | Category(ies) | Role |
| --- | --- | --- |
| **Wolf Defender** | `injection`, `threat` | Prompt-injection detection and threat-type classification. |
| **Orca Sonar** | `sensitive_document` | Document classification for DLP / sensitive-document routing. |
| **Panther Read** | `routing` | User-intent / request-routing classification. |
| **Husky** (Sight / Paw / Nose) | `tool_class` / `tool_action` / `tool_tags` | Agentic tool-type, operation, and data-flow properties. |
| **Lion Warden** | multiple (unified) | Single multi-head model serving several categories from one inference. |
| **GLiNER small v2.5 (edge)** | `dynamic-pii` | Open-vocabulary entity extraction with exact spans. |

All models are published under the [`patronus-studio`](https://huggingface.co/patronus-studio)
Hugging Face organization and each carries its own model card with training data, benchmarks,
and variants.

## Dedicated vs. unified L3

- **Dedicated** (`l3_strategy="dedicated"`): one transformer per category — Wolf Defender for
  injection, Orca Sonar for documents, and so on. Best per-category accuracy tuning.
- **Unified / multi** (`l3_strategy="multi"`): the **Lion Warden** multi-head model serves
  several categories from a single coalesced inference. When several model-backed categories
  are active at once, this is substantially faster because promoted work is run together
  instead of once per model.

The [local benchmark](../how-to/run-local-benchmark.md) runs both strategies so you can compare
them on your own hardware.

## Where assets live

The category → level → repository mapping is defined in
[`rust/src/assets/specs.rs`](https://github.com/patronus-protect/patronus-security/blob/main/rust/src/assets/specs.rs).
Assets are cached under the platform cache directory (or a custom `model_dir`), downloaded on
first use, and verified by hash. See [Manage model assets](../how-to/manage-assets.md) and the
generated [Assets reference](../assets.md) for cache locations, sizes, and offline behavior.
