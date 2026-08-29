# Models & the NTDB format

Patronus Ark's L2 and L3 layers are backed by Patronus-trained models. This page explains
the two model formats (NTDB for L2, ONNX transformers for L3), the model families, and how
assets are organized.

## NTDB — the L2 format

**NTDB** stands for **Non Transformer Decision Block**. It is a small purpose-built network
architecture that bundles several *non-transformer* classifiers so they can be used together —
and, crucially, so they can answer as many requests as possible **without** invoking an L3
transformer. An NTDB package contains:

- a **static token-embedding encoder** — no attention, no per-token transformer pass (this is
  the "non-transformer" part);
- one or more **heads**. Each head runs a small ONNX network over the encoder's features to
  produce its score, optionally enriched by zero or more auxiliary non-transformer feature
  producers (gradient-boosted trees, logistic regression, centroid-cosine, a 1-D text CNN)
  whose outputs feed in as extra features;
- a trained **aggregator** that combines the heads' outputs with local and global heuristic
  features into the final L2 verdict;
- optionally, a trained **promote-router** that decides, per chunk, whether the case should be
  escalated to L3; when a package omits it, the aggregator's own promote output is used instead;
- a `manifest.json` with `format: ntdb_model_package` (version 2) describing operating points
  and metadata.

The aggregator is the point of the design. Rather than picking one classifier, it *learns*
when which features are more reliable — and the promote decision learns when an L3 transformer
would only return redundant or worse information, so that call can be skipped. This is how NTDB
offloads L3: most traffic is resolved by the cheap non-transformer block, and the expensive
transformer runs only where it actually adds signal.

All L2 packages in a process **share a single static encoder instance**. Embedding is done once
per token lookup, so running seven L2 categories costs barely more than running one — which is
what makes L2 fast enough to sit on the request path.

### Final-decision threshold profiles

Patronus Ark also ships bundled **final-decision threshold profiles** derived from validation
sweeps. You select one globally with
[`ntdb_operating_point`](../reference/configuration.md#ntdb-operating-point):

| Profile | Optimizes for |
| --- | --- |
| `best_f1` | Overall balanced final-decision F1 |
| `best_promote` | The bundled final-decision profile named `best_promote` |
| `best_fpr_in_f1` | Low false-positive rate within an F1 band |
| `best_fnr_in_f1` | Low false-negative rate within an F1 band |
| `best_latency_in_f1` | Lowest latency within an F1 band |

These profiles are applied after scoring: L3 can be accepted first, then a weighted L2/L3 union
can be accepted, then L2 can be accepted, otherwise the pipeline returns its default class. They
do not change the NTDB promote-router threshold that decides which chunks are sent to L3.

### Compact tokenizers

For compatible mmBERT byte-fallback BPE packages, asset preparation converts the downloaded
Hugging Face `tokenizer.json` **once** into `tokenizer.mmbpe`. NTDB packages linked to a shared
embedder reuse the generated shared artifact. Dedicated and unified L3 bundles can also generate
`.mmbpe` during verified downloads or cached warmup. The former `.kit` format is unsupported.

The source JSON remains canonical and is used automatically if conversion, validation, or compact
loading fails. Source/content hashes, format versions, and converter versions invalidate stale
generated files; local model overrides are never rewritten. Details are in
[Performance & memory](performance.md).

## ONNX transformers — the L3 format

L3 models are full transformers (the ModernBERT / mmBERT family) exported to ONNX. Ark uses the
combined INT8-weight / INT4-embedding variant by default; Injection, Threat, Sensitive Document,
Lion Warden, and the separate Dynamic-PII GLiNER model also support a pinned FP16 variant when
`PATRONUS_L3_PRECISION=fp16`. Linux `x86_64` production deployments must use FP16 for validated
cross-architecture inference parity. Which L3 models a gateway holds is
determined by configuration — the [L3 strategy](#dedicated-vs-unified-l3) and the configured
categories — and those models are kept **resident in RAM**, subject to an idle-TTL policy
(`PATRONUS_L3_TTL_SECS`, default 300 s) that evicts a session after a period of no use and
re-materializes it on the next promotion. Budget memory for the L3 models you enable. They are
executed by the L3 background worker. Only required assets are downloaded by default;
`PATRONUS_DOWNLOAD_OPTIONAL_ASSETS=1` additionally fetches non-required files (currently
`tokenizer_config.json` for the legacy L3 manifest).

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
Assets are cached under the platform cache directory (or a custom `model_dir`) and downloaded on
first use. The L2 NTDB packages, L3 transformers, the unified L3 model, and the dynamic-pii
bundle are pinned to immutable commit revisions in `specs.rs`. See
[Manage model assets](../how-to/manage-assets.md) and the generated
[Assets reference](../assets.md) for cache locations, sizes, and offline behavior.
