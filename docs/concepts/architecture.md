# Architecture

This page explains how Patronus Ark is put together — the major components, how a scan
flows through them, and why the design looks the way it does. For the moment-to-moment
escalation rules, see [Layered scanning](layered-scanning.md).

## The big picture

Patronus Ark is a **Rust core** with a thin **Python binding**. The core owns all
scanning logic, model execution, asset management, and the async worker; the Python layer is
a typed convenience wrapper over the same gateway object.

```mermaid
flowchart TB
    subgraph client["Your application"]
        Py["Python<br/>patronus_ark.SecurityGateway"]
        Rs["Rust<br/>patronus_ark::SecurityGateway"]
    end

    Py -->|PyO3| GW
    Rs --> GW

    subgraph core["Rust core (patronus-ark)"]
        GW["SecurityGateway<br/>(orchestrator + request registry)"]
        GW --> PIPE["Per-category Pipelines"]
        PIPE --> L1["L1 · native detectors<br/>(injection / dlp / pii / mcp)"]
        PIPE --> L2["L2 · NTDB executor<br/>(shared tokenizer + static embedder + ONNX heads)"]
        L2 -.promote + token IDs.-> WORKER["L3 background worker<br/>(cost-scheduled queue)"]
        WORKER --> L3["L3 · full ONNX transformers<br/>(RAM-resident, TTL-evicted)"]
        WORKER -.check.-> CACHE["Model-output cache<br/>(logits · similarity · PII)"]
        GW --> ASSETS["Asset manager<br/>(download · verify · cache)"]
        L2 --> ASSETS
        L3 --> ASSETS
    end

    ASSETS -->|first use only| HF["Hugging Face<br/>Patronus model repos"]
    WORKER -->|results| QUEUE[["Shared result queue"]]
    L1 --> QUEUE
    L2 --> QUEUE
    QUEUE --> Py
    QUEUE --> Rs
```

## Components

### SecurityGateway

The orchestrator and the only public entry point. It:

- holds the **configuration** (categories, `max_level`, L3 strategy, execution gates, backend);
- builds one **pipeline per category**;
- owns the **request registry** that tracks which scanners and promoted L3 jobs may still
  publish an event for a given request ID;
- exposes the primary **asynchronous** API (`enqueue` + `consume_next_event`) and, as a
  convenience for one-off scripts, blocking helpers (`scan_all`, `scan_category`).

Construction is layered so you can separate a network-capable *asset-sync* phase from a
strictly-local *runtime-start* phase — see [Asset & runtime lifecycle](#asset-and-runtime-lifecycle).

### Pipelines

Each category owns a pipeline that knows which of L1/L2/L3 it supports and how to combine
their outputs into a single [result](../reference/result-schema.md). Some categories are
L1-only (`pii`), some are L3-only (`dynamic-pii`), most run L1→L2 with optional L3 promotion.
See [Categories](categories.md) for the per-category layer map.

### The three layers

| Layer | Implementation | Loaded | Latency class |
| --- | --- | --- | --- |
| **L1** | Native Rust detectors in `detectors/` and `threat/` | no assets; gate-controlled | input-dependent |
| **L2** | NTDB packages using the shared mmBERT tokenizer and static embedder | on warmup (if cached) | milliseconds |
| **L3** | Full ONNX transformers aligned with L2's tokenizer and embeddings | RAM-resident per config, idle-TTL evicted | tens of milliseconds |

The current official L2 and L3 packages use the same mmBERT tokenization contract and embedding
space. L2 performs the cheap static-embedding path; when it promotes compatible chunks, their
token IDs are handed directly to the full L3 transformer rather than computed a second time.

L1 and L2 run on a **pool of gateway workers** (up to 4 threads, sized to available cores). L3
runs in a **single separate background worker** so a heavy transformer never blocks a fast
L1/L2 answer — and because that worker processes one L3 job at a time, its fair scheduler (below)
decides ordering across categories. Detailed escalation logic lives in
[Layered scanning](layered-scanning.md); the model formats live in
[Models & the NTDB format](models-and-ntdb.md).

### The L3 background worker

L3 is expensive, so it is decoupled from the request path:

- When L2 **promotes** a scan, the pipeline first publishes the **L2 fallback** result to the
  shared queue, then enqueues an L3 job.
- The worker **schedules by estimated and observed compute cost** (an exponentially weighted
  moving average of real execution time) and applies a **max-wait guard** against starvation.
- Long texts split into **tokenizer-bounded windows**. With clustering enabled the worker groups
  near-duplicate windows by similarity, infers only cluster **representatives**, and **propagates**
  their verdict to the rest — so most windows never reach the model. **Early exit** stops a head
  once its aggregate can no longer change. See the
  [L3 worker policy](../reference/configuration.md#l3-worker-policy) (clustering is off by default).
- With progress reporting enabled the worker streams non-terminal **`progress`** / **`provisional`**
  events as chunks resolve (dedicated strategy only).
- L3 errors and timeouts **degrade back to the L2 result** where a fallback exists.
- Sessions are evicted after the idle TTL (`PATRONUS_L3_TTL_SECS`, default 300 s; `-1` disables eviction);
  the worker never hot-swaps models per request.

The worker can run **one dedicated model per category** or **one coalesced multi-head model**
for all categories — see the [`l3_strategy`](../reference/configuration.md#l3-strategy) knob
and [Performance](performance.md).

### The shared result queue

All results — L1/L2 or L3 — are published to one shared queue keyed by `request_id`. This is
what lets a ready L2 result for request B overtake request A that is still waiting for L3. You
drain this queue with `consume_next_event()`, which you should run on its own thread so it
never blocks your producer from calling `enqueue`. (The blocking `scan_*` helpers drain the
queue for you internally, which is why they only suit single-shot scripts.)

### The model-output cache

Separate from the asset download cache, an optional **model-output cache** sits in front of L3
and the `dynamic-pii` GLiNER pipeline. It stores **raw per-head logits** — not final decisions,
so policy and thresholds are re-applied on every hit — keyed by the immutable model SHA plus the
exact chunk bytes, so an identical chunk skips inference entirely. A **historical similarity**
tier can propagate a non-safe verdict to a close L2-embedding match without running L3, and a
**dynamic-PII** tier remembers normalized entity spans across texts. A memory tier is always on;
an optional [redb](https://github.com/cberner/redb)-backed file adds persistence across restarts.
Because the PII tier stores cleartext spans, protect that file like other sensitive local data.
See [Configure caching](../how-to/configure-caching.md).

### The asset manager

Native L1 needs no assets. L2/L3 scanners download **Patronus-owned model bundles** from the
Hugging Face repositories listed in [`rust/src/assets/specs.rs`](https://github.com/patronus-protect/patronus-security/blob/main/rust/src/assets/specs.rs).
The manager downloads on first use, verifies integrity by content/source hash, caches under
the platform cache directory (or a custom `model_dir`), and converts tokenizers into a compact
on-disk form once. See [Manage model assets](../how-to/manage-assets.md) and
[Assets](../assets.md).

## How a scan flows

An `enqueue(text)` for a category that supports all three layers. The app enqueues on one
thread and consumes on another:

```mermaid
sequenceDiagram
    participant App
    participant GW as SecurityGateway
    participant L1
    participant L2
    participant W as L3 worker
    participant Q as Result queue

    App->>GW: enqueue(text) → request_id
    GW->>L1: native detectors
    L1-->>GW: L1 verdict
    GW->>L2: NTDB classifiers (if assets ready)
    L2-->>GW: L2 verdict (+ promote?)
    alt L2 promotes to L3
        GW->>Q: publish L2 fallback (result event)
        GW->>W: enqueue L3 job + compatible L2 token IDs
        W->>W: schedule by cost, reuse tokens / window when needed
        W-->>Q: publish final L3 result event
    else no promotion
        GW->>Q: publish L2 result event
    end
    Q-->>App: consume_next_event() → result / finished
```

## Asset and runtime lifecycle

For deployments that must not download during a delivery window, the lifecycle splits into
two phases:

1. **Asset-sync (network allowed).** `prepare_assets()` downloads and verifies everything the
   configured categories need.
2. **Runtime-start (strictly local).** `warmup_from_local_assets()` initializes pipelines
   from the local cache only, never touching the network.

`warmup()` remains a combined convenience call that does both. `asset_readiness()` /
`runtime_readiness()` inspect the local cache and initialized state **without** downloading or
loading models into memory. This is the recommended pattern for air-gapped and installer-based
deployments — see [Offline & air-gapped scanning](../how-to/offline-airgapped.md).

## Design principles

- **On-device first.** No scan content leaves the machine. The only network activity is the
  optional, one-time asset download from Hugging Face.
- **Pay for detection only when needed.** Native L1 avoids model inference; the
  transformer runs only for the uncertain minority that L2 promotes.
- **Rust core, thin bindings.** All logic lives once in Rust; Python (and any future binding)
  is a wrapper, so behavior cannot drift between languages.
- **Graceful degradation.** A missing asset, an L3 timeout, or an inference error degrades to
  the best available lower-layer result instead of failing the scan.
- **Reproducible assets.** Content/source hashes and converter versions invalidate stale
  generated files; local model overrides are never rewritten.
