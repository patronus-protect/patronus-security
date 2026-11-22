# Analysis framework: modules and layers

Patronus Ark analyses text with one framework in two dimensions: **analysis modules** (one per
category, the rows) and **layers** L1 → L2 → L3 (the columns, from cheap to expensive). Which
modules run, which layers they may use and every threshold are configuration. The cascade is
opt-in: with a configured cascade a later layer runs only on what the earlier layers left
undecided; without one, Ark Core and full Ark scan exactly as before (every configured layer runs,
and the new result fields stay absent).

This is the single page for that model. [Architecture](architecture.md) describes the components
of the full Ark gateway; [Native detectors](detectors.md) catalogues the L1 rules.

## Glossary

Analysis module
:   One category's L1 unit in Ark Core: an anchor-based heuristic, an optional L1 model and
    optional policies over the module's results. Modules: PII, DLP, CAT (shell commands) and the
    threat classes (`injection`, `jailbreak`, `prompt_extraction`, `tool_poisoning`,
    `exfiltration`, `unsafe_action`, …).

Heuristic (anchor-based)
:   The rule stage of a module. Cheap literal anchors and prefilters decide whether a rule's
    pattern runs at all; matched rules are scored. A score at or above the module's detect
    threshold (by default the scorer's calibrated point) is **detected**; an optional clear
    threshold clears scores below it.

L1 model
:   An optional small in-memory model per module (for example TF-IDF with logistic regression,
    or a fastText-style text model). It has two thresholds:
    the **detect threshold** (upper; a score above it is detected) and the
    **clear threshold** (lower; a score at or below it is clear), compared as the model file
    declares (`score > threshold`). A score in between escalates. The
    clear threshold can be **switched off**: then the L1 model never clears, and everything below
    the detect threshold escalates.

Policies (Cedar)
:   Optional [Cedar](https://www.cedarpolicy.com/) policies evaluated over a module's results and
    facts, for example `forbid` → block, or ask. CAT uses them today with three tiers (core,
    bundle, user).

Facts
:   The structured, typed description a module derives from its input, which policies evaluate.
    CAT emits the `patronus.facts/1` schema for shell commands; text modules can get their own
    facts schema later.

Layers L1 / L2 / L3
:   **L1**: the analysis modules in Ark Core, tuned for high specificity (about 0.1 % false
    positives on benign data), so an L1 detection is very likely right. **L2**: NTDB model
    packages and their execution logic, full Ark only. **L3**: deep-learning models, in Ark Core
    (Wolf Defender) or full Ark only (unified multitask, Orca, Husky, Panther, GLiNER). Each L3
    model runs at its own default threshold.

Escalation
:   Handing an undecided input to the next configured stage or layer, together with the score,
    the threshold it was compared to, the evidence spans and the source stage.

Early exit
:   A stage that decides (detected or clear) ends the module's run; later stages and layers do
    not run for that input.

`StageOutcome`
:   What one stage says: `Detected`, `Clear` or `Escalate`.

`decided_by`
:   The stage that produced a module's verdict: `heuristic`, `l1_model`, `policy` (reserved), `l2` or `l3`.

Max level
:   `max_level` (`l1`, `l2`, `l3`) is the highest layer a run may use, a hard ceiling.

Conditional gates
:   Predicates (`all` / `any` / `not` over request metadata and the results of modules that
    already ran) that switch a layer on or off for one module and one request. See
    [conditional gates](../reference/configuration.md#conditional-gates).

## The grid: modules × layers

Each row is an analysis module, each column a layer. L1 has up to three stages inside the module.

![Analysis modules (rows) by layers L1, L2 and L3 (columns), with the stages each module has](../img/architecture/analysis-grid.svg)

| Module | Heuristic (L1) | L1 model (L1) | Policies (L1) | L2 (full Ark, NTDB) | L3 |
| --- | --- | --- | --- | --- | --- |
| **PII** | anchors, validators, context, points (`pii_mode`, `rules`) | – | – | none | GLiNER dynamic PII (full Ark) |
| **DLP** | anchors, rule keywords, value runs, points (`dlp_mode`, `rules`) | – | – | Orca Sonar document package (`sensitive_document`) | Orca dedicated or unified (full Ark) |
| **CAT** (shell) | tokens and facts (`patronus.facts/1`) | TF-IDF / logistic regression, two thresholds (1 % and 0.1 % false positives) | Cedar, three tiers: core, bundle, user (`policy_dirs`, `cat.*` rules) | unified tool-class / tool-action package | Husky or unified (full Ark) |
| **Threat: injection** | rule catalog and families behind the anchor gate (`injection_mode`) | text model, two thresholds: detect at 0.1 %, clear at 1 % false positives; clear switchable off | – | injection package (published in the Wolf Defender small repository) | Wolf Defender base / small / edge (Ark Core, default threshold) |
| **Threat: other classes** (`jailbreak`, `prompt_extraction`, `tool_poisoning`, `exfiltration`, `unsafe_action`, …) | class rules behind the anchor gate, points (`<class>_mode`) | text model per class, two thresholds, where it measures better | – | unified threat package (`unsafe_action` only) | unified multitask or threat classifier (full Ark) |

The L2 injection package is an NTDB L2 model; it only shares a repository with Wolf Defender.
Wolf Defender itself is an L3 model.

## Flow inside one module

Without a cascade, every enabled producer and model runs, as before. With a cascade, every stage
either decides or hands on: the next stage runs only if it is switched on and the previous one did
not decide.

![Without a cascade every enabled producer and model runs; with a cascade the stages run one after another per module with early exit](../img/architecture/cascade-modes.svg)

Each L1 stage compares its score with two cuts:

![A score at or above the detect threshold is detected, below the clear threshold clear, in between it goes to the next stage](../img/architecture/stage-cuts.svg)

The heuristic counts a score at its cut (`score >= detect_threshold` detects, `score <
clear_threshold` clears); the L1 model compares as its model file declares (`score >
detect_threshold` detects, `score <= clear_threshold` clears).

The rules behind the diagram:

- **Prepare once.** All modules share one prepared view of the text and one anchor automaton;
  regular expressions run only where an anchor matched.
- **Early exit.** A decision at any stage ends the run for that module; `decided_by` names the
  stage.
- **The cascade is configuration, not a condition.** If only L1 is configured, "not detected"
  is the final answer: **clear**, never "undecided". The same holds for any last configured
  layer: its result is the module's verdict.
- **Clear threshold off.** With the L1 model's clear threshold switched off, the model never
  clears; scores below the detect threshold escalate if a later layer is configured, and are
  clear otherwise.
- **Results stay visible.** Every stage that ran keeps its entry in `layers`; existing result
  fields stay and new ones are only added.
- **Policies.** Cedar policies run inside CAT today. The text modules' cascade does not run
  policies yet; the heuristic's own clear threshold (off by default) can clear before the L1 model.
- **Full Ark.** With the gate key `cascade`, a category L1 decides (by default: detects) skips
  L2 and L3, and so does one no later layer can run for; without it, L2 and L3 run as before.
- **Wolf Defender in Core.** Without a cascade Wolf runs on every scan that selects
  `injection`, as before. With a cascade it runs only on injection inputs the module escalated:
  by default every input whose injection L1 did not detect; with `l1: false` on every input.

## What you can configure

**Per run**

- which modules run (PII, DLP, the threat classes, …);
- up to which layer: `max_level` `l1`, `l2` or `l3`;
- conditional gates over metadata and earlier results;
- deadlines, cancellation and size limits.

**Per module**

- heuristic on or off, single rules on or off, mode (`strict`, `balanced`, `recall`), detect
  threshold, clear threshold;
- L1 model on or off, detect threshold, clear threshold, clear threshold off;
- CAT policies on or off, policy directories;
- L2 model (full Ark), L3 model and its threshold (the model's default unless set).

**Output**

- one verdict per module with `decided_by` (heuristic, L1 model, L2, L3; `policy` is reserved);
- the results of every stage that ran (`layers`);
- existing fields unchanged; new fields are additive.

### Configuration keys

Ark Core takes the cascade as the optional `cascade` gate key of the scanner configuration
(Rust `ScannerConfig::gates.cascade`, Python `ScannerConfig["cascade"]`). Which layers run is
decided by the level keys of the configuration, with the same meaning in full Ark and with or
without a cascade (`max_level` the ceiling; `l1`, `l2`, `l3` switch a level off, unset means
on), so any single layer can run alone. Per module, the rules run unless their native
producers are switched off with the existing `models` gate (for example
`{"models": {"native:injection_l1": false}}`), and the L1 model runs when `l1_model` is set:

```json
{
  "categories": ["pii", "dlp", "injection", "exfiltration"],
  "wolf": {"bundle_dir": "/srv/models/wolf-defender"},
  "max_level": "l3",
  "cascade": {
    "modules": {
      "injection": {
        "clear_threshold": 0.05,
        "l1_model": {"builtin": "instruction_injection"}
      },
      "jailbreak": {"l1_model": {"bundle_dir": "/srv/models/jailbreak-l1", "manifest_sha256": "…"}},
      "exfiltration": {"detect_threshold": 0.3, "clear_threshold": 0.02}
    }
  }
}
```

| Key | Meaning | Default |
| --- | --- | --- |
| `max_level` | Deepest layer that may run: `l1`, `l2` or `l3`. | `l3` |
| `l1`, `l2`, `l3` | `false` switches that level off (`l1: false`: no rules and no L1 models run; for example only Wolf answers `injection`). | on |
| `conditional` | [Conditional gates](../reference/configuration.md#conditional-gates) for L2 and L3, over the L1 results of every scanned module. Only `result` conditions: Core scans carry no request metadata, so `metadata` conditions are refused. | none |
| `cascade.modules.<category>.detect_threshold` | The heuristic's detect cut on its rule scorer's probability (`0.0`–`1.0`): for `injection` (and the classes its rules feed) the injection scorer's candidate score; for the threat classes the document scorer's own probability (recomputed from `details.matched_rules`), not the points score; for PII and DLP the result's confidence. A score at or above it is detected when the category's mode (`<category>_mode`) admits it. A threat points rule accepted on its own, with evidence left after the mode floor, is detected regardless. | the scorer's calibrated point |
| `cascade.modules.<category>.clear_threshold` | The heuristic's clear cut on the same score; an undetected score below it is clear. Not above `detect_threshold`. | off |
| `cascade.modules.<category>.l1_model.builtin` | A model shipped with Ark Core, by name; nothing is downloaded. One per module: `instruction_injection` (module `injection`), `jailbreak`, `prompt_extraction`, `tool_poisoning`, `agent_config_tampering`, `memory_poisoning`, `exfiltration`, `unsafe_action`, `resource_exhaustion`, `harmful_content`, `toxic_language` (module of the same name). Each is a compact fastText-type text model (256 KiB) with cuts at 0.1 % (detect) and 1 % (clear) false positives on German and English benign text. Set either `builtin` or `bundle_dir`. | no model |
| `cascade.modules.<category>.l1_model.bundle_dir` | The L1 model release directory (`manifest.json`, `config.json`, the model file), loaded once when the scanner is created. | no model |
| `cascade.modules.<category>.l1_model.manifest_sha256` | sha256 of the release's `manifest.json`; required with `bundle_dir`. | — |
| `cascade.modules.<category>.l1_model.detect_threshold` | The model's detect cut on its score; a score above it is detected. | the model's 0.1 % false-positive cut |
| `cascade.modules.<category>.l1_model.clear_threshold` | The model's clear cut; a score at or below it is clear. | the model's 1 % false-positive cut |
| `cascade.modules.<category>.l1_model.clear_enabled` | `false` switches the model's clear cut off. | `true` |
| `wolf.threshold` | Wolf Defender's attack-probability cut (the L3 of `injection`); detects above it. | the model's published settings (Edge/Small: threshold 0.5, 2048-token windows with 64 overlap) |
| `threat_points_acceptance` | Least score of an accepted threat points rule: a gate on single findings, not a module cut. | `0.5` |

With `cascade` set, the scan report carries `decision`: per scanned module its `outcome`
(`detected` or `clear`), `decided_by` (`heuristic`, `l1_model`, `l2` or `l3`), the deciding
stage's `score` and the `layers` that ran after the heuristic (L1 model, L3, each with its
`duration_ms`). Without `cascade`, reports are unchanged.

Full Ark reads the same `cascade` key in its gates (Python `execution_gates`, Ark API `gates`),
with only `modules` and their `detect_threshold` / `clear_threshold` inside: its levels and
conditional gates are the gate keys `max_level`, `l1`, `l2`, `l3` and `conditional` themselves,
and it runs no L1 models yet. With it, Ark's blocking `scan_*` calls return the same report shape
as Core (`input_bytes`, `native`, `wolf`, `decision`), with one `decision` entry per module
(`outcome`, `decided_by` `heuristic`, `l2` or `l3`, `score`). In the queue and the distributed
plan, the result that gives a category's final answer carries that entry as `module_decision`; see
the [result schema](../reference/result-schema.md).

## Where the parts live

![Ark Core holds the analysis modules, the execution logic, Wolf Defender and the extension traits; Ark adds NTDB L2, the Ark-only L3 models and serving](../img/architecture/core-and-ark.svg)

| Part | Package | Licence |
| --- | --- | --- |
| Analysis modules (heuristics, L1 models, Cedar policies, facts), Wolf Defender runner, CAT | Ark Core (`patronus-ark-core`) | MIT OR Apache-2.0 |
| Execution logic: levels and gate schema, conditional gates, the cascade with escalation and early exit, L3 scheduling policy, generic chunk aggregation and arbitration | Ark Core | MIT OR Apache-2.0 |
| NTDB executor, L2 packages, threshold tables | full Ark (`patronus-ark`) | GPL-3.0-only or commercial |
| L3 models: unified multitask, Orca, Husky, Panther, threat classifier, GLiNER | full Ark | GPL-3.0-only or commercial |
| L3 workers, model-output cache, async queue and streaming, HTTP API, distributed fleet | full Ark | GPL-3.0-only or commercial |

Ark Core never depends on full Ark. Full Ark builds on Core and plugs its models into the same
seam, a set of traits that Core defines and full Ark implements:

- **`LayerModel`** — an L2 or L3 model for one module: runs inference and returns a result plus
  an escalation signal.
- **`ThresholdTable`** — the thresholds used to arbitrate between layers.
- **`L3Executor`** — runs an L3 job, scheduled locally or distributed.
- **`ExternalL1Detector`** — a plug-in L1 detector; see
  [Add external L1 signals](../how-to/external-l1-signals.md).

## What does not change

PII, DLP and CAT keep their interfaces. In Rust: `Scanner::new`, `scan`, `scan_categories`,
`scan_with_control`, `shell_verdict`, warmup and prepare functions, `ScannerConfig`,
`ScanGateMatrix`, `ShellConfig`, `ShellVerdict`, `WolfConfig`, `ScanReport`, `NativeResult`,
`LayerResult`, `DecisionEnvelope`, `PiiPipeline`, `DlpPipeline` and `ShellRiskPipeline`. In
Python: `Scanner(...).scan` and `.shell_verdict` with their types. The framework adds an
optional cascade block to the configuration and an optional verdict to the report; nothing
existing is removed or renamed. Without a cascade, scans and their results are exactly as before.

## The layers in full Ark

### L1 — analysis modules

The native Rust modules above need **no model assets** and are available fully offline. Runtime
depends on input size and enabled rules; large inputs take milliseconds. L1 covers deterministic
and pattern-based risks: prompt-injection phrasings, obfuscation tricks, secrets and
destructive-operation patterns (DLP), format-validated PII (email, IBAN, credit card, …), and MCP
tool-policy checks. See [Native detectors](detectors.md) for the full catalogue.

One exception: `shell_command` runs natively in L1 but scores with a small downloaded model
(`cat-shell-risk-commander`, 4.4 MiB bundle). Until it is loaded,
`runtime_readiness().l1` reports NotReady. See [Categories](categories.md#model-backed-l1-shell_command).

### L2 — NTDB model packages

Lightweight text classifiers in the Patronus **NTDB** format: the shared mmBERT tokenizer and
static embedder plus small ONNX heads and aggregators, packaged with a `manifest.json`. The
official L2 packages share this representation with compatible L3 models as well as with one
another, so adding categories is cheap and promotion does not start from raw text again. L2
answers in **milliseconds**.

L2 promotion is decided by the NTDB package's promote-router. Separately, classifier verdicts
use a configurable final-decision threshold profile — see
[`ntdb_operating_point`](../reference/configuration.md#ntdb-operating-point).

### L3 — full ONNX transformers

Full transformer models (ModernBERT / mmBERT family), exported to ONNX and quantized. They
are the most accurate and the most expensive. Which L3 models a gateway holds is fixed by
configuration; they are kept **resident in RAM** (idle-TTL evicted) and executed by a
**background worker**, not on the request path. L3 answers in **tens of milliseconds** and
makes the final call for cases L2 could not resolve confidently.

L3 consumes the exact token IDs of the promoted L2 chunks. Both layers use the
same 254-content-token chunks, with BOS/EOS and padding added for the 256-position
L3 input. Invalid chunks report an error; there is no tokenization fallback.

## Escalation in the full Ark gateway

```mermaid
flowchart LR
    IN([text]) --> L1
    L1 -- "decided (with cascade)" --> OUT0([L1 result])
    L1 -- undecided --> L2{L2 assets<br/>ready?}
    L2 -- no --> OUT1([L1 result])
    L2 -- yes --> L2R[L2 classifier]
    L2R --> P{promote?}
    P -- no --> OUT2([L2 result])
    P -- yes --> FB[[publish L2 fallback]]
    FB --> W[L3 worker]
    W --> OUT3([final L3 result])
```

1. **L1 always runs first.** With the gate key `cascade`, a category L1 decides ends there
   (early exit); without it, every category goes on to L2.
2. **L2 runs on what L1 hands on** when its assets are cached and the level allows it
   (`max_level` ≥ L2).
3. **Promotion to L3** happens when L2 is not confident enough to settle the case on its own
   and the level allows it (`max_level` = L3). The exact promotion behavior depends on the
   [operating point](../reference/configuration.md#ntdb-operating-point).
4. On promotion, the pipeline **immediately publishes the L2 fallback result**, then enqueues
   an L3 job. The **final L3 result is published later** by the worker.

Because the L2 fallback is published first, a caller always has a usable answer quickly, even
while the transformer is still running — and if L3 fails or times out, that fallback is what
remains.

### `max_level` is a hard ceiling

| `max_level` | L1 | L2 | L3 |
| --- | :---: | :---: | :---: |
| `l1` | ✅ | — | — |
| `l2` | ✅ | ✅ (if cached, on undecided input) | — |
| `l3` | ✅ | ✅ (if cached, on undecided input) | ✅ (if cached, on promotion) |

[Execution gates](../reference/configuration.md#execution-gates) can further disable
individual levels or specific detectors *below* the ceiling, per request, without changing it.

### Special pipelines

- **L1-only categories** (e.g. `pii`) never load models and never promote.
- **L3-only pipelines** (`dynamic-pii`) enqueue directly to the worker and have no L1/L2 fallback.
  They can emit a non-authoritative first-entity preview before their completed result.

See [Categories](categories.md) for each category's layer support.

### Long text and windowing

Text is split into disjoint UTF-8 windows of at most 128 KiB, each tokenized once
by compact mmBERT. L2 forms chunks of at most 254 content tokens; L3 reuses them
unchanged. Tokenizer input memory is bounded per window; retained chunks and results
still grow with document length. With representative
**clustering** enabled (off by default) it groups near-duplicate
windows by similarity, runs only cluster representatives, and propagates their verdict to the
rest, so most windows never reach the model; **early exit** stops a head once its aggregate can no
longer change. Aggregation strategy, clustering, and early exit are tunable per pipeline — see the
[L3 worker policy](../reference/configuration.md#l3-worker-policy). Window and chunk counts are
surfaced in the [local benchmark](../how-to/run-local-benchmark.md)'s load report.

## Degradation contract

Every failure path degrades to the best available result rather than throwing:

- **L2 assets missing** → return the L1 result.
- **L3 asset missing / not promoted** → return the L2 result.
- **L3 inference error or timeout** → return the published L2 fallback.

Failures are reported as structured `SecurityFailure` entries (stage + kind) on the terminal
event of the async API, so you can observe degradation without it breaking the scan. See the
[Result schema](../reference/result-schema.md).
