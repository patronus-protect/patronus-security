# Categories

A **category** is one kind of security question Patronus Security can answer about a text.
You choose the categories a gateway scans at construction time. Each category is backed by a
specific set of layers — some are native-only, some are model-backed, one is transformer-only.

## The ten categories

| Category | Question it answers | L1 | L2 | L3 model |
| --- | --- | :---: | :---: | --- |
| `injection` | Is this a prompt-injection / jailbreak attempt? | ✅ | ✅ | Wolf Defender (small) or unified Lion Warden |
| `dlp` | Does this leak secrets or trigger a destructive/sensitive operation? | ✅ | — | — |
| `pii` | Does this contain format-validated PII (email, IBAN, card, …)? | ✅ | — | — |
| `dynamic-pii` | Which named entities (GLiNER labels) appear, with exact spans? | — | — | GLiNER small v2.5 (edge) |
| `sensitive_document` | What document class is this (legal, HR, finance, source code, …)? | — | ✅ | Orca Sonar |
| `tool_class` | Which kind of tool does this call/operate (file, db, api, shell, …)? | — | ✅ | Husky Sight |
| `tool_action` | Which operation does the tool perform (read, write, exec, …)? | — | ✅ | Husky Paw |
| `tool_tags` | Data-flow properties (sensitive source, untrusted source, external sink)? | — | ✅ | Husky Nose |
| `routing` | What is the operational intent of the request? | — | ✅ | Panther Read |
| `threat` | What *type* of security threat is this? | ✅ | ✅ | Wolf Defender Threat |

The models are documented on Hugging Face under the
[`patronus-studio`](https://huggingface.co/patronus-studio) organization and mapped to
categories in [`rust/src/assets/specs.rs`](https://github.com/patronus-protect/patronus-security/blob/main/rust/src/assets/specs.rs).
See [Models & the NTDB format](models-and-ntdb.md).

## By layer profile

### Native-only (L1)

`dlp` and `pii` are resolved entirely by native Rust detectors. They **never download model
assets** and are always available offline. `pii` uses format validators (checksum/structure
verification for cards, IBANs, etc.); `dlp` matches secrets, destructive operations, and
sensitive-material transfers. Both populate `evidence_spans` with exact offsets. See
[Native detectors](detectors.md).

### Native + model-backed (L1 → L2 → L3)

`injection` and `threat` start with native L1 detectors and can escalate to an NTDB L2
classifier and, on promotion, a full transformer at L3. This gives immediate rule-based
coverage plus learned generalization for novel phrasings.

### Model-backed (L2 → L3)

`sensitive_document`, `tool_class`, `tool_action`, `tool_tags`, and `routing` are learned
classifiers with an NTDB L2 package and a dedicated L3 transformer. They have no native L1
stage; if their assets are not cached they simply do not produce a model verdict.

### Transformer-only (L3)

`dynamic-pii` is an L3-only GLiNER pipeline with its own labels, thresholds, chunking, text
limit, and timeout. It enqueues directly to the L3 worker and publishes only its completed
entity result — there is no lower-layer fallback. See the
[dynamic PII how-to context in the tutorials](../USAGE.md) and the
[configuration reference](../reference/configuration.md#dynamic-pii).

## The agentic-tool trio

`tool_class`, `tool_action`, and `tool_tags` describe the same tool call from three angles —
*what kind of tool*, *what operation*, and *what data-flow risk*. Combined, they let a policy
engine reason about agentic actions (for example: an `api` tool performing a `write` whose
`tool_tags` include an external sink). They correspond to the Husky model family.

## The unified vs. dedicated split at L3

At L3 you can run **one dedicated transformer per category** (`l3_strategy="dedicated"`) or a
single **coalesced multi-head model** (`l3_strategy="multi"`, the Lion Warden unified model)
that serves several categories from one inference. The multi-head path trades a little
per-category tuning for a large throughput win when several model-backed categories are active
at once. See [`l3_strategy`](../reference/configuration.md#l3-strategy) and
[Performance](performance.md).

## Choosing categories

Scan only what you need — every category adds work. A prompt firewall might run
`["injection", "threat"]`; a DLP gateway `["dlp", "pii", "sensitive_document"]`; an agent
guard `["injection", "tool_class", "tool_action", "tool_tags"]`. See
[Choose categories & levels](../how-to/choose-categories-and-levels.md) for guidance and the
offline implications of each choice.
