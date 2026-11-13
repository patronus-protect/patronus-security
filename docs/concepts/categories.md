# Categories

A **category** is one kind of security question Patronus Ark can answer about a text.
You choose the categories a gateway scans at construction time. Each category is backed by a
specific set of layers — some are native-only, some are model-backed, one is transformer-only.

## The categories

| Category | Question it answers | L1 | L2 | L3 model |
| --- | --- | :---: | :---: | --- |
| `injection` | Is this a prompt-injection attempt? | ✅ | ✅ | Wolf Defender (small) or unified Lion Warden |
| `dlp` | Does this contain credentials, secrets, or sensitive business identifiers/content? | ✅ | — | — |
| `pii` | Does this contain validated or anchor-bound personal identifiers? | ✅ | — | — |
| `dynamic-pii` | Which named entities (GLiNER labels) appear, with exact spans? | — | — | GLiNER small v2.5 (edge) |
| `sensitive_document` | What document class is this (legal, HR, finance, source code, …)? | — | ✅ | Orca Sonar |
| `tool_class` | Which kind of tool does this call/operate (file, db, api, shell, …)? | — | ✅ | Husky Sight |
| `tool_action` | Which operation does the tool perform (read, write, exec, …)? | — | ✅ | Husky Paw |
| `tool_tags` | Data-flow properties (sensitive source, untrusted source, external sink)? | — | ✅ | Husky Nose |
| `routing` | What is the operational intent of the request? | — | ✅ | Panther Read |
| `shell_command` | Is this shell command or script (POSIX/Bash, PowerShell, CMD) risky? | ✅ (model) | — | — |
| `jailbreak` | Does this try to switch off the model's safety behaviour? | — | — | — |
| `prompt_extraction` | Does this try to reveal the system prompt or hidden instructions? | — | — | — |
| `tool_poisoning` | Does a tool description or tool output carry hidden instructions? | — | — | — |
| `agent_config_tampering` | Does this try to change an agent's configuration, rules or guards? | Native rules | — | — |
| `memory_poisoning` | Does this try to plant instructions in an agent's memory? | — | — | — |
| `exfiltration` | Does this try to send data, secrets or sessions to an outside target? | Native rules | — | — |
| `unsafe_action` | Does this ask for a risky operation (remote execution, credential access, destructive or privileged actions)? | Native rules | ✅ | Wolf Defender Threat |
| `resource_exhaustion` | Does this try to exhaust compute, tokens or other resources? | — | — | — |
| `harmful_content` | Does this ask for harmful content or harmful actions? | Native rules | — | — |
| `toxic_language` | Is this toxic or abusive language? | — | — | — |

`injection` and the ten categories below `shell_command` are the **attack classes**: each one
answers one question about attacks on models and agents. When no categories are given, the
library scanner runs `pii`, `dlp`, `injection`, `jailbreak`, `prompt_extraction`,
`tool_poisoning` and `exfiltration`; the example and deployment configurations use the same
defaults. `agent_config_tampering`, `memory_poisoning`, `unsafe_action`,
`resource_exhaustion`, `harmful_content` and `toxic_language` are opt-in. An attack class
without a detector yet returns no finding. The bounded `ark.threat.*` rules each belong to one
attack class and report under it (see [Threat L1](../reference/threat-l1.md)).

The models are documented on Hugging Face under the
[`patronus-studio`](https://huggingface.co/patronus-studio) organization and mapped to
categories in [`rust/src/assets/specs.rs`](https://github.com/patronus-protect/patronus-security/blob/main/rust/src/assets/specs.rs).
See [Models & the NTDB format](models-and-ntdb.md).

## By layer profile

### Native-only (L1)

`dlp` and `pii` are resolved entirely by native Rust detectors. They **never download model
assets** and are always available offline. `pii` combines checksum/structure validators with
field anchors for contact, payment, government, account, and person identifiers. `dlp` detects
credentials and secrets as well as gateable business identifiers, internal metrics, source code,
SQL, dumps, and logs. Risky operations are not `dlp` findings: the destructive-operation,
sensitive-material and MCP runtime-risk detectors report under `unsafe_action`, the
secret-transfer detector under `exfiltration`. Credential/secret findings keep their entity group
(`API_KEY`, `SECRET_TOKEN`, `CREDENTIAL` …) as label and name a `subtype` within it, such as
`password`, `access_token`, `auth_url` or `private_key` (see
[DLP taxonomy](../reference/result-schema.md#dlp-taxonomy)). PII and regex-based DLP findings populate
`evidence_spans` with original-text offsets; native MCP policy rules also retain
source-bound components and finding spans.
Both can publish localized, non-finding `l1_anchors` with `explain: true`. The shared Rust/Python/API default enables only
credential/secret DLP rules and the classification markings by default; other DLP families are opt-in through rule gates. See
[Native detectors](detectors.md), [Choose DLP rule families](../how-to/choose-categories-and-levels.md#choose-dlp-rule-families)
and [DLP coverage and comparison](../reference/dlp-comparison.md) (gitleaks, TruffleHog, detect-secrets).

### Model-backed L1 (`shell_command`)

`shell_command` ("Cat") decides on a shell command or full script (POSIX/Bash, PowerShell,
Windows CMD): `allow`, `ask` or `block`. The **caller** declares that the input is a command by
choosing this category (for example from a PreToolUse hook for a Bash tool); it is not meant for
prose. It runs natively in the L1 phase — so also in distributed mode and with `max_level="l1"` —
but is the one L1 detector that needs a downloaded bundle: `cat-shell-risk-commander` (K26), a
logistic regression over TF-IDF character n-grams and shell tokens (4.4 MiB bundle, no
ONNX/tokenizer). The verdict is the stricter of the model and Cedar policies over the command's
facts (core policies, the bundle's DefenseClaw rules, and your own `.cedar` files). The command is
never executed. In full Ark (library, HTTP API, Cube Coordinator) Cat is the `shell_command`
category: no harness context or session; user policies and allowlist come from `policy_dirs` and
`allowlist` (`set_shell_command_policy_config` in Rust and Python, `pipeline.shell_command` in the
Ark API). Every Cat policy id is an L1 rule id in the shared `rules` gates. In Ark Core it is not a scan category but
`Scanner::shell_verdict`, which also takes the harness context (cwd, home, repo root) and the facts
of earlier commands (`prior_facts`). See [Check shell commands](../how-to/check-shell-commands.md),
[Assets](../assets.md) and the [result schema](../reference/result-schema.md).

### Native + model-backed (L1 → L2 → L3)

`injection` and `unsafe_action` start with native L1 detectors and can escalate to an NTDB L2
classifier and, on promotion, a full transformer at L3. `unsafe_action` uses the Wolf Defender
Threat model at L2/L3. This gives immediate rule-based coverage plus learned
generalization for novel phrasings.

### Model-backed (L2 → L3)

`sensitive_document`, `tool_class`, `tool_action`, `tool_tags`, and `routing` are
learned classifiers with an NTDB L2 package and a dedicated L3 transformer. They have no native
L1 stage; if their assets are not cached they simply do not produce a model verdict.

### Transformer-only (L3)

`dynamic-pii` is an L3-only GLiNER pipeline with its own labels, thresholds, chunking, text
limit, and timeout. It enqueues directly to the L3 worker and has no lower-layer fallback. It can
emit non-authoritative provisional entity previews before the authoritative completed result.
Conditional label groups can be gated by final source-pipeline results and scoped to matching
source chunks. See the
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
`["injection", "jailbreak", "prompt_extraction"]`; a DLP gateway `["dlp", "pii", "sensitive_document"]`; an agent
guard `["injection", "tool_class", "tool_action", "tool_tags"]`; a Bash-tool hook
`["shell_command"]`. See
[Choose categories & levels](../how-to/choose-categories-and-levels.md) for guidance and the
offline implications of each choice.
