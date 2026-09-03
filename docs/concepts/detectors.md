# Native detectors (L1)

Native detectors are the rule-based Rust checks that make up **L1**. They need no model
assets and are available fully offline. Their runtime scales with the input and enabled rule
inventory: short inputs are cheap, while sufficiently large inputs can take milliseconds rather
than microseconds. This page catalogues the detectors by family. The source lives under
[`rust/src/detectors/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/src/detectors)
and [`rust/src/threat/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/src/threat).

All built-in L1 rules produce source-bound evidence first. Regex captures, lexical matches,
ordered token relations, structural matches, and decoded payloads use the shared component
contract: rule identity, matched components, and original-text byte offsets. Validators check
candidate values before a finding is emitted. There is no Boolean detector followed by a
localization adapter.

PII and DLP project this evidence into their public results. Injection combines it into scored
candidates for one `native:injection_l1` result. A complete relationship contributes one rule
vote; its individual anchors do not become extra independent votes.

## Injection

The native Injection stack combines a pinned rule catalog, a structural relationship producer,
and eighteen evidence-producing native rule families. They split into three groups: **instruction
manipulation**, **obfuscation/smuggling**, and **agentic/tool abuse**.

Overlapping signals are merged into candidates and scored by the versioned L1 scorer. Only an
accepted candidate creates public evidence spans and a non-safe result. Rejected candidates retain
their score and evidence in the typed decision contract without becoming findings.

### Instruction manipulation

| Detector | Catches |
| --- | --- |
| `instruction_override` | "Ignore/disregard/forget previous instructions" and equivalents. |
| `instruction_boundary` | Attempts to redraw or escape the system/user instruction boundary. |
| `instruction_leak` | Attempts to make the model reveal its system prompt or hidden instructions. |
| `authority_escalation` | Claims of elevated authority ("as an admin/developer/system…"). |
| `guardrail_tamper` | Attempts to disable, weaken, or talk around safety guardrails. |
| `jailbreak_framing` | Roleplay/persona framings used to bypass restrictions (e.g. "DAN", "developer mode"). |
| `output_manipulation` | Instructions that dictate or constrain the model's output to smuggle a payload. |
| `multi_turn_escalation` | Escalation patterns that build an injection across multiple turns. |

### Obfuscation & smuggling

| Detector | Catches |
| --- | --- |
| `encoded_instruction` | Instructions hidden in base64/hex/other encodings. |
| `binary_smuggling` | Payloads smuggled as binary or non-text byte sequences. |
| `unicode_confusable` | Homoglyph / confusable-character substitution to evade string rules. |
| `zero_width_obfuscation` | Zero-width and invisible characters inserted to break up trigger words. |
| `hidden_html_instruction` | Instructions concealed in HTML (comments, hidden attributes, etc.). |
| `covert_instruction` | Otherwise-concealed instructions that do not fit the above buckets. |

### Agentic & tool abuse

| Detector | Catches |
| --- | --- |
| `tool_call_injection` | Injected or forged tool calls in the input. |
| `tool_output_instruction` | Instructions embedded in tool *output* that try to steer the agent. |
| `cross_tool_instruction` | Instructions that try to make one tool act on another's behalf. |
| `agentic_control_abuse` | Abuse of agent control flow (loops, planning, autonomy) to subvert intent. |

The [`rust/src/threat/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/src/threat)
module provides shared pattern- and obfuscation-detection primitives used internally by several
injection and DLP detectors. The `threat` *category* itself has **no native L1 stage** — it starts
at NTDB L2 (see [Categories](categories.md#model-backed-l2-l3)).

`instruction_override` includes common German imperative variants such as attempts to forget,
ignore, disregard, override, skip, or discard prior instructions, while contextless everyday
uses of those verbs remain safe.

## DLP

Data-loss-prevention detectors report credential material, sensitive technical or business
content, and risky data-handling operations. Ark emits findings; enforcement remains the
caller's responsibility.

| Detector | Catches |
| --- | --- |
| `dlp` | Regex bank for leaked secrets/credentials, business-record identifiers, internal metrics, source code, SQL, dumps, and system logs, reported with exact evidence spans. |
| `secret_transfer` | Requests to transfer secrets to external sinks, or explicit exfiltration. |
| `destructive_operation` | Destructive commands/operations (mass delete, disable protections, wipe). |
| `sensitive_material` | Requests to read or disclose credential material, including sensitive files. |
| `mcp_policy` | A fixed built-in set of MCP tool-policy patterns, including destructive shell operations and credential-file reads. |
| `mcp_runtime_risk` | Risk indicators in an MCP tool invocation. |

All six producers populate `evidence_spans` from their matched source components. MCP policy
matches retain both the tool field and the matching argument. With `explain: true`, the regex detector also exposes
`details.l1_anchors` for credential, authentication, business-record, metric, source/config,
database/dump, and log/stacktrace context. These context-only anchors are not findings; Ark does not enforce blocking.

Rust, Python, and the Ark API share the same DLP default profile: it enables the credential- and
secret-oriented regex rules plus `secret_transfer` and `sensitive_material`, while business
records, source code, SQL, logs, metrics, destructive operations, and MCP-specific producers are
opt-in. See [Configuration → execution gates](../reference/configuration.md#execution-gates).

## PII

The `pii` category has a native-only L1 detector. It combines regex candidates, optional format
validators, and anchor-bound rules rather than running a model: deterministic identifiers such as
email, IP, IBAN, SWIFT/BIC, phone, payment-card data, government/insurance identifiers, and
anchor-bound employee, customer, patient, student, applicant, account, username, and birth-date
values can be reported. Matches are returned as exact `evidence_spans`, retaining overlapping
matches across different labels. With `explain: true`, localized
`details.l1_anchors` cover person, role, contact,
address, birth, identifier, account, payment, financial, government, vehicle, medical,
special-category, and employment/compensation context without inventing a finding. For
open-vocabulary entity extraction (names, organizations, locations, …) use the model-backed
[`dynamic-pii`](categories.md#transformer-only-l3) category instead.

## Language and evidence guarantees

Natural-language relationships and contextual identifiers support English and German.
Technical syntax (API-key prefixes, shell commands, SQL, JSON field names, PEM markers) is
language-neutral and is not translated. A German document can contain the same technical token
as an English document. This is pattern coverage, not a promise to understand every paraphrase.

The checked-in bilingual inventory tests require a DE/EN fixture for every PII and DLP regex
rule, every native Injection family, and all MCP policy entries. They check reachability and
source offsets. Existing source goldens and near-negative tests remain separate regression checks.

Exact original-text ranges are retained through lowercase, Unicode-confusable and zero-width
normalization. For decoded payloads whose character positions cannot be mapped exactly, the
component identifies the original encoded container as `transformed_source`; it never claims
that decoded offsets are original-text offsets.

## Enabling and disabling detectors

Native detectors are eligible when their category and L1 are enabled; model and rule gates can
narrow that set. To disable a complete detector without changing `max_level`, use an execution
gate with its `native:<name>` key. To
disable one stable PII, DLP, or Injection L1 rule while keeping its siblings, use `rules`. Missing
rule IDs inherit the shared defaults. For Injection, `native:injection_l1` disables the complete native stack;
the former model keys such as `native:instruction_override` still disable only that internal
producer:

```python
scanner.set_execution_gates({
    "levels": {"l1": True, "l2": False, "l3": False},
    "models": {"native:instruction_override": False},
    "rules": {"pii_employee_id": False, "dlp_sql_statement": False},
})
```

See [Configuration → execution gates](../reference/configuration.md#execution-gates).
The complete set of accepted PII, DLP, DLP-relationship, and Injection rule IDs is listed in the
[L1 rule catalog](../reference/l1-rule-catalog.md).
