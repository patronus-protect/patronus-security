# Native detectors (L1)

Native detectors are the rule-based Rust checks that make up **L1**. They need no model
assets and are available fully offline. Their runtime scales with the input and enabled rule
inventory: short inputs are cheap, while sufficiently large inputs can take milliseconds rather
than microseconds. This page catalogues the detectors by family. The source lives under
[`rust/src/detectors/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/src/detectors)
and [`rust/src/threat/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/src/threat).

PII and DLP detectors return their own public results. Injection heuristics instead contribute
signals to one scored `native:injection_l1` result; this prevents a single broad regex from
becoming an independent verdict.

## Injection

The native Injection stack combines a pinned rule catalog, a structural relationship producer,
and eighteen legacy heuristic producers. They split into three groups: **instruction
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
| `secret_transfer` | Secrets and credentials being read or moved (API keys, private keys, tokens, `.env`). |
| `destructive_operation` | Destructive commands/operations (mass delete, disable protections, wipe). |
| `sensitive_material` | Transfer of sensitive material beyond a trust boundary. |
| `mcp_policy` | A fixed built-in set of MCP tool-policy patterns, including destructive shell operations and credential-file reads. |
| `mcp_runtime_risk` | Risk indicators in an MCP tool invocation. |

Only the `dlp` regex detector populates `evidence_spans` with the exact matched offsets;
the other five producers are boolean heuristics and return no spans. The regex detector also
exposes localized lexical or structural
`details.l1_anchors` for credential, authentication, business-record, metric, source/config,
database/dump, and log/stacktrace context. These anchors do not block by themselves.

The Rust/Python library leaves all DLP rules eligible unless execution gates disable them. The
Ark API example/default profile is intentionally narrower: it enables the credential- and
secret-oriented regex rules plus `secret_transfer` and `sensitive_material`, while business
records, source code, SQL, logs, metrics, destructive operations, and MCP-specific producers are
opt-in. See [Configuration → execution gates](../reference/configuration.md#execution-gates).

## PII

The `pii` category has a native-only L1 detector. It combines regex candidates, optional format
validators, and anchor-bound rules rather than running a model: deterministic identifiers such as
email, IP, IBAN, SWIFT/BIC, phone, payment-card data, government/insurance identifiers, and
anchor-bound employee, customer, patient, student, applicant, account, username, and birth-date
values can be reported. Matches are returned as exact `evidence_spans`. Localized
`details.l1_anchors` cover person, role, contact,
address, birth, identifier, account, payment, financial, government, vehicle, medical,
special-category, and employment/compensation context without inventing a finding. For
open-vocabulary entity extraction (names, organizations, locations, …) use the model-backed
[`dynamic-pii`](categories.md#transformer-only-l3) category instead.

## Enabling and disabling detectors

Native detectors are eligible when their category and L1 are enabled; model and rule gates can
narrow that set. To disable a complete detector without changing `max_level`, use an execution
gate with its `native:<name>` key. To
disable one stable PII, DLP, or Injection L1 rule while keeping its siblings, use `rules`. Missing
rule IDs remain enabled. For Injection, `native:injection_l1` disables the complete native stack;
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
The complete set of accepted PII, DLP, DLP-heuristic, and Injection rule IDs is listed in the
[L1 rule catalog](../reference/l1-rule-catalog.md).
