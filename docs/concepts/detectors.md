# Native detectors (L1)

Native detectors are the rule-based Rust checks that make up **L1**. They need no model
assets, run in microseconds, and are always available — including fully offline. This page
catalogues them by family. The source lives under
[`rust/src/detectors/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/src/detectors)
and [`rust/src/threat/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/src/threat).

Each detector returns a `class_name` (its own name when it fires, otherwise `safe`), a
confidence, and — for PII/DLP — `evidence_spans` with exact byte/character offsets.

## Injection

Eighteen detectors target prompt-injection and jailbreak techniques. They split into three
groups: **instruction manipulation**, **obfuscation/smuggling**, and **agentic/tool abuse**.

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
at NTDB L2 (see [Categories](categories.md#model-backed-l2--l3)).

`instruction_override` includes common German imperative variants such as attempts to forget,
ignore, disregard, override, skip, or discard prior instructions, while contextless everyday
uses of those verbs remain safe.

## DLP

Data-loss-prevention detectors flag content that leaks or destroys data:

| Detector | Catches |
| --- | --- |
| `dlp` | Regex bank for leaked secrets/credentials — API keys, cloud keys, private keys, JWTs, webhook secrets, and similar — reported with exact evidence spans. |
| `secret_transfer` | Secrets and credentials being read or moved (API keys, private keys, tokens, `.env`). |
| `destructive_operation` | Destructive commands/operations (mass delete, disable protections, wipe). |
| `sensitive_material` | Transfer of sensitive material beyond a trust boundary. |

Only the `dlp` regex detector populates `evidence_spans` with the exact matched offsets;
`secret_transfer`, `destructive_operation`, and `sensitive_material` are boolean heuristics and
return no spans.

## PII

The `pii` category is native-only and uses **format validators** rather than a model:
deterministic identifiers such as email, IP, IBAN, SWIFT/BIC, phone, and credit-card numbers
are recognized and structurally validated (e.g. checksum/format checks) before being reported,
which keeps false positives low. Matches are returned as `evidence_spans`. For open-vocabulary
entity extraction (names, organizations, locations, …) use the model-backed
[`dynamic-pii`](categories.md#transformer-only-l3) category instead.

## MCP (Model Context Protocol)

Two native detectors evaluate agentic tool use against MCP policy:

| Detector | Catches |
| --- | --- |
| `mcp_policy` | Matches against a fixed built-in set of MCP tool-policy rules (e.g. destructive shell ops, credential-file reads) and returns the fired rule name. The internal per-rule severity is not surfaced in the result. |
| `mcp_runtime_risk` | Runtime risk in an MCP tool invocation. |

These can be toggled per request via [execution gates](../reference/configuration.md#execution-gates)
using model keys such as `native:mcp_runtime_risk`.

## Enabling and disabling detectors

All native detectors run when their category and level are enabled. To disable a specific
detector without changing `max_level`, use an execution gate with its `native:<name>` key:

```python
scanner.set_execution_gates({
    "levels": {"l1": True, "l2": False, "l3": False},
    "models": {"native:mcp_runtime_risk": False},
})
```

See [Configuration → execution gates](../reference/configuration.md#execution-gates).
