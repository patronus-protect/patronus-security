# Injection L1 rule-catalog inventory for Ark 0.1.6

## Scope

This inventory covers the first Ark 0.1.6 implementation step: improve the
native prompt-injection heuristics from pinned public references before adding
ensemble scoring or suspicion-window routing. DLP, PII, dynamic PII, routing,
threat, and sensitive-document behavior are outside this change.

The implementation uses the references as rule and coverage sources. It does
not import their runtimes, confidence thresholds, or final-decision policies.

## Current branch status

| Deliverable | Status |
| --- | --- |
| Existing Ark Injection-L1 producers registered | Done: 18/18 |
| Existing positive findings with stable IDs and candidate spans | Done: 18/18 |
| Selected Prompt Armor gap rules | Done: 13 |
| Source-derived P0 relationships | Done: 4 |
| Total registered native producers/rules | 35 |
| Common `InjectionSignal` evidence contract | Done |
| Rule-backed `L1Candidate` contract | Done; no score or action yet |
| Additional open-source pattern scan | Done; composition candidates documented separately |
| Ensemble scoring and suspicion-window routing | Not started; later implementation steps |

The 18 existing detectors remain separately gateable public scanner models for
compatibility. They are no longer evidence-opaque: every positive result now
maps to the common registry and signal contract. The additional data-driven
catalog remains a separate execution producer, but its output uses the same
contract rather than a parallel evidence format.

Every positive registered signal is also represented as a `rule_match` feature
inside `layers[].details.l1_candidates`. Overlapping signal spans form one
candidate; separated passages remain separate. Candidates intentionally omit
ensemble score, action, promotion, and window fields at this stage.

## Pinned references

| Reference | Revision | Use |
| --- | --- | --- |
| [Prompt Armor](https://github.com/prompt-armor/prompt-armor) | `95e532e275280488b3abacb519f8b14ae17a9dcb` | Selected L1 rules and positive/near-negative cases |
| [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/tutorials/09-prompt-injection-detection.md) | `46463ef8689433817fcc0c582a7881f515d4df15` | Attack-family coverage checklist |
| [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) | CheatSheetSeries `c735a6edc4c645eb975754cd908296686a5b3049` | Direct/indirect injection and obfuscation coverage checklist |

Prompt Armor is Apache-2.0 licensed. The selected catalog retains every
upstream rule ID and the source revision. Ark-specific IDs remain stable if the
upstream catalog changes.

## Existing Ark detector inventory

| Attack family | Registered native detector(s) | 0.1.6 catalog change |
| --- | --- | --- |
| Instruction override | `instruction_override` | Adds missing refusal, replacement-task, context-discard, and ES/FR/PT combinations |
| System-prompt extraction | `instruction_leak` | Adds complete-dump, prior-configuration, and repeat-context combinations |
| Role/persona jailbreak | `jailbreak_framing` | Adds a constrained identity-removal rule |
| Instruction boundaries and delimiters | `instruction_boundary`, `hidden_html_instruction` | Adds artificial end-of-system-prompt declarations |
| Encoded/obfuscated injection | `encoded_instruction`, `unicode_confusable`, `zero_width_obfuscation`, `binary_smuggling` | No broad Prompt Armor encoding regex imported |
| Tool and data exfiltration | `cross_tool_instruction`, `tool_call_injection`, `tool_output_instruction`, `agentic_control_abuse` | Adds high-specificity Markdown-image exfiltration |
| Guardrail and authority manipulation | `guardrail_tamper`, `authority_escalation`, `multi_turn_escalation` | Existing structural relationships retained |
| Covert/output manipulation | `covert_instruction`, `output_manipulation` | Existing structural relationships retained |

## Selected catalog delta

The catalog adds 13 high-specificity rules:

- four instruction-override relationships;
- one identity override;
- three system-instruction extraction relationships;
- one artificial instruction-boundary marker;
- one Markdown-image exfiltration pattern;
- one instruction-override relationship each for Spanish, French, and
  Portuguese.

Each match records:

- a stable `ark.injection.*` rule ID;
- the original Prompt Armor rule ID;
- family, severity, description, and upstream weight as metadata;
- exact byte and Unicode character offsets;
- the pinned source revision and licence.

Each positive result from the 18 existing Ark detectors records the same core
fields. Because those producers are procedural combinations rather than single
regexes, their current spans are marked as `clause` or bounded `window` spans;
the imported regex catalog emits `exact` spans. This distinction is explicit in
`matched_rules[].span_precision`.

The upstream weight is provenance only. Ark does not use it as a block or
promotion threshold.

The implemented follow-up source scan is documented in
[`injection-pattern-sources-0.1.6.md`](injection-pattern-sources-0.1.6.md). It
maps new primitives and relationships against the original 31 registered
rules. Four source-derived relationships now add independently verified
coverage, bringing the registered total to 35.

## Rules deliberately not imported

The initial catalog excludes patterns that are too broad to be independent Ark
L1 findings:

- `JB-007`: hypothetical or educational framing;
- `EA-001`: ordinary encode/decode requests;
- `EA-003`: arbitrary Base64-looking strings;
- generic persona renaming and bare `new instructions` phrases;
- standalone urgency and claims of an authorized audit.

These may become ensemble features later, but are not precise enough to create
an L1 finding by themselves.

Prompt Armor `ID-003` was narrowed during import. Its original `a|an`
alternative also matched benign text such as `You are no longer a beginner`.
The Ark mapping requires an actual AI/assistant identity target and exposes the
adaptation in rule evidence.

## Verification contract

`rust/tests/injection_rule_catalog.rs` verifies:

- a positive case for every imported rule;
- nearby benign counterexamples, including multilingual and exfiltration
  examples;
- exact byte and character offsets with Unicode preceding a match;
- stable Ark/upstream IDs, licence, and source revision in layer evidence;
- exclusion of low-specificity educational and arbitrary-Base64 signals.
- registry coverage, IDs, source revision, metadata, and localized evidence for
  all 18 existing native Injection-L1 detectors.

## Remaining heuristic gaps

- Typoglycemia currently has no native Ark detector. It needs a bounded
  structural matcher and its own hard-negative corpus rather than another broad
  regex.
- Quoted security examples and genuinely injected instructions inside documents
  cannot safely be separated by a global allowlist. That distinction belongs in
  the later calibrated ensemble and downstream L2/L3 evaluation.
- Some existing procedural producers still group several internal combinations
  under one stable rule ID. They are now usable ensemble signals, but can be
  split into finer IDs later when evaluation shows that the sub-signals need
  different weights or explanations.
