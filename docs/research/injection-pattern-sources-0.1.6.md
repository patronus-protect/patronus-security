# Injection pattern-source scan for Ark 0.1.6

## Outcome

This scan extends implementation step 1 after the existing Ark and selected
Prompt Armor rules were placed under one signal contract. It identifies new
primitives that can be composed into higher-precision relationships. It does
not add the sources' complete payload lists as production block rules.

The useful result is a composition vocabulary, not another flat keyword list:

```text
source/trust marker + authority transition + imperative action
read verb + sensitive object + transfer verb + destination
decoder/transform + decoded injection signal
fake boundary + replacement instruction + requested action
untrusted context + task mismatch + tool/action request
```

## Reproducible source inventory

| Source | Pinned revision | Licence / use | Decision |
| --- | --- | --- | --- |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | `b4104d5af05b2d861ee6cff43e8d099dbc141c82` | Apache-2.0; rules and normalisation design | Candidate source for high-precision relationships and transform coverage |
| [NVIDIA Garak](https://github.com/NVIDIA/garak) | `8ed1543b985a5722adb659584182faf6f7907d4e` | Apache-2.0; probe taxonomy and test generation | Test-corpus and transform-coverage source; payloads are not runtime rules |
| [PromptInject](https://github.com/agencyenterprise/PromptInject) | `2928a719d5de62d3766226f1b44c51d9570bc530` | MIT; modular attack construction | Regression-test generator for override goal, rogue action, escape and delimiter combinations |
| [AgentWatcher](https://github.com/wang-yanting/AgentWatcher) | `f6ce2c8e0b3ecfdc04e81cd45d8818581c7ee037` | Research implementation; no root licence found in the pinned checkout | Architecture only: source attribution and task/action mismatch; do not import code or data |
| [Promptfoo red-team strategies](https://github.com/promptfoo/promptfoo/blob/main/site/docs/red-team/strategies/index.md) | `cada6df4a1882a628062561e4bab2cf5cfe7967d` | Strategy coverage reference | Layered-transform and indirect/multi-turn regression matrix |
| [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) | CheatSheetSeries `c735a6edc4c645eb975754cd908296686a5b3049` | Coverage reference | Cross-check for indirect injection, HTML/Markdown, typoglycemia, multimodal and RAG contexts |

Source revisions describe what was reviewed. Any later imported rule must still
carry its own source ID, adaptation note, positive case and nearby benign
counterexample.

## Primitive vocabulary

The following bounded groups are useful inputs to relationship rules or the
later L1 feature contract.

| Primitive | Representative members | Existing Ark coverage |
| --- | --- | --- |
| Untrusted source | tool output, observation, retrieved document, web page, email, attachment, metadata | `tool_output_instruction`, `hidden_html_instruction`, `binary_smuggling`; source type is not yet a general candidate feature |
| Claimed authority | system, developer, administrator, policy, maintainer | `authority_escalation`, `agentic_control_abuse`, `instruction_override` |
| Hierarchy transition | new, updated, revised, replacement, higher priority, obsolete, revoked, end/reset | `instruction_override`, `instruction_boundary`; several transitions exist only inside grouped procedural logic |
| Imperative action | obey, follow, execute, invoke, send, upload, reveal, delete | Multiple existing detectors; action type is not yet normalized as a shared feature |
| Sensitive object | system prompt, hidden instructions, credentials, tokens, private keys, session data | `instruction_leak`, `cross_tool_instruction`; sensitive file paths are incomplete |
| Sensitive path | `.ssh/id_*`, `.aws/credentials`, `.env`, `.npmrc`, `.pypirc`, `.netrc`, kubeconfig, `/etc/passwd`, `/etc/shadow` | Partial coverage outside the injection family; no injection relationship currently joins path access to a sink |
| Transfer sink | reply, URL/query, email, Markdown image, upload/post tool, external endpoint | Markdown-image rule and parts of cross-tool/agentic detectors; no common sink feature |
| Transform | Base64/Base16/hex, URL-safe Base64, quoted-printable, MIME, UUencode, ROT13, ASCII85, Base32, Base2048 | Ark covers Base64/hex and selected binary/Unicode cases; the wider set belongs first in regression tests and bounded decoding |
| Text mutation | zero-width, homoglyph, bidi/reordering, leetspeak, optional whitespace, vowel folding, typoglycemia | Ark covers zero-width and confusables; typoglycemia and several normalisations remain gaps |
| Boundary/escape | repeated newlines, delimiter runs, model special tokens, fake end-of-system markers | `instruction_boundary` plus the Prompt Armor end-system rule |
| Social framing | roleplay, hypothetical, educational, authorized test, urgency, prior agreement | `jailbreak_framing`, `multi_turn_escalation`; too weak to create findings alone |

## Proposed compositions

### P0: implemented high-precision runtime relationships

1. **Authority-issued replacement**
   `claimed_authority + hierarchy_transition + instruction_object + imperative`.
   This strengthens the existing authority/override detectors without treating
   bare `system`, `new instructions`, or `execute` as findings.
2. **Sensitive read followed by a sink**
   `read/source verb + sensitive path/object + transfer/output verb +
   destination`. This covers indirect agent attacks such as reading `.env` and
   posting its contents to a URL, while leaving ordinary documentation about a
   path safe.
3. **Decode then execute/follow**
   `decoder declaration + named encoding + execute/follow action`, matching
   Pipelock's explicit relationship. Separately, supported labeled payloads are
   decoded and must contain an existing injection signal; encoded-looking text
   alone remains insufficient for that second path.
4. **Boundary then replacement action**
   `fake boundary/special token + replacement instruction + action`. A special
   token shown in documentation is not independently sufficient.

These are implemented as Ark-specific relationships with exact spans, pinned
source metadata, adaptation notes, positive source variations, and nearby hard
negatives. Pipelock is the primary upstream for the first three. PromptInject
is primary for the delimiter relationship, with Pipelock as its secondary
boundary reference. Garak supplies only its active encoding-name variations
and labeled ROT13 decoding behavior.

### P1: ensemble features, not standalone findings

- explicit untrusted-source attribution and the distance from that marker to
  an imperative;
- mismatch between the user's requested task and an action requested inside a
  tool/document response;
- instruction density inside data-oriented content;
- source-to-sink completeness and whether a real destination is present;
- number and order of encoding layers;
- urgency, secrecy, roleplay, claimed authorization and prior agreement;
- typoglycemia/fuzzy matches to high-risk verbs after normalisation.

AgentWatcher motivates attribution to the influential untrusted context.
InjecAgent's direct-harm and data-stealing cases motivate task/action mismatch.
Neither should be reduced to a broad regex.

### Regression-only material

- DAN, developer-mode and other named jailbreak templates;
- PromptInject rogue strings and complete attack sentences;
- Garak encoded payloads, bad-character variants, Markdown exfiltration and
  latent-injection probes;
- Promptfoo layered transforms, indirect web injection and adaptive multi-turn
  strategies.

These are valuable for mutation and held-out evaluation. Importing their full
text as runtime signatures would overfit known attacks and create false
positives in security documentation.

## Coverage and implementation order

The original baseline was 31 registered rules: 18 existing Ark producers plus
13 selected Prompt Armor relationships. A German multilingual-override mapping
and the four implemented P0 relationships raise the catalog/native rule total
to 36. The first structural relationship producer raises the complete
registered Injection-L1 producer/rule inventory to 37.

Every new semantic relationship has an Ark-authored German lexical adaptation,
derived from and attributed to the same pinned source relationship. These
adaptations are identified as translations in provenance and are covered by
German positives plus nearby German hard negatives. The Markdown-image
relationship is syntax-based and therefore language-neutral.

The implemented P0 relationship catalog follows this order:

1. sensitive read plus transfer sink;
2. authority-issued replacement;
3. decode-then-evaluate for additional bounded encodings;
4. boundary plus replacement action.

The primary positive for every relationship is verified to remain safe under
the prior 31 producers and positive under the new source-derived catalog. P1
primitives are not promoted to rules; they become inputs to the common L1
candidate/feature contract in implementation step 2.
