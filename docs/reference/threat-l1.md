# Threat L1

`threat` now runs `native:threat_l1` without model files or downloads. Configure
`categories=["threat"]` and `max_level="l1"` for an offline native scan. Rules support
English and German prose; command names, API names, paths and JSON/YAML keys keep their
original language-independent syntax. The [rule catalog](l1-rule-catalog.md) lists all gates.

Results use the existing classes `tool_abuse`, `secrets_access`, `exfiltration_attempt`,
`harmful_behavior`, or `benign`. Each finding contains exact original UTF-8 byte and
character offsets. `layers[0].details.matched_rules` contains stable IDs and named
components describing the matched action, source or target. Multiple classes can occur
in evidence; the primary label prioritizes exfiltration, harmful behavior, secrets access,
then tool abuse. An embedded, separately trained logistic scorer evaluates the document's
rule-presence features, distinct rule count, maximum span length, and class count. The acceptance
threshold is `0.10`. Accepted findings carry the document score; rejected documents return
`benign` without finding spans. Raw rule matches remain in `details.matched_rules`.
`details.score`, `accepted`, `acceptance_threshold`, and `score_version` expose the decision.
Confidence is the score for an accepted result and one minus the score for a rejected result;
it is **not** a calibrated probability of malicious intent. Authorized administration may
still contain risky operations.

Disable the entire producer using `models={"native:threat_l1": false}` or an individual
rule using `rules={"ark.threat.remote_execution": false}` in execution gates. Existing
DLP results and gates remain unchanged. A credential transfer may legitimately yield
DLP and Threat evidence; consumers should deduplicate the operation rather than count
category overlap as independent evidence. Like existing native DLP results, the layer's
`matched` field alone is not a danger verdict; check the class and evidence.

The matcher uses overlapping 8 KiB windows and a 256-finding cap. When output is capped,
`match_limit_reached` is true: the evidence list is incomplete, not a full inventory.
Expressions bound their action/target distance. Local grammatical negation is recognized
in English and German; arbitrary quotations and surrounding claims of authorization are
not a universal allowlist. Neither this context handling nor a non-match proves safety.

Metadata SSRF uses URL host parsing (including numeric IPv4 notation) rather than substring
matches in URL paths or usernames. Selected direct code relationships detect untrusted
request input reaching deserialization, URL requests or shell execution, and model output
reaching execution. Kubernetes rules cover immediate `securityContext.privileged: true`
JSON/YAML forms. These are deliberately narrow static relationships, not complete AST,
interprocedural taint analysis, or full Kubernetes validation.

The SkillSpector comparison guided independently authored rules. Source revision and group
references accompany each rule; no upstream confidence scores were imported. External CVE/registry enrichment and stateful MCP rug-pull checks
require data beyond a single text input and are not provided by this detector.
