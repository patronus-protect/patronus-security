# Threat L1

`native:threat_l1` runs bounded threat rules without model files or downloads. Each
`ark.threat.*` rule belongs to one attack-class category and runs only when that category is
selected: most rules report under `unsafe_action` (remote or decoded execution, privileged
containers, disabled security controls, credential access such as credential files, credential
stores and cloud metadata endpoints, money transfers to a new bank account without approval), others under `exfiltration`, `tool_poisoning`,
`agent_config_tampering` or `harmful_content`. `exfiltration` and `tool_poisoning` are on by
default; the other three are opt-in. `tool_poisoning` rules only look at text that carries tool
or MCP metadata (JSON tool definitions with `description`, `inputSchema` or `parameters`, agent
cards, and plain-text listing lines such as `Tool send_report: …`): an instruction to read a sensitive file into a parameter, to keep something from the
user, to change what another tool does (extra copies, a new recipient), a hidden `<IMPORTANT>`
or HTML-comment directive to the model, or a parameter that should collect the conversation or
system prompt. The same instruction in plain text is left to `injection`.
`agent_config_tampering` rules look at agent instruction and configuration files (`AGENTS.md`,
`CLAUDE.md`, `.cursorrules`, skills, `.claude/settings.json`, `mcp.json`): settings that widen
permissions (`bypassPermissions`, auto-approve all, `Bash(*)`, approval policy `never`), removed
protective hooks, HTML comments that give the agent a directive, a step that sends a secret
or environment variables to an outside address and tells the agent to keep it out of its
answers (`… and never mention it`, `… lass diesen Schritt weg`), download-and-run instructions
without asking, MCP server entries that pipe a remote script into a shell or install from a raw
URL, and rules that copy themselves into other rules files; lines a diff removes do not count.
A plain-text request to change such a file so that everything is auto-approved is reported
without the file itself. `exfiltration` rules look for data sent to a foreign
destination: markdown images or links whose URL carries a data placeholder, directives that
send the conversation, system prompt, a mailbox or credentials to a URL, mail address or
collector service, a secret (a value the secret detection finds, or a file such as
`~/.ssh/id_rsa`) sent to a URL, a data source put into an outbound tool parameter, data as a
subdomain of a foreign host, and links with invisible characters or appended encoded data. A
destination the user owns ("to my address") is not reported. Configure, for
example, `categories=["unsafe_action", "exfiltration"]` and `max_level="l1"` for an offline
native scan. Rules support
English and German prose; command names, API names, paths and JSON/YAML keys keep their
original language-independent syntax. The [rule catalog](l1-rule-catalog.md) lists all gates.

A result's `class_name` is its category name (for example `unsafe_action`), or `benign`. Each
finding contains exact original UTF-8 byte and character offsets.
`layers[0].details.matched_rules` contains stable IDs and named components describing the
matched action, source or target. An embedded, separately trained logistic scorer evaluates the document's
rule-presence features, distinct rule count, maximum span length, and class count. The acceptance
threshold is `0.10`. Accepted findings carry the document score; rejected documents return
`benign` without finding spans. Raw rule matches remain in `details.matched_rules`.
`details.score`, `accepted`, `acceptance_threshold`, and `score_version` expose the decision.
Confidence is the score for an accepted result and one minus the score for a rejected result;
it is **not** a calibrated probability of malicious intent. Authorized administration may
still contain risky operations.

Disable the entire producer using `models={"native:threat_l1": false}` or an individual
rule using `rules={"ark.threat.remote_execution": false}` in execution gates. A credential
transfer may legitimately yield both `native:secret_transfer` and `native:threat_l1` evidence in
`exfiltration`, and a secret in the same text a `dlp` finding; consumers should deduplicate the
operation rather than count overlapping findings as independent evidence. Like native DLP
results, the layer's
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
