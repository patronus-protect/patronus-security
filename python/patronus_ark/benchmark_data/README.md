# Benchmark data

Synthetic, historical regression fixtures for the local benchmark
(`python -m patronus_ark.benchmark`). These files exist to measure classifier behavior and
latency across Ark revisions. They are **not** model-release validation splits, their F1 values
must not be reported as release-validation metrics, and they are not shipped as part of the
compiled extension.

## Contents

| File | Records | Purpose |
| --- | --- | --- |
| `benign.jsonl` | 100 | Negative controls — must not trigger any detector |
| `injection.jsonl` | 200 | Prompt-injection and jailbreak phrasings |
| `routing.jsonl` | 500 | Request routing across five classes (100 each) |
| `threat.jsonl` | 200 | Threat classification across seven classes |
| `tool_descriptions.jsonl` | 240 | MCP tool-description risk scoring |
| `tool_executions.jsonl` | 1800 | Tool-execution gating |
| `sensitive_document.jsonl` | 699 | Document-class sensitivity |
| `dynamic_pii.jsonl` | 133 | Dynamic PII entity spans |
| `dynamic_pii_threshold_sweep.jsonl` | 85 | Threshold calibration |
| `education_pii_threshold_sweep.jsonl` | 50 | Education-context threshold calibration |
| `pii_l1.jsonl` | 789 | Native PII L1 exact-span goldens, hard negatives and known gaps (schema v2) |
| `dlp_l1.jsonl` | 692 | Native DLP L1 exact-span goldens, hard negatives and known gaps (schema v2) |

## Native L1 golden-set contract

`pii_l1.jsonl` covers all 28 currently emitted PII L1 labels with PII golden
schema v2, `dlp_l1.jsonl` all 23 currently emitted DLP L1 labels with DLP
golden schema v2 (both below). Each label has German and English cases; a
country-specific identifier appears in German and English text around the same
national format.

Every row declares `case_type`, `target_label`, `language`, `span_unit`, and
`provenance`. Positive rows contain one exact expected entity of the target
label (a split DLP secret has one entity per fragment). PII positives also
annotate every other real entity in the text with its own label, in text
order, for example the card number next to a CVV; the evaluation scores the
target label only. Every PII gold value passes a validator of its label in
`PII_PATTERNS`; known gaps are exempt only from format validators, never from
the checksum labels `CREDITCARD`, `IBAN` and `STEUERID`
(`rust/tests/pii_gold_hygiene.rs`). `start` and
`end` are zero-based Python Unicode-code-point offsets and form a half-open
`[start, end)` interval; they are deliberately not UTF-8 byte offsets. Hard
negative rows explain the excluded lookalike in `negative_reason`. They contain
no entities, except that a PII hard negative may annotate other real entities in
its text, never one of its target label (T07: the valid IBAN around a
card-shaped BBAN). Evaluations score primary findings only; a finding the
scanner lists under `details.secondary_evidence` (T07) is not scored.

Reserved placeholder values (RFC 2606/6761 domains such as `example.com` or
`.invalid`, NANP `555-01xx` and `+1 000-000-0000`) are PII and gold positives in
`pii_l1.jsonl` and the `demo_pii_dlp*` sets. Hard negatives exclude values by
form only (obfuscated, masked, single-label host, invalid prefix), never because
a name or number is reserved. The full convention is in
[`research/l1-pii/README.md`](../../../research/l1-pii/README.md).

### PII golden schema v2

Every `pii_l1.jsonl` row starts with these fields:

```json
{"id": "pii_l1-iban-pos-08", "suite": "pii_l1", "schema_version": 2,
 "language": "de", "case_type": "positive", "target_label": "IBAN",
 "rule_id": "pii_iban_de", "carrier": "json", "tags": ["structured"],
 "known_gap": false, ...}
```

- `rule_id` is the `pii_*` rule of `PII_PATTERNS` the row exercises and belongs
  to `target_label`. For a positive, `13_l1_golden_eval` requires that this rule
  reported every gold span (`matched_rules` of the scan result); another rule of
  the same label may report it as well. For a hard negative it is the rule the
  lookalike aims at; no PII rule may report a primary finding in the text other
  than its annotated entities.
- `carrier` is the document that holds the value: `line` (a single
  `label: value` probe), `prose` (sentence, chat, mail), `json`, `yaml`, `xml`,
  `csv`, `kv` (`key=value` or `Key: value` lines of a form) or `table` (Markdown
  table).
- `tags` are the difficulty tags, in this order: `no_context` (no field name or
  label names the value), `structured` (carrier `json`, `yaml`, `xml`, `csv`,
  `kv` or `table`; derived by the generator), `obfuscated` (characters inserted
  or substituted while the value stays readable: zero-width spaces, full-width
  digits or `＠`, defanged `[.]`; on hard negatives also masked values) and `ocr`
  (scan layout noise: no space after the colon, trailing form fields, table
  pipes, line breaks inside a value, misread letters in the field name). Spans of
  obfuscated and OCR values cover the text as written. Spelled-out e-mail forms
  (`[at]`, `name @ domain . de`) and numbers spaced character by character stay
  hard negatives in `strict` and `balanced` under the gold convention below; rows
  with `pii_mode: recall` may make them positives, because only `recall` undoes
  them (K06).
- `known_gap: true` marks a positive the detector misses today. The eval runs
  it and prints it in the coverage report, but does not gate on it. It fails
  when a known gap starts passing, so the task that closes it flips the flag.
  Hard negatives are never known gaps.
- `pii_mode` (optional, right after `known_gap`) names the opt-in PII mode the
  row runs in, `balanced` or `recall`; rows without it run in the default
  `strict` mode. The K03 context engine scores values there: such a hard
  negative is a value `strict` reports but a nearer counter-context term (order,
  invoice, tracking number ...) lowers below the threshold, such a positive a
  value whose support term outranks a counter term nearby. There are at least
  5 gated `balanced` positives and hard negatives per language. Known gaps
  always run in `strict`.
- Each label has at least 5 gated positives and 5 hard negatives per language
  (DE and EN). Each rule has a gated positive in both languages and a hard
  negative. `python/tests/test_pii_golden_schema.py` and
  `rust/tests/pii_golden_schema.rs` check this statically; `13_l1_golden_eval`
  checks it on the scan results and prints the coverage per `rule_id` and per
  tag and language.

```shell
cd rust && cargo run --example 13_l1_golden_eval -- pii
```

### DLP golden schema v2

Every `dlp_l1.jsonl` row starts with these fields:

```json
{"id": "dlp_l1-cloud-key-pos-06", "suite": "dlp_l1", "schema_version": 2,
 "language": "de", "case_type": "positive", "target_label": "CLOUD_KEY",
 "rule_id": "dlp_aws_access_key", "carrier": "ini", "tags": ["carrier"],
 "known_gap": false, ...}
```

- `rule_id` is the `dlp_*` rule of `DLP_PATTERNS` the row exercises. For a
  positive it belongs to `target_label`, and `13_l1_golden_eval` requires that
  this rule reported every gold span (`matched_rules` of the scan result). For a
  hard negative it is the rule the lookalike aims at; no DLP rule may report
  anything in the text.
- `carrier` is the document that holds the value: `line` (a single
  `label: value` probe), `env`, `yaml`, `json`, `toml`, `ini`, `xml`, `code`,
  `log`, `cli`, `http`, `csv`, `sql`, `markdown` or `prose` (chat, ticket, mail).
- `tags` are the difficulty tags, in this order: `carrier` (any carrier except
  `line` and `prose`), `no_context` (no key name or label names the value),
  `encoded` (the value appears base64-, hex-, URL- or JSON-encoded; the entity
  lists the `encoding` and its span covers the encoded text), `split` (the value
  is cut into fragments; one entity per fragment with its `part` number) and
  `prose` (carrier `prose`). Only `no_context` is set by hand; the generator
  derives the others.
- `known_gap: true` marks a positive the detector misses today. The eval runs
  it and prints it in the coverage report, but does not gate on it. It fails
  when a known gap starts passing, so the task that closes it flips the flag.
  Hard negatives are never known gaps: a lookalike the detector reports today
  cannot be a checked-in literal, because the file must stay free of findings.
- Each label has at least 5 gated positives and 5 hard negatives per language
  (DE and EN). Each rule has a gated positive in both languages and a hard
  negative. `python/tests/test_dlp_golden_schema.py` and
  `rust/tests/dlp_golden_schema.rs` check this statically; `13_l1_golden_eval`
  checks it on the scan results and prints the coverage per `rule_id` and per tag.

```shell
cd rust && cargo run --example 13_l1_golden_eval -- dlp
```

### Secret-safe DLP rows (generator recipes)

`dlp_l1.jsonl` never stores secret values in clear. Every positive row of the
default-on secret groups (`API_KEY`, `CLOUD_KEY`, `CREDENTIAL`, `CRYPTO_KEY`,
`PASSWORD_HASH`, `PAYMENT_KEY`, `PRIVATE_KEY`, `SECRET_TOKEN`) replaces `text`
with a carrier `template` and a list of recipes:

```json
{"template": "GITHUB_TOKEN=<<secret:0>>",
 "secrets": [{"gen": "github_pat_classic", "seed": 801}],
 "text_fingerprint": "<first 24 hex digits of SHA-256 of the materialized text>",
 "entities": [{"label": "SECRET_TOKEN", "start": 13, "end": 53, "secret": 0}]}
```

- `<<secret:N>>` is replaced by the value of `secrets[N]`; each index is used
  exactly once. Entity `start`/`end` are code-point offsets in the
  **materialized** text, and `secret` names the recipe the span covers.
- `<<secret:N|enc>>` inserts the value encoded with `base64`, `hex`, `url`
  (RFC 3986 percent encoding) or `json` (string escaping); the encoding must
  change the value. `<<secret:N[a:b]>>` inserts code points `a` to `b` of the
  value; a split secret uses only slices, at least two, and they cover the value
  in template order.
- In the checked-in file the placeholder colon is written as the JSON escape
  `\u003a` (`<<secret\u003a0>>`). Otherwise a placeholder followed by more text
  in the raw line reads as `secret: <value>` to generic credential scanners.
- Generators are defined once in
  [`dlp_synth/generators.json`](../dlp_synth/generators.json): literal segments,
  fixed-length random segments over a named alphabet, checksum segments
  (`crc32_base62` for GitHub/npm tokens, `iso7064_mod11_10` for the USt-IdNr.)
  and encoded segments that assemble bytes (hex constants, ASCII, random bytes)
  and emit them as hex, base64 (PEM-wrapped), base64url, bcrypt radix-64 or
  Base58Check. Values are drawn with SplitMix64 seeded by `seed`
  (`alphabet[next_u64() % len]` per character, `next_u64() % 256` per byte),
  so every generator has a fixed length and the result is deterministic.
  `recipes.py` documents the segment format.
- Python (`patronus_ark.dlp_synth.recipes.materialize_row`,
  `materialize_fragments`) and Rust (`patronus_ark::golden_recipes::materialize`,
  `materialize_fragments`, compiled with the `test-util`
  feature for tests and `13_l1_golden_eval`) materialize the same text. The
  Rust test `rust/tests/dlp_golden_recipes.rs` checks every row against
  `text_fingerprint` recorded by the Python generator.
- The 24 E02 rows keep their format-shaped generators; the v2 rows use the
  checksum-valid E03 generators, which exist only in memory at test time. Tests
  reject checksum-valid GitHub/npm CRC32 and Base58Check tokens in the file.
  They also require that neither
  `dlp_l1.jsonl` nor `generators.json` triggers a default DLP L1 finding, so
  push protection and pre-commit secret scanners stay quiet.
- A hard negative whose lookalike is a documented example or test value in a
  provider format (T06) is a recipe too, with a `fill` word:
  `{"gen": "github_ghp_token", "seed": 0, "fill": "EXAMPLEKEY"}` keeps the
  generator's literals and length, repeats the word (`EXAMPLEKEY`, `TESTKEY`,
  `deadbeef`, `1234567890` …) in every alphabet segment that holds its
  characters, draws the other segments and zeroes check values. Random-only
  encoded segments repeat the word over their encoded characters, other encoded
  segments encode its bytes; Base58Check segments reject a fill. The row has no
  entities, and `text_fingerprint` pins it like a positive.
- All other hard negatives and non-secret rows (business identifiers, content
  classes) remain literal `text`.

### Synthetic secret generator (`dlp_synth`)

[`dlp_synth/rules.json`](../dlp_synth/rules.json) maps every `dlp_*` rule in
`DLP_PATTERNS` to the generators of the values it should find, plus two probe
carriers (EN/DE, config/prose). Content rules (source code, SQL, logs, business
metrics) have no secret value and are listed under `content_rules`; their
carriers come with E04. Generators listed as `shape_only` are the E02 shapes
without a valid checksum or structure. They stay because the goldens use them.
Generators listed as `weak` (T06) are low-variety but real values (a repeated
password, a token with a `1234567890abcdef` run, a GitHub token shape with one
repeated chunk) that the rule must keep reporting outside example context, and
placeholder-like real passwords (T07: SCREAMING_SNAKE words without a
placeholder word such as `YOUR`/`HERE`/`HIER`/`EINTRAGEN`, a leading `$` with
digits that is no shell variable). The probe tests run them, carriers do not use them, and they need no format check.
Every other generator yields format-, structure- and checksum-valid fakes:

- GitHub `gh[pousr]_` and npm tokens with the base62 CRC-32 suffix, Base58Check
  WIF keys (mainnet, compressed and uncompressed), secp256k1-range Ethereum keys;
- PEM private keys with parseable DER (PKCS#8 Ed25519, PKCS#1 RSA, SEC1 P-256,
  DSA) and an `openssh-key-v1` Ed25519 body;
- JWTs with JSON header and claims, RFC 7617 Basic credentials, bcrypt and
  Argon2id PHC hashes in canonical radix-64, Discord bot tokens with a
  base64url snowflake, and a USt-IdNr. with a valid ISO 7064 check digit;
- the provider prefix, length and alphabet tables cited in each generator's
  `source` (gitleaks rule ID, RFC or vendor format; `ark-rule:<id>` marks
  shapes that only follow today's ARK regex and still need a format source).

Keys and signatures are random bytes, never derived from or checked against a
live account. `dlp_synth.checks` re-verifies every value offline with
code that is independent of the encoders (`python/tests/test_dlp_synth.py`).
The rule probes run in both test suites. Each rule runs alone and must report
exactly the generated span (`python/tests/test_dlp_synth.py`,
`rust/tests/dlp_synth_rules.rs`). Rust and Python output is pinned per generator
in `rust/tests/fixtures/dlp_synth_vectors.json`.

```python
from patronus_ark.dlp_synth import recipes, rules

value = recipes.generate("github_ghp_token", seed=17)          # in memory only
for sample in rules.samples("dlp_btc_wif", range(4)):
    sample.text, sample.span
```

### Carrier templates (`dlp_synth.carriers`)

`dlp_synth.carriers` embeds generated values in realistic documents for the DLP
scoreboard (E10) and the frozen holdout (E09). The families live in
[`dlp_synth/carrier_templates.py`](../dlp_synth/carrier_templates.py) and cover
`.env`, YAML (incl. a Kubernetes Secret), JSON, TOML, HCL (Terraform, Nomad), XML
(app.config, Maven), properties/INI, shell/CLI, Dockerfile, CI YAML (GitHub
Actions, GitLab), Jupyter, text and JSONL logs, HTTP, code in Python, JavaScript,
TypeScript, Go, Java, C#, Rust and Ruby, and DE/EN chat, tickets and mail.

- Every family belongs to exactly one split. Dev and holdout share no family and
  no template, and each split has every format (each code language counted
  under `code`) in both DE and EN.
- Each value rule of `rules.json` has a profile with its entity, group and key
  name (`OPENAI_API_KEY`, `openaiApiKey`, `Openai-Api-Key` …), a DE/EN label and
  an optional wrapper (`Bearer …`, `postgres://app:…@db…`, `JSESSIONID=…`).
- Each baseline entity of `rules.json` (GOLD-D2, GOLD-D3: an entity map entity with
  scope `baseline_only`, such as `comm.telegram.bot_token`) has a profile under its
  entity id. Its generators follow the gitleaks rule of the entity (`source` in
  `generators.json`), so ARK and every baseline are measured on it before ARK has
  a rule; its rows carry `rule_id` null.
- Positives carry one entity whose `start`/`end` are code points in `text` and
  cover only the value, without key, quotes or wrapper. `encoding` lists the
  escapes applied to the value (`json`, `xml`, `indent` for YAML block scalars;
  inner first), so a JSON-escaped PEM in a notebook decodes back to the
  generator output.
- Hard negatives are the same document without entities: `placeholder`,
  `env_ref` (`${KEY}`, `os.environ[…]`, `${{ secrets.KEY }}`, Helm, Maven,
  configparser …), `doc_example` and `test_key`. The last two keep the generator's
  prefix and length but use `EXAMPLEKEY`/`TESTKEY` fill words and an invalid check
  value, so CRC-32, Base58Check, ISO 7064, DER and JWT checks fail. Encoded values
  keep their encoded shape and break only the checksum or decoded structure: WIF
  keys still start with `5`/`K`/`L` and carry a wrong Base58Check value, JWT
  segments still start with `eyJ` and decode to broken JSON, PEM bodies keep label
  and line width with a broken DER/OpenSSH layout. They still match the rule
  pattern, so only structural validation tells them from a real value.
  Baseline entities add `lookalike`: the entity's shape with a wrong prefix,
  length or character set (a Twilio account SID `AC…` for an API key `SK…`, a
  Mailgun `pubkey-`, a short Telegram secret, an Octopus `API-` key in lower case)
  under the neutral key `correlation_id`. Under the entity's own key such a value
  would still be a credential of unknown format.
- Code and notebook families carry the document label `content.source_code`,
  logs `content.system_log`.

```shell
cd python
../.venv/bin/python -m patronus_ark.dlp_synth.carriers --split dev --seed 1 --out /tmp/dlp-carriers-dev.jsonl
```

Rows contain checksum-valid synthetic tokens. Write them outside the repository
and never commit them. The holdout split is built only by E09 with a secret seed.

The golden generator is deterministic:

```shell
.venv/bin/python python/patronus_ark/benchmark_data/generate_l1_goldens.py
```

It imports `patronus_ark.dlp_synth`, so run it from a virtualenv with the
package installed (`maturin develop --manifest-path python/Cargo.toml`).

Most cases are hand-authored with invented values. A small subset is derived
from `dynamic_pii.jsonl` and identifies the source row in
`provenance.source_fixture_id`. `dynamic_pii.jsonl` keeps its seven
Luhn-invalid `credit_card` values for the L3 NER but marks them with
`"checksum_valid": false`; `12_l1_pii_fixture_eval` skips marked spans. This links the native regression set to the
existing NER fixture without pretending that synthetic data is an external
release-validation corpus. No text from `sensitive_current`, `v4.1`, or other
sensitive-document stores is copied into these redistributable fixtures.

The controlled local-corpus candidate workflow is documented separately in
[`docs/research/local-pii-dlp-preannotation.md`](../../../docs/research/local-pii-dlp-preannotation.md).
Its Ark findings and Anchor-selected negatives are explicitly pre-annotations,
not additions to these Golden Sets until human review and adjudication are
complete.

## Provenance

Most records are synthetic: written or generated for this project, using
invented people, companies, addresses, and reference numbers. Any resemblance
to a real person or organisation in those records is coincidental.

Some records — chiefly the instruction-style prompts in `routing.jsonl`
(`benign_conv`, `code_development_request`, `data_analytics_request`) — derive
from publicly available instruction and task datasets. These were incorporated
under permissive terms (Apache-2.0 or more permissive). **The specific upstream
sources were not recorded at the time of import and cannot now be reconstructed
with confidence.** We state this openly rather than assert a provenance we
cannot evidence.

The practical consequence is that the attribution notices such licenses
normally expect cannot be reproduced here, because the upstream is unidentified.
If you recognise material of yours in these files, contact
`team@patronus.studio` and we will attribute or remove it promptly.

## Reporting

If you find personal data, copyrighted third-party text, or anything else that
should not be redistributed here, report it to `team@patronus.studio`. We treat
these as defects and fix them, rather than waiting for a formal complaint.

## License

These fixtures are distributed under the same terms as the project — see
[LICENSE](../../../LICENSE) — except for any third-party material described
above, which remains under its original terms.
