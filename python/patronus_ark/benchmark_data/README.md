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
| `pii_l1.jsonl` | 140 | Native PII L1 exact-span capability goldens and hard negatives |
| `dlp_l1.jsonl` | 115 | Native DLP L1 exact-span capability goldens and hard negatives |

## Native L1 golden-set contract

`pii_l1.jsonl` covers all 28 currently emitted PII L1 labels with three
positive variants and two hard negatives per label. `dlp_l1.jsonl` applies the
same 3+2 structure to all 23 currently emitted DLP L1 labels. The cases are
balanced across German and English where the identifier is not intrinsically
country-specific.

Every row declares `case_type`, `target_label`, `language`, `span_unit`, and
`provenance`. Positive rows contain one exact expected entity. `start` and
`end` are zero-based Python Unicode-code-point offsets and form a half-open
`[start, end)` interval; they are deliberately not UTF-8 byte offsets. Hard
negative rows contain no entities and explain the excluded lookalike in
`negative_reason`.

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
- Generators are defined once in
  [`dlp_synth/generators.json`](../dlp_synth/generators.json): literal segments
  plus fixed-length random segments over a named alphabet. Values are drawn
  with SplitMix64 seeded by `seed` (`alphabet[next_u64() % len]` per
  character), so every generator has a fixed length and the result is
  deterministic.
- Python (`patronus_ark.dlp_synth.recipes.materialize_row`) and Rust
  (`patronus_ark::golden_recipes::materialize`, compiled with the `test-util`
  feature for tests and `13_l1_golden_eval`) materialize the same text. The
  Rust test `rust/tests/dlp_golden_recipes.rs` checks every row against
  `text_fingerprint` recorded by the Python generator.
- Generated values are synthetic and only format-shaped; they carry no valid
  provider checksum. Tests reject checksum-valid GitHub/npm CRC32 and
  Base58Check tokens in the file. They also require that neither
  `dlp_l1.jsonl` nor `generators.json` triggers a default DLP L1 finding, so
  push protection and pre-commit secret scanners stay quiet.
- Hard negatives and non-secret rows (business identifiers, content classes)
  remain literal `text`.

The generator is deterministic:

```shell
.venv/bin/python python/patronus_ark/benchmark_data/generate_l1_goldens.py
```

It imports `patronus_ark.dlp_synth`, so run it from a virtualenv with the
package installed (`maturin develop --manifest-path python/Cargo.toml`).

Most cases are hand-authored with invented values. A small subset is derived
from `dynamic_pii.jsonl` and identifies the source row in
`provenance.source_fixture_id`. This links the native regression set to the
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
