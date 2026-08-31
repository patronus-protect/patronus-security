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

The generator is deterministic:

```shell
.venv/bin/python python/patronus_ark/benchmark_data/generate_l1_goldens.py
```

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
