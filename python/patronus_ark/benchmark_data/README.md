# Benchmark data

Evaluation fixtures for the local benchmark (`python -m patronus_ark.benchmark`).
These files exist to measure classifier accuracy and latency. They are **not**
training data and are not shipped as part of the compiled extension.

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
| `dynamic_pii.jsonl` | 129 | Dynamic PII entity spans |
| `dynamic_pii_threshold_sweep.jsonl` | 85 | Threshold calibration |
| `education_pii_threshold_sweep.jsonl` | 50 | Education-context threshold calibration |

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
