# PII external corpus baseline 0.1.6

Status: first reproducible external-corpus ingest and native PII baseline, 2026-08-31.

## Pinned gold inventory

No external raw text is committed. The checked-in manifest pins source revision,
license, file path, and SHA-256; `--verify-source` rejects a different input.

| Corpus | Role | Documents | mapped gold spans | Language |
|---|---|---:|---:|---|
| AI4Privacy OpenPII Nano train | synthetic multilingual boundary/format gold | 900 | 4,222 | 30 languages; 66 DE, 113 EN |
| TAB ECHR test | real, manually annotated semantic/reidentification gold | 127 | 5,516 `DIRECT`/`QUASI` spans | EN |

OpenPII revision: `421ebabbfdd9cc55c1a936fdc8f51cb384a6d0a1`,
`data/train.jsonl` SHA-256
`223b10df760833ff050fbd246c79e30060d536413b013a74708da6f6b62feba9`.

TAB revision: `558e09e26d6b36f5f78440074e6a233946d98bd9`,
`echr_test.json` SHA-256
`cd0f0f15f84a8739654c7cf30c6be8ce27b051ef73974d39d792a0cb8c846379`.

TAB spans are the deterministic union of identical annotator mentions. The
privacy-oriented view includes `DIRECT` and `QUASI`; `NO_MASK` is excluded.
No GLiNER score is reported yet because that requires the pinned model bundle
and a separately recorded threshold/bundle run.

## Native PII on OpenPII Nano

The native 0.1.6 PII scanner was evaluated on the corpus-declared native scope
only: `pii.email`, `pii.phone`, and `pii.credit_card.pan`. Semantic NER labels
such as person, location, street, and generic date are reported separately and
must not lower the L1 score. Ark labels outside the upstream ontology are not
counted as false positives.

| Slice | Gold | Predicted | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| all 30 languages | 1,046 | 843 | 638 | 205 | 408 | 0.7568 | 0.6099 | 0.6755 |
| German | 65 | 54 | 43 | 11 | 22 | 0.7963 | 0.6615 | 0.7227 |
| English | 136 | 128 | 95 | 33 | 41 | 0.7422 | 0.6985 | 0.7197 |

Per native entity across all languages:

| Entity | Gold | Predicted | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| E-mail | 484 | 470 | 451 | 19 | 33 | 0.9596 | 0.9318 | 0.9455 |
| Phone | 366 | 345 | 163 | 182 | 203 | 0.4725 | 0.4454 | 0.4585 |
| Payment-card PAN | 196 | 28 | 24 | 4 | 172 | 0.8571 | 0.1224 | 0.2143 |

These results are an error-discovery baseline, not a release-wide PII metric.
OpenPII is synthetic, multilingual telephone parsing is not yet region-aware,
and many generated PAN values fail the deliberate Luhn validator. Rules and
validators were not relaxed to improve this first run.

## Reproduction boundary

The normalization commands are documented in
`python/patronus_ark/benchmark_data/external_pii/README.md`. Predictions are
attached by stable document ID and evaluated with
`python/patronus_ark/external_pii_eval.py`. Reports require complete prediction
coverage and are split by corpus, language, scope, and entity.

Internal `sensitive_current`/v4.1 data still has no human-verified PII span
sidecar. It therefore contributes no metric to this report.

## Subsequent Golden expansion

After this first baseline, the pinned Apache-2.0 Gretel Finance test shards
added 5,141 synthetic documents and 19 mapped Ark metric classes. A separate
local pre-annotation run also produced a text-free review pool, but no local
candidate is counted as Gold before human adjudication. The current class
matrix, 250-span selection contract and fair L1/GLiNER/future-fusion scopes are
maintained in `docs/research/pii-dlp-benchmark-contract-0.1.6.md`.
