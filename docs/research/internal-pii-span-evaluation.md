# Internal PII span evaluation

`sensitive_current` and the v4.1 datasets are document-classification assets. Their labels (for example, medical, HR, legal, or finance) are not PII entities and must never be converted into PII span truth.

The repository therefore contains a text-free evaluation contract, implemented by `scripts/evaluate_internal_pii_spans.py`. Private data and any annotations remain in the controlled dataset environment; the repository contains only invented controlled fixtures.

## Gold contract

Each private annotation row has an opaque `id`, `corpus`, `language`, SHA-256 of the exact source document, `annotation_kind`, and `entities`. Offsets are Unicode-code-point, half-open intervals. `annotation_kind` must be one of:

- `verified_span`: human-verified PII spans; at least one span is required.
- `verified_no_pii`: human verification that the reviewed document is a deidentified hard negative; the entity list is empty.

Neither `text` nor document-class fields are permitted. A document is not gold merely because it is sampled, deidentified, or classified as sensitive.

## Workflow

Create a deterministic, text-free review manifest from a controlled corpus:

```shell
.venv/bin/python scripts/evaluate_internal_pii_spans.py sample \
  --source /controlled/path/sensitive_current.jsonl \
  --corpus sensitive_current --limit 200 \
  --output /controlled/path/pii-review-manifest.jsonl
```

Annotators add only verified sidecars in the controlled environment. For deidentified medical, HR, legal, and education documents, use `verified_no_pii` only after direct review; this measures overredaction/false positives and does not infer that every deidentified document has no PII.

Export detector output separately as `{id, entities:[{label,start,end}]}` and evaluate without copying text:

```shell
.venv/bin/python scripts/evaluate_internal_pii_spans.py evaluate \
  --gold /controlled/path/pii-gold.jsonl \
  --predictions /controlled/path/pii-predictions.jsonl \
  --output /controlled/path/pii-exact-span-report.json
```

The report emits exact label-and-offset precision, recall, and F1 overall and split by corpus, entity, corpus/entity, language, and language/entity. Entity buckets contain only that entity's spans; a false positive for one label cannot alter another label's metric. It intentionally refuses incomplete prediction coverage and rows carrying raw text or document labels.

The internal and external evaluators intentionally remain separate. The external adapter normalizes licensed raw-text corpus exports and maps upstream labels onto stable benchmark IDs; this internal adapter never writes text and binds controlled annotations to the document hash instead.

## Current evidence boundary

The checked-in `python/patronus_ark/benchmark_data/pii_l1.jsonl` is a synthetic native-L1 regression fixture, not external or internal production validation. During the August 2026 discovery pass, `sensitive_current` was found to be a model export and v4.1 to contain generated/document-classification data; no human-verified PII span sidecar was identified. Consequently, no metric from either corpus is reported yet.
