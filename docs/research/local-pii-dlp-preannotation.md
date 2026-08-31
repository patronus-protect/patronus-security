# Local PII/DLP pre-annotation inventory

Status: machine pre-annotation, **not human-verified gold**.

This note records what can safely be derived from the local
`Patronus-Datasets` checkout without copying private text into this repository.
Document-topic labels are used only for sampling and error analysis. They are
never converted into PII/DLP span labels.

## Corpora actually present

| Logical path below the datasets root | Format and size | Language | Origin status | Span supervision |
| --- | --- | --- | --- | --- |
| `patronus-document-classifier-dataset/data/{train,val,test}.jsonl` | 13,000 JSONL documents; `text`, `label`, `language`, `source`, `generated`, `license_review` | DE, EN, code | Local README declares 7,844 third-party real and 5,156 synthetic documents. 550 real rows have uncertain redistribution rights. | None |
| `v4.1_run/base_training/{train,val,test}.jsonl` | 207,875 multi-task JSONL rows; 15,687 have a non-null `sensitive_document` class | Mostly `unknown`; a conservative DE/EN heuristic is recorded separately | 12,941 rows have source `sensitive`, 1,364 `synthetic_hybrid`, 1,345 `unified_real_runs_1`, plus 37 merged-source rows. Provenance was not carried forward uniformly. | None |
| `v4.1_run/ap9/documents_final/{train,validation,benchmark}.jsonl` | 4,500 JSONL documents: 2,250 education and 2,250 medical | EN | Derived document renderings from anonymised structured source rows; not raw human-authored records | None |
| `ntdb/artifacts/export/sensitive_current/` | ONNX/LightGBM/centroid model export and manifests | n/a | Trained artefact referencing v4.1 and AP9 inputs | None; this directory is not a text corpus |

The seven base document classes are `legal`, `hr`, `finance`,
`internal_and_tech`, `source_code`, `marketing`, and `other`; AP9 adds
`education` and `medical`. These classes provide useful strata for review, but
they say nothing about the location or even presence of a PII/DLP value.

## Reproducible safe workflow

`scripts/build_local_l1_preannotation.py` streams the three text corpora, takes
a deterministic sample by corpus, document class, language, and provenance,
and runs only the current Ark `pii` and `dlp` L1 scanners. A private HMAC key
binds records, documents, and spans to the local source without exposing raw
identifiers or trivially reversible hashes.

The generated inventory contains offsets, Ark category/model/label, provenance
and HMAC bindings. It deliberately excludes:

- source text and surrounding context;
- Ark's matched span text and Anchor text;
- original row identifiers;
- the HMAC key.

Example (outputs should remain outside the repository until their review and
retention policy is approved):

```shell
openssl rand -out /private/secure/patronus-preannotation.key 48
.venv/bin/python scripts/build_local_l1_preannotation.py \
  --datasets-root /path/to/Patronus-Datasets \
  --inventory /private/review/l1-candidates.jsonl \
  --summary /private/review/l1-summary.json \
  --hmac-key-file /private/secure/patronus-preannotation.key \
  --max-documents-per-stratum 50 \
  --max-candidates-per-label 300 \
  --workers 6
```

`--max-documents-per-stratum 0` scans all available documents. Parallel runs
remain deterministic because each worker owns its own Ark gateway and final
records are sorted by their HMAC candidate ID.

## Representative run

The recorded run used 100 documents per corpus/class/language/provenance stratum:

- 33,187 eligible documents found; 5,938 scanned;
- 6,591 raw candidates discovered and 6,308 unique after cross-corpus content
  deduplication;
- 4,274 unique Ark L1 evidence-span candidates;
- 2,034 unique documents with Anchors but no Ark evidence span, retained only
  as hard-negative **review candidates**;
- 3,566 records in the capped review inventory (300 per Ark label or
  hard-negative stratum).

Evidence-span candidate counts before the review cap:

| Ark label | Candidates |
| --- | ---: |
| `dlp.content.source_code` | 2,729 |
| `EMAIL` | 466 |
| `PHONE` | 447 |
| `IP_ADDRESS` | 154 |
| `CREDITCARD` | 132 |
| `CREDENTIAL` | 57 |
| `dlp.content.sql` | 48 |
| `EMPLOYEE_ID`, `USERNAME` | 35 each |
| `DOB` | 29 |
| `PAYMENT_KEY` | 28 |
| `dlp.de.commercial_register_number` | 22 |
| `dlp.internal.business_metric` | 13 |
| `SECRET_TOKEN`, `SWIFT_CODE` | 11 each |
| `SOCIALID` | 10 |
| `dlp.content.database_dump` | 9 |
| `IBAN` | 7 |
| `CREDITCARD_EXPIRY` | 5 |
| `dlp.content.system_log`, `PASSPORT_NUMBER` | 4 each |
| `FINANCIAL_ACCOUNT_NUMBER`, `SSN` | 3 each |
| `dlp.de.vat_id`, `dlp.record.case_id`, `CUSTOMER_ID`, `STEUERID`, `TAX_NUMBER_DE` | 2 each |
| `dlp.record.contract_id`, `dlp.record.invoice_id` | 1 each |

By corpus and inferred/declared language, the evidence candidates were:

| Corpus | Language | Candidates |
| --- | --- | ---: |
| document classifier | code | 489 |
| document classifier | DE | 353 |
| document classifier | EN | 543 |
| v4.1 sensitive | DE | 654 |
| v4.1 sensitive | EN | 1,917 |
| v4.1 sensitive | unknown | 318 |
| AP9 documents | EN | 0 |

AP9 produced 100 Anchor-only review candidates in this sample, but no evidence
span. This is useful negative-review material; it is not evidence that the full
AP9 corpus contains no PII/DLP and it does not make those rows verified
negatives.

## What is and is not a Golden Set

Every generated record starts with:

```json
{"review_status":"unreviewed","gold_status":"not_gold_machine_candidate"}
```

An Ark hit is a proposal to review, not proof that the span is correct. An
Anchor without a hit is a proposal for a difficult negative, not proof that no
sensitive value is present. A Golden Set exists only after a human has checked
the source text, exact boundaries, normalized Ark entity class, and negative
scope under an approved private-data review process.

The current local corpora can already supply at least 300 review candidates for
source code, phone numbers, and email addresses. IP addresses are below the
target at 154 even after doubling the document sample.
They do not supply 200--300 credible candidates for most identifier and secret
classes. Those classes need targeted sampling from independently licensed
span-annotated PII/DLP datasets, controlled generated cases, or newly reviewed
internal examples. Repeating the same document-topic rows or treating all
Anchors as positives would inflate counts without adding Gold quality.

## Required review output

Review decisions should live in a separate text-free file keyed by
`candidate_id`, with at least `accepted`, `rejected`, or `needs_adjudication`,
the corrected Ark label and offsets when necessary, reviewer identity/version,
and adjudication status. Only accepted and adjudicated records may be counted
as Gold. Reports must publish both candidate counts and verified-Gold counts so
the two cannot be confused.
