# Gretel PII exact-span matrix 0.1.6

Status: verified 2026-08-31. This is an externally published, fully synthetic
Apache-2.0 corpus; it is useful for format, validator, offset and multilingual
coverage, but is not real-world evidence. Raw documents are deliberately not
checked in.

Source: [gretelai/synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual),
revision `7b844d16738527a04264f50214cb426a4cea0897`. The six pinned Parquet
test shards contain 5,141 documents. Every upstream span was checked to have
`0 <= start < end <= len(generated_text)`; no invalid offset was found.
The manifest contains the SHA-256 of every shard and the adapter rejects a
different local source.

The target is a reporting cap of 200--250 spans per Ark class where available.
Classes below 200 are still valid but explicitly short of the target; they are
not silently padded with synthetic fixtures. Counts are after upstream-to-Ark
mapping and before any cap.

| Metric ID | upstream class(es) | verified spans | recommended cap | DE / EN spans | runtime evaluable |
|---|---|---:|---:|---:|---|
| `pii.email` | `email` | 539 | 250 | 33 / 330 | PII-L1 |
| `pii.phone` | `phone_number` | 832 | 250 | 49 / 480 | PII-L1 |
| `pii.iban` | `iban` | 175 | 175 | 19 / 69 | PII-L1, below target |
| `pii.swift_bic` | `swift_bic_code` | 209 | 209 | 22 / 112 | PII-L1 |
| `pii.credit_card.pan` | `credit_card_number` | 138 | 138 | 5 / 83 | PII-L1, below target |
| `pii.credit_card.cvv` | `credit_card_security_code` | 115 | 115 | 3 / 76 | PII-L1, below target |
| `pii.ip_address` | `ipv4`, `ipv6` | 226 | 226 | 15 / 123 | PII-L1 |
| `pii.financial_account_number` | `bban`, `bank_routing_number` | 299 | 250 | 32 / 174 | PII-L1 |
| `pii.customer_id` | `customer_id` | 201 | 201 | 23 / 94 | PII-L1 |
| `pii.employee_id` | `employee_id` | 195 | 195 | 24 / 114 | PII-L1, below target |
| `pii.date_of_birth` | `date_of_birth` | 243 | 243 | 17 / 126 | PII-L1 |
| `pii.us.social_security_number` | `ssn` | 135 | 135 | 9 / 85 | PII-L1 (`SSN`), below target |
| `pii.username` | `user_name` | 69 | 69 | 6 / 32 | PII-L1, below target |
| `entity.person_name` | `name`, `first_name`, `last_name` | 6,736 | 250 | 565 / 3,730 | GLiNER |
| `entity.organization` | `company` | 5,734 | 250 | 436 / 3,476 | GLiNER |
| `entity.date` | `date`, `date_time` | 1,559 | 250 | 120 / 961 | GLiNER |
| `entity.street_address` | `street_address` | 3,814 | 250 | 282 / 2,194 | GLiNER |
| `entity.passport_number` | `passport_number` | 137 | 137 | 12 / 76 | PII-L1 (`PASSPORT_NUMBER`), below target |
| `entity.driver_license_number` | `driver_license_number` | 123 | 123 | 9 / 68 | PII-L1 (`DRIVER_LICENSE_NUMBER`), below target |

`api_key`, `password`, `account_pin`, `local_latlng`, `time`, and the
unmapped account subtypes are intentionally excluded. Their labels do not by
themselves establish a compatible Ark finding contract, and adding them would
turn a source taxonomy into invented gold. They remain candidates for a
separate DLP source audit.

The left column is a stable **metric ID**, not always the literal native
runtime label. For example the PII scanner emits `EMAIL`, `PASSPORT_NUMBER`
and `DRIVER_LICENSE_NUMBER`; the evaluator maps them to `pii.email`,
`entity.passport_number` and `entity.driver_license_number`. Conversely,
GLiNER's configured labels (`person`, `organization`, `date`,
`street_address`) map to the `entity.*` metric IDs. This mapping is explicit
in `ARK_OUTPUT_MAP`/`ENTITY_MAP`, so native and GLiNER metrics do not silently
compare different label taxonomies.

This corpus supports exact-span precision/recall/F1 and false-positive counts
within its mapped ontology. It does **not** yield a meaningful FPR rate by
itself: a rate needs an explicitly annotated negative population and a defined
unit (document, token, candidate, or character). Capability hard-negatives and
separate real-text holdouts remain necessary for that gate.
