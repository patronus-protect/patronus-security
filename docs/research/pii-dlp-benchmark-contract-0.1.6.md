# PII/DLP benchmark and Golden contract 0.1.6

This is the one reporting contract for native PII-L1, native DLP-L1, GLiNER,
and a later L1+GLiNER fusion. It deliberately does not implement fusion.

The first measured baseline using this contract is
[`pii-dlp-measured-baseline-0.1.6.md`](pii-dlp-measured-baseline-0.1.6.md).

## What counts as Gold

| Evidence tier | May report recall / exact spans? | Current source |
|---|---|---|
| External real, human annotated | yes | TAB: EN person, organization, location, date |
| External synthetic, offset checked | yes, reported separately from real | OpenPII and Gretel |
| External derived content label | only the stated document/content task | Gitleaks Go source code; SchemaPile SQL statements |
| Local Ark preannotation | no | `sensitive_current`/v4.1/base/AP9 inventory |
| Local human-reviewed sidecar | yes, once adjudicated | none yet |

`pii_l1.jsonl` and `dlp_l1.jsonl` remain synthetic capability regressions:
they prove the current rules and hard negatives, not generalization quality.

## Prioritized span matrix

Counts are verified upstream spans before capping. `250` means use at most 250
in a per-class aggregate; a lower available count is reported as such and is
never padded. DE/EN figures are only available for Gretel; TAB is EN.

| Metric ID | Runtime label / producer | external Gold | available | goal | DE / EN | local candidates | status |
|---|---|---|---:|---:|---:|---|
| `pii.email` | `EMAIL` / PII-L1 | Gretel; OpenPII synthetic | 539 G; 484 O | 250 | 33 / 330 G | 466 | 250-cap per source; L1 |
| `pii.phone` | `PHONE` / PII-L1 | Gretel; OpenPII synthetic | 832 G; 366 O | 250 | 49 / 480 G | 447 | 250-cap per source; L1 |
| `pii.ip_address` | `IP_ADDRESS` / PII-L1 | Gretel synthetic | 226 | 226 | 15 / 123 | 154 | all; L1 |
| `pii.iban` | `IBAN` / PII-L1 | Gretel synthetic | 175 | 175 | 19 / 69 | 7 | below target; L1 |
| `pii.swift_bic` | `SWIFT_CODE` / PII-L1 | Gretel synthetic | 209 | 209 | 22 / 112 | 11 | all; L1 |
| `pii.credit_card.pan` | `CREDITCARD` / PII-L1 | Gretel; OpenPII synthetic | 138 G; 196 O | 138 holdout; 250 dev | 5 / 83 G | 132 | below target on final; L1 |
| `pii.credit_card.cvv` | `CREDITCARD_CVV` / PII-L1 | Gretel synthetic | 115 | 115 | 3 / 76 | — | below target; L1 |
| `pii.financial_account_number` | `FINANCIAL_ACCOUNT_NUMBER` / PII-L1 | Gretel synthetic | 299 | 250 | 32 / 174 | 3 | 250-cap; L1 |
| `pii.customer_id` | `CUSTOMER_ID` / PII-L1 | Gretel synthetic | 201 | 201 | 23 / 94 | 2 | all; L1 |
| `pii.employee_id` | `EMPLOYEE_ID` / PII-L1 | Gretel synthetic | 195 | 195 | 24 / 114 | 35 | below target; L1 |
| `pii.date_of_birth` | `DOB` / PII-L1 | Gretel synthetic | 243 | 243 | 17 / 126 | 29 | all; L1 |
| `pii.us.social_security_number` | `SSN` / PII-L1 | Gretel synthetic | 135 | 135 | 9 / 85 | 3 | below target; L1 |
| `pii.username` | `USERNAME` / PII-L1 | Gretel synthetic | 69 | 69 | 6 / 32 | 35 | below target; L1 |
| `entity.person_name` | `person` / GLiNER | Gretel; OpenPII synthetic; TAB real | 6,736 G; 1,428 O; 1,136 T | 250 | 565 / 3,730 G | — | 250-cap per source; GLiNER |
| `entity.organization` | `organization` / GLiNER | Gretel synthetic; TAB real | 5,734; 1,099 | 250 | 436 / 3,476 | — | 250-cap per source; GLiNER |
| `entity.date` | `date` / GLiNER | Gretel; OpenPII synthetic; TAB real | 1,559 G; 751 O; 2,747 T | 250 | 120 / 961 G | — | 250-cap per source; GLiNER |
| `entity.street_address` | `street_address` / GLiNER when enabled | Gretel; OpenPII synthetic | 3,814 G; 282 O | 250 | 282 / 2,194 G | — | 250-cap per source; GLiNER |
| `entity.location` | `city`/`country` / GLiNER | OpenPII synthetic; TAB real | 414 O; 534 T | 250 | — / 534 T; O not span-stratified | — | 250-cap per source; GLiNER |
| `entity.passport_number` | `PASSPORT_NUMBER` / PII-L1 | Gretel; OpenPII synthetic | 137 G; 124 O | 137 holdout; 250 dev | 12 / 76 G | 4 | below target on final; L1 |
| `entity.driver_license_number` | `DRIVER_LICENSE_NUMBER` / PII-L1 | Gretel; OpenPII synthetic | 123 G; 177 O | 123 holdout; 250 dev | 9 / 68 G | — | below target on final; L1 |
| `dlp.content.source_code` | `dlp.content.source_code` / DLP-L1 | Gitleaks derived document labels | 214 docs | 214 docs | n/a / code | 2,729 | document task only |
| `dlp.content.sql` | `dlp.content.sql` / DLP-L1 | SchemaPile derived source-statement spans | 250 | 250 | n/a / SQL | 48 | boundary candidate; no score yet |

All local counts are unreviewed machine candidates from the documented sample,
not Gold. A dash means no count was published, not a verified zero. Secrets,
logs, dumps, business metrics and record IDs have no admitted external
200--300-span Gold at present; their local candidates remain review queues.

The metric IDs above are evaluator namespaces. Native PII emits uppercase
runtime labels, which `ARK_OUTPUT_MAP` normalizes to those IDs. GLiNER emits
configured labels such as `person` and `organization`, which `ENTITY_MAP`
normalizes. This prevents a false claim that `pii.email` is an emitted native
label, while still allowing all three systems to be compared on one metric ID.

## Frozen, leakage-aware selection

For each corpus and metric ID, create a selection manifest before tuning:

1. Freeze OpenPII `train.jsonl` as the current synthetic **development**
   source. It is never a final holdout. Freeze Gretel's upstream test shards
   and TAB's supplied test split as holdouts; do not tune on either. A future
   OpenPII validation file may become an additional holdout only after a
   revision and SHA pin.
2. Within a capped source, group documents by upstream template
   (`expanded_type` for Gretel), or by source document where no template
   exists. Sort `(group hash, document id, start, end)` and retain the first
   250 Gold spans for that metric ID. Retain all available spans for classes
   below 200. This prevents multiple near-identical variants dominating a cap.
3. If a future corpus must be split into development and holdout, hash
   `(corpus revision, group)` to assign every group once. Variants of a
   template/document cannot cross that boundary. The selection manifest records
   source revision, group rule, hash seed, selected IDs and selected counts.
4. Use development only for label choice, thresholds and a future fusion rule.
   Run L1, GLiNER, and the frozen fusion once on the untouched holdout. The
   same holdout rows may be scored by all three arms; that is a paired
   comparison, not leakage.

`external_pii_eval select` now writes this text-free selection manifest from
normalized Gold. It records the pinned revision, seed, group rule, selected
document IDs and exact selected offsets; Gretel preserves upstream
`expanded_type` as the group ID. Do not call an uncapped full-corpus run a
capped holdout.

## Metrics and negatives

For each model arm report exact `(metric ID, Unicode code-point start, end)`
precision, recall and F1, per corpus, language and class. Keep real and
synthetic rows separate; never pool TAB with synthetic data into one headline
number.

Run the detector arms over identical frozen rows, but keep exact findings and
structural candidates as different tasks:

1. **L1 only:** native PII/DLP evidence normalized to metric IDs.
2. **L1 candidate coverage:** for semantic classes, report whether a compatible
   typed Anchor or L1 candidate occurs inside the frozen relation window around
   each Gold span. This is gate/boost recall, not an exact entity finding and
   must not be reported as span F1.
3. **GLiNER only:** configured entity labels normalized to metric IDs; only
   classes enabled by that bundle are in scope.
4. **L1+GLiNER:** a later, frozen fusion policy. It must be reported as a
   separate arm, never inferred from the union of two independently tuned
   reports.

The intended boost experiment is therefore explicit: measure GLiNER alone,
then the same GLiNER outputs with the frozen L1 candidate/Anchor boost, and
report the change in exact precision, recall and F1. Separately report Anchor
gate activation on verified negative documents. This shows whether L1 context
adds recall or only raises false positives; it does not pretend that an Anchor
already localized the PII value.

Arm scope is an explicit part of every report. A system receives no false
negative for a metric ID it was not configured or designed to emit:

| Fair comparison scope | Current metric IDs |
|---|---|
| L1 only | E-mail, phone, IP, IBAN, BIC, PAN, CVV, financial account, customer and employee ID, US SSN, plus native passport/driver-license output |
| GLiNER only | person, organization, date, location and (when enabled) street address |
| Pairwise L1 vs GLiNER vs later fusion | Only a frozen bundle that explicitly enables matching GLiNER labels: `date_of_birth`/DOB, `employee_identifier`/employee ID, `username`, `passport_number`, and `driver_license_number`. These are available in the GLiNER label registry but are not all in the current small default core bundle. |
| Semantic anchor-only classes | Compare L1 candidate coverage, GLiNER exact spans and later boosted GLiNER. Do not score Anchors as exact L1 findings. |

For the current default core bundle, the pairwise row is empty until those
optional labels are enabled and frozen. The semantic core rows may still be
reported as GLiNER-only; native L1 is not scored against person, organization,
generic date, location or street-address Gold.

Precision exposes false-positive spans on positive documents but is not an
FPR. For an FPR gate use human-verified no-PII documents and publish both:

- document FPR = negative documents with at least one in-scope prediction /
  verified negative documents;
- span false-positive rate = in-scope false-positive spans per 10,000 Unicode
  code points of those negative documents.

The 214 Gitleaks Go documents are SQL-negative only for the stated derived SQL
document task. They are not generic PII/DLP negatives and cannot establish a
secret or production-wide FPR. Local anchor-only records are not negatives
until human review produces `verified_no_pii` sidecars.
