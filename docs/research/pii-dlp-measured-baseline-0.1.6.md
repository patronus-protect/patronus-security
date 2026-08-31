# PII/DLP measured baseline 0.1.6

Measured on 2026-08-31 at commit `6b5af93` plus the Unicode boundary fix
documented below. Hardware: Apple M1 (8 cores, 16 GB), macOS 14.8.7. Native
100-KiB latency uses an optimized release build. GLiNER runs only on the real
document sizes selected by the Goldens; it is **not** run on a synthetic
100-KiB payload.

This report measures the detector primitives needed by the
[Patronus demo](https://patronus.studio/demo). Website "Schutzregeln" are a
product grouping and do not define the detector architecture.

## Demo contract

The exact texts currently shown by the demo produce the following results.
`Yes` means that an evidence span with the expected class is present; a safe
result or a wrong class is not counted as success.

| Scenario | Expected presentation | Current Ark result | Status |
|---|---|---|---|
| Kundendaten | person name | GLiNER `person`: `Frau Meier`, 0.936 | yes |
| Kundendaten | e-mail | PII-L1 `EMAIL` | yes |
| Kundendaten | telephone | no `PHONE` span | **no** |
| Kundendaten | IBAN | value emitted as `CREDITCARD`, not `IBAN` | **wrong class** |
| Kundendaten | internal margin | DLP-L1 `dlp.internal.business_metric` | yes |
| Personalakte | person name | `Herrn Bergmann` emitted as `organization`, 0.903 | **wrong class** |
| Personalakte | employee number | PII-L1 `EMPLOYEE_ID` | yes |
| Personalakte | e-mail | PII-L1 `EMAIL` | yes |
| Personalakte | telephone | no `PHONE` span | **no** |
| Personalakte | salary | no internal-metric span | **no** |
| Personalakte | contribution margin | DLP-L1 `dlp.internal.business_metric` | yes |
| Quellcode | source statement | DLP-L1 `dlp.content.source_code` | yes |
| Quellcode | Stripe live key | DLP-L1 `PAYMENT_KEY` | yes |
| Quellcode | SQL statement | DLP-L1 `dlp.content.sql` | yes |
| Quellcode | assigned password | DLP-L1 `CREDENTIAL` | yes |
| Prompt Injection | block | L1 returns `safe`, confidence 0.242 | **no** |

The demo is therefore a useful acceptance fixture, but it is not fully met by
0.1.6. In particular, the isolated examples working for code and SQL must not
be confused with broad corpus quality below.

## Admitted Golden inventory

| Source | Kind | Full documents | Full spans / labels | Frozen selected evaluation |
|---|---|---:|---:|---:|
| Gretel finance PII | synthetic, offset checked, six languages | 5,141 | 21,479 | 3,716 spans, 19 classes, 2,142 unique docs |
| OpenPII Nano | synthetic, offset checked, 30 languages | 900 | 4,222 | 1,997 spans, 9 classes, 777 unique docs |
| TAB | real, human annotated, English | 127 | 5,516 | 998 spans, 4 classes, 89 unique docs |
| Gitleaks Go/Markdown | derived content document task | 227 | 214 positive / 13 negative docs | all 227 docs |
| SchemaPile-Perm | derived SQL source boundaries | 10 source files | 250 selected statement spans | all 250 spans |

That is 6,168 external PII documents with 31,217 available PII/entity spans;
the frozen capped PII evaluation contains 6,711 spans. DLP adds 214 positive
source-code documents, 13 document controls, and 250 SQL boundaries. Local
`sensitive_current`/v4.1 candidates remain preannotations and contribute zero
Gold until human review.

## Native PII-L1 holdout

Exact character-span metrics on the capped synthetic Gretel test split:

| Metric | Gold | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| IP address | 226 | 0.949 | 0.987 | **0.968** |
| IBAN | 175 | 1.000 | 0.714 | **0.833** |
| E-mail | 250 | 0.731 | 0.804 | **0.766** |
| PAN | 138 | 0.912 | 0.449 | 0.602 |
| Phone | 250 | 0.607 | 0.556 | 0.580 |
| US SSN | 135 | 1.000 | 0.370 | 0.541 |
| Date of birth | 243 | 0.989 | 0.366 | 0.535 |
| BIC/SWIFT | 209 | 0.947 | 0.340 | 0.500 |
| Employee ID | 195 | 1.000 | 0.323 | 0.488 |
| Passport number | 137 | 1.000 | 0.285 | 0.443 |
| Customer ID | 201 | 1.000 | 0.259 | 0.411 |
| Username | 69 | 0.750 | 0.044 | 0.082 |
| CVV | 115 | 0.750 | 0.026 | 0.050 |
| Financial account number | 250 | 0.600 | 0.024 | 0.046 |
| Driver-license number | 123 | 0.000 | 0.000 | 0.000 |

OpenPII independently confirms strong e-mail detection (250 Gold, P 0.963,
R 0.936, F1 0.949), but only moderate phone detection (250 Gold, P 0.581,
R 0.432, F1 0.495). PAN reaches F1 0.216; passport F1 0.032; driver-license
number remains zero.

### German and English

Gretel is the source with a controlled DE/EN split. Selected exact-span recall:

| Metric | DE Gold | DE recall | EN Gold | EN recall |
|---|---:|---:|---:|---:|
| E-mail | 19 | 0.947 | 156 | 0.801 |
| Phone | 21 | 0.476 | 129 | 0.434 |
| IP address | 15 | 1.000 | 123 | 0.992 |
| IBAN | 19 | 0.316 | 69 | 0.971 |
| BIC/SWIFT | 22 | 0.182 | 112 | 0.366 |
| PAN | 5 | 0.800 | 83 | 0.518 |
| Date of birth | 17 | 0.765 | 126 | 0.571 |
| Employee ID | 24 | 0.333 | 114 | 0.421 |
| Customer ID | 23 | 0.304 | 94 | 0.447 |
| Passport | 12 | 0.500 | 76 | 0.395 |

The holdout has 60 DOB values containing letters. L1 matches 11 exactly
(18.3%); English is 10/28, while the other five languages together are 1/32.
The capped Gretel DE slice contains only one letter-bearing value and it is an
English-formatted month inside a German document, so it is not adequate
German written-date Gold. The checked-in capability suite separately verifies
valid `Geboren am 14. März 1985`, `Geburtsdatum: 28. Februar 1985`,
`14 March 1985`, and `February 29th, 2000`, including invalid-date negatives.
More external DE written-date Gold is still required.

## GLiNER core

Production label thresholds were used with one frozen label bundle:
`person`, `organization`, `date`, `city`, `country`, and `street_address`.
Exact F1 matters for redaction boundaries; overlap F1 additionally answers
whether the correct entity was found with a different boundary convention.

| Corpus / metric | Gold | Exact P/R/F1 | Overlap P/R/F1 |
|---|---:|---:|---:|
| Gretel person | 250 | .890 / .680 / **.771** | .895 / .684 / **.776** |
| Gretel organization | 250 | .497 / .640 / .559 | .544 / .700 / .612 |
| Gretel date | 250 | .784 / .232 / .358 | .824 / .244 / .377 |
| Gretel street address | 250 | .314 / .128 / .182 | .912 / .372 / .528 |
| OpenPII person | 250 | .352 / .124 / .183 | .955 / .336 / .497 |
| OpenPII date | 250 | .973 / .284 / .440 | 1.000 / .292 / .452 |
| OpenPII location | 250 | .676 / .100 / .174 | .946 / .140 / .244 |
| OpenPII street address | 250 | .152 / .064 / .090 | .848 / .356 / .501 |
| TAB person (real) | 250 | .599 / .400 / .480 | .964 / .644 / **.772** |
| TAB organization (real) | 250 | .397 / .584 / .473 | .443 / .652 / .528 |
| TAB location (real) | 250 | .672 / .508 / .579 | .720 / .544 / .620 |
| TAB date (real) | 248 | .917 / .044 / .085 | 1.000 / .048 / .092 |

On Gretel, exact person recall is 0.563 DE and 0.718 EN; organization recall
is 0.516 DE and 0.742 EN. Generic date recall is 0.150 DE and 0.303 EN.

GLiNER document latency reflects corpus size, not a 100-KiB stress input:

| Corpus | Documents | Median bytes | P95 bytes | Median latency | P95 latency |
|---|---:|---:|---:|---:|---:|
| Gretel | 572 | 1,303 | 2,287 | 1,019 ms | 2,844 ms |
| OpenPII | 520 | 350 | 1,026 | 206 ms | 715 ms |
| TAB | 89 | 3,879 | 10,210 | 1,977 ms | 4,474 ms |

One Gretel document took 47.9 seconds in the core run; this outlier requires
separate profiling before setting a production timeout/SLO.

## Native L1 versus optional GLiNER labels

This is a paired diagnostic on identical Gretel selections, not a fusion
result. It shows why neither producer should blindly replace the other.

| Metric | L1 exact P/R/F1 | GLiNER exact P/R/F1 | Current reading |
|---|---:|---:|---|
| Date of birth | .989 / .366 / .535 | 0 / 0 / 0 | keep native L1 |
| Employee ID | 1.000 / .323 / .488 | .406 / .528 / .459 | GLiNER adds recall but many FP |
| Username | .750 / .044 / .082 | .364 / .232 / .283 | GLiNER adds recall, quality still weak |
| Passport | 1.000 / .285 / .443 | .829 / .212 / .337 | keep native L1 |
| Driver license | 0 / 0 / 0 | .591 / .317 / .413 | GLiNER fills a real L1 gap |

On OpenPII, GLiNER improves driver-license F1 from 0 to 0.157 and passport F1
from 0.032 to 0.072, but neither is strong enough to present as stable alone.
No `L1 + GLiNER boost` number exists yet because the fusion/boost rule has not
been implemented and frozen. Reporting a union would be misleading.

## DLP derived-content tasks

These are deliberately weaker forms of Gold than human span annotation:

| Task | Result |
|---|---|
| Gitleaks Go source-code document recall | 60/214 = **28.0%** |
| Gitleaks Markdown control document FPR | 3/13 = **23.1%** |
| SchemaPile exact SQL-boundary recall | 3/250 = **1.2%** |
| SchemaPile overlap recall | 15/250 = **6.0%** |

SchemaPile precision is not reported: the cap stops after 250 statements and
therefore does not fully annotate every scanned source file. Predictions after
the selected boundary would otherwise be counted as false positives. The demo
code/SQL examples pass, but broad code/SQL content detection is not yet stable.

## Native L1 latency at exactly 100 KiB

Release build, one unmeasured warm-up, then 10 benign or 5 signal-dense
iterations. Signal-dense text intentionally repeats e-mail, phone, IBAN,
source, SQL, credential, and injection phrases; it is a stress case, not a
natural-language distribution.

| Categories | Benign median / P95 | Signal-dense median / P95 | Dense evidence spans |
|---|---:|---:|---:|
| PII | 13.3 / 15.9 ms | 31.2 / 33.0 ms | 794 |
| DLP | 13.4 / 17.0 ms | 72.7 / 82.4 ms | 1,191 |
| Injection | 54.6 / 140.6 ms | 1,398.1 / 1,640.9 ms | 3,169 |
| PII + DLP + Injection | 29.6 / 182.7 ms | 1,549.8 / 1,715.8 ms | 5,154 |

The combined benign P95 has one 182.7-ms outlier in ten iterations; use a
larger isolated run before treating it as an SLO. Injection's dense latency is
primarily proportional to thousands of emitted candidate spans and needs its
own output-cap/aggregation profile if adversarial 100-KiB inputs are in scope.

## Runtime defect found by the Goldens

OpenPII exposed a panic on narrow no-break space (`U+202F`). The local-path
post-filter advanced one byte after a Unicode whitespace character and then
sliced at a non-character boundary. The fix advances by `char::len_utf8`; a
regression test covers `Alex\u{202f}Vithurjan`. The formerly panicking real row
and the complete 520-document OpenPII GLiNER run pass after rebuilding the
Python binding.

## Reproduction

Normalize and select with `python -m patronus_ark.external_pii_eval`, then run:

```bash
.venv/bin/python scripts/measure_external_pii_runtime.py \
  --gold /path/to/normalized.jsonl \
  --selection /path/to/selection.json \
  --arm l1 \
  --output /tmp/l1-runtime.json

.venv/bin/python scripts/measure_external_pii_runtime.py \
  --gold /path/to/normalized.jsonl \
  --selection /path/to/selection.json \
  --arm gliner-core \
  --output /tmp/gliner-runtime.json
```

The runner preserves the manifest's cap, group selection, corpus revision,
language split, production GLiNER thresholds, exact metrics, overlap metrics,
and document latency. External raw text remains outside the repository.
