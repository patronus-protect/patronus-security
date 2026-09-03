# Injection L1 calibration 0.1.6

Status: development calibration for the audited-evidence augmentation is complete. The frozen
hard-benign holdout was consumed by the preceding baseline and is retained as historical evidence;
it was not reopened for this augmentation.

## Goal

The scorer accepts only a high-confidence subset of Injection L1 candidates. It is intentionally
optimized for precision rather than broad recall because rejected candidate classes and scores
remain available to conditional L2/L3 routing. They are routing predicates, not extra model
features. The score is a versioned logistic model over transparent candidate evidence; it has no
runtime ML dependency.

## Data contract

The deterministic development run used:

- 8,000 attack-labelled and 20,000 benign `injection_current` training documents;
- all 2,572 `hard_benign_full_calibration` documents;
- 4,000 attack-labelled and 8,000 benign `injection_current` validation documents;
- all 2,523 `hard_benign_full_validation` documents.

Only locally corroborated positive candidates are evaluated. A document label is not copied blindly
onto every span: the extracted span must reproduce at least one acceptance-eligible rule when
scanned alone. `candidate_only` observations remain visible in the runtime contract but are excluded
from fitting, threshold selection, feature counts, candidate bridging, and accepted evidence. This
retained 511 fit and 388 validation positive scoring-candidate records. Raw text and candidate JSONL
remain outside the repository.

The full manifest, input hashes, feature order, and gates are in `injection-l1-calibration-0.1.6-manifest.json`.

## Scorer

The runtime computes:

```text
score = sigmoid(intercept + sum(coefficient[i] * feature[i]))
accepted = score >= 0.844886
```

Evidence-count coefficients are constrained to be nonnegative. Only candidate span length may have a nonpositive coefficient, reflecting lower localization precision for large clause/window spans. The fitted artifact is `rust/src/detectors/injection/rules/l1_scorer_0_1_6.json`.

The augmentation preserves the baseline intercept, threshold, and all 13 baseline coefficients
bit-for-bit. It adds one transparent feature, `audited_evidence_rule_count`, with coefficient
`3.7166`. The maximum score delta for candidates without audited evidence is exactly zero. The fit
and validation partitions contain 30,572 and 14,523 unique normalized text hashes respectively,
with zero overlap. Normalization is deliberately narrow: CRLF is converted to LF, outer whitespace
is stripped, then SHA-256 is computed.

## Development results

| Split | Candidate precision | Candidate recall | Candidate F1 | Accepted benign docs | Benign docs | Document FPR |
|---|---:|---:|---:|---:|---:|---:|
| Fit | 1.0000 | 0.6751 | 0.8061 | 0 | 22,572 | 0.0000 |
| Development validation | 1.0000 | 0.7423 | 0.8521 | 0 | 10,523 | 0.0000 |

The candidate F1 of 0.8521 is conditional on an acceptance-eligible candidate already existing.
Candidate observations are also correlated because one document may produce multiple candidates.
It is therefore neither an independent-sample estimate nor an end-to-end document F1. On
development validation, 964 of 4,000 attack-labelled documents produced any candidate (24.10%),
187 produced a scoring candidate, 138 contained a retained strong candidate, and 66 received an
accepted L1 prediction. End-to-end document precision is 1.0000, recall is 1.65%, and F1 is
3.2464%. The baseline equation over the same expanded candidates accepted 40 documents (1.9802%
document F1); the earlier frozen runtime accepted 37 (1.8330% document F1). This deliberately low
recall is reported rather than hidden: `injection_current` is much broader than the high-precision
relationships targeted by L1, and L2/L3 handle the remainder.

Hard-benign results are independently visible:

| Split | Documents | Documents with candidates | Accepted candidates | Accepted documents |
|---|---:|---:|---:|---:|
| Calibration | 2,572 | 743 (2 scoring) | 0 | 0 |
| Development validation | 2,523 | 645 (6 scoring) | 0 | 0 |

Zero observed development-validation false positives over 10,523 benign documents gives a rule-of-three 95% upper bound of approximately 0.0285%; it does not prove the true production FPR is zero.

### Threshold review

The threshold remains the frozen baseline value `0.844886`; it is not relaxed for the new rules.
The baseline threshold was selected against both fit negatives and development-validation negatives,
so development validation remains tuning data rather than a final holdout. Its highest observed
negative score is `0.8448756274254595`. The audited coefficient is the smallest quantized value
that places all 17 source goldens at least ten score quanta above the threshold; all 17 pass, and no
development negative contains audited acceptance evidence. Embedded Python and typed Rust golden
cases exercise the observed top negative and both sides of the threshold boundary.

The highest-scoring negatives include short procedural instruction-override spans, an exact German override plus a procedural native override, and exact sensitive-path transfer requests. These profiles overlap genuine positives at the available feature level. A separate monotone operating rule based only on multiple rules, multiple producers, exact spans, source-derived rules, or the structural combination did not improve zero-FP recall: the broad multi-rule and multi-producer variants admitted three fit false positives, while the zero-FP variants accepted fewer positives than the fitted score. No rule-ID exception or text-specific carve-out was added.

## Release gates

The development gates are executable and nonzero: candidate precision must be at least 0.995, document FPR at most 0.0005, and accepted hard-benign development documents exactly zero. Run them with:

```bash
.venv/bin/python scripts/calibrate_injection_l1.py validate \
  --artifact rust/src/detectors/injection/rules/l1_scorer_0_1_6.json \
  --release-manifest docs/research/injection-l1-calibration-0.1.6-manifest.json
```

Three separate suites are tracked. Language/family regressions and latency are rerun for the current
augmentation. The holdout was executed once against pre-holdout commit `fd42762` and is not claimed
as an evaluation of the subsequently added audited evidence:

- Language/family regression tests, including `every_new_catalog_relationship_has_german_coverage`, `injection_l1_covers_every_legacy_pi_pattern_family`, and `accepted_english_and_german_embedded_attacks_use_l1_decision_source`.
- The public-gateway latency suite in `scripts/benchmark_injection_l1.py`, covering benign and
  embedded-attack inputs at 1, 10, and 100 KiB and reporting milliseconds, median, and p95. The
  frozen results are in `injection-l1-latency-0.1.6.md`.
- Historical baseline evidence: a single frozen evaluation of `hard_benign_full_holdout`. All 3,576
  documents were scanned; six produced rejected candidates and zero produced an accepted false
  positive. The archived report is `injection-l1-final-holdout-0.1.6.json` and records the evaluated
  baseline artifact digest. The holdout was not reopened after adding audited evidence.

The archived runtime metadata reports `repository_dirty: true` because unrelated concurrent
worktree edits were present outside the Injection-L1 change set. The evaluated Injection-L1 Rust
sources matched commit `fd42762`, and the embedded baseline scorer matched SHA-256
`88a57b166d1963f578fb8a3bf0caa9e40cfa0d2bd38b70200121b8fe21501380`. The current release
manifest explicitly marks this holdout result as historical-baseline-only.

## Reproduction

Use the project virtual environment:

```bash
.venv/bin/python scripts/calibrate_injection_l1.py extract \
  --dataset-root /path/to/Patronus-Datasets \
  --output /tmp/injection_l1_candidates.jsonl \
  --manifest /tmp/injection_l1_candidates_manifest.json

.venv/bin/python scripts/calibrate_injection_l1.py augment-baseline \
  --candidates /tmp/injection_l1_candidates.jsonl \
  --manifest /tmp/injection_l1_candidates_manifest.json \
  --baseline-artifact /path/to/frozen-baseline.json \
  --source-goldens scripts/fixtures/injection_l1_source_goldens_0_1_6.json \
  --artifact rust/src/detectors/injection/rules/l1_scorer_0_1_6.json \
  --report /tmp/injection_l1_fit_report.json
```

The final holdout is not part of the normal development workflow. It was run once for the frozen
baseline using the explicit input contract below. This command is retained for auditability, not as
an instruction to rerun the consumed holdout:

```bash
.venv/bin/python scripts/calibrate_injection_l1.py final-eval \
  --dataset-root /path/to/Patronus-Datasets \
  --artifact rust/src/detectors/injection/rules/l1_scorer_0_1_6.json \
  --release-manifest docs/research/injection-l1-calibration-0.1.6-manifest.json \
  --expected-artifact-sha256 88a57b166d1963f578fb8a3bf0caa9e40cfa0d2bd38b70200121b8fe21501380 \
  --expected-holdout-sha256 bb09053c677ad28802d286ca117db3280c647188f786e992ef532590a227152a \
  --expected-holdout-documents 3576 \
  --output docs/research/injection-l1-final-holdout-0.1.6.json \
  --allow-holdout
```

The command refuses to overwrite a report, validates the frozen artifact digest and release manifest before accessing data, verifies the holdout digest and document count, and records scanner, Ark package, tool, Python, NumPy, and repository versions. It atomically archives the report even when the zero-FP holdout gate fails, then returns a nonzero exit status so the failure cannot be mistaken for release approval. A call without `--allow-holdout` fails before opening the holdout. The report cannot establish production FPR and does not replace language, family, or latency testing.
