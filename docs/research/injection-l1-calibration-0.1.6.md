# Injection L1 calibration 0.1.6

Status: development calibration complete; final hard-benign holdout locked.

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

Only locally corroborated positive candidates are fitted. A document label is not copied blindly onto every span: the extracted span must reproduce at least one rule when scanned alone and must also have critical, source-derived, multi-producer, or rule-plus-structural evidence. This retained 488 fit and 375 validation positive candidate records. Raw text and candidate JSONL remain outside the repository.

The full manifest, input hashes, feature order, and gates are in `injection-l1-calibration-0.1.6-manifest.json`.

## Scorer

The runtime computes:

```text
score = sigmoid(intercept + sum(coefficient[i] * feature[i]))
accepted = score >= 0.844886
```

Evidence-count coefficients are constrained to be nonnegative. Only candidate span length may have a nonpositive coefficient, reflecting lower localization precision for large clause/window spans. The fitted artifact is `rust/src/detectors/injection/rules/l1_scorer_0_1_6.json`.

The projected fit converged deterministically after 634 iterations (objective `0.38190993395955875`, final projected-gradient L2 norm `9.07e-10`). The fit and validation partitions contain 30,572 and 14,523 unique normalized text hashes respectively, with zero overlap. Normalization is deliberately narrow: CRLF is converted to LF, outer whitespace is stripped, then SHA-256 is computed.

## Development results

| Split | Candidate precision | Candidate recall | Candidate F1 | Accepted benign docs | Benign docs | Document FPR |
|---|---:|---:|---:|---:|---:|---:|
| Fit | 1.0000 | 0.5820 | 0.7358 | 0 | 22,572 | 0.0000 |
| Development validation | 1.0000 | 0.6747 | 0.8057 | 0 | 10,523 | 0.0000 |

The candidate F1 of 0.8057 applies only to the reproducible strong candidates selected by the candidate-level contract. Candidate observations are also correlated because one document may produce multiple candidates. It is therefore neither an independent-sample estimate nor an end-to-end document F1. On development validation, 174 of 4,000 attack-labelled documents produced any L1 candidate (4.35% any-candidate coverage), 126 contained a retained strong candidate, and 37 received an accepted L1 prediction. The resulting end-to-end document recall is 0.925%. This deliberately low value is reported rather than hidden: `injection_current` is much broader than the high-precision relationships targeted by this L1 release, and L2 handles the remainder.

Hard-benign results are independently visible:

| Split | Documents | Documents with candidates | Accepted candidates | Accepted documents |
|---|---:|---:|---:|---:|
| Calibration | 2,572 | 2 | 0 | 0 |
| Development validation | 2,523 | 4 | 0 | 0 |

Zero observed development-validation false positives over 10,523 benign documents gives a rule-of-three 95% upper bound of approximately 0.0285%; it does not prove the true production FPR is zero.

### Threshold review

The threshold is selected against both fit negatives and development-validation negatives. Development validation therefore participates in tuning and is not a final holdout. Its highest observed negative score was `0.8448756274254595`. Scores are quantized at `0.000001`, and the threshold builder requires at least ten quanta of safety margin before rounding; the frozen threshold is `0.844886`. Embedded Python and typed Rust golden cases exercise the observed top negative and both sides of the threshold boundary.

The highest-scoring negatives include short procedural instruction-override spans, an exact German override plus a procedural native override, and exact sensitive-path transfer requests. These profiles overlap genuine positives at the available feature level. A separate monotone operating rule based only on multiple rules, multiple producers, exact spans, source-derived rules, or the structural combination did not improve zero-FP recall: the broad multi-rule and multi-producer variants admitted three fit false positives, while the zero-FP variants accepted fewer positives than the fitted score. No rule-ID exception or text-specific carve-out was added.

## Release gates

The development gates are executable and nonzero: candidate precision must be at least 0.995, document FPR at most 0.0005, and accepted hard-benign development documents exactly zero. Run them with:

```bash
.venv/bin/python scripts/calibrate_injection_l1.py validate \
  --artifact rust/src/detectors/injection/rules/l1_scorer_0_1_6.json \
  --release-manifest docs/research/injection-l1-calibration-0.1.6-manifest.json
```

Three separate suites are release requirements. The first two passed on the frozen branch; the
holdout remains pending until the pre-holdout commit:

- Language/family regression tests, including `every_new_catalog_relationship_has_german_coverage`, `injection_l1_covers_every_legacy_pi_pattern_family`, and `accepted_english_and_german_embedded_attacks_use_l1_decision_source`.
- The public-gateway latency suite in `scripts/benchmark_injection_l1.py`, covering benign and
  embedded-attack inputs at 1, 10, and 100 KiB and reporting milliseconds, median, and p95. The
  frozen results are in `injection-l1-latency-0.1.6.md`.
- A single frozen evaluation of `hard_benign_full_holdout` after code, scorer, manifests, and the other suites are frozen.

## Reproduction

Use the project virtual environment:

```bash
.venv/bin/python scripts/calibrate_injection_l1.py extract \
  --dataset-root /path/to/Patronus-Datasets \
  --output /tmp/injection_l1_candidates.jsonl \
  --manifest /tmp/injection_l1_candidates_manifest.json

.venv/bin/python scripts/calibrate_injection_l1.py fit \
  --candidates /tmp/injection_l1_candidates.jsonl \
  --manifest /tmp/injection_l1_candidates_manifest.json \
  --artifact rust/src/detectors/injection/rules/l1_scorer_0_1_6.json \
  --report /tmp/injection_l1_fit_report.json
```

The final holdout is not part of this workflow. After the runtime implementation and scorer artifact are frozen, independently record the expected holdout digest and run `final-eval` exactly once with the explicit `--allow-holdout` flag:

```bash
.venv/bin/python scripts/calibrate_injection_l1.py final-eval \
  --dataset-root /path/to/Patronus-Datasets \
  --artifact rust/src/detectors/injection/rules/l1_scorer_0_1_6.json \
  --release-manifest docs/research/injection-l1-calibration-0.1.6-manifest.json \
  --expected-artifact-sha256 88a57b166d1963f578fb8a3bf0caa9e40cfa0d2bd38b70200121b8fe21501380 \
  --expected-holdout-sha256 <frozen-lowercase-sha256> \
  --expected-holdout-documents 3576 \
  --output /new/path/injection-l1-final-holdout-report.json \
  --allow-holdout
```

The command refuses to overwrite a report, validates the frozen artifact digest and release manifest before accessing data, verifies the holdout digest and document count, and records scanner, Ark package, tool, Python, NumPy, and repository versions. It atomically archives the report even when the zero-FP holdout gate fails, then returns a nonzero exit status so the failure cannot be mistaken for release approval. A call without `--allow-holdout` fails before opening the holdout. The report cannot establish production FPR and does not replace language, family, or latency testing.
