# Ark 0.1.6: calibrated Injection L1

## Status and release model

Ark 0.1.6 is developed on one feature branch and released when the implementation and its
quality gates are complete. There is no staged product rollout.

The scope of this plan is the native Injection L1 stack. DLP, PII and registered external L1
detectors retain their existing behaviour. Embedding prototypes, OOD detection, embedding-cache
work and additional suspicion-window evaluation belong to L2/L3 and are not part of this L1
implementation.

## Target behaviour

The existing native Injection heuristics are internal signal producers. They no longer publish
independent public verdicts. Their registered signals are merged by overlapping or directly
touching original-document spans and scored once by a small, versioned and transparent model.

For each candidate, the aggregate retains:

- exact byte and character offsets;
- contributing producer names, rule IDs, families and severities;
- structural and rule features with pinned provenance;
- the calibrated score, threshold and acceptance result.

The gateway publishes exactly one native Injection L1 result, `native:injection_l1`:

- an accepted candidate produces an Injection finding, public evidence spans and a decision with
  `source: "l1"`;
- a rejected candidate leaves the top-level result safe but remains in the decision contract as
  `accepted: false` and is available internally as a conditional L2/L3 routing signal;
- inputs without a candidate remain safe;
- producer failures preserve the existing degraded/failed queue semantics.

This operating point deliberately prioritizes precision. L1 is not expected to recognize every
semantic injection; L2 and L3 remain responsible for broader analysis.

## Evidence sources

Rules and structural relationships are based on pinned public material rather than an invented
keyword list:

- Prompt Armor supplies the primary catalog structure and selected positive/negative cases;
- OWASP supplies the injection-family coverage checklist;
- Pipelock, PromptInject, Garak and the Microsoft Agent Governance material supply additional
  pinned relationship examples and variations.

Every imported or adapted rule retains its source revision and has a positive plus a nearby
benign counterexample. Broad policy, guardrail or refusal wording is not promoted when it also
occurs in legitimate security documentation.

## Calibration data and policy

Development calibration uses deterministic subsets from `injection_current`, the full
Hard-Benign calibration split and the full Hard-Benign development-validation split. Positive
candidate labels must reproduce locally when their span is rescanned; a document label is never
blindly copied to every candidate.

The final Hard-Benign holdout stayed closed until the scorer, tests and release gates were frozen.
The calibration artifact records the feature order, coefficients, threshold, input hashes and
tool provenance. The detailed method and the distinction between candidate metrics and
end-to-end document coverage are reported in
[`research/injection-l1-calibration-0.1.6.md`](research/injection-l1-calibration-0.1.6.md).

## Implementation sequence

1. Improve and register the existing Injection heuristics from pinned real-world sources,
   including German variants and benign counterexamples.
2. Introduce the common `L1Candidate`/feature contract and an independent structural producer.
3. Convert every native Injection heuristic into an internal producer and aggregate candidates
   across producers by span.
4. Fit and embed the transparent monotone scorer; publish accepted and rejected typed L1
   candidates through one `native:injection_l1` result.
5. Make rejected candidates available to existing conditional L2/L3 routing without exposing
   private routing state or adding L2 model logic to L1.
6. Update Rust, Python and schema contracts for the single-result model and `source: "l1"`.
7. Run independent architecture, calibration and false-positive reviews; remove obsolete code.
8. Freeze the scorer and execute the final holdout once. Completed against commit `fd42762` with
   zero accepted false positives across 3,576 Hard-Benign documents.

## Release gates

- zero accepted false positives in the final Hard-Benign holdout;
- development candidate precision at least 0.995 and document FPR at most 0.0005;
- explicit English and German coverage for every newly added relationship;
- every legacy native Injection producer still emits candidates for its pinned regression cases;
- exactly one public native Injection L1 result, with External L1 and DLP unchanged;
- accepted English and German embedded attacks expose correct byte/character spans and
  `decision.final_result.source: "l1"`;
- rejected candidates can open an explicitly configured conditional L2 gate but do not create a
  public finding;
- release-mode latency at 1 KiB, 10 KiB and 100 KiB stays within the recorded 0.1.6 budget.

The branch is not releaseable merely because the candidate-level F1 is high. Candidate coverage,
end-to-end document recall and the denominator for every false-positive claim must be reported
alongside it.
