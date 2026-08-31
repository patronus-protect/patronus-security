# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

This project is **pre-1.0**: any change to detection thresholds, the asset manifest, or public
result shapes may be breaking for downstream users, and is called out explicitly below.

## [Unreleased]

### Added

- Added native PII and DLP L1 capabilities with validated exact spans, German and English
  anchor-bound identifiers, written birth dates, source/config/SQL/log detection, and non-blocking
  localized `layers[].details.l1_anchors` context facts. Added deterministic capability goldens,
  hard negatives, validators, and 100 KiB latency/evaluation tools.
- Added stable per-rule execution gates through Rust, Python, and Ark API configuration. Missing
  rule IDs remain enabled; PII/DLP patterns use `pii_*`/`dlp_*` IDs and Injection uses its existing
  `ark.injection.*` IDs.
- Added a version-pinned native injection rule catalog derived from selected Prompt Armor rules.
  Catalog findings expose stable Ark/upstream rule IDs, exact byte and character spans, source
  revision, licence, family, severity, and descriptions. The first catalog closes high-specificity
  override, instruction-leak, boundary, Markdown exfiltration, and ES/FR/PT gaps without importing
  Prompt Armor's runtime or thresholds.
- Registered all 18 existing native injection detectors in the same `InjectionSignal` evidence
  contract. Positive findings now expose stable Ark rule IDs, source revision, family, severity,
  explanations, localized candidate spans, and explicit clause/window span precision while
  retaining the existing separately gateable scanner model names.
- Added four source-derived, high-precision injection relationships for sensitive-path exfiltration,
  authority-issued replacement instructions, decode-then-execute directives, and delimited
  replacement actions. Each finding retains its pinned Pipelock or PromptInject source and any
  secondary Garak reference. Labeled ROT13 and URL-safe Base64 payloads are decoded before the
  existing injection-signal evaluation.
- Added the injection `L1Candidate` contract. Positive rule signals become auditable `rule_match`
  features; overlapping or directly touching spans form one deterministic candidate and separated
  regions remain separate. Candidates expose spans, rule IDs, families, severity, explanations,
  provenance and the versioned calibrated L1 score.
- Added a native structural injection producer for override-plus-sensitive-disclosure
  relationships. It can create a candidate independently of the flat rule catalog and decomposes
  the decisive region into exact context-override, hierarchy-reference, disclosure-action, and
  sensitive-object features. Added German adaptations and nearby benign counterexamples for every
  new 0.1.6 catalog relationship; language-neutral Markdown exfiltration syntax is shared.
- Added a precision-first, monotone Injection L1 scorer calibrated on deterministic
  `injection_current` samples and the complete Hard-Benign development splits. Its artifact,
  dataset hashes, feature order, threshold, candidate/document metrics and reproducible tooling
  are versioned in the repository; the final holdout remains a separate release gate.

### Changed

- Added `PATRONUS_L3_TTL_SECS=-1` to keep loaded L3 and Dynamic-PII ONNX sessions resident.
  The Ark API image and reference Compose deployment now use this setting to avoid the model
  reload latency spike on the first promoted request after an idle period.
- Changed the reference and OVH Ark API deployment to two FP16 workers limited to 2.5 CPUs each.
  On the canonical cold-cache HTTP benchmark this improved throughput from 6.761 to 7.728
  requests/s and reduced p50 latency from 440 ms to 168 ms versus three two-CPU workers. The
  Dockerfile now builds both API binaries explicitly and defaults its baked L3 assets to FP16.
- Changed native Injection L1 to publish one `native:injection_l1` aggregate instead of separate
  public results for every heuristic. The former detector model gates still control their internal
  producers. Accepted candidates expose evidence spans and `decision.final_result.source: "l1"`;
  rejected candidates keep their score and evidence without creating a finding and can be used by
  explicitly configured conditional L2/L3 gates. Registered external L1 detectors and DLP are
  unchanged.

### Breaking

- `ScanGateMatrix` has a new public `rules` field, and native PII/DLP layer `details` can now
  contain `l1_anchors`. External Rust struct literals and consumers that assumed empty native
  details must account for these intentional pre-1.0 additions.
- Native Injection consumers that selected models such as `native:instruction_override` or
  `native:injection_rule_catalog` from public scan results must migrate to
  `native:injection_l1` and inspect `layers[].details.l1_candidates[].producers`, rule provenance,
  and the typed decision candidates. This intentional pre-1.0 result-shape change ships with
  0.1.6.

## [0.1.5] - 2026-08-29

### Added

- Added NTDB Package-v4/mmBERT loading for the exported
  `raw_text_to_joint_v3_chunk_promoter_union_v1` contract: the neural stack and LightGBM promoter
  score each chunk independently, only promoted chunks run through L3, and document decisions use
  the export's L2-only, L3-only, and Union aggregation modes and thresholds. Manifest/model
  feature dimensions are validated at load time. Package-v2 runtime types remain available but
  are deprecated.
- Added cache-backed Package-v4 parity evaluation for L2 probabilities, per-chunk promoter masks,
  and final document decisions, including multiclass and binary validation sets.
- Added pinned FP16 L3 selection via `PATRONUS_L3_PRECISION=fp16` for Injection, Threat,
  Sensitive Document, and the Lion Warden unified model.
- Added pinned FP16 Dynamic-PII/GLiNER selection. The image warmup now selects
  `onnx/fp16/model_fp16.onnx` from the current revision of the Edge bundle when
  `PATRONUS_L3_PRECISION=fp16` is set.
- Added request-local Ark configuration to the existing multipart `POST /v1/scan` endpoint. A
  request can override categories, maximum level, execution gates, metadata, and the NTDB
  operating point without restarting the API; omitted values retain the server/API-key defaults,
  and category overrides cannot exceed the worker or API-key scope. Existing text and multi-file
  uploads keep their original jobs contract.
- Added `decision.decision_candidate.chunk_evidence` for Package-v4 Union decisions. It records
  the aggregation method, every contributing L2/L3 chunk, and the decisive chunk(s), so clients
  can attribute the final document verdict without reconstructing it from layer diagnostics.
- Added `ark-api` YAML support for API-key default categories, Dynamic PII/GLiNER configuration,
  and the complete L3 scheduler policy (including per-pipeline overrides). Request-local gate
  policies use the same validated policy shape; invalid conditional gates and invalid scheduler
  bounds are rejected at configuration load time.
- Added native and HTTP throughput regression tools for the production-style gated
  injection/DLP/threat profile using unified L3. The native benchmark runs one Ark with parallel
  requests for at least 60 seconds, reports progress while consuming events, and uses a mixed
  workload averaging 100 KiB per request (96 KiB median) with repeated and varied content, small
  2–26 KiB requests, and 1 MiB spikes. It reports MiB/s, RPS, and latency percentiles and verifies
  completed requests, executed pipelines, levels, and the L3 model; Dynamic PII/GLiNER remains
  excluded because it requires a separate representative request-size profile.
- Added a CI throughput job that builds and installs a fresh release wheel, caches downloaded model
  assets, runs the gated unified benchmark without GLiNER, and publishes its JSON report.
- Added validated `pipeline.onnx_runtime` CPU session settings to `ark-api`. Intra-op/inter-op
  thread counts and spinning are applied before startup warmup, so every ONNX session uses the
  deployment's bounded thread policy; zero thread counts and unknown fields are rejected.
- Added explicit category and NTDB operating-point controls to the HTTP throughput benchmark so
  full injection/DLP/threat, no-threat, and `best_promote` runs record the configuration they test.

### Changed

- Re-pinned the Injection Package-v4/L3 bundle to Wolf Defender Small v2 and the three Tool Tags
  Package-v4 bundles to the current Husky Nose revision. Both model families now use the same
  immutable upstream revision for every runtime asset they supply.
- Pinned all nine published Package-v4/mmBERT L2 bundles (Injection, Sensitive Document, Tool
  Class, Tool Action, the three split Tool Tags, Routing, and Threat) to their immutable Hugging
  Face revisions. The unified L3 strategy uses the pinned public Lion Warden bundle, including
  FP16 selection; the former `-edge` repositories are no longer referenced.
- Changed Package-v4 routing to promote exclusively per chunk. `best_promote` uses the exported
  25% calibration operating point, while `best_f1` and `best_latency_in_f1` use the exported
  utility operating point. Post-L3 benefit and document-decider state are no longer part of the
  runtime contract; promoted chunks replace their L2 probabilities with L3 probabilities and
  non-promoted chunks retain L2 for export-defined Union aggregation.
- Changed Joint-v3 ONNX execution to the export's exact per-chunk tensor contract across Injection,
  Threat, Sensitive Document, Routing, Tool Class, Tool Action, and the split Tool Tags pipelines.
  Independent chunks remain parallelizable without document padding or attention-mask changes.
- Preserved the existing L3 strategy engine for Package-v4 promotions, including request-wide
  Early Exit, Representatives, Verify Representative, clustering, Exact Cache, and similarity
  propagation. Package-v4 changes which chunks are promoted, not how L3 schedules them.
- Changed Package-v4 final arbitration to use the export's default Union view while retaining
  L2-only, L3-only, and Union decision candidates for policy inspection. A rejected Union candidate
  returns the default class and is not overridden by an accepted L2-only candidate. Package-v2
  keeps its existing `decision_thresholds.json` arbitration unchanged.
- Changed the `ark-api` deployment to use the shared Unified L3 classifier for regular model heads
  and the separate Dynamic PII/GLiNER runtime. The Docker build bakes both asset bundles, and the
  reference build configuration now enables the production Injection/DLP/PII/Sensitive Document/
  Threat/Routing/Dynamic PII profile at L3 with one request worker per container.
- Changed `ark-api` scan input handling to accept both `text` and `content` multipart fields;
  request-local configuration is resolved once and snapshotted into each text or file job.
- Changed completed `ark-api` SSE request retention from five minutes to one minute.

- Optimized the CPU inference setup by updating the default ONNX Runtime Rust bindings to `ort`
  `2.0.0-rc.13` / ONNX Runtime 1.28 and making execution-provider selection feature-aware:
  accelerator builds prefer their configured provider and fall back to CPU, while CPU-only builds
  select the optimized CPU execution path directly instead of probing unavailable accelerators.
- Changed unified-L3 warmup to execute a real inference after loading the session, so Docker build
  warmup prepares both the embedded model assets and the runtime's first-inference path.
- Extended API readiness output with the available and actually active ONNX execution providers.

### Removed

- Removed NTDB `.kit` tokenizer loading and generation. Official Package-v4 models use the
  mmBERT-specific `.mmbpe` runtime, with `tokenizer.json` as the fallback.

### Fixed

- Fixed public gateway job polling to retain worker `evidence_spans` for every category. Native
  PII/DLP and Dynamic-PII consumers now receive labels, matched text, score, and byte/character
  offsets needed for redaction alongside classifier `decision_evidence`.
- Fixed x86_64 CPU inference parity for the verified German greeting and Dynamic-PII person-span
  cases by using the pinned FP16 ONNX graphs in production. On x86_64 deployments, build and run
  the API with `PATRONUS_L3_PRECISION=fp16`; the default quantized graphs remain suitable only
  where their output has been validated for the target runtime.
- Fixed Dynamic PII asset selection so a pinned FP16 GLiNER model is downloaded, baked, and loaded
  as one coherent bundle instead of validating it against the quantized model manifest.

- Updated Lion Warden, Wolf Defender Injection, Wolf Defender Threat, and Orca Sonar L3 assets
  to their public non-`-edge` Hugging Face repositories and current immutable revisions. FP16
  selection now uses the repositories' `onnx/onnx_fp16/model_fp16.onnx` layout, and Lion
  Warden's Sensitive Document head accepts its new `education` and `medical` classes.
- Fixed automatic Package-v4 model updates so the downloader parses freshly fetched manifests
  and the warmup validator through the Package-v4-aware parser before resolving or loading their
  runtime artifacts, including exported non-finite report-only metric values.
- Fixed warmup revision enforcement for official L2 packages: an existing manifest no longer
  suppresses an update when its `.patronus-revision` marker is absent or stale, or when its shared
  embedding matrix does not match the pinned manifest dimensions. Explicit local package
  overrides remain untouched.
- Fixed shared-embedder cache migration across encoder generations: embedding matrices with a
  mismatched manifest size are no longer reused, and asset downloads replace hard links or
  symlinks atomically instead of truncating another package's shared cache inode.
- Fixed an `ark-api` event-delivery race: scans that emit before the HTTP handler registers their
  request buffer now create that buffer in the dispatcher, preserving the event history for the
  subsequent SSE subscriber.
- Clarified that the built-in benchmark corpus contains synthetic historical regression fixtures,
  not the model-release validation splits; its F1 values are therefore not release-validation
  metrics.

- Prevented CPU-only builds from attempting to register an accelerator execution provider that was
  not compiled into the binary.

### Breaking

- Completed `ark-api` scan event streams are retained for one minute instead of five. Clients must
  begin consuming `GET /v1/scan/{request_id}/events` within that shorter window.

## [0.1.4] - 2026-08-18

### Added

- Added the public `PrivateNetworkDiagnosticHook`, which retains private and local IP predictions
  for diagnostics while filtering their evidence spans from network-diagnostic output.
- Added shared tokenizer caching and direct mmBERT token-ID handoff from compatible NTDB L2
  chunks to dedicated and unified L3 inference.
- Added `ark-api`, an ephemeral HTTP API around the security pipeline for self-hosted and
  Patronus-hosted deployment: `POST /v1/scan` accepts text and/or one or more files and returns a
  `request_id` per input, `GET /v1/scan/{request_id}/events` streams progress and per-category
  results over Server-Sent Events, buffering events so a client that only starts polling after a
  fast scan completes still sees the full history instead of a 404.
- Added YAML-based `ark-api` configuration, including per-API-key category scoping and gate
  overrides: `pipeline.gates` (and per-key `auth.keys[].gates`) deserialize directly into
  `ConditionalPipelineGate`/`GateExpression`, so the full metadata/prior-result condition tree and
  per-pipeline L3 policy overrides are configurable in YAML without a bespoke parser.
- Added a multi-stage `ark-api` Dockerfile that bakes model assets in at build time (via
  `ark-api --warmup-only`) and a `docker-compose.yml` reference deployment for self-hosting.

### Changed

- Changed compatible mmBERT NTDB runtime chunks to 254 content tokens so L2 tokenization can be
  reused safely by 256-token L3 models with their boundary tokens.
- Tightened native injection, DLP, and MCP relationship matching so actionable verbs, targets,
  and destinations must occur in supported request forms.
- Expanded Unicode-confusable normalization so mixed-script security signals are evaluated through
  an ASCII skeleton before a finding is emitted.

### Fixed

- Reduced false-positive native findings in source code, test names, logs, documentation, benign
  tool output, and ordinary developer-mode or network-diagnostic text.
- Prevented compatible L2 spans from being re-tokenized or silently truncated during L3 inference;
  incompatible or oversized handoffs now fall back to model-backed L3 rechunking.
- Allowed unified and dedicated L3 bundles to load a compact `tokenizer.mmbpe` when
  `tokenizer.json` is unavailable, while preserving the JSON fallback.
- Worked around a `serde_yaml` 0.9 bug deserializing recursive enums nested inside sequences (hit
  by `ark-api`'s conditional gate config) by routing YAML config parsing through `serde_json`.

### Breaking

- Native injection, DLP, MCP, obfuscation, and PII evidence decisions can change because matching
  relationships, Unicode-confusable handling, and post-prediction evidence filtering were updated.
- Compatible mmBERT NTDB packages now use 254 content tokens per runtime chunk instead of 256.

## [0.1.3] - 2026-08-11

### Added

- Added public post-prediction hooks for filtering non-actionable credential and local-path
  evidence while retaining model predictions for diagnostics.
- Added precision-first, real-corpus calibration data and a local sweep tool for general Dynamic
  PII labels, plus benchmark coverage for names, dates of birth, cities, and countries.

### Changed

- Expanded the default and document-aware Dynamic PII label sets with calibrated `first_name`,
  `last_name`, `date_of_birth`, `city`, and `country` entities, and recalibrated `date`.

### Fixed

- Reduced false-positive DLP and MCP findings for template `.env` copies, empty or placeholder
  secret assignments, and low-entropy credential values.
- Suppressed `person` evidence when a detected name is only a username inside a local filesystem
  path.
- Rejected loopback, multicast, unspecified, and truncated IPv6 candidates as PII, and rejected
  terminal metadata words and invalid zero postal codes as German postal addresses.

### Breaking

- Dynamic PII findings and native PII/DLP/MCP decisions can change because label sets, thresholds,
  evidence filtering, and native validators were updated.

## [0.1.2] - 2026-07-26

### Added

- Added compact `.mmbpe` tokenizer generation for compatible mmBERT byte-fallback BPE
  tokenizers during verified downloads and cached warmup. The original `tokenizer.json` remains
  the canonical fallback.
- Added German imperative variants to the native `instruction_override` L1 detector.

### Changed

- Added the structured `decision` envelope to model-backed classifier results. The envelope exposes
  the final Ark verdict, the canonical policy candidate, all typed L2/L3/Union candidates, Ark's
  calibrated recommendation, terminality, and minimal provenance.
- Restricted `decision` to terminal authoritative classifier results. Early L2 results with
  `l3_pending`, provisional events, and result-preview events now leave `decision` unset so
  downstream policy consumers can key on `result.decision.is_some()`.
- Extended compact tokenizer asset preparation beyond Granite `.kit` generation so supported
  mmBERT L2/L3 bundles can reuse hash- and version-invalidated generated artifacts.
- Changed classifier default arbitration to preserve a calibrated default-class confidence when
  the producing model exposes one, instead of always forcing `0.0`.

### Fixed

- Fixed promoted NTDB L2 fallback results so the final-decision threshold profile is still applied
  before publishing the fallback class.
- Fixed L2-only classifier arbitration so accepted candidates are selected from model label scores
  instead of the already defaulted top-level result.
- Fixed persistent `redb` cache handling to recreate a missing or externally deleted database file
  while still surfacing corrupt databases and active second-writer conflicts as errors.

### Breaking

- Removed the redundant NTDB L2 `details.raw_class_name` and `details.raw_confidence` fields.
  Consumers should read `decision.decision_candidate` and `decision.candidates[]` instead.
- Candidate arbitration data is no longer exposed as public `layers[].details.arbitration_*` fields.
  The public contract is the top-level `decision` envelope.

## [0.1.1] - 2026-07-26

### Added

- Added bundled NTDB final-decision thresholds for L2, L3, and weighted L2/L3 union arbitration
  across classifier pipelines.
- Added request-local `enqueue(..., ntdb_operating_point=...)` support for overriding the
  final-decision threshold profile on queued scans.
- Added `threat` validation samples to the built-in local benchmark.

### Changed

- Changed classifier final arbitration to accept L3 first, then a weighted L2/L3 union, then L2,
  and otherwise return the pipeline default class.
- Changed Python's `ntdb_operating_point` meaning to select the final-decision threshold profile;
  L2 promotion continues to use the NTDB package promote operating point and is not changed by
  that Python setting.
- Changed the default final-decision threshold profile to `best_f1`.

### Removed

- Removed `tool_class` validation samples from the built-in local benchmark fixture set.

### Breaking

- Classifier result decisions can change because calibrated final-decision thresholds now apply
  to L2, L3, and union arbitration.
- Benchmark comparisons against previous local runs are not one-to-one for `tool_class`, because
  the packaged benchmark fixture was removed and `threat` was added.

### Added

- Added `normalize_text(text, configs={})` as a pure text-normalization API for applying
  `canonical_security_text_v1` before scanning or for direct caller use.

### Fixed

- Added a separate macOS Intel wheel build that pins `ort` to `2.0.0-rc.10`, which still provides
  prebuilt ONNX Runtime binaries for `x86_64-apple-darwin`.
- Kept macOS arm64, Linux, and Windows wheel builds on `ort` `2.0.0-rc.12`.

## [0.1.0] - 2026-07-24

Initial public release of Patronus Ark.

### Added

- Hybrid Rust/Python security scanning library published as the `patronus-ark` Rust crate and
  Python package.
- `SecurityGateway` for synchronous scans and queued request processing.
- Scan categories for prompt injection, DLP, PII, dynamic PII, sensitive documents, tool
  classification, tool actions, tool tags, routing, and threat detection.
- Layered scanning with native L1 detectors, NTDB L2 model packages, and promoted L3 ONNX
  models.
- Configurable model asset download and cache management.
- Configurable execution gates, L3 scheduling policy, L3 strategy selection, and ONNX backend
  options.
- Hot and persistent result caching.
- Built-in local benchmark runner with packaged benchmark fixtures.
- Rust and Python examples plus documentation for installation, quickstart, configuration,
  assets, result schema, and release/testing workflows.

## Notes

This is the first public changelogged release. Future releases will record Added / Changed /
Deprecated / Removed / Fixed / Security sections here.
