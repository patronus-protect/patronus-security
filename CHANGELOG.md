# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

This project is **pre-1.0**: any change to detection thresholds, the asset manifest, or public
result shapes may be breaking for downstream users, and is called out explicitly below.

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
