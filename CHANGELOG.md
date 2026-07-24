# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

This project is **pre-1.0**: any change to detection thresholds, the asset manifest, or public
result shapes may be breaking for downstream users, and is called out explicitly below.

## [Unreleased]

No unreleased changes yet.

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
