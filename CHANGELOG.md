# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

This project is **pre-1.0**: any change to detection thresholds, the asset manifest, or public
result shapes may be breaking for downstream users, and is called out explicitly below.

## [Unreleased]

### Added

- Full documentation site (MkDocs Material) under `docs/`, organized with the
  [Diátaxis](https://diataxis.fr/) framework: getting-started, tutorials, how-to guides,
  concepts (architecture, layered scanning, categories, detectors, models/NTDB, threat model,
  performance), reference (configuration, result schema), and contributing guides.
- `docs.yml` workflow to build and deploy the docs to GitHub Pages.
- Threat model documentation covering trust boundaries, assumptions, and non-goals.

### Changed

- Model asset repositories in `rust/src/assets/specs.rs` updated to the animal-named model
  line (Lion Warden, Wolf Defender, Panther Read, Husky Sight/Paw/Nose, Orca Sonar, Shark
  Scent). Hugging Face keeps redirects from the previous repository ids, so existing caches
  and references continue to resolve.

## Notes

Earlier history predates this changelog; see the Git history for details. Future releases will
record Added / Changed / Deprecated / Removed / Fixed / Security sections here.
