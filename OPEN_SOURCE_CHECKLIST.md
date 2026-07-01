# Open Source Readiness Checklist

## Required Before Public Release

- Confirm the copyright holder in `LICENSE`.
- Remove generated/local artifacts before the first commit:
  - `.DS_Store`
  - `rust/.DS_Store`
  - `.venv/`
  - `target/`
  - `python/patronus_security/_patronus_security*.so`
  - `benchmarks/__pycache__/`
- Keep `benchmarks/legacy_*` out of the public repository unless regenerated with neutral paths.
- Document that the Hugging Face model assets referenced by `rust/src/assets/specs.rs` are owned by Patronus.

## Strongly Recommended

- Add CI for formatting, Rust tests, Python binding build, and Python API tests.
- Add a release workflow for Python wheels via maturin and Rust crate publishing.
- Add crate and package badges after the first public release.
- Expand tests beyond the current validator/downloader coverage to include public scanner behavior for each category.
- Document model download size, cache location, offline mode, and expected behavior when assets are missing.
- Add API reference docs for Rust and Python.

## Library Quality

- Keep the Python API snake_case as the primary public API. Preserve `useLibrary` only as a compatibility alias if needed.
- Return stable result shapes and document class names, confidence semantics, and security levels.
- Replace `println!` progress output in library code with a configurable logging strategy.
- Avoid panics from malformed external config files; convert them to structured errors where configs can be user-provided.
