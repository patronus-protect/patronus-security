# Open Source Readiness Checklist

## Done

- CI for formatting, Rust tests, Python binding build, and Python API tests (`.github/workflows/ci.yml`).
- Release workflow for Python wheels and crate publishing (`.github/workflows/release.yml`).
- API reference docs generated for Rust and Python (`scripts/generate_docs.py`).
- Asset size, cache location, offline mode, and missing-asset behavior documented (`docs/assets.md`).
- Single public API name: `SecurityGateway` with `model_dir`; legacy aliases removed.
- Library logging goes through the `log` facade instead of `println!`.
- Benchmarks are built in: `SecurityGateway.run_local_benchmark()` runs on validation samples shipped with the package and writes per-device results to the gitignored `benchmark/` directory. No datasets or environment variables needed.
- Tests live in `rust/tests/` and `python/tests/`; internal hooks are gated behind the `test-util` feature.
- NTDB L2 package downloads install shared L2 embedder files once under `l2_ntdb/_shared/encoders`; package-local tokenizer/minilm paths link to the shared files.

## Before Public Release

- Confirm the copyright holder in `LICENSE`.
- Run `git status --ignored` and confirm no generated/local artifacts are tracked (`.DS_Store`, `.venv/`, `target/`, `*.so`, benchmark outputs).
- Document that the Hugging Face model assets referenced by `rust/src/assets/specs.rs` are owned by Patronus.
- Run the ignored HF L3 E2E (`hf_l3_download_assets_and_run_with_local_ntdb_l2`) with `download_files=true` and a local NTDB L2 export symlink before release; it is present but intentionally not part of the default test run.
- Squash or restart the git history so internal iteration does not ship.
- Add crate and package badges after the first public release.

## Ongoing Quality

- Return stable result shapes and document class names, confidence semantics, and security levels.
- Avoid panics from malformed external config files; convert them to structured errors where configs can be user-provided.
- Expand tests toward public scanner behavior for each category.
- Keep the embedder referenced by L2 manifests installed/loaded once per shared embedder identity, not once per L2 model package.
