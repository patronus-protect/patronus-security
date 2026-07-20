# Development

How to set up a working environment and make a change. See [Architecture](../concepts/architecture.md)
for how the code is organized.

## Prerequisites

- Rust stable toolchain
- Python 3.11 or newer
- [maturin](https://www.maturin.rs/)

## Setup

```bash
git clone https://github.com/patronus-protect/patronus-security
cd patronus-security

python -m venv .venv
.venv/bin/python -m pip install maturin

# Build the Rust core and install the Python extension into the venv
maturin develop --manifest-path python/Cargo.toml
```

`maturin develop` rebuilds the Rust extension and reinstalls the `patronus_ark` module.
Re-run it after changing Rust code that the Python bindings touch.

## Repository layout

| Path | What lives here |
| --- | --- |
| `rust/src/` | The `patronus-ark` crate: gateway, pipelines, detectors, ml, assets, threat. |
| `rust/src/detectors/` | Native L1 detectors (injection, dlp, pii, mcp). |
| `rust/src/pipeline/` | Gateway, per-category pipelines, L3 worker, strategies, caching. |
| `rust/src/ml/`, `rust/src/assets/` | ONNX/NTDB execution and asset download/verify/cache. |
| `rust/examples/`, `python/examples/` | Runnable examples for the six core flows (+ stress harnesses). |
| `rust/tests/`, `python/tests/` | Integration and unit tests. |
| `python/patronus_ark/` | Python wrapper, benchmark harness, GLiNER category map. |
| `scripts/generate_docs.py` | **Generates** `docs/{rust-api,python-api,assets}.md` — do not hand-edit those. |
| `docs/` | This documentation site (MkDocs Material). |

## Making a maintainer change

1. Work in a focused branch.
2. Add or update tests for any behavior change ([Testing](testing.md)).
3. If you changed public Rust/Python API or the asset manifest, regenerate the reference docs:
   ```bash
   python scripts/generate_docs.py
   ```
   CI checks these are up to date (`generate_docs.py --check`).
4. Run all [checks](testing.md#pre-release-checks) before merging.

## Change expectations

- Keep changes focused and reversible.
- Add or update tests for behavior changes.
- **Do not** commit generated binaries, virtualenvs, model downloads, `target/`, or
  machine-specific benchmark output (all covered by `.gitignore`).
- **Explicitly call out** any change to detection thresholds, asset manifests, or public result
  shapes — these affect downstream users and are reviewed with extra care.

External pull requests are not accepted at this time.

## Editing this documentation

The docs are Markdown under `docs/`, built with MkDocs Material. Preview locally:

```bash
pip install mkdocs-material
mkdocs serve      # http://127.0.0.1:8000
mkdocs build --strict   # what CI runs
```

The generated API reference pages (`docs/rust-api.md`, `docs/python-api.md`, `docs/assets.md`)
come from `scripts/generate_docs.py` — edit the source comments/specs, not the Markdown.
