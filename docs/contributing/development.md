# Development

How to set up a working environment and make a change. See [Architecture](../concepts/architecture.md)
for how the code is organized.

## Prerequisites

- Rust 1.98.0 (selected automatically by `rust-toolchain.toml`, matching CI)
- Python 3.11 or newer
- [maturin](https://www.maturin.rs/)

## Setup

```bash
git clone https://github.com/patronus-protect/patronus-security
cd patronus-ark

python -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt

# Build the Rust core and install the Python extension into the venv
.venv/bin/python -m maturin develop --manifest-path python/Cargo.toml
```

`maturin develop` rebuilds the Rust extension and reinstalls the `patronus_ark` module.
Re-run it after changing Rust code that the Python bindings touch.

## Repository layout

| Path | What lives here |
| --- | --- |
| `rust/src/` | The `patronus-ark` crate: gateway, queues, model pipelines and assets. |
| `ark-core/` | Synchronous native scanner, optional offline Wolf (`fp16` or `int8_int4`) and Cat shell verdicts; shared with the gateway. |
| `ark-core/src/detectors/`, `ark-core/src/threat/` | Shared native L1 detectors (injection, dlp, pii, mcp, shell) and the threat rules. |
| `rust/src/pipeline/` | Gateway, per-category pipelines, L3 worker, strategies, caching. |
| `rust/src/ml/`, `rust/src/assets/` | ONNX/NTDB execution and asset download/verify/cache. |
| `rust/examples/`, `python/examples/` | Runnable examples for the main flows. |
| `rust/tests/`, `python/tests/` | Integration and unit tests. |
| `python/patronus_ark/` | Python wrapper, benchmark harness, GLiNER category map. |
| `scripts/generate_docs.py` | **Generates** `docs/{rust-api,python-api,assets}.md` and `docs/reference/{l1-rule-catalog,l1-capabilities}.md` — do not hand-edit those. |
| `docs/` | This documentation site (MkDocs Material). |

## Making a maintainer change

1. Work in a focused branch.
2. Add or update tests for any behavior change ([Testing](testing.md)).
3. If you changed public Rust/Python API or the asset manifest, regenerate the reference docs:
   ```bash
   python scripts/generate_docs.py
   ```
   Both regular push/PR CI and the release pipeline verify these are current
   (`generate_docs.py --check`), so regenerate and commit them with the source change.
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

The generated pages (`docs/rust-api.md`, `docs/python-api.md`, `docs/assets.md`,
`docs/reference/l1-rule-catalog.md`, `docs/reference/l1-capabilities.md`) come from `scripts/generate_docs.py` — edit the source comments/specs, not the Markdown.
