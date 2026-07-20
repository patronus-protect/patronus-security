# Releasing

Releases are driven by the [`release.yml`](https://github.com/patronus-protect/patronus-security/blob/main/.github/workflows/release.yml)
workflow. The project is pre-1.0; see [`SECURITY.md`](../security.md) for the support policy.

## What a release publishes

- The **Rust crate** `patronus-ark` to crates.io.
- The **Python wheels** and source distribution to PyPI.

## The pipeline

1. **Validate** — on manual dispatch, CI runs:
   ```bash
   cargo fmt --check
   cargo test -p patronus-ark
   cargo publish -p patronus-ark --dry-run
   python scripts/generate_docs.py --check   # generated docs must be current
   ```
2. **Build artifacts** — `PyO3/maturin-action` builds `abi3-py311` wheels for Linux x86_64,
   macOS ARM64, and Windows x86_64, plus a source distribution. Every wheel is installed and
   smoke-tested; the source distribution must rebuild into a wheel.
3. **Publish** — choose one workflow channel:
   - `build` only stores the artifacts;
   - `testpypi` uploads the Python artifacts to TestPyPI;
   - `production` publishes the Rust crate first and then uploads the Python artifacts to PyPI.

## Cutting a release

1. Update [`CHANGELOG.md`](../changelog.md) — move items from *Unreleased* into a new versioned
   section with the date.
2. Bump the version in `Cargo.toml` (and `python/` metadata if applicable).
3. Ensure generated docs are current:
   ```bash
   python scripts/generate_docs.py
   git diff --exit-code docs/   # must be clean
   ```
4. Create and push the release tag, then manually run the Release workflow on that tag. Start
   with `testpypi`; after installation succeeds, rerun the same tag with `production`.
5. After publishing, enable a GitHub Security Advisory draft channel for coordinated disclosure
   (per [`SECURITY.md`](../security.md)).

TestPyPI and PyPI publishing use trusted publishing. Configure the GitHub environments
`testpypi` and `release` as trusted publishers for `.github/workflows/release.yml`. crates.io
publishing uses the `CARGO_REGISTRY_TOKEN` secret in the `release` environment.

For a local macOS check before dispatching the workflow:

```bash
maturin build --manifest-path python/Cargo.toml --release --out dist
.venv/bin/python -m pip install --force-reinstall dist/*.whl
.venv/bin/python -c "import patronus_ark"
```

## Versioning

Pre-1.0, treat any change to **detection thresholds**, the **asset manifest**, or **public
result shapes** as potentially breaking for downstream users and document it prominently in the
changelog, even if the semver bump is small.

## Documentation site

The docs site is deployed separately by the [`docs.yml`](https://github.com/patronus-protect/patronus-security/blob/main/.github/workflows/docs.yml)
workflow on every push to `main` that touches `docs/` or `mkdocs.yml` — it is not tied to the
package release.
