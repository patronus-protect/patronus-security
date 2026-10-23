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
   cargo deny check licenses
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

Releases are cut from a release branch, so `main` (and the scheduled L1 runners that merge into
it) keeps moving while the release is prepared.

1. Branch `release/X.Y.Z` from `main`. Fixes for the release land on `main` first and are
   cherry-picked into the release branch through a pull request.
2. On the release branch, update [`CHANGELOG.md`](../changelog.md) — move items from
   *Unreleased* into a new versioned section with the date. Summarize every detection change of
   the default modes at the top of the section.
3. Bump the version in every workspace manifest — `rust/`, `python/`, `ark-api/`,
   `ark-coordinator/` and `ark-distributed-protocol/` `Cargo.toml`, `python/pyproject.toml` and
   `Cargo.lock` — and in the image checks of `ark-api/deploy/bootstrap.sh`,
   `ark-coordinator/deploy/bootstrap.sh` and `scripts/tests/test_cube_runtime_config.py`. The
   image workflows read the version from the manifests and fail if they disagree.
4. Ensure generated docs are current:
   ```bash
   python scripts/generate_docs.py
   git diff --exit-code docs/   # must be clean
   ```
5. Merge the release prep into the release branch and tag it:
   ```bash
   git tag vX.Y.Z origin/release/X.Y.Z
   git push origin vX.Y.Z
   ```
   Pushes to `release/**` build the ARK API and Coordinator images and their versioned
   deployment assets.
6. Manually run the Release workflow on that tag. Start with `testpypi`; after installation
   succeeds, rerun the same tag with `production`.
7. Merge the release branch back into `main` with a merge commit; keep *Unreleased* entries
   added on `main` meanwhile above the new section.
8. After publishing, verify install commands from crates.io and PyPI, then add live package
   badges to `README.md`.
9. Enable a GitHub Security Advisory draft channel for coordinated disclosure (per
   [`SECURITY.md`](../security.md)).

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
