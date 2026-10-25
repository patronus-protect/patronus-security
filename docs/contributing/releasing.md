# Releasing

Releases are driven by the [`release.yml`](https://github.com/patronus-protect/patronus-security/blob/main/.github/workflows/release.yml)
workflow. The project is pre-1.0; see [`SECURITY.md`](../security.md) for the support policy.

## What a release publishes

- The **Rust crates** `patronus-ark-core` and `patronus-ark` to crates.io, in that order.
- The **Python wheels** and source distribution to PyPI.

Release preparation does not authorize publication. The release owner reviews the artifacts,
creates and pushes the release tag, and dispatches publishing; preparing agents stop before
those steps.

## The pipeline

1. **Validate** — on manual dispatch, CI checks formatting, workspace Clippy, Core native
   and Wolf tests, the legacy Ark and service tests, licenses, generated docs, and package
   contents. The Rust package check includes both crates so the unpublished Core dependency
   is verified with its consumer:
   ```bash
   cargo fmt --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test -p patronus-ark-core --no-default-features
   cargo test -p patronus-ark-core --features wolf
   cargo test -p patronus-ark-core --features download
   cargo test -p patronus-ark
   cargo deny check licenses
   cargo package -p patronus-ark-core -p patronus-ark
   python scripts/generate_docs.py --check   # generated docs must be current
   ```
   Package verification must compile the packaged source; `--no-verify` is not a release
   check. Record any ignored real-model tests separately from the default test results.
2. **Build artifacts** — `PyO3/maturin-action` builds `abi3-py311` wheels for Linux x86_64,
   macOS ARM64 and x86_64, and Windows x86_64, plus a source distribution. Every wheel is installed and
   smoke-tested; the source distribution must rebuild into a wheel.
3. **Publish** — choose one workflow channel:
   - `build` only stores the artifacts;
   - `testpypi` uploads the Python artifacts to TestPyPI;
   - `production` publishes `patronus-ark-core`, then its dependent `patronus-ark` crate,
     and only then uploads the Python artifacts to PyPI.

## Cutting a release

Releases are cut from a release branch, so `main` (and the scheduled L1 runners that merge into
it) keeps moving while the release is prepared.

1. Branch `release/X.Y.Z` from `main`. Fixes for the release land on `main` first and are
   cherry-picked into the release branch through a pull request.
2. On the release branch, update [`CHANGELOG.md`](../changelog.md) — move items from
   *Unreleased* into a new versioned section with the date. Summarize every detection change of
   the default modes at the top of the section.
3. Bump all **six Cargo package versions** — `ark-core/`, `rust/`, `python/`, `ark-api/`,
   `ark-coordinator/` and `ark-distributed-protocol/` `Cargo.toml` — plus
   `python/pyproject.toml`, the corresponding local dependency requirements and `Cargo.lock`.
   Update the image checks of `ark-api/deploy/bootstrap.sh`,
   `ark-coordinator/deploy/bootstrap.sh` and `scripts/tests/test_cube_runtime_config.py`. The
   image workflows read it with `scripts/release_version.py`, which fails if any source disagrees
   or a workspace package is omitted from the version-source inventory.
4. Ensure generated docs are current:
   ```bash
   python scripts/generate_docs.py
   git diff --exit-code docs/   # must be clean
   ```
5. Run the Release workflow with channel `build` on the prepared release branch. Inspect the
   package-verification result, wheel smoke tests and source-distribution rebuild before
   tagging. For local Python checks use the project venv:
   ```bash
   .venv/bin/python scripts/release_version.py
   .venv/bin/python -m pytest scripts/tests/test_release_version.py
   ```
6. After review, the release owner merges the preparation into the release branch and tags
   that exact commit. The tag must match the checked package version:
   ```bash
   git tag vX.Y.Z origin/release/X.Y.Z
   git push origin vX.Y.Z
   ```
   Pushes to `release/**` build the ARK API and Coordinator images and their versioned
   deployment assets.
7. The release owner manually runs the Release workflow on that tag. Start with `testpypi`;
   after installation succeeds, rerun the same tag with `production`. A branch build is not
   a production release. If publication stops after Core succeeds, inspect the registry state
   before retrying; an already published crate version cannot be replaced.
8. Merge the release branch back into `main` with a merge commit; keep *Unreleased* entries
   added on `main` meanwhile above the new section.
9. After publishing, verify install commands from crates.io and PyPI, then add live package
   badges to `README.md`.
10. Enable a GitHub Security Advisory draft channel for coordinated disclosure (per
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
