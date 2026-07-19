# Releasing

Releases are driven by the [`release.yml`](https://github.com/patronus-protect/patronus-security/blob/main/.github/workflows/release.yml)
workflow. The project is pre-1.0; see [`SECURITY.md`](../security.md) for the support policy.

## What a release publishes

- The **Rust crate** `patronus-security` to crates.io.
- The **Python wheels** (built per-OS with maturin) to PyPI.

## The pipeline

1. **Validate** — on a release tag or manual dispatch, CI runs:
   ```bash
   cargo fmt --check
   cargo test -p patronus-security
   cargo publish -p patronus-security --dry-run
   python scripts/generate_docs.py --check   # generated docs must be current
   ```
2. **Build wheels** — `PyO3/maturin-action` builds `abi3-py311` wheels on each target OS and
   uploads them as artifacts.
3. **Publish** — the crate is published to crates.io and the wheels to PyPI.

## Cutting a release

1. Update [`CHANGELOG.md`](../changelog.md) — move items from *Unreleased* into a new versioned
   section with the date.
2. Bump the version in `Cargo.toml` (and `python/` metadata if applicable).
3. Ensure generated docs are current:
   ```bash
   python scripts/generate_docs.py
   git diff --exit-code docs/   # must be clean
   ```
4. Tag the release (the workflow triggers on the tag) or run the workflow manually with the
   publish input.
5. After publishing, enable a GitHub Security Advisory draft channel for coordinated disclosure
   (per [`SECURITY.md`](../security.md)).

## Versioning

Pre-1.0, treat any change to **detection thresholds**, the **asset manifest**, or **public
result shapes** as potentially breaking for downstream users and document it prominently in the
changelog, even if the semver bump is small.

## Documentation site

The docs site is deployed separately by the [`docs.yml`](https://github.com/patronus-protect/patronus-security/blob/main/.github/workflows/docs.yml)
workflow on every push to `main` that touches `docs/` or `mkdocs.yml` — it is not tied to the
package release.
