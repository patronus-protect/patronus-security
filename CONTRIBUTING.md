# Contributing

Thanks for helping improve Patronus Security. This file is the quick version; the full guides
live in the documentation:

- [Development](docs/contributing/development.md) — environment setup, repo layout, PR expectations.
- [Testing](docs/contributing/testing.md) — the test suite and pre-PR checks.
- [Releasing](docs/contributing/releasing.md) — how releases are cut and published.

## Development setup

Install Rust stable and Python 3.11 or newer.

```bash
python -m venv .venv
.venv/bin/python -m pip install maturin
maturin develop --manifest-path python/Cargo.toml
```

## Checks

Run these before opening a pull request (they mirror CI):

```bash
cargo fmt --check
cargo test -p patronus-security
.venv/bin/python -m unittest discover -s python/tests
```

If you changed the public API or the asset manifest, regenerate the reference docs and commit
the result (CI checks it is current):

```bash
python scripts/generate_docs.py
```

## Pull requests

- Keep changes focused.
- Add or update tests for behavior changes.
- Do not commit generated binaries, local virtualenvs, model downloads, or machine-specific
  benchmark outputs.
- Explicitly call out any changes to detection thresholds, asset manifests, or public result
  shapes — record them in [`CHANGELOG.md`](CHANGELOG.md).

Contributions are accepted under the terms in [`CLA.md`](CLA.md) and the project's dual
AGPL-3.0 / commercial license.

## Security issues

Please do **not** open public issues for suspected vulnerabilities. Follow the
[Security Policy](SECURITY.md) for private disclosure.
