# Contributing

Patronus Ark is currently maintained as an open-source project, but
external pull requests are not accepted at this time. The guides below document
the maintainer workflow:

- [Development](docs/contributing/development.md) — environment setup and repository layout.
- [Testing](docs/contributing/testing.md) — the test suite and pre-release checks.
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
cargo test -p patronus-ark
.venv/bin/python -m unittest discover -s python/tests
```

If you changed the public API or the asset manifest, regenerate the reference docs and commit
the result (CI checks it is current):

```bash
python scripts/generate_docs.py
```

## Maintainer changes

- Keep changes focused.
- Add or update tests for behavior changes.
- Do not commit generated binaries, local virtualenvs, model downloads, or machine-specific
  benchmark outputs.
- Explicitly call out any changes to detection thresholds, asset manifests, or public result
  shapes — record them in [`CHANGELOG.md`](CHANGELOG.md).

## Security issues

Please do **not** open public issues for suspected vulnerabilities. Follow the
[Security Policy](SECURITY.md) for private disclosure.
