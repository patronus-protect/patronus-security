# Contributing

## Development Setup

Install Rust stable and Python 3.11 or newer.

```bash
python -m venv .venv
.venv/bin/python -m pip install maturin
cd python
../.venv/bin/maturin develop
```

## Checks

Run these before opening a pull request:

```bash
cargo fmt --check
cargo test -p patronus-security
.venv/bin/python -m unittest discover -s python/tests
```

## Pull Requests

- Keep changes focused.
- Add or update tests for behavior changes.
- Do not commit generated binaries, local virtualenvs, model downloads, or machine-specific benchmark outputs.
- Call out any changes to detection thresholds, asset manifests, or public result shapes.
