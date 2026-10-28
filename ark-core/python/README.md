# Patronus Ark Core for Python

Local PII, DLP and prompt-injection scanning with optional Wolf Defender.
This package binds only `patronus-ark-core`, under MIT OR Apache-2.0.

Install the Core Python package into the same environment as your application:

```sh
python -m pip install 'patronus-ark-core>=0.1.14'
```

Version **0.1.14** is the first standalone Core Python release. Model weights
are separate assets; native checks do not need a model or an API connection.

```python
from patronus_ark_core import Scanner, ScanControl, ScannerConfig

config: ScannerConfig = {"categories": ["pii", "dlp", "injection"]}
scanner = Scanner(config)
report = scanner.scan("Text to inspect", control=ScanControl(timeout_ms=1000))
```

Optional `ScannerConfig`, `WolfConfig`, `WarmupOptions`, `WolfExecutionOptions`
and `OnnxRuntimeOptions` TypedDicts describe accepted settings. Plain dictionary
arguments remain supported; runtime validation stays in Core.

`report` contains `input_bytes`, `native` (Core results including layers and
original UTF-8 byte/character evidence spans), and `wolf` (a separate model
result, or `None`). Native results preserve Core labels and policy evidence;
the host decides whether to block or redact. Native layer `matched` may be true
for a `safe` classification; use class/evidence/decision for native policy.
`wolf["matched"]` means the model attack probability met its threshold.

For local Wolf, configure existing assets explicitly:

```python
scanner = Scanner(
    {"wolf": {"bundle_dir": "/srv/models/wolf-defender", "threshold": 0.8,
              "precision": "fp16", "backend": "cpu"}},
    warmup={"download": "never"},
    wolf_options={"window_tokens": 256, "overlap_tokens": 0, "batch_size": 1},
)
report = scanner.scan("Text to inspect", pii=False, dlp=False)
```

Thresholds are deployment-specific. The default Wolf window profile preserves
Core's 256 total tokens / overlap 0 / batch 1 behavior. Downloads require explicit
`warmup={"download": "missing"}` during construction; scans never download.
Scanner construction warms the configured model and subsequent calls reuse it.

Calls release the GIL and run synchronously on the calling thread. Async hosts
should use a reusable worker pool. Finite ONNX deadlines share Core's timer thread.
Serialize calls to a scanner or use a bounded pool of
scanners; simultaneous use raises `ScannerBusyError`. `ScanControl.cancel()` can
be called from another thread and propagates into Core/ONNX. Expired deadlines
raise `TimeoutError`, explicit cancellation raises `CancelledError`, invalid
configuration raises `ValueError`, and scanner/resource failures raise
`RuntimeError`. No partial report is returned on failure. The timeout starts when
`ScanControl` is constructed, so sharing it across fields shares one remaining
budget, including time spent waiting before the scan.

Build from the repository using a virtual environment:

```sh
.venv/bin/python -m maturin develop --manifest-path ark-core/python/Cargo.toml
.venv/bin/python -m pytest ark-core/python/tests
```

Published wheels include CPU Wolf support. Source builds may opt out with
`maturin build --no-default-features`; such builds reject Wolf configuration.
Model weights are separate assets, not bundled with the Python package.

## Publishing setup

The first upload uses a GitHub Actions pending publisher configured at
[PyPI account publishing](https://pypi.org/manage/account/publishing/) with:

| Field | Value |
|---|---|
| PyPI project name | `patronus-ark-core` |
| Owner | `patronus-protect` |
| Repository | `patronus-security` |
| Workflow filename | `core-python.yml` |
| Environment | `release` |

The filename is relative to `.github/workflows/`. Use the existing `release`
environment, matching the publish job in `core-python.yml`. Registering the
pending publisher neither uploads files nor reserves the package name. PyPI
creates the project and converts the publisher on the first successful upload.

The Core Python workflow builds and tests wheels on Linux, macOS and Windows,
and rebuilds the source distribution. Publishing requires a separate manual
workflow dispatch with `publish: true`; its default is `false`. Preparing the
release or merging changes does not request publication. Keep `publish` off
until the release commit and publisher are reviewed.

See [PyPI's pending-publisher instructions](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
