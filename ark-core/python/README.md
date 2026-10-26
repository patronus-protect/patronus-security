# Patronus Ark Core for Python

Local PII, DLP and prompt-injection scanning with optional Wolf Defender.
This package binds only `patronus-ark-core`, under MIT OR Apache-2.0.

```sh
pip install patronus-ark-core
```

```python
from patronus_ark_core import Scanner, ScanControl

scanner = Scanner({"categories": ["pii", "dlp", "injection"]})
report = scanner.scan("Text to inspect", control=ScanControl(timeout_ms=1000))
```

`report` contains `input_bytes`, `native` (Core results including layers and
original UTF-8 byte/character evidence spans), and `wolf` (a separate model
result, or `None`). Native results preserve Core labels and policy evidence;
the host decides whether to block or redact.

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
`RuntimeError`. No partial report is returned on failure.

Build from the repository using a virtual environment:

```sh
.venv/bin/python -m maturin develop --manifest-path ark-core/python/Cargo.toml
.venv/bin/python -m pytest ark-core/python/tests
```

Published wheels include CPU Wolf support. Source builds may opt out with
`maturin build --no-default-features`; such builds reject Wolf configuration.
Model weights are separate assets, not bundled with the Python package.
