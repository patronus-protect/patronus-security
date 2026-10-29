# Ark Core: L1 and Wolf only

Ark Core (`patronus-ark-core`) is the standalone, synchronous part of Patronus Ark. It scans for
**PII, DLP and prompt injection** with the native L1 rules and, optionally, local
[Wolf Defender](https://huggingface.co/patronus-studio/wolf-defender-prompt-injection-small)
inference. It is licensed **MIT OR Apache-2.0** and does not load the full Ark runtime.

## Core or full Ark?

| | Ark Core | Full Ark |
| --- | --- | --- |
| Package | `patronus-ark-core` (crate and PyPI, imports as `patronus_ark_core`) | `patronus-ark` (crate and PyPI, imports as `patronus_ark`) |
| Categories | `pii`, `dlp`, `injection` | all [eleven categories](../concepts/categories.md) |
| Detection | native L1 rules; Wolf as an optional prompt-injection model | L1, NTDB L2 heads and L3 transformers ([layered scanning](../concepts/layered-scanning.md)) |
| Execution | synchronous on the calling thread; no queue, no worker threads | asynchronous queue with background L3 workers |
| Assets | none for native rules; one Wolf bundle when enabled | L2/L3 model bundles ([manage assets](../how-to/manage-assets.md)) |
| License | MIT OR Apache-2.0 | GPL-3.0-only or commercial |

Choose Core when you embed scanning in your own process and the three categories cover your
policy: an agent hook, a proxy, a CLI, a desktop app. Choose full Ark when you need the
model-backed categories, the L2→L3 promotion, or the queue.

Both share one implementation of the native detectors, the [L1 rule catalog](../reference/l1-rule-catalog.md)
and the Wolf runner, so L1 findings and rule IDs are identical in Core and Ark.

## Install

=== "Python"

    ```bash
    pip install patronus-ark-core
    ```

    Python 3.11+. Published wheels include CPU Wolf support; model weights are separate assets.

=== "Rust"

    ```bash
    cargo add patronus-ark-core              # native rules only
    cargo add patronus-ark-core -F wolf      # + local Wolf inference from existing assets
    cargo add patronus-ark-core -F download  # + Wolf and the official asset downloader
    ```

    Native-only builds carry no HTTP client and no ONNX Runtime. GPU execution providers are
    opt-in features: `onnx-coreml`, `onnx-cuda`, `onnx-directml`, `onnx-tensorrt`.

## Scan text

=== "Python"

    ```python
    from patronus_ark_core import Scanner

    scanner = Scanner({"categories": ["pii", "dlp", "injection"]})
    report = scanner.scan("Text to inspect")
    for result in report["native"]:
        print(result["category"], result["class_name"], result["confidence"])
        for span in result["evidence_spans"]:
            print("  ", span["label"], span["start_char"], span["end_char"])
    ```

=== "Rust"

    ```rust
    use patronus_ark_core::{Scanner, ScannerConfig};

    let mut scanner = Scanner::new(ScannerConfig::default())?;
    let report = scanner.scan("Text to inspect")?;
    for result in &report.native {
        println!("{} {} {:.2}", result.category, result.class_name, result.confidence);
    }
    ```

A report has three parts:

- `input_bytes` — the size of the scanned input.
- `native` — one result per category, with `class_name`, `confidence`, ordered `layers` and
  `evidence_spans` carrying UTF-8 byte and character offsets into the original text.
- `wolf` — the separate Wolf result (`attack_probability`, `threshold`, `matched`), or `None`
  when Wolf is not configured.

Core reports findings; your application decides whether to block, redact or log. Interpret
native results by `class_name`, evidence and `decision`: a native layer's `matched` flag can be
true for a `safe` class. `wolf.matched` means the attack probability met your threshold.

The configuration also takes per-rule gates (`rules`, keyed by the stable rule IDs from the
[L1 rule catalog](../reference/l1-rule-catalog.md)), the PII/DLP scoring modes and `explain`.
The [configuration reference](../reference/configuration.md) describes these options for full Ark;
Core accepts the same rule IDs.

### Choose checks per input

One scanner can skip categories for a single input without being rebuilt. Skipping `injection`
skips both the native prompt-injection rules and Wolf.

=== "Python"

    ```python
    report = scanner.scan(tool_output, pii=False, dlp=True, injection=True)
    ```

=== "Rust"

    ```rust
    use patronus_ark_core::ScanChecks;

    let report = scanner.scan_with_checks(
        tool_output,
        ScanChecks { pii: false, dlp: true, injection: true },
    )?;
    ```

## Add Wolf Defender

Wolf Defender is a local prompt-injection classifier. Point the scanner at a bundle directory and
choose a threshold for your deployment; the examples use `0.8`.

=== "Python"

    ```python
    scanner = Scanner(
        {"wolf": {"bundle_dir": "/srv/models/wolf-defender", "threshold": 0.8}},
        warmup={"download": "missing"},
    )
    report = scanner.scan("Text to inspect", pii=False, dlp=False)
    print(report["wolf"]["attack_probability"], report["wolf"]["matched"])
    ```

=== "Rust (`download` feature)"

    ```rust
    use patronus_ark_core::{DownloadPolicy, Scanner, ScannerConfig, WarmupOptions};
    use patronus_ark_core::wolf::WolfConfig;

    let mut config = ScannerConfig::default();
    config.wolf = Some(WolfConfig::new("/srv/models/wolf-defender", 0.8));
    let mut scanner = Scanner::warmup(config, WarmupOptions {
        download: DownloadPolicy::Missing,
        ..WarmupOptions::default()
    })?;
    ```

- **Downloads happen only at construction.** The default is `download: "never"`, which accepts an
  existing complete bundle. `"missing"` fetches the official files into an empty or managed cache;
  scans never download.
- **One warm session per scanner.** Construction loads the model; later scans reuse it. Create the
  scanner once and keep it.
- **Offline and air-gapped:** prepare the bundle in a separate step with
  `warmup::prepare_assets(&config, &options)`, ship the directory, then construct with
  `download: "never"`. See [Offline & air-gapped scanning](../how-to/offline-airgapped.md).
- **Long inputs:** window size, overlap and batch size are configurable
  (`wolf_options` in Python, `WolfExecutionOptions` in Rust). The default is 256 tokens, no
  overlap, batch 1. Changing them changes the document scores, so recalibrate the threshold.
- **Precision and backend:** `precision` is `auto`, `fp16` or `int8_int4`; `backend` selects CPU or
  a GPU execution provider.

## Timeouts, cancellation and concurrency

Scans run synchronously on the calling thread. A scanner holds one session and is not shared
across simultaneous calls: serialize calls, or keep a bounded pool of scanners. In Python,
simultaneous use raises `ScannerBusyError`; calls release the GIL, so async hosts should run them
on a worker pool.

`ScanControl` adds a deadline and cancellation. The budget starts when the control is created,
and cancelling from another thread also stops an active ONNX run. On timeout or cancellation the
scan fails; it never returns a partial report.

=== "Python"

    ```python
    from patronus_ark_core import ScanControl

    control = ScanControl(timeout_ms=200)
    report = scanner.scan(text, control=control)  # TimeoutError / CancelledError on failure
    ```

=== "Rust"

    ```rust
    use std::time::Duration;
    use patronus_ark_core::{ScanChecks, ScanControl};

    let control = ScanControl::with_timeout(Duration::from_millis(200))?;
    let report = scanner.scan_with_control(text, ScanChecks::default(), &control)?;
    ```

Inputs are limited to 1 MiB and 10,000 evidence spans by default (`max_input_bytes`,
`max_findings`). Exceeding a limit returns an error, never a truncated clean report.

## Further reading

- [Core crate README](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/README.md)
  — Rust API, Wolf execution details, bundle preparation and verification.
- [Core Python package README](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/python/README.md)
  — typed configuration dictionaries and error types.
- [Native detectors](../concepts/detectors.md) and [L1 capabilities](../reference/l1-capabilities.md)
  — what the L1 rules cover.
