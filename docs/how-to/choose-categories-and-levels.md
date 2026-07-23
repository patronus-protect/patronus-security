# Choose categories & levels

**Goal:** pick the right set of `categories` and the right `max_level` for your use case, so
you scan what matters without paying for what you don't.

## Pick categories by use case

| Use case | Suggested categories |
| --- | --- |
| Prompt firewall (block injections) | `injection`, `threat` |
| DLP / leak prevention | `dlp`, `pii`, `sensitive_document` |
| Open-vocabulary PII extraction | `dynamic-pii` (+ `pii` for validated identifiers) |
| Agent tool-use guard | `injection`, `tool_class`, `tool_action`, `tool_tags` |
| Request router | `routing` |

Scan only what you will act on — each category adds work. See [Categories](../concepts/categories.md)
for what each one classifies and which layers back it.

## Pick a level

`max_level` is the hard ceiling on escalation:

| `max_level` | Use when |
| --- | --- |
| `l1` | You want microsecond, always-offline, rule-based coverage only. |
| `l2` | You want learned classification but never the transformer cost. Great default for high-throughput paths. |
| `l3` | You want maximum accuracy and can afford occasional transformer inference on promoted requests. |

=== "Python"

    ```python
    scanner = SecurityGateway(
        categories=["injection", "threat"],
        max_level="l2",          # learned classifiers, no L3
        download_files=True,
        download_categories=["injection", "threat"],
    )
    scanner.warmup()
    ```

=== "Rust"

    ```rust
    use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};

    let mut scanner = SecurityGateway::with_download_categories(
        vec![SecurityCategory::Injection, SecurityCategory::Threat],
        SecurityLevel::L2,       // learned classifiers, no L3
        None,
        true,                    // download_files
        Some(vec![SecurityCategory::Injection, SecurityCategory::Threat]),
    );
    scanner.warmup().expect("warmup");
    ```

## Consider the offline implications

- `pii`, `dlp` → native L1, no assets ever.
- `injection`, `threat` → native L1 always works; L2/L3 need assets.
- `sensitive_document`, `tool_*`, `routing` → **model-only**; with no cached assets they produce
  no verdict.
- `dynamic-pii` → **L3-only**; needs its GLiNER bundle or it cannot run.

If you need guaranteed coverage in an air-gapped environment, prefer categories with a native
L1 stage or pre-cache assets (see [Offline & air-gapped](offline-airgapped.md)).

## Download only what you use

Enable downloads for just the categories you configured with `download_categories`:

```python
scanner = SecurityGateway(
    categories=["injection", "dlp", "pii"],
    max_level="l2",
    download_files=True,
    download_categories=["injection"],   # dlp/pii are native; only injection downloads
)
```

## Turn levels or detectors off per request

Use [execution gates](../reference/configuration.md#execution-gates) to disable a level or a
specific detector below the ceiling, without rebuilding the gateway:

=== "Python"

    ```python
    scanner.set_execution_gates({"levels": {"l1": True, "l2": True, "l3": False}})
    # ... later ...
    scanner.set_execution_gates(None)   # reset to all enabled
    ```

=== "Rust"

    ```rust
    use patronus_ark::ScanGateMatrix;

    scanner.set_execution_gates(ScanGateMatrix::levels(true, true, false));
    // ... later ...
    scanner.set_execution_gates(ScanGateMatrix::all_enabled());   // reset
    ```
