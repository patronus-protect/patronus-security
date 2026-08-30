# Add external L1 signals

**Goal:** attach your own rule-based heuristic to a category's L1 stage — for example a
company-specific secret pattern or an allow-list check — without forking the library.

This is a **Rust** extension point: implement the `ExternalL1Detector` trait and register it
with the gateway. Your detector runs alongside the native L1 stage and appears as its own,
unchanged result under the model name `external:<id>`. Injection's built-in heuristics are
aggregated separately as `native:injection_l1`; external detectors are not folded into that
calibrated native score.

## Implement the trait

```rust
use patronus_ark::{
    EvaluationResult, ExternalL1Detector, ExternalL1Input, SecurityCategory, SecurityLevel,
};

struct InternalTokenRule;

impl ExternalL1Detector for InternalTokenRule {
    /// Stable id — surfaces as the public model name `external:internal_token`.
    fn id(&self) -> &'static str {
        "internal_token"
    }

    /// The category this heuristic extends.
    fn category(&self) -> SecurityCategory {
        SecurityCategory::Dlp
    }

    /// Evaluate one input and return a classifier result.
    fn evaluate(&self, input: &ExternalL1Input) -> EvaluationResult {
        if input.text.contains("ACME-SECRET-") {
            EvaluationResult {
                class_name: "internal_token_leak".to_string(),
                confidence: 0.99,
                level: SecurityLevel::L1.as_str().to_string(),
            }
        } else {
            EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            }
        }
    }
}
```

`EvaluationResult` is a plain struct with public fields `class_name`, `confidence`, and `level`
(the framework overwrites `level` to `L1` for external L1 detectors, so its value here does not
matter) — see the [Rust API reference](../rust-api.md). The input carries the `category` and the
`text` to score.

## Register it with the gateway

Register your detector on the gateway — `register_external_l1` takes `&self`, so you can call it
any time before the scans that should use it, not only at construction. It then runs on every scan
of that category and continues to publish its own result.

## Control it per request

Because it is exposed as `external:<id>`, you can toggle it with an
[execution gate](../reference/configuration.md#execution-gates) exactly like a native detector:

```rust
scanner.set_execution_gates(
    ScanGateMatrix::levels(true, false, false)
        .with_model("external:internal_token", false),
);
```

## When to use this

- **Yes:** deterministic, organization-specific rules (internal token formats, banned strings,
  allow-lists) that belong at L1 next to the native detectors.
- **No:** learned/statistical classification — that is what L2/L3 models are for. If you need a
  trained classifier, train an NTDB/ONNX model rather than an L1 heuristic.

External L1 detectors keep L1's guarantees: no assets, microsecond latency, always available.
