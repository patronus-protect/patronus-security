# Add external L1 signals

**Goal:** attach your own rule-based heuristic to a category's L1 stage — for example a
company-specific secret pattern or an allow-list check — without forking the library.

This is a **Rust** extension point: implement the `ExternalL1Detector` trait and register it
with the gateway. Your detector runs alongside the native L1 detectors and appears in results
under the model name `external:<id>`.

## Implement the trait

```rust
use patronus_ark::{
    EvaluationResult, ExternalL1Detector, ExternalL1Input, SecurityCategory,
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
            EvaluationResult::detected("internal_token_leak", 0.99)
        } else {
            EvaluationResult::safe()
        }
    }
}
```

The exact constructors on `EvaluationResult` are in the
[Rust API reference](../rust-api.md); the input carries the `category` and the
`text` to score.

## Register it with the gateway

Attach your detector when building the gateway so it participates in L1 for its category. It
then runs on every scan of that category, and its verdict is combined into the category result
just like a native detector.

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
