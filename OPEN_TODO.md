# Open TODOs

Product and engineering work that is intentionally out of scope for the current
release. Each item should be independently measurable and shippable.

## Model coverage

- [ ] Add an input-origin and trust model. First define the product taxonomy and
  decision semantics, then build representative multilingual training and hard-
  negative sets. Keep model-inferred trust separate from authoritative provenance
  metadata; expose both when metadata is available. Ship only after per-class
  quality and calibration have been measured for the intended policy decisions.
- [ ] Add an input-stability model. Define the observable meaning of “stable” and
  its target classes before collecting data; distinguish content-based prediction
  from explicit source/version metadata. Validate on paraphrases, partial updates,
  stale copies, and previously unseen sources before integrating the head.
- [ ] Extend `sensitive_document` beyond its current seven classes with at least
  `medical` and `education`. Select further verticals from real product demand,
  add multilingual positive and confusing-neighbour datasets, retrain the L2 and
  L3 heads, update manifests and runtime label maps, and report per-class recall,
  precision, calibration, and cross-class confusion. The existing education
  GLiNER labels do not replace a document-level `education` class.

## Tooling

- [ ] Enforce dependency-license policy in CI by running
  `cargo deny check licenses`. `deny.toml` currently documents the allowed
  licenses, but a pull request can violate the policy without failing a check.

## Structure

- [ ] Extract `rust/gliner-onnx-engine/` into a regular workspace crate and
  replace the `#[path = "../gliner-onnx-engine/mod.rs"]` include with a normal
  Cargo dependency.

## Legal / release

- [ ] Conclude and sign the commercial license agreement (Casdo Labs GmbH).
  `LICENSE-COMMERCIAL.md` is only a summary/pointer, not the binding agreement.
