# Open TODOs

Engineering follow-ups that are real but out of scope for now. Each is its own
focused task.

## Tokenizer consolidation

Four tokenizer paths currently exist: `kitoken` (`.kit`, NTDB L2), a custom
`MmbertPairTokenizer` (`.mmbpe`, Wolf L3), HuggingFace `tokenizers` (runtime
fallback + conversion), and `sentencepiece-rust` (GLiNER). Goal: consolidate onto
kitoken — it can load SentencePiece models via the `convert-sentencepiece`
feature (not yet enabled).

**Gate:** each replacement is a parity risk. A byte-exact token-ID parity test
against the current reference must pass before removing a load-bearing tokenizer
(see the normalizer issue documented in `gliner-integration.md`).

- [ ] Parity-test kitoken vs `sentencepiece-rust` on GLiNER `spm.model`, then drop `sentencepiece-rust`.
- [ ] Replace the custom `MmbertPairTokenizer` with kitoken; parity-test against the `.mmbpe` reference.
- [ ] Remove the HuggingFace `tokenizers` runtime fallback in `onnx.rs` once compact formats are always present; keep only as an offline converter (or drop entirely).
- [ ] Verify the RAM reduction against the numbers in `OPTIMISATIONS.md`.

## Tooling

- [ ] Add a CI job running `cargo deny check licenses` — the local `deny.toml` is not enforced until CI runs it.
- [ ] Convert the parity dev scripts (`dev/ntdb_tokenizer_parity`, `dev/mmbert_pair_tokenizer`) into real `#[test]`s.

## GLiNER semantic indicators

- [ ] Evaluate GLiNER as a high-recall binary document signal rather than only
  as exact-span NER. For semantic categories such as `trade_secret_indicator`,
  derive a document score from the maximum matching span score and tune the
  threshold for minimum false-negative rate under an explicit false-positive
  rate limit. Keep this evaluation separate from NER precision/recall and
  include hard negatives such as policies, questions, generic mentions, and
  negations (for example, "this document contains no trade secrets"). If the
  signal is useful, use it to route documents into a more precise DLP/L3
  classifier rather than treating it as the final decision.

## Structure

- [ ] Extract `rust/gliner-onnx-engine/` into a real workspace crate instead of the `#[path = "../gliner-onnx-engine/mod.rs"]` include.
- [ ] Rename `patronus-security` → `patronus-ark` (crate, Python dist `patronus_ark`, repo URLs, all imports/tests/docs). Update the `deny.toml` `exceptions` crate names accordingly.

## Legal / release

- [ ] Conclude and sign the commercial license agreement (Casdo Labs GmbH). `LICENSE-COMMERCIAL.md` is only a summary/pointer, not the binding agreement.
