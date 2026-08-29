# dev/ — internal scripts

These are **not** user-facing examples. They are development, benchmark, and
tokenizer-parity scripts used while working on the library. User-facing examples
live in [`../examples/`](../examples/) (`01_basic_scan`, `02_enqueue_consume`,
`03_l2_l3_promotion`, `04_execution_gates`, `05_dynamic_pii`).

Each script is registered in `Cargo.toml` with an explicit `path`, so it keeps
compiling and can be run with:

```bash
cargo run --example <name> -- <args>
```

Most require local model assets or datasets and print usage when run without
arguments.

| Script | Purpose |
| --- | --- |
| `all_categories_benchmark` | End-to-end latency/accuracy across all categories |
| `gliner_onnx_ner_benchmark` | GLiNER NER latency/quality benchmark |
| `injection_pair_gliner_benchmark` | Injection + GLiNER paired benchmark |
| `local_l1_l2_gliner_benchmark` | Local L1/L2 + GLiNER benchmark |
| `injection_gliner_memory_smoke` | Process RSS smoke for injection + GLiNER |
| `ntdb_memory_smoke` | Process RSS smoke for the NTDB L2 executor |
| `wolf_memory_smoke` | Process RSS smoke for Wolf Defender L3 |
| `mmbert_pair_tokenizer` | mmBERT `.mmbpe` vs HuggingFace parity check |
