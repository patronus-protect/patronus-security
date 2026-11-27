# Ark Core examples

Each example runs on its own. The Python examples are in
[`../python/examples`](../python/examples) and use the same config keys.

| What | Rust | Python | Model files |
| --- | --- | --- | --- |
| PII and DLP, evidence spans, redaction, rules on/off | [`pii_dlp.rs`](pii_dlp.rs) | [`01_pii_dlp.py`](../python/examples/01_pii_dlp.py) | none |
| Threat L1: the eleven attack classes, rules and built-in L1 models | [`threat_l1.rs`](threat_l1.rs) | [`02_threat_l1.py`](../python/examples/02_threat_l1.py) | none |
| Wolf Defender on every scan (Python also as the last step of the injection cascade) | [`core_scanner.rs`](core_scanner.rs) | [`03_wolf.py`](../python/examples/03_wolf.py) | Wolf (downloaded on first run) |
| Cat: `allow` / `ask` / `block` for shell commands, Cedar policies, sessions | [`core_scanner.rs`](core_scanner.rs) | [`04_cat_shell.py`](../python/examples/04_cat_shell.py) | Cat (downloaded on first run) |

```sh
cargo run -p patronus-ark-core --example pii_dlp
cargo run -p patronus-ark-core --example threat_l1
cargo run --release -p patronus-ark-core --features download --example core_scanner -- ./models

pip install patronus-ark-core
python ark-core/python/examples/01_pii_dlp.py
python ark-core/python/examples/02_threat_l1.py
python ark-core/python/examples/03_wolf.py ./models
python ark-core/python/examples/04_cat_shell.py ./models
```

`shell_policies/` holds the two Cedar policies the Cat examples load.

## Development tools

These are not usage examples. The evaluation and benchmark scripts run them:

- `threat_cascade.rs`: runs the cascade over the L1-Threat scoreboard rows.
- `text_facts.rs`: adds the text facts the L1 model training reads.
- `text_model_latency.rs`: times a text category model on the latency windows.
- `threat_profile.rs`: times every attack-class detector and L1 model at four input sizes.
- `wolf_benchmark.rs`: Wolf latency and memory on one warm scanner.
- `prepare_wolf_bundle.rs`: builds a local Wolf bundle from existing assets.
