# Installation

Patronus Ark ships as a Rust crate (`patronus-ark`) and a Python package (`patronus-ark`,
imported as `patronus_ark`). Both are built from the same Rust core, so you install whichever
fits your stack — no repository checkout required.

## Requirements

| | Minimum | Notes |
| --- | --- | --- |
| Python | 3.11+ | wheels target the stable ABI (`abi3-py311`), so one wheel covers 3.11+ |
| Rust | stable toolchain | for the `patronus-ark` crate |
| Disk | ~100–250 MB per model bundle | native L1 needs none; L2/L3 assets download on demand |

Model assets are downloaded from Hugging Face on first use. Set `HF_TOKEN` if you need
authenticated or rate-limited access (see [Manage model assets](../how-to/manage-assets.md)).

## Python

```bash
pip install patronus-ark
```

Verify the install:

```python
from patronus_ark import SecurityGateway

scanner = SecurityGateway(categories=["injection"], max_level="l1", download_files=False)
scanner.warmup()
print(scanner.runtime_readiness())
```

The wheel bundles the compiled Rust extension, so no Rust toolchain is needed to *use* the
Python package.

## Rust

Add the crate with Cargo:

```bash
cargo add patronus-ark
```

Or in `Cargo.toml`:

```toml
[dependencies]
patronus-ark = "0.1"
```

Verify:

```rust
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};

fn main() {
    let mut scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Injection],
        SecurityLevel::L1,
        None,   // model dir; None uses the platform cache directory
        false,  // download_files
    );
    scanner.warmup().expect("warmup");
    println!("{:?}", scanner.runtime_readiness());
}
```

### Optional ONNX execution providers

The Rust crate exposes feature flags for hardware-accelerated ONNX Runtime backends. Enable the
one matching your target (CPU is the default and needs no feature):

```toml
patronus-ark = { version = "0.1", features = ["onnx-coreml"] }   # macOS
# other options: onnx-cuda, onnx-directml, onnx-tensorrt
```

See [Tune performance & memory](../how-to/tune-performance.md) for when each backend helps.

## Logging

The library logs through the [`log`](https://crates.io/crates/log) facade (warmup progress,
asset downloads). Messages are silent by default — install a logger such as `env_logger` in
your application to see them:

```rust
env_logger::init();
```

## Next steps

- [Quickstart](quickstart.md) — your first scan, in Python and Rust.
- [Choose categories & levels](../how-to/choose-categories-and-levels.md) — pick what to scan.
- [Architecture](../concepts/architecture.md) — how the pieces fit together.
