<p align="center">
  <img src="https://raw.githubusercontent.com/patronus-protect/patronus-security/main/docs/img/patronus-ark-banner.svg" alt="Patronus Ark — layered security scanning for LLM and agent traffic" width="100%">
</p>

<p align="center">
  <a href="https://crates.io/crates/patronus-ark"><img src="https://img.shields.io/crates/v/patronus-ark.svg?style=flat-square&logo=rust&logoColor=white" alt="crates.io"></a>
  <a href="https://pypi.org/project/patronus-ark/"><img src="https://img.shields.io/pypi/v/patronus-ark.svg?style=flat-square&logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://pepy.tech/projects/patronus-ark?timeRange=threeMonths&amp;category=version&amp;includeCIDownloads=true&amp;granularity=weekly&amp;viewType=line&amp;versions=Total%2C0.*"><img src="https://img.shields.io/pepy/dt/patronus-ark?style=flat-square&amp;label=downloads" alt="PyPI downloads (Pepy)"></a>
  <a href="https://pypi.org/project/patronus-ark/"><img src="https://img.shields.io/pypi/pyversions/patronus-ark.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://patronus-protect.github.io/patronus-security/"><img src="https://img.shields.io/badge/docs-patronus--ark-38bdf8?style=flat-square" alt="Documentation"></a>
  <a href="https://github.com/patronus-protect/patronus-security/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/patronus-protect/patronus-security/ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
  <a href="https://github.com/patronus-protect/patronus-security/blob/main/ark-core/LICENSE-MIT"><img src="https://img.shields.io/badge/core%20license-MIT%20OR%20Apache--2.0-34d399?style=flat-square" alt="Ark Core license: MIT OR Apache-2.0"></a>
  <a href="https://github.com/patronus-protect/patronus-security/blob/main/LICENSE"><img src="https://img.shields.io/badge/ark%20license-GPL--3.0--only%20or%20commercial-34d399?style=flat-square" alt="Ark license: GPL-3.0-only or commercial"></a>
</p>

# Patronus Ark

**Local security scanning for prompt injection, DLP, PII, and agentic tool risks — in Rust and Python.**

Patronus Ark is the open-source scanning engine behind [Patronus Protect](https://patronus.studio),
an on-device AI firewall. It inspects the text flowing in and out of AI applications — prompts,
tool calls, tool outputs, and documents — and classifies the security risk **locally**, without
sending anything to a cloud service.

📖 **[Documentation](https://patronus-protect.github.io/patronus-security/)** ·
[Choose a package](https://patronus-protect.github.io/patronus-security/getting-started/core/) ·
[Installation](https://patronus-protect.github.io/patronus-security/getting-started/installation/) ·
[Quickstart](https://patronus-protect.github.io/patronus-security/getting-started/quickstart/) ·
[Python API](https://patronus-protect.github.io/patronus-security/python-api/) ·
[Rust API](https://patronus-protect.github.io/patronus-security/rust-api/)

## Choose a package

Patronus Ark comes in two layers. Start with **Core** unless you need the model-backed categories.

| | **Ark Core** | **Ark** (full runtime) |
| --- | --- | --- |
| Packages | `patronus-ark-core` (crate and PyPI, imports as `patronus_ark_core`) | `patronus-ark` (crate and PyPI, imports as `patronus_ark`) |
| Categories | PII, DLP, prompt injection | eleven categories, including dynamic PII, sensitive documents, agentic tools, routing intent, threat type and shell commands |
| Detection | native L1 rules, plus optional local [Wolf Defender](https://huggingface.co/patronus-studio/wolf-defender-prompt-injection-small) inference for prompt injection | L1 rules, NTDB L2 heads and L3 transformers with a trained promote-router |
| Execution | synchronous, on the calling thread; no queue, no worker threads | asynchronous queue with background L3 workers, plus synchronous `scan_all()` |
| Assets | none for native rules; one Wolf bundle when enabled | L2/L3 model bundles, downloaded on demand or synced offline |
| License | **MIT OR Apache-2.0** | **GPL-3.0-only** or commercial |

Full Ark builds on Core: it runs the same native detectors and the same Wolf runner, so L1
results match between the two. For an HTTP service, [`ark-api`](https://github.com/patronus-protect/patronus-security/blob/main/ark-api/README.md) wraps the full
runtime; see [Deploy the HTTP API](https://patronus-protect.github.io/patronus-security/how-to/deploy-http-api/).

## Quickstart: Ark Core

```bash
pip install patronus-ark-core            # Python 3.11+, wheels include CPU Wolf support
cargo add patronus-ark-core              # Rust, native rules only
cargo add patronus-ark-core -F download  # Rust, with Wolf inference and asset download
```

```python
from patronus_ark_core import Scanner

scanner = Scanner({"categories": ["pii", "dlp", "injection"]})
report = scanner.scan("Text to inspect")
for result in report["native"]:
    print(result["category"], result["class_name"], result["confidence"])
```

```rust
use patronus_ark_core::{Scanner, ScannerConfig};

let mut scanner = Scanner::new(ScannerConfig::default())?;
let report = scanner.scan("Text to inspect")?;
for result in &report.native {
    println!("{} {} {:.2}", result.category, result.class_name, result.confidence);
}
```

Native rules need no downloads. To add local Wolf inference for prompt injection, point the
scanner at a model directory and allow the first warmup to fetch the official bundle:

```python
scanner = Scanner(
    {"wolf": {"bundle_dir": "/srv/models/wolf-defender", "threshold": 0.8}},
    warmup={"download": "missing"},
)
report = scanner.scan("Text to inspect")
print(report["wolf"]["attack_probability"], report["wolf"]["matched"])
```

Reports keep native findings (with byte and character evidence spans) and the Wolf result
separate; your application decides whether to block or redact. See the
[Core guide](https://patronus-protect.github.io/patronus-security/getting-started/core/) for
per-input checks, cancellation and deadlines, and the [Core crate README](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/README.md) for
the full Rust API and Wolf execution options.

## Quickstart: full Ark

```bash
pip install patronus-ark      # Python 3.11+
cargo add patronus-ark        # Rust
```

See [Installation](https://patronus-protect.github.io/patronus-security/getting-started/installation/)
for model-asset requirements and `HF_TOKEN` setup. The primary path is the asynchronous queue:
enqueue texts, drain results from the shared queue.

```python
from patronus_ark import SecurityGateway

scanner = SecurityGateway(categories=["injection", "dlp", "pii"], max_level="l2")
scanner.warmup()

# In a real app the consume loop runs on its own thread so you can keep enqueuing —
# see the Quickstart.
scanner.enqueue("Text to inspect")
while (event := scanner.consume_next_event(timeout=1.0)) is not None:
    if event["event_type"] == "result":
        r = event["result"]
        print(r["category"], r["class_name"], r["confidence"])
    else:
        break  # terminal "finished" event
```

```rust
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};

let mut scanner = SecurityGateway::with_max_level(
    vec![SecurityCategory::Injection, SecurityCategory::Dlp],
    SecurityLevel::L2,
    None,  // model dir; None uses the platform cache directory
    true,  // download missing L2 assets on first warmup
);
scanner.warmup().expect("warmup");

let results = scanner.scan_all("Text to inspect");
```

A synchronous `scan_all()` is available in both languages for simple, single-text call sites.

### What full Ark adds

- **Layered scanning** — native L1 rules provide immediate findings and context; model-backed
  categories use NTDB L2 to select the chunks that genuinely need a transformer.
- **Eleven categories** — prompt injection, DLP, PII, dynamic PII (GLiNER spans), sensitive
  documents, the agentic tool trio (class/action/tags), routing intent, threat type, and shell
  command risk.
- **Asynchronous by default** — `enqueue()` returns immediately, results stream back through one
  shared queue, and promoted L3 work never blocks ready L1/L2 results.
- **Execution gates** — turn levels, individual scanners, and stable L1 rule IDs on or off per
  request; L2/L3 and extra GLiNER label groups can depend on metadata or earlier final results.
- **Offline-capable** — split asset sync from runtime start for air-gapped deployments.
- **Built-in benchmark** — every gateway can measure itself on the validation samples shipped with
  the package: accuracy, macro-F1, latency, throughput, and peak RSS.

## How scanning works

Categories use the layers that fit their detector contract:

| Layer | What it is | Cost | Availability |
| --- | --- | --- | --- |
| **L1** | Native rule-based detectors (Core and Ark) | input-dependent | no assets; gate-controlled |
| **L2** | NTDB packages (shared mmBERT tokenizer/static embedder + lightweight ONNX heads) | milliseconds | Ark, when assets are cached |
| **L3** | Full ONNX transformers aligned with L2's tokenizer and embeddings, run by a background worker | tens of ms | Ark, when assets are cached |

Core runs L1 and, when configured, Wolf Defender as a separate prompt-injection model result.

L2 packages carry a trained promote-router that decides when a case actually needs L3, so most
traffic never touches a transformer. When a scan is promoted, the queue publishes the L2 fallback
first and the final L3 result later. Compatible L2 chunks pass their existing mmBERT token IDs to
L3 instead of being tokenized again; L3 errors and timeouts degrade back to L2.

Native-only `pii` and `dlp` do not escalate. PII L1 validates deterministic identifiers and
anchor-bound values such as contact, payment, government, account, and employee identifiers. DLP
L1 covers credentials and secrets plus opt-in business identifiers, internal metrics, source code,
SQL, dumps, and logs. All built-in L1 matchers produce source-bound components before a result;
PII and DLP findings return evidence spans, including native operation and MCP rules. Both can
expose non-finding `l1_anchors` as structured context when `execution_gates.explain` is enabled.
`dynamic-pii` is the complementary GLiNER L3 pipeline for semantic entities such as people,
organizations, and locations.

Stable rule gates can disable one native rule without disabling its siblings:

```python
scanner.set_execution_gates({
    "rules": {"pii_employee_id": False, "dlp_sql_statement": False},
})
```

Rust, Python, and the Ark API share credential/secret-only DLP rule defaults;
broader DLP families are available through an explicit `gates.rules` profile.

Read more: [Architecture](https://patronus-protect.github.io/patronus-security/concepts/architecture/) ·
[Layered scanning](https://patronus-protect.github.io/patronus-security/concepts/layered-scanning/) ·
[Categories](https://patronus-protect.github.io/patronus-security/concepts/categories/) ·
[L1 rule catalog](https://patronus-protect.github.io/patronus-security/reference/l1-rule-catalog/) ·
[Models & NTDB](https://patronus-protect.github.io/patronus-security/concepts/models-and-ntdb/) ·
[Threat model](https://patronus-protect.github.io/patronus-security/concepts/threat-model/)

## Examples

Runnable examples for the full runtime live in [`rust/examples/`](https://github.com/patronus-protect/patronus-security/blob/main/rust/examples) and
[`python/examples/`](https://github.com/patronus-protect/patronus-security/blob/main/python/examples) — basic scan, enqueue/consume, L2→L3 promotion, execution
gates, dynamic PII, cache configuration, and a Dedicated-vs-Multi L3 comparison.

```bash
cargo run --example 01_basic_scan
python python/examples/01_basic_scan.py
```

The [examples walkthrough](https://patronus-protect.github.io/patronus-security/USAGE/) explains
when to use each. Core ships Wolf tooling examples in [`ark-core/examples/`](https://github.com/patronus-protect/patronus-security/tree/main/ark-core/examples)
(bundle preparation and a latency/RSS benchmark).

## Repository layout

- `ark-core/` — `patronus-ark-core`: synchronous native scanner and optional Wolf runtime, with its
  Python bindings in `ark-core/python/`.
- `rust/` — `patronus-ark`: the full runtime (levels, queue, L2/L3 models) built on Core.
- `python/` — Python bindings for the full runtime, built with maturin/PyO3, plus the validation
  samples used by the built-in local benchmark.
- `ark-api/`, `ark-coordinator/`, `ark-distributed-protocol/` — the HTTP service, the L3 fleet
  coordinator and their shared wire contract (not published as crates).
- `docs/` — the MkDocs Material site published at
  [patronus-protect.github.io/patronus-security](https://patronus-protect.github.io/patronus-security/).

## Development

```bash
cargo fmt --check
cargo test -p patronus-ark-core --features wolf
cargo test -p patronus-ark

cd python && maturin develop && cd ..
.venv/bin/python -m unittest discover -s python/tests
```

This repository does not accept external contributions. Maintainer documentation:
[Development](https://patronus-protect.github.io/patronus-security/contributing/development/) ·
[Testing](https://patronus-protect.github.io/patronus-security/contributing/testing/) ·
[Releasing](https://patronus-protect.github.io/patronus-security/contributing/releasing/)

## Security

Report vulnerabilities privately — see [SECURITY.md](https://github.com/patronus-protect/patronus-security/blob/main/SECURITY.md). The
[threat model](https://patronus-protect.github.io/patronus-security/concepts/threat-model/)
documents what Patronus Ark does and does not defend against.

## License

- **Ark Core** (`ark-core/`, including its Python package): **MIT OR Apache-2.0**. Core-authored
  rule catalogs carry the same license; per-rule `source_license` fields describe upstream
  provenance. See [`ark-core/LICENSE-MIT`](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/LICENSE-MIT) and
  [`ark-core/LICENSE-APACHE`](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/LICENSE-APACHE).
- **Full Ark** and everything else in this repository: **GPL-3.0-only** for open-source use, or a
  **commercial license** for distributing Patronus Ark in proprietary products. See
  [LICENSE](https://github.com/patronus-protect/patronus-security/blob/main/LICENSE) and
  [LICENSE-COMMERCIAL.md](https://github.com/patronus-protect/patronus-security/blob/main/LICENSE-COMMERCIAL.md).
