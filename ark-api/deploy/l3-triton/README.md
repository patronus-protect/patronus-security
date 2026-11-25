# Unified L3 on an NVIDIA GPU

## Dedicated Wolf Small alongside Lion

Ark's dedicated Injection L3 uses Wolf Small, not the Unified Lion adapter below.
The pinned Wolf Small revision `e3749b44a0f85268347cdfb6818f4ef39e8ff203`
has a separate TensorRT plan and Triton model name
`wolf_defender_small_e3749b44a0f85268347cdfb6818f4ef39e8ff203_fp16_256`.
On the GPU host, `prepare_wolf.sh` builds it in `wolf-models/` without changing
the live Lion repository. Run `verify_wolf.py` against a test Triton endpoint
before copying the verified model into the live `models/` repository. Set
`TRITON_VERIFY_URL` to the private test endpoint and `LION_VERIFY_URL` to the
private live endpoint when running `verify_wolf.py`. After a
controlled Triton restart, verify that **both** model names report ready.

Set `PATRONUS_WOLF_TRITON_URL=http://<triton-wireguard-address>:8090` on Ark
workers to send dedicated Wolf logits over WireGuard. The IONOS image contains
only Wolf tokenizer and configuration metadata, never the Wolf ONNX graph or
TensorRT weights. The Worker retains local tokenization, document windows,
thresholds and verdict assembly. The remote
response must name the pinned model and version 1 and contain finite FP32
`logits` with shape `[batch, 2]`; an invalid or unavailable response fails the
scan instead of falling back to CPU. The IONOS Compose deployment requires the
URL and its image cannot run Wolf locally. The library still supports local Wolf
when used outside this deployment.
`PATRONUS_WOLF_TRITON_TIMEOUT_MS` defaults to 1000 ms. Keep the Triton endpoint
private because the HTTP service has no application authentication.

## Dynamic PII GLiNER on the same L4

The dedicated dynamic PII L3 model is the pinned GLiNER small v2.5 edge export
`6cfcbd93d7fc6f5e1658f80afa38f73891b91693`. Run `prepare_gliner.sh` on
the GPU host to stage its FP16 graph in `gliner-models/`. It runs through
Triton's ONNX Runtime CUDA backend. Verify its logits and entity spans against
the pinned ONNX source before adding it to the live model repository. The
Worker keeps only GLiNER tokenizer/configuration files for text preparation
and span decoding; the image excludes its ONNX graph.

Set `PATRONUS_GLINER_TRITON_URL=http://<triton-wireguard-address>:8090` on the
Worker. Startup performs real dynamic PII warmup inference on Triton. Remote
responses must identify the pinned model and version 1 and return finite FP32
logits of the expected shape. There is no local CPU fallback in the IONOS image.
`PATRONUS_GLINER_TRITON_TIMEOUT_MS` defaults to 3000 ms.

Lion Warden uses the same pinned revision and seven heads already configured by
Ark: `30ea449339d1075a31fcffa9199ebee4f2cfaf9a`. The remote adapter changes model
execution while local L1/L2, Unified scheduling, head decoding, caches,
and gateway admission retain their existing behavior. Tool-property projection
preserves independent per-property promotion, aggregation, and arbitration.

## GPU host

Requirements: Docker with NVIDIA GPU support, Python 3 with venv, curl, and a
private WireGuard address. From this directory:

```sh
bash prepare.sh
export TRITON_BIND_ADDRESS="<triton-wireguard-address>"
docker compose up -d
.venv/bin/pip install numpy tokenizers onnxruntime
.venv/bin/python verify.py
```

`TRITON_BIND_ADDRESS` is required and must be the GPU host's WireGuard address.
Triton's HTTP endpoint has no application authentication. Do not bind it to a
public or wildcard address, and do not expose port 8090 through the cloud
security group. Every WireGuard peer that can route to this address is inside the
service trust boundary. Metrics bind to loopback and gRPC is disabled.

`prepare.sh` downloads the pinned FP16 graph and builds the TensorRT engine on
the target GPU. TensorRT uses the explicit precision of that graph. Only final
logit tensors are cast to FP32 because Triton's JSON API cannot serialize FP16
outputs.

The engine accepts `[batch, 256]` INT64 input IDs and attention masks for batch
sizes 1–16. Triton waits at most 5 ms to collect a partial batch. Its queue is
limited to 256 requests and rejects requests waiting more than 250 ms. One model
instance runs on GPU 0.

## Ark workers

Use an Ark binary containing the remote Unified adapter and set:

```sh
PATRONUS_UNIFIED_TRITON_URL=http://<triton-wireguard-address>:8090
PATRONUS_UNIFIED_TRITON_TIMEOUT_MS=1000
```

The client pins the model revision and Triton model version 1. Startup checks
readiness and a real inference response. Every response must contain all seven
expected finite logit tensors with their expected names and shapes. Invalid
responses, network failures, server rejection, and timeout enter Ark's existing
degraded-result path; there is no silent local fallback.

The client uses the existing tokenizer and 256-token input contract. Local model
files remain present for asset validation and rollback. Worker containers should
use the restricted egress network described in the
[AWS network guide](../../../docs/how-to/aws-l3-network-deployment.md).

## Checks

`verify.py` compares all seven TensorRT heads against the pinned ONNX graph,
checks single-row and batch outputs, runs a synthetic concurrent load, and
verifies that Triton forms full batches. It writes `verification.json` locally.
These service checks do not replace application quality evaluation.

Run the Rust transport tests with:

```sh
cargo test --locked -p patronus-ark --lib remote_unified
```

Also test the Linux build and normal L1/L2-to-Unified-L3 application path before
fleet activation. Tool tags use three independent sigmoid probabilities, projected
onto their individual L2 property pipelines before aggregation and arbitration.

To restore local inference, unset `PATRONUS_UNIFIED_TRITON_URL`, restore the
worker image if it was overridden, and recreate workers incrementally.

The [batching-delay study](../../../docs/benchmarks/l4-batching-latency.md)
records the measured latency/throughput tradeoff behind the 5 ms default.

## External inference monitoring

Run `healthcheck.py` on a separate host with private access to Triton. It submits
fresh synthetic tokens and validates all seven output tensors; a readiness HTTP
200 alone cannot detect a failed GPU. The supplied systemd timer checks every
minute. Three consecutive failures trigger one email, followed by one recovery
email. Failed mail delivery is retried on subsequent checks.

Install the script at `/opt/patronus/l3-healthcheck/healthcheck.py`, and install
the supplied service and timer in `/etc/systemd/system/`. Create a root-owned,
mode-0600 `/etc/ark-l3-healthcheck.json` containing `triton_url` and `model`.
For email, add a `mail` object with `host`, `from`, `to` (exactly one recipient), and optionally
`username` and `password`. TLS defaults to `starttls` on port 587; `tls: "ssl"`
defaults to port 465. `port` can override either default. Keep credentials out
of the repository. systemd passes this configuration through `LoadCredential`.

Enable with `systemctl daemon-reload` and
`systemctl enable --now ark-l3-healthcheck.timer`. Inspect
`/var/lib/ark-l3-healthcheck/state.json` and the service journal. Without a mail
configuration the inference check still runs, but `mail_configured` is false
and no notification is delivered. Verify SMTP delivery before relying on alerts.
This check covers the private inference path; it does not cover the public API,
and cannot alert if its monitoring host itself is unavailable.
