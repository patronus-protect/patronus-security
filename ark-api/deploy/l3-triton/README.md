# Unified L3 on an NVIDIA GPU

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
