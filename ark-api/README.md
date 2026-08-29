# ark-api

Ephemeral HTTP API around the `patronus-ark` security pipeline. Submit text
and/or files, get a `request_id` back immediately, then follow that
request's Server-Sent Events stream for progress and the final verdict per
category. Nothing is persisted beyond the optional exact-match decision
cache (`cache.dir` in the config).

## Running

```bash
cp config.example.yaml config.yaml
# edit config.yaml: generate a real key hash with
#   printf '%s' '<your-secret-token>' | sha256sum
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
```

## API

All endpoints except `/healthz` and `/readyz` require
`Authorization: Bearer <token>` matching a `key_hash` in the config.

- `POST /v1/scan` — `multipart/form-data` with an optional `text` or `content`
  field and/or one or more text-decodable files. An optional `config` field
  contains JSON with `categories`, `max_level`, `gates`, `metadata`, and an
  optional request-local `ntdb_operating_point` and is
  snapshotted into every queued job. Missing config uses the existing defaults.
  Returns `202` with `{"jobs": [{"request_id", "source"}, ...]}`.
- `GET /v1/scan/{request_id}/events` — Server-Sent Events stream for one
  request: `progress`, `provisional`, `result` (one per configured category),
  and a terminal `finished` event. `404` if the id is unknown or already
  finished.
- `GET /healthz` — liveness, no auth.
- `GET /readyz` — `200` once L1/L2/L3 assets required by `pipeline.categories`
  are loaded, `503` otherwise.

Result payloads match [`docs/reference/result-schema.md`](../docs/reference/result-schema.md).

The deployment gateway always uses the shared Unified model for regular L3
heads and the separate Dynamic-PII GLiNER model. The Docker build warms and
bakes both bundles into `/data/models`; production runs with downloads disabled.

## x86_64 production: use FP16 L3 models

For Linux `x86_64` production deployments, build the image with the pinned FP16
graphs and retain the same setting at runtime:

```bash
docker build --build-arg L3_PRECISION=fp16 -f ark-api/Dockerfile -t patronus/ark-api:fp16 .
docker run -e PATRONUS_L3_PRECISION=fp16 patronus/ark-api:fp16
```

This selects `onnx/onnx_fp16/model_fp16.onnx` for the regular L3 classifiers and
`onnx/fp16/model_fp16.onnx` for Dynamic PII's GLiNER model. The FP16 graph is
larger and may add CPU latency, but it is the validated production choice for
x86_64: the default quantized graphs produced architecture-dependent results in
the verified Injection and Dynamic-PII person-span cases.

For ARM64 or another execution provider, benchmark and validate the selected
graph on the target before changing this setting.

## Licensing

This container conveys `patronus-ark` under GPL-3.0-only (see
[`LICENSE`](../LICENSE), [`NOTICE`](../NOTICE)). Self-hosted deployment and
distribution of this image is subject to those terms; see
[`LICENSE-COMMERCIAL.md`](../LICENSE-COMMERCIAL.md) if you need rights beyond
the GPL (e.g. embedding in a closed-source product).
