# ark-api

Authenticated HTTP deployment around the `patronus-ark` security pipeline.
The reference stack exposes `ark-api-entrypoint`: submit text and/or files,
receive a global `job_id`, and poll the job independently of which worker ran
it. Redis retains completed jobs for the configured TTL; workers keep their
own optional decision caches (`cache.dir` in the config).

## Running

```bash
cp config.example.yaml config.yaml
# config.yaml: hash an internal gateway-to-worker token
#   printf '%s' '<internal-worker-token>' | sha256sum
cp entrypoint.example.yaml entrypoint.yaml
# entrypoint.yaml: set the raw internal token above, then hash a separate
# public client token for auth.keys[].key_hash (bare digest, no sha256: prefix)
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
```

The reference deployment runs two FP16 workers with separate decision caches,
a 2.5-CPU quota each, and `PATRONUS_L3_TTL_SECS=-1` so loaded L3 sessions remain
resident. Redis and `ark-api-entrypoint` provide the global job API on port
8080. On the benchmarked six-vCPU OVH host this topology reached
7.728 requests/s with 168 ms p50 HTTP latency, compared with 6.761 requests/s
and 440 ms for three workers limited to two CPUs each. The remaining CPU is
left to the gateway, Redis, reverse proxy, and operating system.

## API

All endpoints except `/healthz` and `/readyz` require
`Authorization: Bearer <token>` matching a public `key_hash` in
`entrypoint.yaml`.

- `POST /v1/scan` — `multipart/form-data` with an optional `text` or `content`
  field and/or one or more text-decodable files. An optional `config` field
  contains JSON with `categories`, `max_level`, `gates`, `metadata`, and an
  optional request-local `ntdb_operating_point` and is
  snapshotted into every queued job. Missing config uses the existing defaults.
  `gates.rules` is a map from stable L1 rule IDs to booleans; absent IDs are
  enabled. PII IDs are the `pii_*` names in `PII_PATTERNS`, DLP IDs are the
  `dlp_*` names in `DLP_PATTERNS` plus `dlp_sensitive_material`,
  `dlp_secret_transfer`, `dlp_mcp_runtime_risk`, `dlp_mcp_policy`, and
  `dlp_destructive_operation`. Injection IDs are the `ark.injection.*` IDs
  returned in evidence spans and candidate metadata.
  In the checked-in `config.example.yaml`, DLP L1 defaults to credential, key,
  token, password, hash, private-key, and sensitive-transfer detection. Business
  identifiers, internal metrics, source/SQL/dump/log content, MCP/runtime risk,
  and destructive operations require explicit `gates.rules`/`gates.models`
  opt-ins. PII and Injection rules remain enabled unless configured otherwise.
  Returns `202` with `{"jobs": [{"job_id", "source", "status_url"}, ...]}`.
- `GET /v1/scan/{job_id}` — durable job status plus accumulated progress,
  compact category results, `decision_evidence`, and the overall decision.
- `GET /healthz` — liveness, no auth.
- `GET /readyz` — gateway readiness. Worker readiness is checked separately by
  the Compose health checks before the gateway starts.

When `ark-api` is run directly instead of through the reference gateway,
`POST /v1/scan` returns worker-local `request_id` values and
`GET /v1/scan/{request_id}/events` exposes their native SSE stream.

Result payloads match [`docs/reference/result-schema.md`](../docs/reference/result-schema.md).

The deployment gateway always uses the shared Unified model for regular L3
heads and the separate Dynamic-PII GLiNER model. The Docker build warms and
bakes both bundles into `/data/models`; production runs with downloads disabled.

## x86_64 production: use FP16 L3 models

For Linux `x86_64` production deployments, the image defaults to the pinned FP16
graphs and the Compose deployment retains the same setting at runtime:

```bash
docker build -f Dockerfile -t patronus/ark-api:fp16 ..
docker run -e PATRONUS_L3_PRECISION=fp16 patronus/ark-api:fp16
```

The container default also sets `PATRONUS_L3_TTL_SECS=-1`. This disables idle
session eviction and avoids a multi-second model reload on the first promoted
request after an idle period. Override it with a non-negative number of seconds
only when reclaiming model RAM is more important than stable request latency.

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
