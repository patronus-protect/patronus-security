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

- `POST /v1/scan` — `multipart/form-data` with an optional `text` field and/or
  one or more `files` fields. Each non-empty field becomes its own scan
  request. Returns `202` with `{"jobs": [{"request_id", "source"}, ...]}`.
- `GET /v1/scan/{request_id}/events` — Server-Sent Events stream for one
  request: `progress`, `provisional`, `result` (one per configured category),
  and a terminal `finished` event. `404` if the id is unknown or already
  finished.
- `GET /healthz` — liveness, no auth.
- `GET /readyz` — `200` once L1/L2/L3 assets required by `pipeline.categories`
  are loaded, `503` otherwise.

Result payloads match [`docs/reference/result-schema.md`](../docs/reference/result-schema.md).

## Licensing

This container conveys `patronus-ark` under GPL-3.0-only (see
[`LICENSE`](../LICENSE), [`NOTICE`](../NOTICE)). Self-hosted deployment and
distribution of this image is subject to those terms; see
[`LICENSE-COMMERCIAL.md`](../LICENSE-COMMERCIAL.md) if you need rights beyond
the GPL (e.g. embedding in a closed-source product).
