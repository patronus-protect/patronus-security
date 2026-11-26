# syntax=docker/dockerfile:1

# FP16 is the validated Linux x86_64 production graph. Override this build
# argument only after validating another graph on the target architecture.
ARG L3_PRECISION=fp16

# ---- builder ---------------------------------------------------------------
FROM rust:1.98-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake pkg-config protobuf-compiler libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY ark-core/python/Cargo.toml ./ark-core/python/Cargo.toml
COPY ark-core ./ark-core
COPY rust ./rust
COPY python ./python
COPY ark-api ./ark-api
COPY ark-distributed-protocol ./ark-distributed-protocol
COPY ark-coordinator ./ark-coordinator

RUN cargo build --locked --release -p ark-api --bins

# ---- assets -----------------------------------------------------------------
# Reuse the immutable, public production bundle instead of redownloading every
# L1/L2 model during each build. Remote L3 keeps only its local tokenizers.
FROM ghcr.io/patronus-protect/ark-api@sha256:65cf4a8b7a48842431d6ef0a6a8d11696fddad5c0683b6d73754ba6318ddf4b7 AS published-assets

FROM published-assets AS assets
USER root
RUN rm -rf /data/models/wolf/wolf-defender-small/onnx \
           /data/models/dynamic_pii/gliner_small_v2_5/onnx \
           /data/models/dynamic_pii/gliner_small_v2_5/model_int4_embeddings_int8.onnx*

# ---- runtime -----------------------------------------------------------------
FROM debian:trixie-slim AS runtime

ARG L3_PRECISION
ENV PATRONUS_L3_PRECISION=${L3_PRECISION} \
    PATRONUS_L3_TTL_SECS=-1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 arkapi

COPY --from=builder /src/target/release/ark-api /usr/local/bin/ark-api
COPY --from=builder /src/target/release/ark-api-entrypoint /usr/local/bin/ark-api-entrypoint
COPY --from=assets /data/models /data/models
COPY ark-api/LICENSE ark-api/LICENSE-COMMERCIAL.md ark-api/NOTICE /usr/share/doc/ark-api/

RUN mkdir -p /data/cache /etc/ark-api \
    && chown -R arkapi:arkapi /data /etc/ark-api

USER arkapi
RUN /usr/local/bin/ark-api --help >/dev/null \
    && /usr/local/bin/ark-api-entrypoint --help >/dev/null
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ark-api"]
CMD ["--config", "/etc/ark-api/config.yaml"]
