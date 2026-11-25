# syntax=docker/dockerfile:1

# FP16 is the validated Linux x86_64 production graph. Override this build
# argument only after validating another graph on the target architecture.
ARG L3_PRECISION=fp16

# ---- builder ---------------------------------------------------------------
FROM rust:1.98-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake pkg-config protobuf-compiler libssl-dev wget \
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

# ---- asset warmup -----------------------------------------------------------
# Bakes model assets into the image so the runtime container never needs
# network access or `pipeline.download: missing` to serve requests.
FROM builder AS assets

ARG L3_PRECISION
ENV PATRONUS_L3_PRECISION=${L3_PRECISION} \
    PATRONUS_L3_TTL_SECS=-1

COPY ark-api/config.build.yaml /etc/ark-api/config.yaml
RUN mkdir -p /data/models /data/cache \
    && /src/target/release/ark-api --config /etc/ark-api/config.yaml --warmup-only

# Remote L3 inference still tokenizes on the Worker. Fetch only the small,
# revision-pinned metadata files it loads; no L3 graph is requested or baked.
RUN wolf_dir=/data/models/wolf/wolf-defender-small \
    && wolf_url=https://huggingface.co/patronus-studio/wolf-defender-prompt-injection-small/resolve/e3749b44a0f85268347cdfb6818f4ef39e8ff203 \
    && mkdir -p "${wolf_dir}" \
    && for file in config.json tokenizer.json tokenizer_config.json POOLING.json; do \
         wget --https-only --quiet --timeout=120 --tries=3 -O "${wolf_dir}/${file}" "${wolf_url}/${file}"; \
       done \
    && printf '%s' e3749b44a0f85268347cdfb6818f4ef39e8ff203 > "${wolf_dir}/.patronus-revision" \
    && gliner_dir=/data/models/dynamic_pii/gliner_small_v2_5 \
    && gliner_url=https://huggingface.co/patronus-studio/gliner_small-v2.5-edge/resolve/6cfcbd93d7fc6f5e1658f80afa38f73891b91693 \
    && mkdir -p "${gliner_dir}" \
    && for file in gliner_config.json gliner_onnx_config.json quantization_manifest.json special_tokens_map.json spm.model tokenizer.json tokenizer_config.json; do \
         wget --https-only --quiet --timeout=120 --tries=3 -O "${gliner_dir}/${file}" "${gliner_url}/${file}"; \
       done \
    && printf '%s' 6cfcbd93d7fc6f5e1658f80afa38f73891b91693 > "${gliner_dir}/.patronus-revision"

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
COPY LICENSE LICENSE-COMMERCIAL.md NOTICE /usr/share/doc/ark-api/

RUN mkdir -p /data/cache /etc/ark-api \
    && chown -R arkapi:arkapi /data /etc/ark-api

USER arkapi
RUN /usr/local/bin/ark-api --help >/dev/null \
    && /usr/local/bin/ark-api-entrypoint --help >/dev/null
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ark-api"]
CMD ["--config", "/etc/ark-api/config.yaml"]
