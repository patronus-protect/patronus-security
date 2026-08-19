# syntax=docker/dockerfile:1

# ---- builder ---------------------------------------------------------------
FROM rust:1.89-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config protobuf-compiler libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY rust ./rust
COPY python ./python
COPY ark-api ./ark-api

RUN cargo build --release -p ark-api

# ---- asset warmup -----------------------------------------------------------
# Bakes model assets into the image so the runtime container never needs
# network access or `pipeline.download_files: true` to serve requests.
FROM builder AS assets

COPY ark-api/config.build.yaml /etc/ark-api/config.yaml
RUN mkdir -p /data/models /data/cache \
    && /src/target/release/ark-api --config /etc/ark-api/config.yaml --warmup-only

# ---- runtime -----------------------------------------------------------------
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 arkapi

COPY --from=builder /src/target/release/ark-api /usr/local/bin/ark-api
COPY --from=assets /data/models /data/models
COPY LICENSE LICENSE-COMMERCIAL.md NOTICE /usr/share/doc/ark-api/

RUN mkdir -p /data/cache /etc/ark-api \
    && chown -R arkapi:arkapi /data /etc/ark-api

USER arkapi
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ark-api"]
CMD ["--config", "/etc/ark-api/config.yaml"]
