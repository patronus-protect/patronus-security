# syntax=docker/dockerfile:1

FROM rust:1.98-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config protobuf-compiler libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY rust/Cargo.toml ./rust/Cargo.toml
COPY python/Cargo.toml ./python/Cargo.toml
COPY ark-api/Cargo.toml ./ark-api/Cargo.toml
COPY ark-coordinator/Cargo.toml ./ark-coordinator/Cargo.toml
COPY ark-coordinator/src ./ark-coordinator/src

# Cargo loads every workspace manifest before selecting the Coordinator package.
# Empty targets satisfy manifest discovery without copying ARK or model sources.
RUN mkdir -p ark-api/src python/src rust/src rust/dev \
    && touch \
        ark-api/src/main.rs \
        python/src/lib.rs \
        rust/src/lib.rs \
        rust/dev/all_categories_benchmark.rs \
        rust/dev/gliner_onnx_ner_benchmark.rs \
        rust/dev/injection_gliner_memory_smoke.rs \
        rust/dev/injection_pair_gliner_benchmark.rs \
        rust/dev/local_l1_l2_gliner_benchmark.rs \
        rust/dev/ntdb_memory_smoke.rs \
        rust/dev/ntdb_joint_v3_cache_eval.rs \
        rust/dev/wolf_memory_smoke.rs

# Build only the model-free Cube proxy. The runtime contains no ARK models,
# worker, or Cube entrypoint.
RUN cargo build --locked --release -p ark-coordinator --bin ark-coordinator

FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 arkcoordinator

COPY --from=builder /src/target/release/ark-coordinator /usr/local/bin/ark-coordinator
COPY LICENSE LICENSE-COMMERCIAL.md NOTICE /usr/share/doc/ark-coordinator/

RUN mkdir -p /etc/ark-coordinator /run/ark-coordinator \
    && chown -R arkcoordinator:arkcoordinator /etc/ark-coordinator /run/ark-coordinator

USER arkcoordinator
RUN /usr/local/bin/ark-coordinator --help >/dev/null

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/ark-coordinator"]
CMD ["--config", "/etc/ark-coordinator/config.yaml"]
