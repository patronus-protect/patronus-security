# syntax=docker/dockerfile:1

FROM rust:1.98-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config protobuf-compiler libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/ark-coordinator
COPY Cargo.lock ./Cargo.lock
COPY ark-coordinator/Cargo.toml ./Cargo.toml
COPY ark-coordinator/src ./src

# Build only the model-free Cube proxy. The runtime contains no ARK models,
# worker, or Cube entrypoint.
RUN cargo build --locked --release --bin ark-coordinator

FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 arkcoordinator

COPY --from=builder /src/ark-coordinator/target/release/ark-coordinator /usr/local/bin/ark-coordinator
COPY LICENSE LICENSE-COMMERCIAL.md NOTICE /usr/share/doc/ark-coordinator/

RUN mkdir -p /etc/ark-coordinator /run/ark-coordinator \
    && chown -R arkcoordinator:arkcoordinator /etc/ark-coordinator /run/ark-coordinator

USER arkcoordinator
RUN /usr/local/bin/ark-coordinator --help >/dev/null

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/ark-coordinator"]
CMD ["--config", "/etc/ark-coordinator/config.yaml"]
