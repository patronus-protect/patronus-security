# syntax=docker/dockerfile:1

FROM rust:1.98-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config protobuf-compiler libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.lock ./Cargo.lock
COPY ark-coordinator/Cargo.toml ./ark-coordinator/Cargo.toml
COPY ark-coordinator/src ./ark-coordinator/src

# Keep the repository lockfile while excluding unrelated workspace sources.
RUN printf '%s\n' \
    '[workspace]' \
    'members = ["ark-coordinator"]' \
    'resolver = "2"' \
    > Cargo.toml

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
