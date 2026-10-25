# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p velt-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin velt
COPY --from=builder /src/target/release/velt-server /usr/local/bin/velt-server
USER 10001
EXPOSE 8080
ENV VELT_BIND=0.0.0.0:8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/readyz || exit 1
ENTRYPOINT ["/usr/local/bin/velt-server"]
