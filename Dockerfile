# Build stage
FROM rust:1.86-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependency builds
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Build the actual application
COPY src/ src/
RUN touch src/main.rs src/lib.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

RUN groupadd -r forwardauth && useradd -r -g forwardauth -d /app -s /sbin/nologin forwardauth

WORKDIR /app
COPY --from=builder /app/target/release/forwardauth-rs /app/forwardauth-rs

RUN chown -R forwardauth:forwardauth /app

USER forwardauth

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/forwardauth-rs", "--health-check"] || exit 1

ENTRYPOINT ["/app/forwardauth-rs"]
