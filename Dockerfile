FROM rust:latest AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY prompts/ prompts/

# Build release binary
RUN cargo build --release --bin naptrace

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    unzip \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/naptrace /usr/local/bin/naptrace
COPY --from=builder /build/prompts/ /usr/share/naptrace/prompts/

ENV NAPTRACE_PROMPTS_DIR=/usr/share/naptrace/prompts

ENTRYPOINT ["naptrace"]
CMD ["--help"]
