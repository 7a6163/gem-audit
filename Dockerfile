FROM rust:1 AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/gem-audit

# Pre-download advisory database
RUN mkdir -p /root/.local/share && target/release/gem-audit download --quiet

# -----------------------------------------------------------
# Use the debug variant which includes busybox (/bin/sh) for CI compatibility
FROM gcr.io/distroless/cc-debian13:debug

COPY --from=builder /build/target/release/gem-audit /usr/local/bin/gem-audit
COPY --from=builder /root/.local/share/ruby-advisory-db /usr/local/share/ruby-advisory-db

ENV GEM_AUDIT_DB=/usr/local/share/ruby-advisory-db

WORKDIR /workspace
CMD ["gem-audit", "check", "--update"]
