FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev git

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/gem-audit

# Pre-download advisory database
RUN mkdir -p /root/.local/share && target/release/gem-audit download --quiet

# -----------------------------------------------------------
FROM alpine

RUN apk add --no-cache ca-certificates git

COPY --from=builder /build/target/release/gem-audit /usr/local/bin/gem-audit
COPY --from=builder /root/.local/share/ruby-advisory-db /usr/local/share/ruby-advisory-db

ENV GEM_AUDIT_DB=/usr/local/share/ruby-advisory-db

WORKDIR /workspace

ENTRYPOINT ["gem-audit"]
CMD ["check", "--update"]
