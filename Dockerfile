# Debug Dockerfile for building a TEE-Enabled Docker image

FROM rust:1.82-bookworm AS rust-builder

RUN apt-get update && apt-get install -y \
    libclang-dev \
    clang \
	protobuf-compiler \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN cd /app/proofs && make web-prover-circuits
RUN cargo build --release -p notary

FROM debian:bookworm
RUN apt-get update && \
    apt-get install -y libssl-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=rust-builder /app/target/release/notary /app/notary
COPY --from=rust-builder /app/fixture /app/fixture
COPY --from=rust-builder /app/proofs /app/proofs
EXPOSE 7443
WORKDIR /app
ENV RUST_LOG=info
CMD ["./notary", "--config", "./fixture/notary-config.toml"]
