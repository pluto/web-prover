FROM rust:1.82-bookworm AS rust-builder
WORKDIR /app
COPY . /app
# RUN cd /app/proofs && make web-prover-circuits-512
RUN cargo build --release -p notary


# FROM golang:1.23-bookworm AS golang-builder
# WORKDIR /app
# COPY tee/util /app
# RUN go build


FROM debian:bookworm
COPY --from=rust-builder /app/target/release/notary /app/notary
COPY --from=rust-builder /app/fixture /app/fixture
# COPY --from=golang-builder /app/tee /app/tee-util
EXPOSE 7443
WORKDIR /app
ENV RUST_LOG=info
CMD ["./notary", "--config", "./fixture/notary-config.toml"]
