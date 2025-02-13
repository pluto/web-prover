FROM debian:bookworm-slim
COPY proofs /app/proofs
COPY fixture /app/fixture
COPY .github/workflows/staging-deploy-gcs/notary /app/notary
COPY .github/workflows/staging-deploy-gcs/notary-config.toml /app/fixture/notary-config.toml
EXPOSE 443
WORKDIR /app
ENV RUST_LOG=warn
CMD ["./notary", "--config", "./fixture/notary-config.toml"]