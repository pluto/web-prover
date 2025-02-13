FROM debian:bookworm-slim
RUN mkdir /app
COPY proofs /app/proofs
COPY .github/workflows/staging-deploy-gcs/notary /app/notary
COPY .github/workflows/staging-deploy-gcs/notary-config.toml /app/notary-config.toml
RUN chmod +x /app/notary
EXPOSE 443
WORKDIR /app
ENV RUST_LOG=warn
CMD ["./notary", "--config", "./notary-config.toml"]