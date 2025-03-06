FROM debian:bookworm
RUN apt-get update && \
    apt-get install -y libssl-dev && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir /app
COPY .github/workflows/staging-deploy-gcs/notary /app/notary
COPY .github/workflows/staging-deploy-gcs/notary-config.toml /app/notary-config.toml
RUN chmod +x /app/notary
EXPOSE 443
WORKDIR /app
ENV RUST_LOG=warn
CMD ["./notary", "--config", "./notary-config.toml"]