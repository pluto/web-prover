use notary_server::{
  init_tracing, run_server, AuthorizationProperties, LoggingProperties, NotarizationProperties,
  NotaryServerProperties, NotarySigningKeyProperties, ServerProperties, TLSProperties,
};

#[tokio::main]
async fn main() {
  let config = NotaryServerProperties {
    server:        ServerProperties {
      name:      "notary-server".into(),
      host:      "0.0.0.0".into(), // TODO CLI or ENV
      port:      7074,             // TODO CLI or ENV
      html_info: "".into(),
    },
    notarization:  NotarizationProperties { max_transcript_size: 20480 },
    tls:           TLSProperties {
      enabled:              true,
      private_key_pem_path: "./fixture/certs/server-key.pem".into(), // TODO CLI or ENV
      certificate_pem_path: "./fixture/certs/server-cert.pem".into(), // TODO CLI or ENV
    },
    notary_key:    NotarySigningKeyProperties {
      private_key_pem_path: "./fixture/certs/notary.key".into(), // TODO CLI or ENV
      public_key_pem_path:  "./fixture/certs/notary.pub".into(), // TODO CLI or ENV
    },
    logging:       LoggingProperties { level: "DEBUG".into(), filter: None },
    authorization: AuthorizationProperties {
      enabled:            false,
      whitelist_csv_path: "".into(),
    },
  };

  // Set up tracing for logging
  init_tracing(&config).unwrap();

  // Run the server
  run_server(&config).await.unwrap();
}
