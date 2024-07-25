//! This is a mock client for local testing that should have some degree of
//! logic parity with the mobile target

use anyhow::Result;
use clap::Parser;
use client::{prover_inner, ClientType, Config, NotarizationSessionRequest};
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[clap(name = "TLSN Client")]
#[clap(about = "A dummy client for Pluto TLSN WebProofs.", long_about = None)]
struct Args {
  #[clap(short, long, global = true, required = false, default_value = "TRACE")]
  log_level: String,

  #[clap(short, long, global = true, required = false, default_value = "health")]
  endpoint: String,
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Args::parse();

  let log_level = match args.log_level.to_lowercase().as_str() {
    "error" => Level::ERROR,
    "warn" => Level::WARN,
    "info" => Level::INFO,
    "debug" => Level::DEBUG,
    _ => Level::TRACE,
  };
  let _crate_name = env!("CARGO_PKG_NAME");

  let env_filter = EnvFilter::builder().parse_lossy(format!("{}={},info", _crate_name, log_level));

  tracing_subscriber::fmt().with_env_filter(env_filter).init();

  let config = Config {
    notary_host:                  "localhost".into(), // prod: tlsnotary.pluto.xyz
    notary_port:                  7047,               // prod: 443
    target_method:                "GET".into(),
    target_url:                   format!("https://localhost:8080/{}", args.endpoint),
    target_headers:               Default::default(),
    target_body:                  "".to_string(),
    websocket_proxy_url:          "https://0.0.0.0:8050".into(), /* prod: ./tlsnotary.pluto.
                                                                  * xyz-rootca.crt */
    notarization_session_request: NotarizationSessionRequest {
      client_type:   ClientType::Tcp,
      max_sent_data: Some(4096),
      max_recv_data: Some(16384),
    },
  };
  info!("Client config: {:?}", config);

  let proof = prover_inner(config).await?;
  let proof_json = serde_json::to_string_pretty(&proof)?;
  std::fs::write("webproof.json", proof_json)?;
  info!("Proof complete. Proof written to `webproof.json`");
  Ok(())
}
