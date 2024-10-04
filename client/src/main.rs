use anyhow::Result;
use clap::Parser;
use client::config::Config;
use tracing::Level;

#[derive(Parser)]
#[clap(name = "Web Proof Client")]
#[clap(about = "A client to generate Web Proofs.", long_about = None)]
struct Args {
  #[clap(short, long, required = false, default_value = "DEBUG")]
  log_level: String,

  #[clap(short, long, required = true, default_value = "config.json")]
  config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Args::parse();

  let log_level = match args.log_level.to_lowercase().as_str() {
    "error" => Level::ERROR,
    "warn" => Level::WARN,
    "info" => Level::INFO,
    "debug" => Level::DEBUG,
    "trace" => Level::TRACE,
    _ => Level::TRACE,
  };
  tracing_subscriber::fmt().with_max_level(log_level).with_line_number(true).init();

  let config_json = std::fs::read_to_string(args.config)?;
  let config: Config = serde_json::from_str(&config_json)?;

  let proof = client::prover_inner(config).await.unwrap();
  let proof_json = serde_json::to_string_pretty(&proof)?;
  println!("Proving Successful: proof_len={:?}", proof_json.len());
  Ok(())
}
