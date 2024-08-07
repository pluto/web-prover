use anyhow::Result;
use clap::Parser;
use client::config::Config;
use tracing::Level;
use tracing_subscriber::EnvFilter;

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
    _ => Level::TRACE,
  };
  let _crate_name = env!("CARGO_PKG_NAME");
  let env_filter = EnvFilter::builder().parse_lossy(format!("{}={},info", _crate_name, log_level));
  tracing_subscriber::fmt().with_env_filter(env_filter).init();

  let config_json = std::fs::read_to_string(args.config)?;
  let config: Config = serde_json::from_str(&config_json)?;

  let proof = client::prover_inner(config).await.unwrap();
  let proof_json = serde_json::to_string_pretty(&proof)?;
  println!("{}", proof_json);
  Ok(())
}
