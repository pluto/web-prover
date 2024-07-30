use std::fs;

use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
  #[arg(short, long, default_value = "config.toml")]
  config: String,
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Config {
  pub server_cert:        String,
  pub server_key:         String,
  pub listen:             String,
  pub notary_signing_key: String,

  pub tlsn_max_sent_data: usize,
  pub tlsn_max_recv_data: usize,

  pub acme_email:  String,
  pub acme_domain: String,
}

// TODO read_config should not use unwrap
pub fn read_config() -> Config {
  let args = Args::parse();

  let builder = config::Config::builder()
    .set_default("listen", "0.0.0.0:443")
    .unwrap()
    .set_default("server_cert", "") // TODO is this the right way to make server_cert optional?
    .unwrap()
    .set_default("server_key", "") // TODO is this the right way to make server_key optional?
    .unwrap()
    .set_default("acme_email", "") // TODO is this the right way to make acme_email optional?
    .unwrap()
    .set_default("acme_domain", "") // TODO is this the right way to make acme_domain optional?
    .unwrap();

  // does config file exist?
  let config_file = args.config;
  let builder = if fs::metadata(config_file.clone()).is_ok() {
    builder.add_source(config::File::new(&config_file, config::FileFormat::Toml))
  } else {
    builder
  };

  // allow ENV to override
  let builder =
    builder.add_source(config::Environment::with_prefix("NOTARY").try_parsing(true).separator("_"));

  let c: Config = builder.build().unwrap().try_deserialize().unwrap();
  c
}
