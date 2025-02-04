use std::path::PathBuf;

use clap::Parser;
// use proofs::program::{self};
// use proofs::{program, ProgramData};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "prove")]
pub struct Args {
  /// Setup file to use for generating proof
  #[arg(long, short, required = true)]
  input_file: PathBuf,

  /// Increase logging verbosity (-v, -vv, -vvv, etc.)
  #[arg(short, long, action = clap::ArgAction::Count)]
  verbose: u8,
}

// TODO: This should be given a setup interface too.
// // Note:
// // Run with `cargo run --release -i setup/test.json`
// // from the `./proofs/` dir.
fn main() {
  let args = Args::parse();

  // Logging options
  let log_level = match args.verbose {
    0 => Level::ERROR,
    1 => Level::WARN,
    2 => Level::INFO,
    3 => Level::DEBUG,
    _ => Level::TRACE,
  };
  let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
  tracing::subscriber::set_global_default(subscriber).expect(
    "setting default subscriber
failed",
  );
}
