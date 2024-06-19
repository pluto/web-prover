use std::{
    fs::{create_dir_all, OpenOptions},
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
};

use clap::{command, Parser};
use strip_ansi_escapes::strip;
use tui::PaneType;

pub mod tui;

#[derive(Parser)]
#[command(name = "Tester for TLSN WebProofs")]
#[command(about = "Control panel for testing TLSN Webproofs", long_about = None)]
struct Args {
    /// Endpoint to test (default: health)
    #[clap(short, long, global = true, required = false, default_value = "health")]
    endpoint: String,

    /// Log level for all the components (default: TRACE)
    #[clap(short, long, global = true, required = false, default_value = "TRACE")]
    log_level: String,

    /// Enable TCP KeepAlive for the Go server (default: false)
    #[clap(long, global = true, required = false, default_value = "false")]
    tcp_keep_alive: bool,

    /// TCP KeepAlive Timeout for the Go server (default: 1m0s)
    #[arg(long, default_value = "1m0s")]
    tcp_idle_timeout: String,

    /// Enable HTTP KeepAlive for the Go server (default: false)
    #[clap(long, global = true, required = false, default_value = "false")]
    http_keep_alive: bool,

    #[clap(long, global = true, required = false, default_value = "30s")]
    http_idle_timeout: String,

    #[clap(long, global = true, required = false, default_value = "10s")]
    http_read_timeout: String,

    #[clap(long, global = true, required = false, default_value = "10s")]
    http_write_timeout: String,
}

fn main() {
    let args = Args::parse();
    create_dir_all("logs").expect("Failed to create logs directory");

    let (tx, rx) = mpsc::channel();
    let (notary_ready_tx, notary_ready_rx) = mpsc::channel();
    let (go_ready_tx, go_ready_rx) = mpsc::channel();

    let notary_thread = {
        let tx = tx.clone();
        thread::spawn(move || {
            run_command(
                PaneType::Notary,
                "cargo",
                &["run", "-p", "notary-server", "--release"],
                "logs/notary-server.log",
                tx,
                Some(notary_ready_tx),
                Some("Listening for TCP traffic".to_string()),
            );
        })
    };

    let go_thread = {
        let tx = tx.clone();
        thread::spawn(move || {
            while notary_ready_rx.recv().is_err() {}
            run_command(
                PaneType::Go,
                "go",
                &[
                    "run",
                    "-mod=mod",
                    "vanilla-go-app/main.go",
                    "-shutdown-delay=0s",
                    "-tls-cert-path=vanilla-go-app/certs/server-cert.pem",
                    "-tls-key-path=vanilla-go-app/certs/server-key.pem",
                    "-listen=:8065",
                    &format!("-tcp-keep-alive={}", args.tcp_keep_alive),
                    &format!("-tcp-idle-timeout={}", args.tcp_idle_timeout),
                    &format!("-http-keep-alive={}", args.http_keep_alive),
                    &format!("-http-idle-timeout={}", args.http_idle_timeout),
                    &format!("-http-read-timeout={}", args.http_read_timeout),
                    &format!("-http-write-timeout={}", args.http_write_timeout),
                ],
                "logs/go-server.log",
                tx,
                Some(go_ready_tx),
                Some("Start listening".to_string()),
            );
        })
    };

    let client_thread = {
        let tx = tx.clone();
        thread::spawn(move || {
            while go_ready_rx.recv().is_err() {}
            run_command(
                PaneType::Client,
                "cargo",
                &[
                    "run",
                    "-p",
                    "client",
                    "--release",
                    "--",
                    "--log-level",
                    &args.log_level,
                    "--endpoint",
                    &args.endpoint,
                ],
                "logs/client.log",
                tx,
                None,
                None,
            );
        })
    };

    tui::split_and_view_logs(rx);

    notary_thread.join().unwrap();
    go_thread.join().unwrap();
    client_thread.join().unwrap();
}

fn run_command(
    pane_type: PaneType,
    command: &str,
    args: &[&str],
    log_file: &str,
    tx: mpsc::Sender<(PaneType, String)>,
    ready_tx: Option<mpsc::Sender<()>>,
    ready_indicator: Option<String>,
) {
    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_file)
        .expect("Failed to create log file");

    let stdout_tx = tx;

    let stdout_thread = thread::spawn(move || {
        let stdout = child.stdout.take().expect("Failed to get stdout");

        let reader = BufReader::new(stdout);

        for line in reader.lines() {
            let line = line.expect("Failed to read line from stdout");
            let cleaned_line = strip(&line);
            let cleaned_line = String::from_utf8_lossy(&cleaned_line);
            stdout_tx
                .send((pane_type, line.clone()))
                .expect("Failed to send log line");
            log_file
                .write_all(cleaned_line.as_bytes())
                .expect("Failed to write to log file");
            log_file.write_all(b"\n").expect("Failed to write newline");
            if let Some(ready_indicator) = &ready_indicator {
                if line.contains(ready_indicator) {
                    stdout_tx
                        .send((
                            pane_type,
                            format!("Sending ready message for {:?}", pane_type),
                        ))
                        .unwrap();
                    if let Some(ref ready_tx) = ready_tx {
                        ready_tx.send(()).expect("Failed to send ready message");
                    }
                }
            }
        }
    });

    stdout_thread.join().unwrap();
}
