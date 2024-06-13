use std::{
    fs::{create_dir_all, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
};

use clap::{command, Parser};
use tui::PaneType;

pub mod tui;

#[derive(Parser)]
#[command(name = "Tester for TLSN WebProofs")]
#[command(about = "Control panel for testing TLSN Webproofs", long_about = None)]
struct Args {
    /// TCP KeepAlive Timeout for the Go server (default: 1m0s)
    #[arg(long, default_value = "1m0s")]
    tcp_idle_timeout: String,
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
                &["run", "-p", "notary-server"],
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
            println!("waiting for notary to be ready");
            while notary_ready_rx.recv().is_err() {}
            run_command(
                PaneType::Go,
                "go",
                &[
                    "run",
                    "-mod=mod",
                    "vanilla-go-app/main.go",
                    &format!("-tcp-idle-timeout={}", args.tcp_idle_timeout),
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
                &["run", "-p", "client"],
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
        let stderr = child.stderr.take().expect("Failed to get stderr");
        let combined = stdout.chain(stderr);

        let reader = BufReader::new(combined);

        for line in reader.lines() {
            let line = line.expect("Failed to read line from stdout");
            stdout_tx
                .send((pane_type, line.clone()))
                .expect("Failed to send log line");
            log_file
                .write_all(line.as_bytes())
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
