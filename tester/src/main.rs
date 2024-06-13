use std::{
    fs::{create_dir_all, OpenOptions},
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    sync::{mpsc, Arc},
    thread,
};

use tui::PaneType;

pub mod tui;

fn main() {
    // Ensure the logs directory exists
    create_dir_all("logs").expect("Failed to create logs directory");

    let (tx, rx) = mpsc::channel();
    let (notary_ready_tx, notary_ready_rx) = mpsc::channel();

    let notary_thread = {
        let tx = tx.clone();
        thread::spawn(move || {
            run_command(
                PaneType::Notary,
                "cargo",
                &["run", "-p", "notary-server"],
                "logs/notary-server.log",
                tx,
                notary_ready_tx,
                "Listening for TCP traffic".to_string(),
            );
        })
    };

    tui::split_and_view_logs(rx);

    notary_thread.join().unwrap();
}

fn run_command(
    pane_type: PaneType,
    command: &str,
    args: &[&str],
    log_file: &str,
    tx: mpsc::Sender<(PaneType, String)>,
    ready_tx: mpsc::Sender<()>,
    ready_indicator: String,
) {
    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
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
            stdout_tx
                .send((pane_type, line.clone()))
                .expect("Failed to send log line");
            log_file
                .write_all(line.as_bytes())
                .expect("Failed to write to log file");
            log_file.write_all(b"\n").expect("Failed to write newline");
            // println!("FROM THE PRINT: {}", line);

            // if line.contains(&ready_indicator) {
            //     ready_tx.send(()).expect("Failed to send ready message");
            // }
        }
    });

    stdout_thread.join().unwrap();
}
