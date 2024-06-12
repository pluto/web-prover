use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::thread;

fn main() {
    let notary_thread = thread::spawn(|| {
        run_command(
            "cargo",
            &["run", "-p", "notary-server"],
            "logs/notary-server.log",
        );
    });

    let go_thread = thread::spawn(|| {
        run_command("go", &["run", "-mod=mod", "main.go"], "logs/go-server.log");
    });

    let client_thread = thread::spawn(|| {
        run_command("cargo", &["run", "-p", "client"], "logs/client.log");
    });

    notary_thread.join().unwrap();
    go_thread.join().unwrap();
    client_thread.join().unwrap();
}

fn run_command(command: &str, args: &[&str], log_file: &str) {
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

    let stdout_thread = thread::spawn(move || {
        let stdout = child.stdout.take().expect("Failed to get stdout");
        let mut reader = BufReader::new(stdout);
        let mut buffer = vec![];

        loop {
            let bytes_read = reader
                .read_until(b'\n', &mut buffer)
                .expect("Failed to read stdout");
            if bytes_read == 0 {
                break;
            }
            log_file
                .write_all(&buffer)
                .expect("Failed to write to log file");
            buffer.clear();
        }
    });

    stdout_thread.join().unwrap();
}
