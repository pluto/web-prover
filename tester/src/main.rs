use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

use crossterm::{
    cursor,
    event::{poll, read, Event, KeyCode},
    terminal,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};

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

fn split_and_view_logs() {
    let (tx, rx) = mpsc::channel();

    terminal::enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    terminal::EnterAlternateScreen::execute(&mut stdout).unwrap();

    let mut panes = vec![
        Pane::new("logs/notary-server.log", (0, 0), (40, 100)),
        Pane::new("logs/go-server.log", (40, 0), (60, 100)),
        Pane::new("logs/client.log", (0, 60), (40, 40)),
    ];

    let handle = thread::spawn(move || loop {
        if poll(std::time::Duration::from_millis(100)).unwrap() {
            match read().unwrap() {
                Event::Key(event) => {
                    if event.code == KeyCode::Char('q') {
                        tx.send(()).unwrap();
                        break;
                    }
                }
                _ => {}
            }
        }

        for pane in &mut panes {
            pane.update();
        }
    });

    rx.recv().unwrap();
    terminal::LeaveAlternateScreen::execute(&mut stdout).unwrap();
    terminal::disable_raw_mode().unwrap();
    handle.join().unwrap();
}

struct Pane<'a> {
    log_file: &'a str,
    position: (u16, u16),
    size: (u16, u16),
    lines: Vec<String>,
}

impl<'a> Pane<'a> {
    fn new(log_file: &'a str, position: (u16, u16), size: (u16, u16)) -> Self {
        Pane {
            log_file,
            position,
            size,
            lines: vec![],
        }
    }

    fn update(&mut self) {
        let mut file = OpenOptions::new()
            .read(true)
            .open(self.log_file)
            .expect("Failed to open log file");

        let mut new_lines = vec![];
        let mut buffer = String::new();

        file.read_to_string(&mut buffer)
            .expect("Failed to read log file");

        for line in buffer.lines().skip(self.lines.len()) {
            new_lines.push(line.to_owned());
        }

        self.lines.extend(new_lines);
        self.render();
    }

    fn render(&self) {
        let mut stdout = std::io::stdout();
        crossterm::cursor::MoveTo(self.position.0, self.position.1)
            .execute(&mut stdout)
            .unwrap();

        let lines = self
            .lines
            .iter()
            .rev()
            .take(self.size.1 as usize)
            .rev()
            .collect::<Vec<_>>();

        for line in lines {
            let line = line.trim_end();
            println!("{}", line);
        }

        stdout.flush().unwrap();
    }
}
