use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use crossterm::{
    event::{poll, read, Event, KeyCode, KeyModifiers},
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
    {cursor, execute},
};

pub fn split_and_view_logs(rx: mpsc::Receiver<(PaneType, String)>) {
    // terminal::enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();

    let terminal_size = terminal::size().unwrap();
    let pane_width = terminal_size.0 / 3;
    let pane_height = terminal_size.1;

    let mut panes = vec![
        Pane::new(PaneType::Notary, 0, pane_width, pane_height),
        Pane::new(PaneType::Go, pane_width, pane_width, pane_height),
        Pane::new(PaneType::Client, pane_width * 2, pane_width, pane_height),
    ];

    for pane in &panes {
        pane.draw_border(&mut stdout);
        pane.draw_title(&mut stdout);
    }

    let handle = thread::spawn(move || {
        while let Ok((pane_type, line)) = rx.recv() {
            // println!("Received line: {}", line);
            for pane in &mut panes {
                if pane.pane_type == pane_type {
                    pane.lines.push(line.clone());
                    pane.render(&mut stdout);
                    break;
                }
            }
        }

        // for pane in &mut panes {
        //     pane.render(&mut stdout);
        // }

        // Ensure terminal cleanup after breaking from loop
        execute!(stdout, LeaveAlternateScreen).unwrap();
        // terminal::disable_raw_mode().unwrap();
    });

    handle.join().unwrap();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaneType {
    Notary,
    Go,
    Client,
}

struct Pane {
    pane_type: PaneType,
    x: u16,
    width: u16,
    height: u16,
    lines: Vec<String>,
}

impl Pane {
    fn new(pane_type: PaneType, x: u16, width: u16, height: u16) -> Self {
        Pane {
            pane_type,
            x,
            width,
            height,
            lines: vec![],
        }
    }

    fn render(&self, stdout: &mut std::io::Stdout) {
        let content_height = self.height - 3; // Leave space for title and borders
        let mut lines_to_display = vec![];

        // Wrap long lines
        for line in &self.lines {
            let mut current_line = line.clone();
            while current_line.len() > self.width as usize - 2 {
                let (part, rest) = current_line.split_at(self.width as usize - 2);
                lines_to_display.push(part.to_string());
                current_line = rest.to_string();
            }
            lines_to_display.push(current_line);
        }

        let lines = lines_to_display
            .iter()
            .rev()
            .take(content_height as usize)
            .rev()
            .collect::<Vec<_>>();

        for (i, line) in self.lines.iter().enumerate() {
            let line = line.trim_end();

            execute!(
                stdout,
                cursor::MoveTo(self.x + 1, i as u16 + 2),
                Clear(ClearType::CurrentLine),
                Print(line)
            )
            .unwrap();
        }

        stdout.flush().unwrap();
    }

    fn draw_border(&self, stdout: &mut std::io::Stdout) {
        for y in 0..self.height {
            if y == 0 || y == self.height - 1 {
                execute!(
                    stdout,
                    cursor::MoveTo(self.x, y),
                    Print("┌"),
                    Print("─".repeat((self.width - 2) as usize)),
                    Print("┐")
                )
                .unwrap();
            } else {
                execute!(
                    stdout,
                    cursor::MoveTo(self.x, y),
                    Print("│"),
                    cursor::MoveTo(self.x + self.width - 1, y),
                    Print("│")
                )
                .unwrap();
            }
        }
    }

    fn draw_title(&self, stdout: &mut std::io::Stdout) {
        let title_x = self.x + (self.width - format!(" {:?}", self.pane_type).len() as u16) / 2;
        execute!(
            stdout,
            cursor::MoveTo(title_x, 0),
            SetForegroundColor(Color::Green),
            Print(format!(" {:?}", self.pane_type)),
            ResetColor
        )
        .unwrap();
    }
}
