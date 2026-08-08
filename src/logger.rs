use chrono::{Local, Datelike};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

pub struct LogManager {
    pub tx: Sender<String>,
}

impl LogManager {
    pub fn new(log_dir: PathBuf) -> (Self, Receiver<String>) {
        let (log_tx, log_rx) = channel::<String>();
        let (echo_tx, echo_rx) = channel::<String>();

        thread::spawn(move || {
            Self::writer_thread(log_dir, log_rx, echo_tx);
        });

        (Self { tx: log_tx }, echo_rx)
    }

    pub fn log(&self, msg: String) {
        let _ = self.tx.send(msg);
    }

    fn writer_thread(log_dir: PathBuf, rx: Receiver<String>, echo_tx: Sender<String>) {
        let _ = fs::create_dir_all(&log_dir);
        let mut current_file: Option<fs::File> = None;
        let mut current_date = Local::now().date_naive();

        loop {
            let today = Local::now().date_naive();
            if today != current_date || current_file.is_none() {
                current_date = today;
                let filename = format!(
                    "{:02}-{:02}-{:02}.log",
                    today.month(),
                    today.day(),
                    today.year() % 100
                );
                let path = log_dir.join(&filename);
                current_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .ok();
                Self::cleanup_old_logs(&log_dir);
            }
            match rx.recv() {
                Ok(msg) => {
                    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
                    let line = format!("[{}] {}", timestamp, msg);
                    if let Some(ref mut file) = current_file {
                        let _ = writeln!(file, "{}", line);
                        let _ = file.flush();
                    }
                    let _ = echo_tx.send(line);
                }
                Err(_) => break,
            }
        }
    }

    fn cleanup_old_logs(log_dir: &PathBuf) {
        let cutoff = Local::now().date_naive() - chrono::Duration::days(7);
        if let Ok(entries) = fs::read_dir(log_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        let dt = chrono::DateTime::<Local>::from(modified).date_naive();
                        if dt < cutoff {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
}
