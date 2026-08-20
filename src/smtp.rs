use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct ReceivedEmail {
    pub from: String,
    pub subject: String,
    pub body: String,
}

pub struct SmtpServer {
    port: u16,
    tx: mpsc::Sender<ReceivedEmail>,
    log_tx: std::sync::mpsc::Sender<String>,
}

impl SmtpServer {
    pub fn new(port: u16, tx: mpsc::Sender<ReceivedEmail>, log_tx: std::sync::mpsc::Sender<String>) -> Self {
        Self { port, tx, log_tx }
    }

    pub async fn run(&self) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            format!("Failed to bind SMTP to {}: {}", addr, e)
        })?;

        let local_addr = listener.local_addr().map_err(|e| e.to_string())?;
        let _ = self.log_tx.send(format!(
            "SMTP server listening on {} (port {})", local_addr, self.port
        ));

        let tx = self.tx.clone();
        let log_tx = self.log_tx.clone();

        tokio::spawn(async move {
            let log_tx = log_tx;
            let tx = tx;
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let log_conn = log_tx.clone();
                        let _ = log_conn.send(format!("SMTP client connected from {}", peer));
                        let tx_c = tx.clone();
                        let log_h = log_tx.clone();
                        let log_e = log_tx.clone();
                        tokio::spawn(run_client(stream, peer, tx_c, log_h, log_e));
                    }
                    Err(e) => {
                        let _ = log_tx.send(format!("SMTP accept error: {}", e));
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(())
    }
}

async fn run_client(
    stream: TcpStream,
    peer: SocketAddr,
    tx: mpsc::Sender<ReceivedEmail>,
    log_handler: std::sync::mpsc::Sender<String>,
    log_error: std::sync::mpsc::Sender<String>,
) {
    if let Err(e) = handle_client(stream, tx, log_handler).await {
        let _ = log_error.send(format!("SMTP client {} error: {}", peer, e));
    }
}

async fn handle_client(
    stream: TcpStream,
    tx: mpsc::Sender<ReceivedEmail>,
    log_tx: std::sync::mpsc::Sender<String>,
) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    writer.write_all(b"220 TaskManager SMTP Server Ready\r\n").await
        .map_err(|e| format!("Failed to send greeting: {}", e))?;
    let _ = log_tx.send("SMTP: sent 220 greeting".to_string());

    let mut from = String::new();
    let mut subject = String::new();
    let mut in_data = false;
    let mut email_data = String::new();
    let mut helo_received = false;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                let _ = log_tx.send("SMTP: client disconnected".to_string());
                break;
            }
            Ok(_) => {
                let cmd = line.trim_end().trim_end_matches('\r').to_string();
                let _ = log_tx.send(format!("SMTP recv: {}", cmd));

                if in_data {
                    if cmd == "." {
                        in_data = false;
                        let email = parse_email(&email_data);
                        let _ = log_tx.send(format!(
                            "SMTP: received email from='{}' subject='{}' body_len={}",
                            email.from, email.subject, email.body.len()
                        ));
                        let _ = tx.send(email).await;
                        email_data.clear();
                        writer.write_all(b"250 OK Message accepted\r\n").await.ok();
                    } else {
                        if cmd.starts_with("..") {
                            email_data.push_str(&cmd[1..]);
                        } else {
                            email_data.push_str(&cmd);
                        }
                        email_data.push('\n');
                    }
                    continue;
                }

                let upper = cmd.to_uppercase();
                if upper.starts_with("HELO") || upper.starts_with("EHLO") {
                    helo_received = true;
                    writer.write_all(b"250 Hello\r\n").await.ok();
                } else if upper.starts_with("MAIL FROM:") {
                    from = extract_angle_addr(&cmd[10..]);
                    writer.write_all(b"250 OK\r\n").await.ok();
                } else if upper.starts_with("RCPT TO:") {
                    writer.write_all(b"250 OK\r\n").await.ok();
                } else if upper == "DATA" {
                    if !helo_received {
                        writer.write_all(b"503 Send HELO/EHLO first\r\n").await.ok();
                    } else {
                        in_data = true;
                        writer.write_all(b"354 End data with .\r\n").await.ok();
                    }
                } else if upper == "QUIT" {
                    writer.write_all(b"221 Bye\r\n").await.ok();
                    let _ = log_tx.send("SMTP: client QUIT".to_string());
                    break;
                } else if upper == "RSET" {
                    from.clear();
                    subject.clear();
                    email_data.clear();
                    in_data = false;
                    writer.write_all(b"250 OK\r\n").await.ok();
                } else if upper == "NOOP" {
                    writer.write_all(b"250 OK\r\n").await.ok();
                } else if cmd.is_empty() {
                    // keep-alive or empty line, ignore
                } else {
                    writer.write_all(b"500 Command not recognized\r\n").await.ok();
                }
            }
            Err(e) => {
                let _ = log_tx.send(format!("SMTP read error: {}", e));
                break;
            }
        }
    }

    Ok(())
}

fn extract_angle_addr(s: &str) -> String {
    let s = s.trim();
    if let Some(start) = s.find('<') {
        if let Some(end) = s.find('>') {
            return s[start + 1..end].to_string();
        }
    }
    s.to_string()
}

fn parse_email(data: &str) -> ReceivedEmail {
    let mut from = String::new();
    let mut subject = String::new();

    let parts: Vec<&str> = data.splitn(2, "\n\n").collect();
    let headers = parts.get(0).unwrap_or(&"");
    let body_text = parts.get(1).unwrap_or(&"");

    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("from:") {
            from = extract_angle_addr(&line[5..]);
        } else if lower.starts_with("subject:") {
            subject = line[8..].trim().to_string();
        }
    }

    let body = body_text.trim().to_string();
    ReceivedEmail { from, subject, body }
}
