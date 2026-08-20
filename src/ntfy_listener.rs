use crate::scheduler::SchedulerCommand;
use crate::task::{Task, TriggerType};
use futures_util::StreamExt;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;

pub enum NtfyListenerCommand {
    UpdateTasks(Vec<Task>),
}

#[derive(Debug, Clone)]
struct NtfyMessage {
    topic: String,
    title: String,
    message: String,
    tags: String,
}

pub struct NtfyListener {
    scheduler_tx: mpsc::Sender<SchedulerCommand>,
    log_tx: std::sync::mpsc::Sender<String>,
}

impl NtfyListener {
    pub fn new(
        scheduler_tx: mpsc::Sender<SchedulerCommand>,
        log_tx: std::sync::mpsc::Sender<String>,
    ) -> Self {
        Self { scheduler_tx, log_tx }
    }

    pub async fn run(&self, mut cmd_rx: mpsc::Receiver<NtfyListenerCommand>) {
        let mut active_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let (msg_tx, mut msg_rx) = mpsc::channel::<NtfyMessage>(100);

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(NtfyListenerCommand::UpdateTasks(tasks)) => {
                            for handle in active_handles.drain(..) { handle.abort(); }

                            let mut subscriptions: HashSet<(String, String)> = HashSet::new();
                            for task in &tasks {
                                if !task.enabled { continue; }
                                if let TriggerType::Ntfy { server, topic, .. } = &task.trigger {
                                    subscriptions.insert((server.clone(), topic.clone()));
                                }
                            }

                            let sub_count = subscriptions.len();
                            for (server, topic) in subscriptions {
                                let msg_tx_c = msg_tx.clone();
                                let log_tx_c = self.log_tx.clone();
                                active_handles.push(tokio::spawn(async move {
                                    listen_topic(server, topic, msg_tx_c, log_tx_c).await;
                                }));
                            }

                            if sub_count > 0 {
                                let _ = self.log_tx.send(format!("ntfy: monitoring {} topic(s)", sub_count));
                            }
                        }
                        None => break,
                    }
                }
                Some(msg) = msg_rx.recv() => {
                    let _ = self.scheduler_tx.send(SchedulerCommand::NtfyReceived {
                        topic: msg.topic,
                        title: msg.title,
                        message: msg.message,
                        tags: msg.tags,
                    }).await;
                }
            }
        }

        for handle in active_handles { handle.abort(); }
    }
}

async fn listen_topic(
    server: String,
    topic: String,
    msg_tx: mpsc::Sender<NtfyMessage>,
    log_tx: std::sync::mpsc::Sender<String>,
) {
    let url = format!("{}/{}/sse", server.trim_end_matches('/'), topic);
    let _ = log_tx.send(format!("ntfy: connecting to {}", url));

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(86400))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = log_tx.send(format!("ntfy: failed to create client: {}", e));
            return;
        }
    };

    loop {
        let res = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                let _ = log_tx.send(format!("ntfy: request failed for '{}': {}", topic, e));
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        let status = res.status();
        let _ = log_tx.send(format!("ntfy: HTTP {} for '{}'", status, topic));

        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            let _ = log_tx.send(format!("ntfy: error body: {}", body));
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }

        let _ = log_tx.send(format!("ntfy: SSE stream started for '{}'", topic));
        let mut stream = res.bytes_stream();
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        let mut last_data = tokio::time::Instant::now();
        let mut chunk_count = 0u64;

        loop {
            match tokio::time::timeout(Duration::from_secs(180), stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    chunk_count += 1;
                    last_data = tokio::time::Instant::now();
                    buffer.extend_from_slice(&chunk);

                    if chunk_count <= 3 || chunk_count % 50 == 0 {
                        let _ = log_tx.send(format!(
                            "ntfy: chunk #{} for '{}', {} bytes, buffer {} bytes",
                            chunk_count, topic, chunk.len(), buffer.len()
                        ));
                    }

                    // Process all complete events in buffer without reallocation
                    while let Some(pos) = find_boundary(&buffer) {
                        let boundary_len = if buffer.get(pos..pos + 4) == Some(b"\r\n\r\n") { 4 } else { 2 };
                        let event_text = String::from_utf8_lossy(&buffer[..pos]);

                        if let Some(msg) = parse_sse_message(&event_text) {
                            let _ = log_tx.send(format!(
                                "ntfy: EVENT on '{}': title='{}' msg_len={}",
                                topic, msg.title, msg.message.len()
                            ));
                            let _ = msg_tx.send(NtfyMessage {
                                topic: topic.clone(),
                                title: msg.title,
                                message: msg.message,
                                tags: msg.tags,
                            }).await;
                        } else if !event_text.trim().is_empty() {
                            let ev_type = event_text.lines()
                                .find(|l| l.trim_start().starts_with("event:"))
                                .map(|l| l[6..].trim().to_string())
                                .unwrap_or_else(|| "(no event type)".to_string());
                            let _ = log_tx.send(format!(
                                "ntfy: non-message event on '{}': type='{}' first_line='{}'",
                                topic, ev_type,
                                event_text.lines().next().unwrap_or("").chars().take(60).collect::<String>()
                            ));
                        }

                        // Drain processed bytes instead of reallocating
                        let new_start = pos + boundary_len;
                        buffer.copy_within(new_start.., 0);
                        buffer.truncate(buffer.len() - new_start);
                    }

                    if buffer.len() > 16384 {
                        let drop = buffer.len() - 8192;
                        let _ = log_tx.send(format!("ntfy: buffer overflow on '{}', dropping {} bytes", topic, drop));
                        buffer.copy_within(drop.., 0);
                        buffer.truncate(8192);
                    }
                }
                Ok(Some(Err(e))) => {
                    let _ = log_tx.send(format!("ntfy: stream error for '{}': {}", topic, e));
                    break;
                }
                Ok(None) => {
                    let _ = log_tx.send(format!("ntfy: stream ended for '{}'", topic));
                    break;
                }
                Err(_) => {
                    if last_data.elapsed().as_secs() > 240 {
                        let _ = log_tx.send(format!("ntfy: stale connection on '{}', reconnecting", topic));
                        break;
                    }
                }
            }
        }

        let _ = log_tx.send(format!("ntfy: disconnected from '{}', reconnecting in 5s...", topic));
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn find_boundary(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i+1] == b'\n' && buf[i+2] == b'\r' && buf[i+3] == b'\n' {
            return Some(i);
        }
    }
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\n' && buf[i+1] == b'\n' {
            return Some(i);
        }
    }
    None
}

#[derive(Debug, Default)]
struct ParsedNtfyMessage {
    title: String,
    message: String,
    tags: String,
}

fn parse_sse_message(event_text: &str) -> Option<ParsedNtfyMessage> {
    let mut event_type: Option<String> = None;
    let mut data_lines: Vec<&str> = Vec::new();

    for line in event_text.lines() {
        let line = line.trim_end();
        if line.starts_with("event: ") {
            event_type = Some(line[7..].trim().to_string());
        } else if line.starts_with("data: ") {
            data_lines.push(&line[6..]);
        }
    }

    // Per SSE spec: if no event: field is present, default event type is "message"
    let is_message_event = event_type.as_deref().unwrap_or("message") == "message";
    if !is_message_event || data_lines.is_empty() {
        return None;
    }

    let data = data_lines.join("\n");
    let mut msg = ParsedNtfyMessage::default();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
        if let Some(t) = json.get("title").and_then(|v| v.as_str()) {
            msg.title = t.to_string();
        }
        if let Some(m) = json.get("message").and_then(|v| v.as_str()) {
            msg.message = m.to_string();
        }
        if let Some(tags_arr) = json.get("tags").and_then(|v| v.as_array()) {
            msg.tags = tags_arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
                .join(", ");
        }
    }

    Some(msg)
}
