use crate::pushover::PushoverClient;
use crate::task::{Task, TaskType, TriggerType};
use crate::smtp::ReceivedEmail;
use chrono::{Local, Timelike, Datelike};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use futures_util::StreamExt;
use tokio::sync::{mpsc, Mutex};

pub enum SchedulerCommand {
    UpdateTasks(Vec<Task>),
    EmailReceived(ReceivedEmail),
    NtfyReceived { topic: String, title: String, message: String },
    Shutdown,
}

pub struct Scheduler {
    tasks: Arc<Mutex<Vec<Task>>>,
    pushover: Option<PushoverClient>,
    log_tx: std::sync::mpsc::Sender<String>,
}

impl Scheduler {
    pub fn new(
        tasks: Arc<Mutex<Vec<Task>>>,
        pushover: Option<PushoverClient>,
        log_tx: std::sync::mpsc::Sender<String>,
    ) -> Self {
        Self { tasks, pushover, log_tx }
    }

    pub async fn run(&self, mut cmd_rx: mpsc::Receiver<SchedulerCommand>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.check_time_triggers().await;
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(SchedulerCommand::UpdateTasks(new_tasks)) => {
                            let mut tasks = self.tasks.lock().await;
                            *tasks = new_tasks;
                        }
                        Some(SchedulerCommand::EmailReceived(email)) => {
                            self.handle_email(email).await;
                        }
                        Some(SchedulerCommand::NtfyReceived { topic, title, message }) => {
                            self.handle_ntfy(topic, title, message).await;
                        }
                        Some(SchedulerCommand::Shutdown) | None => break,
                    }
                }
            }
        }
    }

    async fn check_time_triggers(&self) {
        let now = Local::now();
        let current_time = now.time();
        let current_weekday = now.weekday();
        let today = now.date_naive();
        let current_minute = current_time.hour() * 60 + current_time.minute();

        let mut to_run = Vec::new();
        {
            let mut tasks = self.tasks.lock().await;
            for task in tasks.iter_mut() {
                if !task.enabled {
                    continue;
                }
                let should_run = match &task.trigger {
                    TriggerType::Time { hour, minute } => {
                        let trigger_minute = *hour as u32 * 60 + *minute as u32;
                        current_minute == trigger_minute
                            && task.last_triggered_date != Some(today)
                            && current_time.second() == 0
                    }
                    TriggerType::DaysOfWeek { days, hour, minute } => {
                        let trigger_minute = *hour as u32 * 60 + *minute as u32;
                        days.contains(&current_weekday)
                            && current_minute == trigger_minute
                            && task.last_triggered_date != Some(today)
                            && current_time.second() == 0
                    }
                    TriggerType::Interval { minutes } => {
                        if let Some(last) = task.interval_last_run {
                            let elapsed = now.signed_duration_since(last).num_minutes() as u64;
                            elapsed >= *minutes
                        } else {
                            true
                        }
                    }
                    TriggerType::Email { .. } => false,
                    TriggerType::Ntfy { .. } => false,
                };
                if should_run {
                    task.last_triggered_date = Some(today);
                    task.interval_last_run = Some(now);
                    to_run.push(task.clone());
                }
            }
        }
        for task in to_run {
            self.execute_task(task).await;
        }
    }

    async fn handle_email(&self, email: ReceivedEmail) {
        let mut to_run = Vec::new();
        {
            let tasks = self.tasks.lock().await;
            for task in tasks.iter() {
                if !task.enabled {
                    continue;
                }
                if let TriggerType::Email { from_pattern, subject_pattern, body_pattern } = &task.trigger {
                    let from_match = from_pattern.is_empty()
                        || email.from.to_lowercase().contains(&from_pattern.to_lowercase());
                    let subject_match = subject_pattern.is_empty()
                        || email.subject.to_lowercase().contains(&subject_pattern.to_lowercase());
                    let body_match = body_pattern.is_empty()
                        || email.body.to_lowercase().contains(&body_pattern.to_lowercase());
                    if from_match && subject_match && body_match {
                        to_run.push(task.clone());
                    }
                }
            }
        }
        for task in to_run {
            self.log(format!("Email trigger matched for task: {}", task.name));
            self.execute_task(task).await;
        }
    }

    async fn handle_ntfy(&self, topic: String, title: String, message: String) {
        let mut to_run = Vec::new();
        {
            let tasks = self.tasks.lock().await;
            for task in tasks.iter() {
                if !task.enabled {
                    continue;
                }
                if let crate::task::TriggerType::Ntfy { server: _, topic: t, title_pattern, message_pattern } = &task.trigger {
                    if t != &topic {
                        continue;
                    }
                    let title_match = title_pattern.is_empty()
                        || title.to_lowercase().contains(&title_pattern.to_lowercase());
                    let msg_match = message_pattern.is_empty()
                        || message.to_lowercase().contains(&message_pattern.to_lowercase());
                    if title_match && msg_match {
                        to_run.push(task.clone());
                    }
                }
            }
        }
        for task in to_run {
            self.log(format!("ntfy trigger matched for task: {}", task.name));
            self.execute_task(task).await;
        }
    }

    async fn execute_task(&self, mut task: Task) {
        self.log(format!("Executing task: {}", task.name));
        let result = match &task.task_type {
            TaskType::HttpGet { url } => self.run_http_get(url).await,
            TaskType::HttpPost { url, body, headers } => self.run_http_post(url, body, headers).await,
            TaskType::Command { command, args, working_dir } => {
                self.run_command(command, args, working_dir).await
            }
            TaskType::PathCheck { path, check_file_exists, file_path } => {
                self.run_path_check(path, *check_file_exists, file_path).await
            }
            TaskType::FileChanged { file_path, baseline_hash } => {
                self.run_file_changed(file_path, baseline_hash.as_deref()).await
            }
            TaskType::Ntfy { server, topic, title, message, priority, tags, action, subscribe_timeout_secs } => {
                self.run_ntfy(server, topic, title, message, priority, tags, action, *subscribe_timeout_secs).await
            }
        };
        let (success, error_msg) = match result {
            Ok(s) => (s, None),
            Err(e) => (false, Some(e)),
        };
        task.last_run = Some(Local::now());
        task.last_result = Some(success);
        task.last_error = error_msg.clone();
        if task.pushover_enabled && task.should_notify(success) {
            if let Some(ref client) = self.pushover {
                let title = if success { &task.pushover_title_success } else { &task.pushover_title_failure };
                let message = if success { &task.pushover_message_success } else { &task.pushover_message_failure };
                let msg = if let Some(ref err) = error_msg {
                    format!("{}: {}", message, err)
                } else {
                    message.clone()
                };
                let _ = client.send(title, &msg, task.pushover_priority, &task.pushover_sound).await;
            }
        }
        self.log(format!(
            "Task '{}' completed: {}{}",
            task.name,
            if success { "SUCCESS" } else { "FAILURE" },
            if let Some(ref e) = error_msg { format!(" - {}", e) } else { String::new() }
        ));
        let mut tasks = self.tasks.lock().await;
        if let Some(t) = tasks.iter_mut().find(|t| t.id == task.id) {
            t.last_run = task.last_run;
            t.last_result = task.last_result;
            t.last_error = task.last_error;
        }
    }

    async fn run_http_get(&self, url: &str) -> Result<bool, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        let res = client.get(url).send().await.map_err(|e| e.to_string())?;
        Ok(res.status().is_success())
    }

    async fn run_http_post(&self, url: &str, body: &str, headers: &str) -> Result<bool, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        let mut req = client.post(url).body(body.to_string());
        for line in headers.lines() {
            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim();
                let val = line[pos + 1..].trim();
                req = req.header(key, val);
            }
        }
        let res = req.send().await.map_err(|e| e.to_string())?;
        Ok(res.status().is_success())
    }

    async fn run_command(&self, command: &str, args: &str, working_dir: &str) -> Result<bool, String> {
        let output = tokio::task::spawn_blocking({
            let cmd = command.to_string();
            let args = args.to_string();
            let wd = working_dir.to_string();
            move || {
                let mut command = std::process::Command::new("cmd");
                command.arg("/C").arg(&cmd);
                if !args.is_empty() {
                    command.arg(&args);
                }
                if !wd.is_empty() {
                    command.current_dir(&wd);
                }
                command.output()
            }
        }).await.map_err(|e| e.to_string())?;
        match output {
            Ok(out) => {
                if out.status.success() {
                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    Err(format!("Command failed: {}", stderr))
                }
            }
            Err(e) => Err(format!("Failed to execute: {}", e)),
        }
    }

    async fn run_path_check(&self, path: &str, check_file: bool, file_path: &str) -> Result<bool, String> {
        let path_exists = tokio::task::spawn_blocking({
            let p = path.to_string();
            move || std::fs::metadata(&p).is_ok()
        }).await.map_err(|e| e.to_string())?;
        if !path_exists {
            return Ok(false);
        }
        if check_file {
            let file_exists = tokio::task::spawn_blocking({
                let fp = file_path.to_string();
                move || std::fs::metadata(&fp).is_ok()
            }).await.map_err(|e| e.to_string())?;
            Ok(file_exists)
        } else {
            Ok(true)
        }
    }

    async fn run_file_changed(&self, file_path: &str, baseline_hash: Option<&str>) -> Result<bool, String> {
        let current_hash = tokio::task::spawn_blocking({
            let fp = file_path.to_string();
            move || {
                let mut file = std::fs::File::open(&fp).ok()?;
                let mut hasher = Sha256::new();
                std::io::copy(&mut file, &mut hasher).ok()?;
                Some(hex::encode(hasher.finalize()))
            }
        }).await.map_err(|e| e.to_string())?;
        let current_hash = current_hash.ok_or("Cannot read file")?;
        let baseline = baseline_hash.ok_or("No baseline hash set")?;
        Ok(current_hash != baseline)
    }

    async fn run_ntfy(
        &self,
        server: &str,
        topic: &str,
        title: &str,
        message: &str,
        priority: &str,
        tags: &str,
        action: &crate::task::NtfyAction,
        timeout_secs: u64,
    ) -> Result<bool, String> {
        let base = server.trim_end_matches('/');
        match action {
            crate::task::NtfyAction::Publish => {
                let url = format!("{}/{}", base, topic);
                self.log(format!("ntfy: publishing to {}", url));
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|e| e.to_string())?;
                let mut req = client.post(&url).body(message.to_string());
                if !title.is_empty() {
                    req = req.header("Title", title);
                }
                if !priority.is_empty() {
                    req = req.header("Priority", priority);
                }
                if !tags.is_empty() {
                    req = req.header("Tags", tags);
                }
                let res = req.send().await.map_err(|e| e.to_string())?;
                Ok(res.status().is_success())
            }
            crate::task::NtfyAction::Subscribe => {
                let url = format!("{}/{}/sse", base, topic);
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(timeout_secs + 5))
                    .build()
                    .map_err(|e| e.to_string())?;
                let res = client.get(&url).send().await.map_err(|e| e.to_string())?;
                if !res.status().is_success() {
                    return Ok(false);
                }
                let mut stream = res.bytes_stream();
                let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
                let mut buffer = String::new();
                while tokio::time::Instant::now() < deadline {
                    match tokio::time::timeout(Duration::from_secs(1), stream.next()).await {
                        Ok(Some(Ok(chunk))) => {
                            buffer.push_str(&String::from_utf8_lossy(&chunk));
                            if buffer.contains("event: message") && buffer.contains("data: {") {
                                return Ok(true);
                            }
                            // Keep only last 4KB of buffer to prevent unbounded growth
                            if buffer.len() > 4096 {
                                buffer = buffer[buffer.len() - 4096..].to_string();
                            }
                        }
                        Ok(Some(Err(e))) => return Err(format!("SSE stream error: {}", e)),
                        Ok(None) => return Ok(false),
                        Err(_) => continue, // timeout, keep waiting
                    }
                }
                Ok(false) // timeout expired, no message received
            }
        }
    }

    fn log(&self, msg: String) {
        let _ = self.log_tx.send(msg);
    }
}
