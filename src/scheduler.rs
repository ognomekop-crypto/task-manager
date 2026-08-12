use crate::cloudflare::CloudflareClient;
use crate::pushover::PushoverClient;
use crate::task::{Task, TaskType, TriggerType};
use crate::smtp::ReceivedEmail;
use chrono::{Local, Timelike, Datelike};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;
use futures_util::StreamExt;
use tokio::sync::{mpsc, Mutex};

pub enum SchedulerCommand {
    UpdateTasks(Vec<Task>),
    EmailReceived(ReceivedEmail),
    NtfyReceived { topic: String, title: String, message: String },
    RunStartupTasks,
    Shutdown,
}

pub struct Scheduler {
    tasks: Arc<Mutex<Vec<Task>>>,
    pushover: Option<PushoverClient>,
    cloudflare: Option<CloudflareClient>,
    log_tx: std::sync::mpsc::Sender<String>,
}

impl Scheduler {
    pub fn new(
        tasks: Arc<Mutex<Vec<Task>>>,
        pushover: Option<PushoverClient>,
        cloudflare: Option<CloudflareClient>,
        log_tx: std::sync::mpsc::Sender<String>,
    ) -> Self {
        Self { tasks, pushover, cloudflare, log_tx }
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
                        Some(SchedulerCommand::RunStartupTasks) => {
                            self.run_startup_tasks().await;
                        }
                        Some(SchedulerCommand::Shutdown) | None => break,
                    }
                }
            }
        }
    }

    async fn run_startup_tasks(&self) {
        let tasks = self.tasks.lock().await;
        let startup_tasks: Vec<Task> = tasks.iter()
            .filter(|t| t.enabled && matches!(t.trigger, TriggerType::Startup))
            .cloned()
            .collect();
        drop(tasks);
        for task in startup_tasks {
            self.execute_task(task).await;
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
                    TriggerType::Startup => false,
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

    pub async fn execute_task(&self, task: Task) {
        self.execute_task_with_depth(task, 0).await;
    }

    fn execute_task_with_depth<'a>(&'a self, mut task: Task, chain_depth: u8) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if chain_depth > 10 {
                self.log(format!("Chain depth exceeded for task '{}' -- aborting chain", task.name));
                return;
            }

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
                TaskType::GetPublicIp => self.run_get_public_ip().await,
                TaskType::CloudflareDnsUpdate { zone_id, record_name, record_type, record_id, content, proxied, ttl } => {
                    self.run_cloudflare_dns_update(zone_id, record_name, record_type, record_id, content, *proxied, *ttl).await
                }
            };
            let (success, error_msg) = match result {
                Ok(s) => (s, None),
                Err(e) => (false, Some(e)),
            };

            let on_success_id = task.on_success_task_id;
            let on_failure_id = task.on_failure_task_id;

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
                t.last_error = task.last_error.clone();
            }
            let on_success = on_success_id.and_then(|id| tasks.iter().find(|t| t.id == id).cloned());
            let on_failure = on_failure_id.and_then(|id| tasks.iter().find(|t| t.id == id).cloned());
            drop(tasks);

            if success {
                if let Some(next) = on_success {
                    self.log(format!("Chaining to success task: {}", next.name));
                    self.execute_task_with_depth(next, chain_depth + 1).await;
                }
            } else {
                if let Some(next) = on_failure {
                    self.log(format!("Chaining to failure task: {}", next.name));
                    self.execute_task_with_depth(next, chain_depth + 1).await;
                }
            }
        })
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

    async fn run_get_public_ip(&self) -> Result<bool, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        let res = client.get("https://api.ipify.org")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let ip = res.text().await.map_err(|e| e.to_string())?.trim().to_string();

        let mut config = crate::config::Config::load();
        config.public_ip = Some(ip.clone());
        if let Err(e) = config.save() {
            return Err(format!("Failed to save config: {}", e));
        }
        self.log(format!("Public IP updated: {}", ip));
        Ok(true)
    }

    async fn run_cloudflare_dns_update(
        &self,
        zone_id: &str,
        record_name: &str,
        record_type: &str,
        record_id: &str,
        content: &str,
        proxied: bool,
        ttl: u32,
    ) -> Result<bool, String> {
        let client = self.cloudflare.as_ref().ok_or("Cloudflare credentials not configured")?;

        let resolved_content = if content.is_empty() {
            let config = crate::config::Config::load();
            config.public_ip.ok_or("No public IP saved in config. Run a GetPublicIp task first.")?
        } else {
            self.substitute_variables(content)
        };

        let rid = if record_id.is_empty() {
            client.find_record_id(zone_id, record_name, record_type).await?
                .ok_or_else(|| format!("Could not find {} record '{}' in zone {}", record_type, record_name, zone_id))?
        } else {
            record_id.to_string()
        };

        self.log(format!(
            "Cloudflare: updating {} record '{}' (zone: {}) to {} (TTL: {})",
            record_type, record_name, zone_id, resolved_content, ttl
        ));

        client.update_dns_record(zone_id, &rid, record_type, record_name, &resolved_content, proxied, ttl).await
    }

    fn substitute_variables(&self, text: &str) -> String {
        let config = crate::config::Config::load();
        let mut result = text.to_string();
        if let Some(ip) = &config.public_ip {
            result = result.replace("{{public_ip}}", ip);
        }
        result
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

                let sub_title = self.substitute_variables(title);
                let sub_message = self.substitute_variables(message);

                let mut req = client.post(&url).body(sub_message);
                if !sub_title.is_empty() {
                    req = req.header("Title", sub_title);
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
                            if buffer.len() > 4096 {
                                buffer = buffer[buffer.len() - 4096..].to_string();
                            }
                        }
                        Ok(Some(Err(e))) => return Err(format!("SSE stream error: {}", e)),
                        Ok(None) => return Ok(false),
                        Err(_) => continue,
                    }
                }
                Ok(false)
            }
        }
    }

    fn log(&self, msg: String) {
        let _ = self.log_tx.send(msg);
    }
}
