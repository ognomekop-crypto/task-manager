use crate::cloudflare::CloudflareClient;
use crate::crypto::Crypto;
use crate::pushover::PushoverClient;
use crate::task::{IpListAction, NtfyAction, NtfyContext, Task, TaskType, TriggerType};
use crate::smtp::ReceivedEmail;
use chrono::{Local, Timelike, Datelike};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;
use tokio::sync::{mpsc, Mutex};
use futures_util::StreamExt;

pub enum SchedulerCommand {
    UpdateTasks(Vec<Task>),
    EmailReceived(ReceivedEmail),
    NtfyReceived { topic: String, title: String, message: String, tags: String },
    RunStartupTasks,
    Shutdown,
}

pub struct Scheduler {
    tasks: Arc<Mutex<Vec<Task>>>,
    pushover: Option<PushoverClient>,
    cloudflare: Option<CloudflareClient>,
    log_tx: std::sync::mpsc::Sender<String>,
    master_password: Option<String>,
    password_salt: Option<Vec<u8>>,
}

impl Scheduler {
    pub fn new(
        tasks: Arc<Mutex<Vec<Task>>>,
        pushover: Option<PushoverClient>,
        cloudflare: Option<CloudflareClient>,
        log_tx: std::sync::mpsc::Sender<String>,
        master_password: Option<String>,
        password_salt: Option<Vec<u8>>,
    ) -> Self {
        Self { tasks, pushover, cloudflare, log_tx, master_password, password_salt }
    }

    pub async fn run(&self, mut cmd_rx: mpsc::Receiver<SchedulerCommand>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => self.check_time_triggers().await,
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(SchedulerCommand::UpdateTasks(new_tasks)) => {
                            *self.tasks.lock().await = new_tasks;
                        }
                        Some(SchedulerCommand::EmailReceived(email)) => self.handle_email(email).await,
                        Some(SchedulerCommand::NtfyReceived { topic, title, message, tags }) => {
                            self.handle_ntfy(topic, title, message, tags).await;
                        }
                        Some(SchedulerCommand::RunStartupTasks) => self.run_startup_tasks().await,
                        Some(SchedulerCommand::Shutdown) | None => break,
                    }
                }
            }
        }
    }

    async fn run_startup_tasks(&self) {
        let tasks: Vec<Task> = self.tasks.lock().await
            .iter()
            .filter(|t| t.enabled && matches!(t.trigger, TriggerType::Startup))
            .cloned()
            .collect();
        for task in tasks {
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
                        task.interval_last_run
                            .map_or(true, |last| now.signed_duration_since(last).num_minutes() as u64 >= *minutes)
                    }
                    _ => false,
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
        let email_from = email.from.to_lowercase();
        let email_subject = email.subject.to_lowercase();
        let email_body = email.body.to_lowercase();

        let to_run: Vec<Task> = self.tasks.lock().await
            .iter()
            .filter(|t| t.enabled)
            .filter(|t| matches!(t.trigger, TriggerType::Email { .. }))
            .filter(|t| {
                if let TriggerType::Email { from_pattern, subject_pattern, body_pattern } = &t.trigger {
                    (from_pattern.is_empty() || email_from.contains(&from_pattern.to_lowercase()))
                        && (subject_pattern.is_empty() || email_subject.contains(&subject_pattern.to_lowercase()))
                        && (body_pattern.is_empty() || email_body.contains(&body_pattern.to_lowercase()))
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        for task in to_run {
            self.log(format!("Email trigger matched for task: {}", task.name));
            self.execute_task(task).await;
        }
    }

    async fn handle_ntfy(&self, topic: String, title: String, message: String, tags: String) {
        let context = NtfyContext {
            topic: topic.clone(),
            title: title.clone(),
            message: message.clone(),
            tags: tags.clone(),
        };

        let to_run: Vec<Task> = self.tasks.lock().await
            .iter()
            .filter(|t| t.enabled)
            .filter(|t| matches!(t.trigger, TriggerType::Ntfy { .. }))
            .filter(|t| {
                if let TriggerType::Ntfy { topic: t, title_pattern, message_pattern, .. } = &t.trigger {
                    t == &topic
                        && (title_pattern.is_empty() || title.to_lowercase().contains(&title_pattern.to_lowercase()))
                        && (message_pattern.is_empty() || message.to_lowercase().contains(&message_pattern.to_lowercase()))
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        for mut task in to_run {
            task.ntfy_context = Some(context.clone());
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
            let ntfy = task.ntfy_context.as_ref();
            let public_ip = crate::config::Config::load().public_ip;

            let result = self.run_task_action(&task.task_type, ntfy, public_ip.as_deref()).await;
            let (success, error_msg) = match result {
                Ok(s) => (s, None),
                Err(e) => (false, Some(e)),
            };

            let on_success_id = task.on_success_task_id;
            let on_failure_id = task.on_failure_task_id;
            let ntfy_context = task.ntfy_context.clone();

            task.last_run = Some(Local::now());
            task.last_result = Some(success);
            task.last_error = error_msg.clone();

            if task.pushover_enabled && task.should_notify(success) {
                if let Some(ref client) = self.pushover {
                    let (title_raw, msg_raw) = if success {
                        (&task.pushover_title_success, &task.pushover_message_success)
                    } else {
                        (&task.pushover_title_failure, &task.pushover_message_failure)
                    };
                    let title = self.substitute_variables(title_raw, ntfy, public_ip.as_deref());
                    let message = self.substitute_variables(msg_raw, ntfy, public_ip.as_deref());
                    let msg = error_msg.as_ref()
                        .map(|e| format!("{}: {}", message, e))
                        .unwrap_or(message);
                    let _ = client.send(&title, &msg, task.pushover_priority, &task.pushover_sound).await;
                }
            }

            self.log(format!(
                "Task '{}' completed: {}{}",
                task.name,
                if success { "SUCCESS" } else { "FAILURE" },
                error_msg.as_ref().map_or(String::new(), |e| format!(" - {}", e))
            ));

            let mut tasks = self.tasks.lock().await;
            if let Some(t) = tasks.iter_mut().find(|t| t.id == task.id) {
                t.last_run = task.last_run;
                t.last_result = task.last_result;
                t.last_error = task.last_error.clone();
                t.ntfy_context = task.ntfy_context.clone();
            }
            let on_success = on_success_id.and_then(|id| tasks.iter().find(|t| t.id == id).cloned());
            let on_failure = on_failure_id.and_then(|id| tasks.iter().find(|t| t.id == id).cloned());
            drop(tasks);

            let next = if success { on_success } else { on_failure };
            if let Some(mut next_task) = next {
                next_task.ntfy_context = ntfy_context.clone();
                self.log(format!("Chaining to {} task: {}", if success { "success" } else { "failure" }, next_task.name));
                self.execute_task_with_depth(next_task, chain_depth + 1).await;
            }
        })
    }

    async fn run_task_action(&self, task_type: &TaskType, ntfy: Option<&NtfyContext>, public_ip: Option<&str>) -> Result<bool, String> {
        match task_type {
            TaskType::HttpGet { url } => {
                self.run_http_get(&self.substitute_variables(url, ntfy, public_ip)).await
            }
            TaskType::HttpPost { url, body, headers } => {
                self.run_http_post(
                    &self.substitute_variables(url, ntfy, public_ip),
                    &self.substitute_variables(body, ntfy, public_ip),
                    &self.substitute_variables(headers, ntfy, public_ip),
                ).await
            }
            TaskType::Command { command, args, working_dir } => {
                self.run_command(
                    &self.substitute_variables(command, ntfy, public_ip),
                    &self.substitute_variables(args, ntfy, public_ip),
                    &self.substitute_variables(working_dir, ntfy, public_ip),
                ).await
            }
            TaskType::PathCheck { path, check_file_exists, file_path } => {
                self.run_path_check(
                    &self.substitute_variables(path, ntfy, public_ip),
                    *check_file_exists,
                    &self.substitute_variables(file_path, ntfy, public_ip),
                ).await
            }
            TaskType::FileChanged { file_path, baseline_hash } => {
                self.run_file_changed(&self.substitute_variables(file_path, ntfy, public_ip), baseline_hash.as_deref()).await
            }
            TaskType::Ntfy { server, topic, title, message, priority, tags, action, subscribe_timeout_secs } => {
                self.run_ntfy(
                    &self.substitute_variables(server, ntfy, public_ip),
                    &self.substitute_variables(topic, ntfy, public_ip),
                    &self.substitute_variables(title, ntfy, public_ip),
                    &self.substitute_variables(message, ntfy, public_ip),
                    &self.substitute_variables(priority, ntfy, public_ip),
                    &self.substitute_variables(tags, ntfy, public_ip),
                    action,
                    *subscribe_timeout_secs,
                    ntfy,
                ).await
            }
            TaskType::GetPublicIp => self.run_get_public_ip().await,
            TaskType::CloudflareDnsUpdate { zone_id, record_name, record_type, record_id, content, proxied, ttl, api_token_encrypted, api_email_encrypted, .. } => {
                self.run_cloudflare_dns_update(
                    &self.substitute_variables(zone_id, ntfy, public_ip),
                    &self.substitute_variables(record_name, ntfy, public_ip),
                    record_type,
                    &self.substitute_variables(record_id, ntfy, public_ip),
                    &self.substitute_variables(content, ntfy, public_ip),
                    &self.substitute_variables(proxied, ntfy, public_ip),
                    &self.substitute_variables(ttl, ntfy, public_ip),
                    api_token_encrypted.as_ref(),
                    api_email_encrypted.as_ref(),
                ).await
            }
            TaskType::CloudflareIpListUpdate { account_id, list_id, list_name, ip, comment, action, api_token_encrypted, api_email_encrypted, .. } => {
                self.run_cloudflare_ip_list_update(
                    &self.substitute_variables(account_id, ntfy, public_ip),
                    &self.substitute_variables(list_id, ntfy, public_ip),
                    &self.substitute_variables(list_name, ntfy, public_ip),
                    &self.substitute_variables(ip, ntfy, public_ip),
                    &self.substitute_variables(comment, ntfy, public_ip),
                    action,
                    api_token_encrypted.as_ref(),
                    api_email_encrypted.as_ref(),
                ).await
            }
        }
    }

    // ------------------------------------------------------------------
    // HTTP
    // ------------------------------------------------------------------
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
                req = req.header(line[..pos].trim(), line[pos + 1..].trim());
            }
        }
        let res = req.send().await.map_err(|e| e.to_string())?;
        Ok(res.status().is_success())
    }

    // ------------------------------------------------------------------
    // Command
    // ------------------------------------------------------------------
    async fn run_command(&self, command: &str, args: &str, working_dir: &str) -> Result<bool, String> {
        let output = tokio::task::spawn_blocking({
            let cmd = command.to_string();
            let args = args.to_string();
            let wd = working_dir.to_string();
            move || {
                let mut c = std::process::Command::new("cmd");
                c.arg("/C").arg(&cmd);
                if !args.is_empty() { c.arg(&args); }
                if !wd.is_empty() { c.current_dir(&wd); }
                c.output()
            }
        }).await.map_err(|e| e.to_string())?;

        match output {
            Ok(out) if out.status.success() => Ok(true),
            Ok(out) => Err(format!("Command failed: {}", String::from_utf8_lossy(&out.stderr))),
            Err(e) => Err(format!("Failed to execute: {}", e)),
        }
    }

    // ------------------------------------------------------------------
    // Path / File
    // ------------------------------------------------------------------
    async fn run_path_check(&self, path: &str, check_file: bool, file_path: &str) -> Result<bool, String> {
        let path_exists = tokio::task::spawn_blocking({
            let p = path.to_string();
            move || std::fs::metadata(&p).is_ok()
        }).await.map_err(|e| e.to_string())?;

        if !path_exists {
            return Ok(false);
        }
        if !check_file {
            return Ok(true);
        }

        let full = std::path::Path::new(path).join(file_path);
        let fp_str = full.to_string_lossy().to_string();
        let file_exists = tokio::task::spawn_blocking({
            let fp = fp_str;
            move || std::fs::metadata(&fp).is_ok()
        }).await.map_err(|e| e.to_string())?;
        Ok(file_exists)
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

    // ------------------------------------------------------------------
    // Public IP
    // ------------------------------------------------------------------
    async fn run_get_public_ip(&self) -> Result<bool, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        let ip = client.get("https://api.ipify.org")
            .send().await.map_err(|e| e.to_string())?
            .text().await.map_err(|e| e.to_string())?
            .trim().to_string();

        let mut config = crate::config::Config::load();
        config.public_ip = Some(ip.clone());
        config.save().map_err(|e| format!("Failed to save config: {}", e))?;
        self.log(format!("Public IP updated: {}", ip));
        Ok(true)
    }

    // ------------------------------------------------------------------
    // Cloudflare
    // ------------------------------------------------------------------
    async fn run_cloudflare_dns_update(
        &self,
        zone_id: &str,
        record_name: &str,
        record_type: &str,
        record_id: &str,
        content: &str,
        proxied_str: &str,
        ttl_str: &str,
        api_token_encrypted: Option<&Vec<u8>>,
        api_email_encrypted: Option<&Vec<u8>>,
    ) -> Result<bool, String> {
        let per_task_client = self.decrypt_per_task_client(api_token_encrypted, api_email_encrypted);
        let client = per_task_client.as_ref().or(self.cloudflare.as_ref())
            .ok_or("Cloudflare credentials not configured")?;

        self.log(format!(
            "Cloudflare client: per_task={} global={}",
            per_task_client.is_some(),
            self.cloudflare.is_some()
        ));

        let (resolved_zone_id, resolved_record_name, proxied, ttl) = self.resolve_cloudflare_defaults(zone_id, record_name, proxied_str, ttl_str)?;

        let resolved_content = if content.is_empty() {
            crate::config::Config::load().public_ip
                .ok_or("No public IP saved in config. Run a GetPublicIp task first.")?
        } else {
            content.to_string()
        };

        let rid = if record_id.is_empty() {
            client.find_record_id(&resolved_zone_id, &resolved_record_name, record_type).await?
                .ok_or_else(|| format!(
                    "Could not find {} record '{}' in zone {}",
                    record_type, resolved_record_name, resolved_zone_id
                ))?
        } else {
            record_id.to_string()
        };

        self.log(format!(
            "Cloudflare: updating {} record '{}' (zone: {}) to {} (TTL: {})",
            record_type, resolved_record_name, resolved_zone_id, resolved_content, ttl
        ));

        client.update_dns_record(&resolved_zone_id, &rid, record_type, &resolved_record_name, &resolved_content, proxied, ttl).await
    }

    async fn run_cloudflare_ip_list_update(
        &self,
        account_id: &str,
        list_id: &str,
        list_name: &str,
        ip: &str,
        comment: &str,
        action: &IpListAction,
        api_token_encrypted: Option<&Vec<u8>>,
        api_email_encrypted: Option<&Vec<u8>>,
    ) -> Result<bool, String> {
        if account_id.is_empty() {
            return Err("Account ID is required for IP List operations".to_string());
        }
        if ip.is_empty() {
            return Err("IP address is required".to_string());
        }

        let per_task_client = self.decrypt_per_task_client(api_token_encrypted, api_email_encrypted);
        let client = per_task_client.as_ref().or(self.cloudflare.as_ref())
            .ok_or("Cloudflare credentials not configured")?;

        self.log(format!(
            "Cloudflare IP List: per_task={} global={}",
            per_task_client.is_some(),
            self.cloudflare.is_some()
        ));

        let resolved_list_id = if list_id.is_empty() {
            if list_name.is_empty() {
                return Err("Either List ID or List Name must be provided".to_string());
            }
            client.find_ip_list_id(account_id, list_name).await?
                .ok_or_else(|| format!("Could not find IP list named '{}' in account {}", list_name, account_id))?
        } else {
            list_id.to_string()
        };

        self.log(format!(
            "Cloudflare IP List: {} IP {} to list {} (acct: {})",
            match action { IpListAction::Add => "Adding", IpListAction::Remove => "Removing", IpListAction::ReplaceAll => "Replacing" },
            ip, resolved_list_id, account_id
        ));

        match action {
            IpListAction::Add => {
                let (did_something, ok) = client.add_or_update_ip_by_comment(account_id, &resolved_list_id, ip, comment).await?;
                if !did_something {
                    self.log(format!("Cloudflare IP List: IP {} already exists in list — no changes made", ip));
                } else if !comment.is_empty() {
                    self.log(format!("Cloudflare IP List: added/updated IP {} with comment '{}'", ip, comment));
                } else {
                    self.log(format!("Cloudflare IP List: added new IP {} (no comment)", ip));
                }
                Ok(ok)
            }
            IpListAction::Remove => client.remove_ip_from_list(account_id, &resolved_list_id, ip).await,
            IpListAction::ReplaceAll => client.replace_ip_list_items(account_id, &resolved_list_id, ip, comment).await,
        }
    }

    fn decrypt_per_task_client(&self, api_token_encrypted: Option<&Vec<u8>>, api_email_encrypted: Option<&Vec<u8>>) -> Option<CloudflareClient> {
        let (pwd, salt) = (self.master_password.as_ref()?, self.password_salt.as_ref()?);
        let token = api_token_encrypted
            .and_then(|enc| Crypto::decrypt(enc, pwd, salt).ok())?
            .trim()
            .to_string();
        let email = api_email_encrypted
            .and_then(|enc| Crypto::decrypt(enc, pwd, salt).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Some(match email {
            Some(em) => CloudflareClient::with_global_key(em, token),
            None => CloudflareClient::with_token(token),
        })
    }

    fn resolve_cloudflare_defaults(
        &self,
        zone_id: &str,
        record_name: &str,
        proxied_str: &str,
        ttl_str: &str,
    ) -> Result<(String, String, bool, u32), String> {
        let config = crate::config::Config::load();
        let mut default_zone_id = config.cloudflare_default_zone_id;
        let mut default_record_name = config.cloudflare_default_record_name;
        let mut default_proxied = config.cloudflare_default_proxied;
        let mut default_ttl = config.cloudflare_default_ttl;

        // Fallback: read raw JSON if struct fields are empty (handles old binary overwrite)
        if default_zone_id.is_empty() || default_record_name.is_empty() || default_proxied.is_empty() || default_ttl.is_empty() {
            if let Ok(raw) = std::fs::read_to_string(crate::config::Config::config_path()) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if default_zone_id.is_empty() {
                        default_zone_id = json.get("cloudflare_default_zone_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    }
                    if default_record_name.is_empty() {
                        default_record_name = json.get("cloudflare_default_record_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    }
                    if default_proxied.is_empty() {
                        default_proxied = json.get("cloudflare_default_proxied").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    }
                    if default_ttl.is_empty() {
                        default_ttl = json.get("cloudflare_default_ttl").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    }
                }
            }
        }

        self.log(format!(
            "Cloudflare defaults loaded: zone_id='{}' record_name='{}' proxied='{}' ttl='{}'",
            default_zone_id, default_record_name, default_proxied, default_ttl
        ));

        let zid = if zone_id.is_empty() { &default_zone_id } else { zone_id };
        let rname = if record_name.is_empty() { &default_record_name } else { record_name };
        let p_str = if proxied_str.is_empty() { &default_proxied } else { proxied_str };
        let t_str = if ttl_str.is_empty() { &default_ttl } else { ttl_str };

        self.log(format!(
            "Cloudflare resolved: zone_id='{}' record_name='{}' proxied='{}' ttl='{}' (task empty: zone={} name={} proxied={} ttl={})",
            zid, rname, p_str, t_str, zone_id.is_empty(), record_name.is_empty(), proxied_str.is_empty(), ttl_str.is_empty()
        ));

        if zid.is_empty() {
            return Err("Zone ID is empty and no default is configured in Settings".to_string());
        }
        if rname.is_empty() {
            return Err("Record Name is empty and no default is configured in Settings".to_string());
        }

        let proxied = p_str.trim().parse::<bool>()
            .map_err(|_| format!("Invalid proxied value '{}'. Use 'true' or 'false'.", p_str))?;
        let ttl = t_str.trim().parse::<u32>()
            .map_err(|_| format!("Invalid TTL value '{}'. Must be a number.", t_str))?;

        Ok((zid.to_string(), rname.to_string(), proxied, ttl))
    }

    // ------------------------------------------------------------------
    // ntfy
    // ------------------------------------------------------------------
    async fn run_ntfy(
        &self,
        server: &str,
        topic: &str,
        title: &str,
        message: &str,
        priority: &str,
        tags: &str,
        action: &NtfyAction,
        timeout_secs: u64,
        ntfy: Option<&NtfyContext>,
    ) -> Result<bool, String> {
        let base = server.trim_end_matches('/');
        match action {
            NtfyAction::Publish => {
                let url = format!("{}/{}", base, topic);
                self.log(format!("ntfy: publishing to {}", url));
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|e| e.to_string())?;

                let sub_title = self.substitute_variables(title, ntfy, None);
                let sub_message = self.substitute_variables(message, ntfy, None);

                let mut req = client.post(&url).body(sub_message);
                if !sub_title.is_empty() { req = req.header("Title", sub_title); }
                if !priority.is_empty() { req = req.header("Priority", priority); }
                if !tags.is_empty() { req = req.header("Tags", tags); }
                let res = req.send().await.map_err(|e| e.to_string())?;
                Ok(res.status().is_success())
            }
            NtfyAction::Subscribe => {
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

    // ------------------------------------------------------------------
    // Variable substitution — now takes public_ip instead of loading config every call
    // ------------------------------------------------------------------
    fn substitute_variables(&self, text: &str, ntfy: Option<&NtfyContext>, public_ip: Option<&str>) -> String {
        let mut result = text.to_string();
        if let Some(ip) = public_ip {
            result = result.replace("{{public_ip}}", ip);
        }
        if let Some(ctx) = ntfy {
            result = result.replace("{{ntfy_topic}}", &ctx.topic);
            result = result.replace("{{ntfy_title}}", &ctx.title);
            result = result.replace("{{ntfy_message}}", &ctx.message);
            for (idx, tag) in ctx.tags.split(',').enumerate() {
                let tag = tag.trim();
                if !tag.is_empty() {
                    result = result.replace(&format!("{{{{ntfy_tags{}}}}}", idx + 1), tag);
                }
            }
        }
        result
    }

    fn log(&self, msg: String) {
        let _ = self.log_tx.send(msg);
    }
}
