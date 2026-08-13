use chrono::{DateTime, Local, Weekday};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct NtfyContext {
    pub topic: String,
    pub title: String,
    pub message: String,
    pub tags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TriggerType {
    Time { hour: u8, minute: u8 },
    DaysOfWeek { days: Vec<Weekday>, hour: u8, minute: u8 },
    Interval { minutes: u64 },
    Email {
        from_pattern: String,
        subject_pattern: String,
        body_pattern: String,
    },
    Ntfy {
        server: String,
        topic: String,
        title_pattern: String,
        message_pattern: String,
    },
    Startup,
    OnDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NtfyAction {
    Publish,
    Subscribe,
}

impl Default for NtfyAction {
    fn default() -> Self {
        NtfyAction::Publish
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskType {
    HttpGet { url: String },
    HttpPost {
        url: String,
        body: String,
        headers: String,
    },
    Command {
        command: String,
        args: String,
        working_dir: String,
    },
    PathCheck {
        path: String,
        check_file_exists: bool,
        file_path: String,
    },
    FileChanged {
        file_path: String,
        baseline_hash: Option<String>,
    },
    Ntfy {
        server: String,
        topic: String,
        title: String,
        message: String,
        priority: String,
        tags: String,
        action: NtfyAction,
        subscribe_timeout_secs: u64,
    },
    GetPublicIp,
    CloudflareDnsUpdate {
        zone_id: String,
        record_name: String,
        record_type: String,
        record_id: String,
        content: String,
        proxied: bool,
        ttl: u32,
        #[serde(skip)]
        api_token_plain: Option<String>,
        #[serde(skip)]
        api_email_plain: Option<String>,
        api_token_encrypted: Option<Vec<u8>>,
        api_email_encrypted: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NotifyWhen {
    Success,
    Failure,
    Both,
}

impl Default for NotifyWhen {
    fn default() -> Self {
        NotifyWhen::Both
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub trigger: TriggerType,
    pub task_type: TaskType,
    pub notify_when: NotifyWhen,
    pub pushover_enabled: bool,
    pub pushover_title_success: String,
    pub pushover_message_success: String,
    pub pushover_title_failure: String,
    pub pushover_message_failure: String,
    pub pushover_priority: i8,
    pub pushover_sound: String,
    pub last_run: Option<DateTime<Local>>,
    pub last_result: Option<bool>,
    pub last_error: Option<String>,
    #[serde(skip)]
    pub last_triggered_date: Option<chrono::NaiveDate>,
    #[serde(skip)]
    pub interval_last_run: Option<DateTime<Local>>,
    pub on_success_task_id: Option<Uuid>,
    pub on_failure_task_id: Option<Uuid>,
    #[serde(skip)]
    pub ntfy_context: Option<NtfyContext>,
}

impl Default for Task {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "New Task".to_string(),
            enabled: true,
            trigger: TriggerType::Time { hour: 0, minute: 0 },
            task_type: TaskType::HttpGet { url: String::new() },
            notify_when: NotifyWhen::Both,
            pushover_enabled: true,
            pushover_title_success: "Task Success".to_string(),
            pushover_message_success: "Task completed successfully".to_string(),
            pushover_title_failure: "Task Failed".to_string(),
            pushover_message_failure: "Task failed to complete".to_string(),
            pushover_priority: 0,
            pushover_sound: "pushover".to_string(),
            last_run: None,
            last_result: None,
            last_error: None,
            last_triggered_date: None,
            interval_last_run: None,
            on_success_task_id: None,
            on_failure_task_id: None,
            ntfy_context: None,
        }
    }
}

impl Task {
    pub fn should_notify(&self, success: bool) -> bool {
        match self.notify_when {
            NotifyWhen::Success => success,
            NotifyWhen::Failure => !success,
            NotifyWhen::Both => true,
        }
    }

    pub fn trigger_summary(&self) -> String {
        match &self.trigger {
            TriggerType::Time { hour, minute } => {
                format!("Daily at {:02}:{:02}", hour, minute)
            }
            TriggerType::DaysOfWeek { days, hour, minute } => {
                let days_str: Vec<String> = days.iter().map(|d| format!("{:?}", d)).collect();
                format!("{} at {:02}:{:02}", days_str.join(", "), hour, minute)
            }
            TriggerType::Interval { minutes } => {
                format!("Every {} minute{}", minutes, if *minutes == 1 { "" } else { "s" })
            }
            TriggerType::Email { from_pattern, subject_pattern, body_pattern } => {
                let mut parts = vec![];
                if !from_pattern.is_empty() {
                    parts.push(format!("from: {}", from_pattern));
                }
                if !subject_pattern.is_empty() {
                    parts.push(format!("subject: {}", subject_pattern));
                }
                if !body_pattern.is_empty() {
                    parts.push(format!("body: {}", body_pattern));
                }
                if parts.is_empty() {
                    "Email (any)".to_string()
                } else {
                    format!("Email ({})", parts.join(", "))
                }
            }
            TriggerType::Ntfy { server, topic, title_pattern, message_pattern } => {
                let mut parts = vec![];
                if !title_pattern.is_empty() {
                    parts.push(format!("title: {}", title_pattern));
                }
                if !message_pattern.is_empty() {
                    parts.push(format!("msg: {}", message_pattern));
                }
                let filter = if parts.is_empty() { "any".to_string() } else { parts.join(", ") };
                format!("ntfy {}/{} ({})", server.trim_end_matches('/'), topic, filter)
            }
            TriggerType::Startup => "On service startup".to_string(),
            TriggerType::OnDemand => "On demand (chained)".to_string(),
        }
    }

    pub fn task_summary(&self) -> String {
        match &self.task_type {
            TaskType::HttpGet { url } => format!("HTTP GET {}", url),
            TaskType::HttpPost { url, .. } => format!("HTTP POST {}", url),
            TaskType::Command { command, .. } => format!("CMD: {}", command),
            TaskType::PathCheck { path, .. } => format!("Path: {}", path),
            TaskType::FileChanged { file_path, .. } => format!("File: {}", file_path),
            TaskType::Ntfy { server, topic, action, .. } => {
                let action_str = match action {
                    NtfyAction::Publish => "PUB",
                    NtfyAction::Subscribe => "SUB",
                };
                format!("ntfy {} {}/{}", action_str, server, topic)
            }
            TaskType::GetPublicIp => "Get Public IP".to_string(),
            TaskType::CloudflareDnsUpdate { zone_id, record_name, record_type, .. } => {
                format!("Cloudflare {} {} (zone: {})", record_type, record_name, zone_id)
            }
        }
    }
}
