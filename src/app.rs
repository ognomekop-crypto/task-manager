use crate::config::Config;
use crate::crypto::Crypto;
use crate::task::{NotifyWhen, Task, TaskType, TriggerType, NtfyAction, IpListAction};
use chrono::{Local, Datelike};
use eframe::egui;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime};

pub struct App {
    tasks: Vec<Task>,
    config: Config,
    master_password: String,
    password_verified: bool,
    service_process: Option<std::process::Child>,
    service_status: String,
    selected_task_idx: Option<usize>,
    editing_task: Option<Task>,
    show_settings: bool,
    show_logs: bool,
    show_password_prompt: bool,
    password_input: String,
    password_error: String,
    settings_smtp_port: String,
    settings_app_token: String,
    settings_user_key: String,
    settings_cloudflare_token: String,
    settings_cloudflare_email: String,
    settings_cloudflare_zone_id: String,
    settings_cloudflare_record_name: String,
    settings_cloudflare_proxied: String,
    settings_cloudflare_ttl: String,
    settings_new_password: String,
    settings_confirm_password: String,
    log_lines: Vec<String>,
    last_log_poll: Option<Instant>,
    last_status_mtime: Option<SystemTime>,
    known_log_lines: HashSet<String>,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext) -> Self {
        let config = Config::load();
        let tasks = config.tasks.clone();
        let has_password = config.password_verifier.is_some();
        let smtp_port_str = if config.smtp_port == 0 { "25".to_string() } else { config.smtp_port.to_string() };

        let mut app = Self {
            tasks, config,
            master_password: String::new(),
            password_verified: !has_password,
            service_process: None,
            service_status: "Service: Unknown".to_string(),
            selected_task_idx: None,
            editing_task: None,
            show_settings: !has_password,
            show_logs: false,
            show_password_prompt: has_password,
            password_input: String::new(),
            password_error: String::new(),
            settings_smtp_port: smtp_port_str,
            settings_app_token: String::new(),
            settings_user_key: String::new(),
            settings_cloudflare_token: String::new(),
            settings_cloudflare_email: String::new(),
            settings_cloudflare_zone_id: String::new(),
            settings_cloudflare_record_name: String::new(),
            settings_cloudflare_proxied: String::new(),
            settings_cloudflare_ttl: String::new(),
            settings_new_password: String::new(),
            settings_confirm_password: String::new(),
            log_lines: Vec::new(),
            last_log_poll: None,
            last_status_mtime: None,
            known_log_lines: HashSet::new(),
        };
        app.push_log("GUI started".to_string());
        if !has_password {
            app.push_log("First run - please configure settings and start service".to_string());
        }
        app
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    fn push_log(&mut self, msg: String) {
        let line = format!("[{}] {}", Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
        self.log_lines.push(line);
        if self.log_lines.len() > 2000 { self.log_lines.remove(0); }
    }

    fn compute_file_hash(path: &str) -> Option<String> {
        let mut file = std::fs::File::open(path).ok()?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher).ok()?;
        Some(hex::encode(hasher.finalize()))
    }

    fn decrypt_credentials(&self) -> Option<(String, String)> {
        let salt = self.config.password_salt.as_ref()?;
        let app = Crypto::decrypt(self.config.pushover_app_token_encrypted.as_ref()?, &self.master_password, salt).ok()?;
        let user = Crypto::decrypt(self.config.pushover_user_key_encrypted.as_ref()?, &self.master_password, salt).ok()?;
        Some((app, user))
    }

    fn decrypt_cloudflare_token(&self) -> Option<String> {
        let salt = self.config.password_salt.as_ref()?;
        Crypto::decrypt(self.config.cloudflare_api_token_encrypted.as_ref()?, &self.master_password, salt).ok()
    }

    fn decrypt_cloudflare_email(&self) -> Option<String> {
        let salt = self.config.password_salt.as_ref()?;
        Crypto::decrypt(self.config.cloudflare_api_email_encrypted.as_ref()?, &self.master_password, salt).ok()
    }

    fn is_service_running(&mut self) -> bool {
        if let Some(ref mut child) = self.service_process {
            match child.try_wait() {
                Ok(None) => return true,
                _ => self.service_process = None,
            }
        }
        std::fs::metadata(Config::status_path())
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.elapsed().ok())
            .map_or(false, |e| e < Duration::from_secs(10))
    }

    fn start_service(&mut self) {
        let exe_path = std::env::current_exe()
            .ok()
            .and_then(|mut p| { p.pop(); p.push("task_manager_service.exe"); Some(p) })
            .unwrap_or_else(|| "task_manager_service.exe".into());

        let mut cmd = std::process::Command::new(&exe_path);
        if self.password_verified && !self.master_password.is_empty() {
            cmd.env("TASK_MANAGER_PASSWORD", &self.master_password);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x00000008);
        }
        match cmd.spawn() {
            Ok(child) => { self.service_process = Some(child); self.push_log("Service started".to_string()); }
            Err(e) => self.push_log(format!("Failed to start service: {}", e)),
        }
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service_process.take() {
            let _ = child.kill();
            self.push_log("Service stopped".to_string());
        } else {
            let _ = std::process::Command::new("taskkill").args(&["/F", "/IM", "task_manager_service.exe"]).output();
            self.push_log("Service stop requested".to_string());
        }
    }

    fn poll_service_status(&mut self) {
        let status_path = Config::status_path();
        let mtime = match std::fs::metadata(&status_path).and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(_) => return,
        };
        if self.last_status_mtime == Some(mtime) { return; }
        self.last_status_mtime = Some(mtime);

        let data = match std::fs::read_to_string(&status_path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let status: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return,
        };
        let tasks_json = match status.get("tasks") {
            Some(t) => t,
            None => return,
        };
        let tasks: Vec<Task> = match serde_json::from_value(tasks_json.clone()) {
            Ok(t) => t,
            Err(_) => return,
        };
        for new_task in &tasks {
            if let Some(existing) = self.tasks.iter_mut().find(|t| t.id == new_task.id) {
                existing.last_run = new_task.last_run;
                existing.last_result = new_task.last_result;
                existing.last_error = new_task.last_error.clone();
            }
        }
    }

    fn poll_logs(&mut self) {
        let log_dir = Config::log_dir();
        let today = chrono::Local::now().date_naive();
        let filename = format!("{:02}-{:02}-{:02}.log", today.month(), today.day(), today.year() % 100);
        let path = log_dir.join(&filename);

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        for line in content.lines() {
            let s = line.to_string();
            if self.known_log_lines.insert(s.clone()) {
                self.log_lines.push(s);
            }
        }
        while self.log_lines.len() > 2000 { self.log_lines.remove(0); }
        while self.known_log_lines.len() > 5000 {
            self.known_log_lines = self.log_lines.iter().cloned().collect();
        }
    }

    fn save_config(&mut self) {
        let latest = Config::load();
        let mut config = self.config.clone();
        if latest.public_ip.is_some() { config.public_ip = latest.public_ip; }
        config.tasks = self.tasks.clone();

        match config.save() {
            Ok(_) => {
                self.push_log(format!(
                    "Config saved. token={} email={} zone='{}' record='{}'",
                    config.cloudflare_api_token_encrypted.is_some(),
                    config.cloudflare_api_email_encrypted.is_some(),
                    config.cloudflare_default_zone_id,
                    config.cloudflare_default_record_name
                ));
                self.config = config;
            }
            Err(e) => self.push_log(format!("Failed to save config: {}", e)),
        }
    }

    fn save_settings(&mut self) {
        if let Ok(port) = self.settings_smtp_port.parse::<u16>() {
            self.config.smtp_port = port;
        }

        let saving_pushover = !self.settings_app_token.is_empty() || !self.settings_user_key.is_empty();
        let saving_cloudflare = !self.settings_cloudflare_token.is_empty() || !self.settings_cloudflare_email.is_empty();
        let will_set_password = !self.settings_new_password.is_empty();

        if will_set_password {
            if self.settings_new_password != self.settings_confirm_password {
                self.password_error = "Passwords do not match".to_string();
                return;
            }
            let salt = Crypto::generate_salt();
            if let Ok(verifier) = Crypto::generate_verifier(&self.settings_new_password, &salt) {
                self.config.password_verifier = Some(verifier);
                self.config.password_salt = Some(salt.to_vec());
                self.master_password = self.settings_new_password.clone();
                self.password_verified = true;
            }
            self.settings_new_password.clear();
            self.settings_confirm_password.clear();
        }

        let has_password = self.config.password_verifier.is_some();
        if (saving_pushover || saving_cloudflare) && !has_password {
            self.password_error = "A master password is required to encrypt credentials. Set one in the Master Password section below.".to_string();
            return;
        }

        if !self.settings_app_token.is_empty() && !self.settings_user_key.is_empty() {
            if let Some(ref salt) = self.config.password_salt {
                if let Ok(enc) = Crypto::encrypt(&self.settings_app_token, &self.master_password, salt) {
                    self.config.pushover_app_token_encrypted = Some(enc);
                }
                if let Ok(enc) = Crypto::encrypt(&self.settings_user_key, &self.master_password, salt) {
                    self.config.pushover_user_key_encrypted = Some(enc);
                }
            }
        }

        let cf_token = self.settings_cloudflare_token.trim();
        if !cf_token.is_empty() {
            if let Some(ref salt) = self.config.password_salt {
                match Crypto::encrypt(cf_token, &self.master_password, salt) {
                    Ok(enc) => {
                        self.config.cloudflare_api_token_encrypted = Some(enc);
                        self.push_log("Cloudflare token encrypted and stored".to_string());
                    }
                    Err(e) => self.push_log(format!("ERROR: Failed to encrypt Cloudflare token: {}", e)),
                }
            } else {
                self.push_log("ERROR: Cannot encrypt Cloudflare token — no password salt set".to_string());
            }
        } else {
            self.config.cloudflare_api_token_encrypted = None;
            self.push_log("Cloudflare token cleared".to_string());
        }

        let cf_email = self.settings_cloudflare_email.trim();
        if !cf_email.is_empty() {
            if let Some(ref salt) = self.config.password_salt {
                if let Ok(enc) = Crypto::encrypt(cf_email, &self.master_password, salt) {
                    self.config.cloudflare_api_email_encrypted = Some(enc);
                }
            }
        } else {
            self.config.cloudflare_api_email_encrypted = None;
        }

        self.config.cloudflare_default_zone_id = self.settings_cloudflare_zone_id.trim().to_string();
        self.config.cloudflare_default_record_name = self.settings_cloudflare_record_name.trim().to_string();
        self.config.cloudflare_default_proxied = self.settings_cloudflare_proxied.trim().to_string();
        self.config.cloudflare_default_ttl = self.settings_cloudflare_ttl.trim().to_string();

        self.push_log(format!(
            "Settings prepared: zone_id='{}' record_name='{}' proxied='{}' ttl='{}' token_present={} email_present={}",
            self.config.cloudflare_default_zone_id,
            self.config.cloudflare_default_record_name,
            self.config.cloudflare_default_proxied,
            self.config.cloudflare_default_ttl,
            self.config.cloudflare_api_token_encrypted.is_some(),
            self.config.cloudflare_api_email_encrypted.is_some()
        ));

        self.save_config();
        self.show_settings = false;
        self.password_error.clear();
    }

    fn verify_password(&mut self) {
        let verifier = match self.config.password_verifier.as_ref() {
            Some(v) => v,
            None => return,
        };
        let salt = match self.config.password_salt.as_ref() {
            Some(s) => s,
            None => return,
        };
        if !Crypto::verify_password(verifier, &self.password_input, salt) {
            self.password_error = "Invalid password".to_string();
            return;
        }
        self.master_password = self.password_input.clone();
        self.password_verified = true;
        self.show_password_prompt = false;
        self.password_error.clear();

        if let Some((app, user)) = self.decrypt_credentials() {
            self.settings_app_token = app;
            self.settings_user_key = user;
        }
        if let Some(token) = self.decrypt_cloudflare_token() {
            self.settings_cloudflare_token = token;
        }
        if let Some(email) = self.decrypt_cloudflare_email() {
            self.settings_cloudflare_email = email;
        }
        self.settings_cloudflare_proxied = self.config.cloudflare_default_proxied.clone();
        self.settings_cloudflare_ttl = self.config.cloudflare_default_ttl.clone();
    }

    fn add_task(&mut self) {
        let mut task = Task::default();
        if let TaskType::FileChanged { ref file_path, .. } = task.task_type {
            if let Some(hash) = Self::compute_file_hash(file_path) {
                if let TaskType::FileChanged { ref mut baseline_hash, .. } = task.task_type {
                    *baseline_hash = Some(hash);
                }
            }
        }
        self.editing_task = Some(task);
        self.selected_task_idx = None;
    }

    fn edit_selected_task(&mut self) {
        let idx = match self.selected_task_idx {
            Some(i) if i < self.tasks.len() => i,
            _ => return,
        };
        let mut task = self.tasks[idx].clone();
        let decrypt = |enc: &Option<Vec<u8>>, salt: &Option<Vec<u8>>, pwd: &str| -> Option<String> {
            enc.as_ref().and_then(|e| salt.as_ref().and_then(|s| Crypto::decrypt(e, pwd, s).ok()))
        };
        match &mut task.task_type {
            TaskType::CloudflareDnsUpdate { ref mut api_token_plain, ref mut api_email_plain, ref api_token_encrypted, ref api_email_encrypted, .. }
            | TaskType::CloudflareIpListUpdate { ref mut api_token_plain, ref mut api_email_plain, ref api_token_encrypted, ref api_email_encrypted, .. } => {
                if self.password_verified {
                    *api_token_plain = decrypt(api_token_encrypted, &self.config.password_salt, &self.master_password);
                    *api_email_plain = decrypt(api_email_encrypted, &self.config.password_salt, &self.master_password);
                }
            }
            _ => {}
        }
        self.editing_task = Some(task);
    }

    fn delete_selected_task(&mut self) {
        if let Some(idx) = self.selected_task_idx {
            if idx < self.tasks.len() {
                self.tasks.remove(idx);
                self.selected_task_idx = None;
                self.save_config();
            }
        }
    }

    fn save_task(&mut self) {
        let mut task = match self.editing_task.take() {
            Some(t) => t,
            None => return,
        };
        if let TaskType::FileChanged { ref file_path, ref mut baseline_hash } = task.task_type {
            *baseline_hash = Self::compute_file_hash(file_path);
        }
        if let TaskType::CloudflareDnsUpdate { ref mut api_token_encrypted, ref mut api_email_encrypted, ref mut api_token_plain, ref mut api_email_plain, .. }
            | TaskType::CloudflareIpListUpdate { ref mut api_token_encrypted, ref mut api_email_encrypted, ref mut api_token_plain, ref mut api_email_plain, .. } = task.task_type
        {
            if self.password_verified && !self.master_password.is_empty() {
                if let Some(ref salt) = self.config.password_salt {
                    if let Some(ref plain) = api_token_plain {
                        if !plain.is_empty() {
                            if let Ok(enc) = Crypto::encrypt(plain, &self.master_password, salt) {
                                *api_token_encrypted = Some(enc);
                            }
                        } else {
                            *api_token_encrypted = None;
                        }
                    }
                    if let Some(ref plain) = api_email_plain {
                        if !plain.is_empty() {
                            if let Ok(enc) = Crypto::encrypt(plain, &self.master_password, salt) {
                                *api_email_encrypted = Some(enc);
                            }
                        } else {
                            *api_email_encrypted = None;
                        }
                    }
                }
                *api_token_plain = None;
                *api_email_plain = None;
            }
        }
        if let Some(idx) = self.tasks.iter().position(|t| t.id == task.id) {
            self.tasks[idx] = task;
        } else {
            self.tasks.push(task);
        }
        self.save_config();
    }

    fn cancel_edit(&mut self) {
        self.editing_task = None;
    }

    fn test_smtp_connection(&mut self) {
        let port = self.config.smtp_port;
        std::thread::spawn(move || {
            match std::net::TcpStream::connect(format!("127.0.0.1:{}", port)) {
                Ok(mut stream) => {
                    use std::io::{Read, Write};
                    let mut buf = [0u8; 256];
                    match stream.read(&mut buf) {
                        Ok(n) if n > 0 => println!("SMTP test: Connected. Server: {}", String::from_utf8_lossy(&buf[..n]).trim()),
                        _ => println!("SMTP test: Connected but no greeting"),
                    }
                    let _ = stream.write_all(b"QUIT\r\n");
                }
                Err(e) => println!("SMTP test FAILED: {}", e),
            }
        });
    }

    // ------------------------------------------------------------------
    // UI rendering helpers
    // ------------------------------------------------------------------
    fn render_password_prompt(&mut self, ctx: &egui::Context) {
        egui::Window::new("Enter Master Password")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label("This application is password protected.");
                ui.add_space(8.0);
                let response = ui.add(egui::TextEdit::singleline(&mut self.password_input).password(true).hint_text("Password"));
                if !self.password_error.is_empty() {
                    ui.colored_label(egui::Color32::RED, &self.password_error);
                }
                ui.add_space(8.0);
                let enter_pressed = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Unlock").clicked() || enter_pressed {
                    self.verify_password();
                }
            });
    }

    fn render_menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Settings").clicked() {
                        let latest = Config::load();
                        self.config.public_ip = latest.public_ip;
                        self.show_settings = true;
                        ui.close_menu();
                    }
                    if ui.button("Logs").clicked() {
                        self.show_logs = true;
                        ui.close_menu();
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let color = if self.service_status.contains("Running") { egui::Color32::GREEN } else { egui::Color32::RED };
                    ui.colored_label(color, &self.service_status);
                });
            });
        });
    }

    fn render_task_list(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("task_list").resizable(true).default_width(320.0).show(ctx, |ui| {
            ui.heading("Tasks");
            ui.horizontal(|ui| {
                if ui.button("Add").clicked() { self.add_task(); }
                if ui.button("Edit").clicked() { self.edit_selected_task(); }
                if ui.button("Delete").clicked() { self.delete_selected_task(); }
            });
            ui.horizontal(|ui| {
                if ui.button("Start Service").clicked() { self.start_service(); }
                if ui.button("Stop Service").clicked() { self.stop_service(); }
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (idx, task) in self.tasks.iter().enumerate() {
                    let selected = self.selected_task_idx == Some(idx);
                    let status = match task.last_result {
                        Some(true) => "[OK]",
                        Some(false) => "[FAIL]",
                        None => "[-]",
                    };
                    let label = format!("{} {} {}", status, if task.enabled { "ON" } else { "OFF" }, task.name);
                    let response = ui.selectable_label(selected, label);
                    if response.clicked() {
                        self.selected_task_idx = Some(idx);
                        self.editing_task = None;
                    }
                    if response.hovered() {
                        response.on_hover_text(task.trigger_summary());
                    }
                }
            });
        });
    }

    fn render_trigger_editor(ui: &mut egui::Ui, trigger: &mut TriggerType) {
        ui.label("Trigger Type:");
        let trigger_text = match trigger {
            TriggerType::Time { .. } => "Specific Time",
            TriggerType::DaysOfWeek { .. } => "Days of Week",
            TriggerType::Interval { .. } => "Interval",
            TriggerType::Email { .. } => "Email",
            TriggerType::Ntfy { .. } => "ntfy.sh",
            TriggerType::Startup => "Startup",
            TriggerType::OnDemand => "On Demand",
        };
        egui::ComboBox::new("trigger_combo", "")
            .selected_text(trigger_text)
            .show_ui(ui, |ui| {
                ui.selectable_value(trigger, TriggerType::Time { hour: 0, minute: 0 }, "Specific Time");
                ui.selectable_value(trigger, TriggerType::DaysOfWeek { days: vec![], hour: 0, minute: 0 }, "Days of Week");
                ui.selectable_value(trigger, TriggerType::Interval { minutes: 60 }, "Interval");
                ui.selectable_value(trigger, TriggerType::Email { from_pattern: String::new(), subject_pattern: String::new(), body_pattern: String::new() }, "Email");
                ui.selectable_value(trigger, TriggerType::Ntfy { server: "https://ntfy.sh".to_string(), topic: String::new(), title_pattern: String::new(), message_pattern: String::new() }, "ntfy.sh");
                ui.selectable_value(trigger, TriggerType::Startup, "Startup");
                ui.selectable_value(trigger, TriggerType::OnDemand, "On Demand");
            });

        match trigger {
            TriggerType::Time { hour, minute } => {
                ui.horizontal(|ui| {
                    ui.label("Time:");
                    ui.add(egui::DragValue::new(hour).speed(1.0).clamp_range(0u8..=23u8));
                    ui.label(":");
                    ui.add(egui::DragValue::new(minute).speed(1.0).clamp_range(0u8..=59u8));
                });
            }
            TriggerType::DaysOfWeek { days, hour, minute } => {
                ui.horizontal(|ui| {
                    for day in [chrono::Weekday::Mon, chrono::Weekday::Tue, chrono::Weekday::Wed, chrono::Weekday::Thu, chrono::Weekday::Fri, chrono::Weekday::Sat, chrono::Weekday::Sun] {
                        let mut checked = days.contains(&day);
                        let label = format!("{:?}", day);
                        if ui.checkbox(&mut checked, &label[..3]).changed() {
                            if checked && !days.contains(&day) { days.push(day); }
                            else if !checked { days.retain(|d| *d != day); }
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Time:");
                    ui.add(egui::DragValue::new(hour).speed(1.0).clamp_range(0u8..=23u8));
                    ui.label(":");
                    ui.add(egui::DragValue::new(minute).speed(1.0).clamp_range(0u8..=59u8));
                });
            }
            TriggerType::Interval { minutes } => {
                ui.horizontal(|ui| {
                    ui.label("Every");
                    ui.add(egui::DragValue::new(minutes).speed(1.0).clamp_range(1u64..=10080u64));
                    ui.label("minutes");
                });
            }
            TriggerType::Email { from_pattern, subject_pattern, body_pattern } => {
                ui.horizontal(|ui| { ui.label("From contains:"); ui.add(egui::TextEdit::singleline(from_pattern).desired_width(250.0)); });
                ui.horizontal(|ui| { ui.label("Subject contains:"); ui.add(egui::TextEdit::singleline(subject_pattern).desired_width(250.0)); });
                ui.label("Body contains:");
                ui.add(egui::TextEdit::multiline(body_pattern).desired_rows(3));
            }
            TriggerType::Ntfy { server, topic, title_pattern, message_pattern } => {
                ui.horizontal(|ui| { ui.label("Server:"); ui.add(egui::TextEdit::singleline(server).desired_width(250.0)); });
                ui.horizontal(|ui| { ui.label("Topic:"); ui.add(egui::TextEdit::singleline(topic).desired_width(200.0)); });
                ui.horizontal(|ui| { ui.label("Title contains:"); ui.add(egui::TextEdit::singleline(title_pattern).desired_width(250.0)); });
                ui.label("Message contains:");
                ui.add(egui::TextEdit::multiline(message_pattern).desired_rows(3));
            }
            TriggerType::Startup => { ui.label("This task runs once when the service starts."); }
            TriggerType::OnDemand => { ui.label("This task only runs when called by another task via task chaining."); }
        }
    }

    fn render_task_type_editor(ui: &mut egui::Ui, task_type: &mut TaskType) {
        ui.label("Task Type:");
        let task_text = match task_type {
            TaskType::HttpGet { .. } => "HTTP GET",
            TaskType::HttpPost { .. } => "HTTP POST",
            TaskType::Command { .. } => "Command",
            TaskType::PathCheck { .. } => "Path Check",
            TaskType::FileChanged { .. } => "File Changed",
            TaskType::Ntfy { .. } => "ntfy.sh",
            TaskType::GetPublicIp => "Get Public IP",
            TaskType::CloudflareDnsUpdate { .. } => "Cloudflare DNS",
            TaskType::CloudflareIpListUpdate { .. } => "Cloudflare IP List",
        };
        egui::ComboBox::new("task_combo", "")
            .selected_text(task_text)
            .show_ui(ui, |ui| {
                ui.selectable_value(task_type, TaskType::HttpGet { url: String::new() }, "HTTP GET");
                ui.selectable_value(task_type, TaskType::HttpPost { url: String::new(), body: String::new(), headers: String::new() }, "HTTP POST");
                ui.selectable_value(task_type, TaskType::Command { command: String::new(), args: String::new(), working_dir: String::new() }, "Command");
                ui.selectable_value(task_type, TaskType::PathCheck { path: String::new(), check_file_exists: false, file_path: String::new() }, "Path Check");
                ui.selectable_value(task_type, TaskType::FileChanged { file_path: String::new(), baseline_hash: None }, "File Changed");
                ui.selectable_value(task_type, TaskType::Ntfy { server: "https://ntfy.sh".to_string(), topic: String::new(), title: String::new(), message: String::new(), priority: "default".to_string(), tags: String::new(), action: NtfyAction::Publish, subscribe_timeout_secs: 30 }, "ntfy.sh");
                ui.selectable_value(task_type, TaskType::GetPublicIp, "Get Public IP");
                ui.selectable_value(task_type, TaskType::CloudflareDnsUpdate { zone_id: String::new(), record_name: String::new(), record_type: "A".to_string(), record_id: String::new(), content: String::new(), proxied: "false".to_string(), ttl: "60".to_string(), api_token_plain: None, api_email_plain: None, api_token_encrypted: None, api_email_encrypted: None }, "Cloudflare DNS");
                            ui.selectable_value(task_type, TaskType::CloudflareIpListUpdate { account_id: String::new(), list_id: String::new(), list_name: String::new(), ip: String::new(), comment: String::new(), action: IpListAction::Add, api_token_plain: None, api_email_plain: None, api_token_encrypted: None, api_email_encrypted: None }, "Cloudflare IP List");
            });

        match task_type {
            TaskType::HttpGet { url } => {
                ui.horizontal(|ui| { ui.label("URL:"); ui.add(egui::TextEdit::singleline(url).desired_width(400.0)); });
            }
            TaskType::HttpPost { url, body, headers } => {
                ui.horizontal(|ui| { ui.label("URL:"); ui.add(egui::TextEdit::singleline(url).desired_width(400.0)); });
                ui.label("Headers (one per line, Key: Value):");
                ui.add(egui::TextEdit::multiline(headers).desired_rows(3));
                ui.label("Body:");
                ui.add(egui::TextEdit::multiline(body).desired_rows(5));
            }
            TaskType::Command { command, args, working_dir } => {
                ui.horizontal(|ui| { ui.label("Command:"); ui.add(egui::TextEdit::singleline(command).desired_width(300.0)); });
                ui.horizontal(|ui| { ui.label("Arguments:"); ui.add(egui::TextEdit::singleline(args).desired_width(300.0)); });
                ui.horizontal(|ui| { ui.label("Working Dir:"); ui.add(egui::TextEdit::singleline(working_dir).desired_width(300.0)); });
            }
            TaskType::PathCheck { path, check_file_exists, file_path } => {
                ui.horizontal(|ui| { ui.label("Path:"); ui.add(egui::TextEdit::singleline(path).desired_width(300.0)); });
                ui.checkbox(check_file_exists, "Check if specific file exists");
                if *check_file_exists {
                    ui.horizontal(|ui| { ui.label("File Path:"); ui.add(egui::TextEdit::singleline(file_path).desired_width(300.0)); });
                }
            }
            TaskType::FileChanged { file_path, baseline_hash } => {
                ui.horizontal(|ui| { ui.label("File Path:"); ui.add(egui::TextEdit::singleline(file_path).desired_width(300.0)); });
                if let Some(ref hash) = baseline_hash {
                    ui.label(format!("Baseline: {}...", &hash[..16.min(hash.len())]));
                } else {
                    ui.label("Baseline: Will be computed on save");
                }
            }
            TaskType::Ntfy { server, topic, title, message, priority, tags, action, subscribe_timeout_secs } => {
                ui.horizontal(|ui| { ui.label("Server:"); ui.add(egui::TextEdit::singleline(server).desired_width(250.0)); });
                ui.horizontal(|ui| { ui.label("Topic:"); ui.add(egui::TextEdit::singleline(topic).desired_width(200.0)); });
                let action_text = match action { NtfyAction::Publish => "Publish", NtfyAction::Subscribe => "Subscribe" };
                egui::ComboBox::new("ntfy_action", "").selected_text(action_text).show_ui(ui, |ui| {
                    ui.selectable_value(action, NtfyAction::Publish, "Publish");
                    ui.selectable_value(action, NtfyAction::Subscribe, "Subscribe");
                });
                ui.horizontal(|ui| { ui.label("Title:"); ui.add(egui::TextEdit::singleline(title).desired_width(250.0)); });
                ui.label("Message:");
                ui.add(egui::TextEdit::multiline(message).desired_rows(3));
                ui.horizontal(|ui| { ui.label("Priority:"); ui.add(egui::TextEdit::singleline(priority).desired_width(100.0).hint_text("min/low/default/high/max")); });
                ui.horizontal(|ui| { ui.label("Tags:"); ui.add(egui::TextEdit::singleline(tags).desired_width(200.0).hint_text("comma-separated")); });
                if matches!(action, NtfyAction::Subscribe) {
                    ui.horizontal(|ui| { ui.label("Timeout (sec):"); ui.add(egui::DragValue::new(subscribe_timeout_secs).speed(1.0).clamp_range(1u64..=300u64)); });
                }
            }
            TaskType::GetPublicIp => {
                ui.label("Fetches the public IP address and saves it to the config file.");
                ui.label("Use {{public_ip}} in ntfy title or message fields to reference it.");
            }
            TaskType::CloudflareDnsUpdate { zone_id, record_name, record_type, record_id, content, proxied, ttl, api_token_plain, api_email_plain, .. } => {
                ui.horizontal(|ui| { ui.label("Zone ID:"); ui.add(egui::TextEdit::singleline(zone_id).desired_width(300.0)); });
                ui.horizontal(|ui| { ui.label("Record Name:"); ui.add(egui::TextEdit::singleline(record_name).desired_width(300.0).hint_text("e.g. home.example.com")); });
                ui.horizontal(|ui| { ui.label("Record Type:"); ui.add(egui::TextEdit::singleline(record_type).desired_width(80.0).hint_text("A or AAAA")); });
                ui.horizontal(|ui| { ui.label("Record ID:"); ui.add(egui::TextEdit::singleline(record_id).desired_width(300.0).hint_text("Leave empty to auto-lookup")); });
                ui.horizontal(|ui| { ui.label("Content:"); ui.add(egui::TextEdit::singleline(content).desired_width(300.0).hint_text("Leave empty to use saved public IP")); });
                ui.horizontal(|ui| { ui.label("TTL:"); ui.add(egui::TextEdit::singleline(ttl).desired_width(80.0).hint_text("e.g. 60 or {{var}}")); });
                ui.horizontal(|ui| { ui.label("Proxied:"); ui.add(egui::TextEdit::singleline(proxied).desired_width(80.0).hint_text("true/false or {{var}}")); });
                ui.separator();
                ui.label("Per-Task Cloudflare Credentials (optional — leave empty to use global settings)");
                ui.horizontal(|ui| { ui.label("API Token:"); ui.add(egui::TextEdit::singleline(api_token_plain.get_or_insert_with(String::new)).password(true).hint_text("Leave empty for global default")); });
                ui.horizontal(|ui| { ui.label("Account Email:"); ui.add(egui::TextEdit::singleline(api_email_plain.get_or_insert_with(String::new)).password(true).hint_text("Only for Global API Key")); });
                ui.label("Leave empty to use the global token from Settings.");
            }
            TaskType::CloudflareIpListUpdate { account_id, list_id, list_name, ip, comment, action, api_token_plain, api_email_plain, .. } => {
                ui.horizontal(|ui| { ui.label("Account ID:"); ui.add(egui::TextEdit::singleline(account_id).desired_width(300.0)); });
                ui.horizontal(|ui| { ui.label("List ID:"); ui.add(egui::TextEdit::singleline(list_id).desired_width(300.0).hint_text("Leave empty to lookup by name")); });
                ui.horizontal(|ui| { ui.label("List Name:"); ui.add(egui::TextEdit::singleline(list_name).desired_width(300.0).hint_text("Used if List ID is empty")); });
                ui.horizontal(|ui| { ui.label("IP:"); ui.add(egui::TextEdit::singleline(ip).desired_width(200.0).hint_text("e.g. {{public_ip}}")); });
                ui.horizontal(|ui| { ui.label("Comment:"); ui.add(egui::TextEdit::singleline(comment).desired_width(300.0)); });
                let action_text = match action { IpListAction::Add => "Add", IpListAction::Remove => "Remove", IpListAction::ReplaceAll => "Replace All" };
                egui::ComboBox::new("iplist_action", "").selected_text(action_text).show_ui(ui, |ui| {
                    ui.selectable_value(action, IpListAction::Add, "Add");
                    ui.selectable_value(action, IpListAction::Remove, "Remove");
                    ui.selectable_value(action, IpListAction::ReplaceAll, "Replace All");
                });
                ui.separator();
                ui.label("Per-Task Cloudflare Credentials (optional — leave empty to use global settings)");
                ui.horizontal(|ui| { ui.label("API Token:"); ui.add(egui::TextEdit::singleline(api_token_plain.get_or_insert_with(String::new)).password(true).hint_text("Leave empty for global default")); });
                ui.horizontal(|ui| { ui.label("Account Email:"); ui.add(egui::TextEdit::singleline(api_email_plain.get_or_insert_with(String::new)).password(true).hint_text("Only for Global API Key")); });
                ui.label("Leave empty to use the global token from Settings.");
            }
        }
    }

    fn render_pushover_editor(ui: &mut egui::Ui, task: &mut Task) {
        ui.separator();
        ui.label("Pushover Notification");
        ui.checkbox(&mut task.pushover_enabled, "Enable Pushover notifications for this task");
        ui.add_space(4.0);
        egui::ComboBox::new("notify_combo", "")
            .selected_text(format!("{:?}", task.notify_when))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut task.notify_when, NotifyWhen::Success, "Success Only");
                ui.selectable_value(&mut task.notify_when, NotifyWhen::Failure, "Failure Only");
                ui.selectable_value(&mut task.notify_when, NotifyWhen::Both, "Both");
            });

        ui.label("Success Title:");
        ui.add(egui::TextEdit::singleline(&mut task.pushover_title_success).desired_width(300.0));
        ui.label("Success Message:");
        ui.add(egui::TextEdit::singleline(&mut task.pushover_message_success).desired_width(400.0));
        ui.label("Failure Title:");
        ui.add(egui::TextEdit::singleline(&mut task.pushover_title_failure).desired_width(300.0));
        ui.label("Failure Message:");
        ui.add(egui::TextEdit::singleline(&mut task.pushover_message_failure).desired_width(400.0));

        ui.horizontal(|ui| { ui.label("Priority:"); ui.add(egui::Slider::new(&mut task.pushover_priority, -2..=2)); });
        ui.horizontal(|ui| { ui.label("Sound:"); ui.add(egui::TextEdit::singleline(&mut task.pushover_sound).desired_width(150.0)); });
    }

    fn render_task_chaining(ui: &mut egui::Ui, task: &mut Task, all_tasks: &[Task]) {
        ui.separator();
        ui.label("Task Chaining");
        ui.label("Run another task when this one completes:");
        let tasks_ref = all_tasks;

        let success_label = task.on_success_task_id
            .and_then(|id| tasks_ref.iter().find(|t| t.id == id))
            .map(|t| t.name.as_str())
            .unwrap_or("None");
        egui::ComboBox::new("chain_success_combo", "On Success")
            .selected_text(success_label)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut task.on_success_task_id, None, "None");
                for t in tasks_ref {
                    if t.id != task.id { ui.selectable_value(&mut task.on_success_task_id, Some(t.id), &t.name); }
                }
            });

        let failure_label = task.on_failure_task_id
            .and_then(|id| tasks_ref.iter().find(|t| t.id == id))
            .map(|t| t.name.as_str())
            .unwrap_or("None");
        egui::ComboBox::new("chain_failure_combo", "On Failure")
            .selected_text(failure_label)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut task.on_failure_task_id, None, "None");
                for t in tasks_ref {
                    if t.id != task.id { ui.selectable_value(&mut task.on_failure_task_id, Some(t.id), &t.name); }
                }
            });
    }

    fn render_task_editor(&mut self, ctx: &egui::Context) -> (bool, bool) {
        let mut save_clicked = false;
        let mut cancel_clicked = false;

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                if let Some(ref mut task) = self.editing_task {
                    ui.heading("Edit Task");
                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.label("Name:");
                        ui.add(egui::TextEdit::singleline(&mut task.name).desired_width(300.0));
                    });
                    ui.checkbox(&mut task.enabled, "Enabled");
                    ui.separator();

                    Self::render_trigger_editor(ui, &mut task.trigger);
                    ui.separator();
                    Self::render_task_type_editor(ui, &mut task.task_type);
                    Self::render_pushover_editor(ui, task);
                    Self::render_task_chaining(ui, task, &self.tasks);

                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save Task").clicked() { save_clicked = true; }
                        if ui.button("Cancel").clicked() { cancel_clicked = true; }
                    });
                } else if let Some(idx) = self.selected_task_idx {
                    if idx < self.tasks.len() {
                        let task = &self.tasks[idx];
                        ui.heading(&task.name);
                        ui.add_space(8.0);
                        ui.label(format!("Status: {}", if task.enabled { "Enabled" } else { "Disabled" }));
                        ui.label(format!("Trigger: {}", task.trigger_summary()));
                        ui.label(format!("Action: {}", task.task_summary()));
                        if let Some(last_run) = task.last_run {
                            ui.label(format!("Last Run: {}", last_run.format("%Y-%m-%d %H:%M:%S")));
                        }
                        if let Some(result) = task.last_result {
                            let (text, color) = if result { ("Success", egui::Color32::GREEN) } else { ("Failure", egui::Color32::RED) };
                            ui.horizontal(|ui| { ui.label("Last Result:"); ui.colored_label(color, text); });
                        }
                        if let Some(ref error) = task.last_error {
                            ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
                        }
                        if task.on_success_task_id.is_some() || task.on_failure_task_id.is_some() {
                            ui.separator();
                            ui.label("Task Chaining:");
                            if let Some(id) = task.on_success_task_id {
                                if let Some(t) = self.tasks.iter().find(|t| t.id == id) {
                                    ui.label(format!("  On Success -> {}", t.name));
                                }
                            }
                            if let Some(id) = task.on_failure_task_id {
                                if let Some(t) = self.tasks.iter().find(|t| t.id == id) {
                                    ui.label(format!("  On Failure -> {}", t.name));
                                }
                            }
                        }
                    }
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label("Select a task from the list or click Add to create one");
                    });
                }
            });
        });
        (save_clicked, cancel_clicked)
    }

    fn render_settings(&mut self, ctx: &egui::Context) {
        egui::Window::new("Settings")
            .default_size([400.0, 600.0])
            .show(ctx, |ui| {
                ui.heading("SMTP Server");
                ui.horizontal(|ui| {
                    ui.label("Port:");
                    ui.add(egui::TextEdit::singleline(&mut self.settings_smtp_port).desired_width(80.0));
                });
                ui.label("Unencrypted, no authentication required.");
                ui.separator();

                ui.heading("Master Password");
                if self.config.password_verifier.is_some() {
                    ui.label("Password is set. Enter current password below to change.");
                } else {
                    ui.label("Set a password to encrypt Pushover and Cloudflare credentials.");
                }
                ui.add(egui::TextEdit::singleline(&mut self.settings_new_password).password(true).hint_text("New Password"));
                ui.add(egui::TextEdit::singleline(&mut self.settings_confirm_password).password(true).hint_text("Confirm Password"));
                ui.separator();

                ui.heading("Pushover.net");
                ui.label("App Token:");
                ui.add(egui::TextEdit::singleline(&mut self.settings_app_token).password(true));
                ui.label("User Key:");
                ui.add(egui::TextEdit::singleline(&mut self.settings_user_key).password(true));

                ui.separator();
                ui.heading("Cloudflare DNS");
                ui.label("API Token (or Global API Key):");
                ui.add(egui::TextEdit::singleline(&mut self.settings_cloudflare_token).password(true).hint_text("Leave empty to keep existing"));
                ui.label("Account Email (only for Global API Key):");
                ui.add(egui::TextEdit::singleline(&mut self.settings_cloudflare_email).password(true).hint_text("Leave empty when using API Token"));
                ui.label("Default Zone ID:");
                ui.add(egui::TextEdit::singleline(&mut self.settings_cloudflare_zone_id).desired_width(300.0).hint_text("Used when task Zone ID is empty"));
                ui.label("Default Record Name:");
                ui.add(egui::TextEdit::singleline(&mut self.settings_cloudflare_record_name).desired_width(300.0).hint_text("Used when task Record Name is empty"));
                ui.label("Default Proxied:");
                ui.add(egui::TextEdit::singleline(&mut self.settings_cloudflare_proxied).desired_width(80.0).hint_text("true/false"));
                ui.label("Default TTL:");
                ui.add(egui::TextEdit::singleline(&mut self.settings_cloudflare_ttl).desired_width(80.0).hint_text("e.g. 60"));
                ui.label("Hint: API Tokens use Bearer auth. Global API Keys need email + key.");

                ui.separator();
                ui.heading("Public IP");
                if let Some(ref ip) = self.config.public_ip {
                    ui.label(format!("Saved IP: {}", ip));
                } else {
                    ui.label("No public IP saved yet. Run a 'Get Public IP' task to fetch it.");
                }

                if !self.password_error.is_empty() {
                    ui.colored_label(egui::Color32::RED, &self.password_error);
                }

                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        self.save_settings();
                        self.show_settings = false;
                    }
                    if ui.button("Test SMTP").clicked() { self.test_smtp_connection(); }
                    if ui.button("Cancel").clicked() {
                        self.show_settings = false;
                        self.password_error.clear();
                    }
                });
            });
    }

    fn render_logs(&mut self, ctx: &egui::Context) {
        let mut open = self.show_logs;
        egui::Window::new("Logs")
            .open(&mut open)
            .default_size([600.0, 400.0])
            .show(ctx, |ui| {
                if ui.button("Clear").clicked() {
                    self.log_lines.clear();
                    self.known_log_lines.clear();
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.log_lines { ui.monospace(line); }
                    });
            });
        self.show_logs = open;
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = Instant::now();
        if self.last_log_poll.map(|t| now.duration_since(t).as_secs() >= 1).unwrap_or(true) {
            self.last_log_poll = Some(now);
            self.poll_service_status();
            self.poll_logs();
            self.service_status = if self.is_service_running() {
                "Service: Running".to_string()
            } else {
                "Service: Stopped".to_string()
            };
        }

        if self.show_password_prompt {
            self.render_password_prompt(ctx);
            return;
        }

        self.render_menu_bar(ctx);
        self.render_task_list(ctx);

        let (save_clicked, cancel_clicked) = self.render_task_editor(ctx);
        if save_clicked { self.save_task(); }
        if cancel_clicked { self.cancel_edit(); }

        if self.show_settings { self.render_settings(ctx); }
        if self.show_logs { self.render_logs(ctx); }
    }
}
