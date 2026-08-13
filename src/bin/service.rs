use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

use task_manager::cloudflare::CloudflareClient;
use task_manager::config::Config;
use task_manager::crypto::Crypto;
use task_manager::logger::LogManager;
use task_manager::pushover::PushoverClient;
use task_manager::scheduler::{Scheduler, SchedulerCommand};
use task_manager::smtp::SmtpServer;

#[tokio::main]
async fn main() {
    let config = Config::load();

    let password = std::env::var("TASK_MANAGER_PASSWORD").ok();
    std::env::remove_var("TASK_MANAGER_PASSWORD");

    let log_dir = Config::log_dir();
    let (log_manager, _log_rx) = LogManager::new(log_dir);

    let pushover = if let Some(ref pwd) = password {
        if let Some(ref salt) = config.password_salt {
            if let Some(ref verifier) = config.password_verifier {
                if Crypto::verify_password(verifier, pwd, salt) {
                    let app_token = config.pushover_app_token_encrypted.as_ref()
                        .and_then(|enc| Crypto::decrypt(enc, pwd, salt).ok());
                    let user_key = config.pushover_user_key_encrypted.as_ref()
                        .and_then(|enc| Crypto::decrypt(enc, pwd, salt).ok());
                    if let (Some(app), Some(user)) = (app_token, user_key) {
                        log_manager.log("Pushover credentials loaded".to_string());
                        Some(PushoverClient::new(app, user))
                    } else {
                        log_manager.log("Failed to decrypt Pushover credentials".to_string());
                        None
                    }
                } else {
                    log_manager.log("Invalid password provided".to_string());
                    None
                }
            } else {
                log_manager.log("No password verifier found".to_string());
                None
            }
        } else {
            log_manager.log("No password salt found".to_string());
            None
        }
    } else if config.password_verifier.is_some() {
        log_manager.log("Password required but not provided - Pushover disabled".to_string());
        None
    } else {
        None
    };

    let cloudflare = if let Some(ref pwd) = password {
        if let Some(ref salt) = config.password_salt {
            if let Some(ref verifier) = config.password_verifier {
                if Crypto::verify_password(verifier, pwd, salt) {
                    let api_token = config.cloudflare_api_token_encrypted.as_ref()
                        .and_then(|enc| Crypto::decrypt(enc, pwd, salt).ok());
                    let api_email = config.cloudflare_api_email_encrypted.as_ref()
                        .and_then(|enc| Crypto::decrypt(enc, pwd, salt).ok());
                    match (api_token, api_email) {
                        (Some(token), Some(email)) if !email.is_empty() => {
                            log_manager.log("Cloudflare Global API Key loaded".to_string());
                            Some(CloudflareClient::with_global_key(email, token))
                        }
                        (Some(token), _) if !token.is_empty() => {
                            log_manager.log("Cloudflare API Token loaded".to_string());
                            Some(CloudflareClient::with_token(token))
                        }
                        _ => {
                            log_manager.log("Cloudflare credentials not configured".to_string());
                            None
                        }
                    }
                } else {
                    log_manager.log("Invalid password provided".to_string());
                    None
                }
            } else {
                log_manager.log("No password verifier found".to_string());
                None
            }
        } else {
            log_manager.log("No password salt found".to_string());
            None
        }
    } else if config.password_verifier.is_some() {
        log_manager.log("Password required but not provided - Cloudflare disabled".to_string());
        None
    } else {
        None
    };

    let tasks = Arc::new(Mutex::new(config.tasks.clone()));

    let (sched_tx, sched_rx) = mpsc::channel(100);
    let log_tx = log_manager.tx.clone();
    let tasks_clone = tasks.clone();
    let master_password = password.clone();
    let password_salt = config.password_salt.clone();
    tokio::spawn(async move {
        let scheduler = Scheduler::new(tasks_clone, pushover, cloudflare, log_tx, master_password, password_salt);
        scheduler.run(sched_rx).await;
    });

    // Run startup-triggered tasks once the scheduler is ready
    let _ = sched_tx.send(SchedulerCommand::RunStartupTasks).await;

    let (smtp_tx, mut smtp_rx) = mpsc::channel(100);
    let sched_tx_bridge = sched_tx.clone();
    tokio::spawn(async move {
        while let Some(email) = smtp_rx.recv().await {
            let _ = sched_tx_bridge.send(SchedulerCommand::EmailReceived(email)).await;
        }
    });

    let port = config.smtp_port;
    let log_tx2 = log_manager.tx.clone();
    tokio::spawn(async move {
        let server = SmtpServer::new(port, smtp_tx, log_tx2);
        match server.run().await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("SMTP server failed: {}", e);
            }
        }
    });

    // ntfy listener
    let (ntfy_cmd_tx, ntfy_cmd_rx) = mpsc::channel(100);
    let ntfy_listener = task_manager::ntfy_listener::NtfyListener::new(
        sched_tx.clone(),
        log_manager.tx.clone(),
    );
    tokio::spawn(async move {
        ntfy_listener.run(ntfy_cmd_rx).await;
    });
    // Send initial tasks to ntfy listener
    let ntfy_init_tx = ntfy_cmd_tx.clone();
    let initial_tasks = config.tasks.clone();
    tokio::spawn(async move {
        let _ = ntfy_init_tx.send(task_manager::ntfy_listener::NtfyListenerCommand::UpdateTasks(initial_tasks)).await;
    });

    log_manager.log(format!("Task Manager Service started (SMTP port {})", port));

    let config_path = Config::config_path();
    let mut last_mtime = std::fs::metadata(&config_path)
        .and_then(|m| m.modified()).ok();

    let pid_path = Config::pid_path();
    let _ = std::fs::write(&pid_path, std::process::id().to_string());

    let status_path = Config::status_path();

    loop {
        sleep(Duration::from_secs(2)).await;

        if let Ok(metadata) = std::fs::metadata(&config_path) {
            if let Ok(mtime) = metadata.modified() {
                if last_mtime != Some(mtime) {
                    last_mtime = Some(mtime);
                    if let Ok(new_config) = load_config_safe() {
                        let new_tasks = new_config.tasks.clone();
                        let mut t = tasks.lock().await;
                        *t = new_tasks.clone();
                        let _ = sched_tx.send(SchedulerCommand::UpdateTasks(new_tasks.clone())).await;
                        let _ = ntfy_cmd_tx.send(task_manager::ntfy_listener::NtfyListenerCommand::UpdateTasks(new_tasks)).await;
                        log_manager.log("Configuration reloaded from disk".to_string());
                    }
                }
            }
        }

        let status = {
            let t = tasks.lock().await;
            serde_json::json!({
                "tasks": *t,
                "timestamp": chrono::Local::now().to_rfc3339(),
            })
        };
        let temp_path = status_path.with_extension("tmp");
        if std::fs::write(&temp_path, serde_json::to_string_pretty(&status).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&temp_path, &status_path);
        }
    }
}

fn load_config_safe() -> Result<Config, String> {
    let path = Config::config_path();
    let data = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}
