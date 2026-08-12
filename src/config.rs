use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub smtp_port: u16,
    pub pushover_app_token_encrypted: Option<Vec<u8>>,
    pub pushover_user_key_encrypted: Option<Vec<u8>>,
    pub cloudflare_api_token_encrypted: Option<Vec<u8>>,
    pub cloudflare_api_email_encrypted: Option<Vec<u8>>,
    pub password_verifier: Option<Vec<u8>>,
    pub password_salt: Option<Vec<u8>>,
    pub tasks: Vec<crate::task::Task>,
    #[serde(default)]
    pub public_ip: Option<String>,
}

impl Config {
    fn base_dir() -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    pub fn config_path() -> PathBuf {
        let mut path = Self::base_dir();
        path.push("config.json");
        path
    }

    pub fn log_dir() -> PathBuf {
        let mut path = Self::base_dir();
        path.push("logs");
        path
    }

    pub fn status_path() -> PathBuf {
        let mut path = Self::base_dir();
        path.push("status.json");
        path
    }

    pub fn pid_path() -> PathBuf {
        let mut path = Self::base_dir();
        path.push("service.pid");
        path
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(config) = serde_json::from_str(&data) {
                    return config;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, data).map_err(|e| e.to_string())
    }
}
