use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub smtp_port: u16,
    pub pushover_app_token_encrypted: Option<Vec<u8>>,
    pub pushover_user_key_encrypted: Option<Vec<u8>>,
    pub cloudflare_api_token_encrypted: Option<Vec<u8>>,
    pub cloudflare_api_email_encrypted: Option<Vec<u8>>,
    pub cloudflare_default_zone_id: String,
    pub cloudflare_default_record_name: String,
    pub cloudflare_default_proxied: String,
    pub cloudflare_default_ttl: String,
    pub password_verifier: Option<Vec<u8>>,
    pub password_salt: Option<Vec<u8>>,
    pub public_ip: Option<String>,
    pub tasks: Vec<crate::task::Task>,
}

impl Config {
    /// Returns a stable base directory for config files.
    /// Uses the current executable's directory so the service and GUI
    /// always share the same config regardless of working directory.
    fn base_dir() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(PathBuf::from))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    #[inline]
    pub fn config_path() -> PathBuf {
        Self::base_dir().join("config.json")
    }

    #[inline]
    pub fn log_dir() -> PathBuf {
        Self::base_dir().join("logs")
    }

    #[inline]
    pub fn status_path() -> PathBuf {
        Self::base_dir().join("status.json")
    }

    #[inline]
    pub fn pid_path() -> PathBuf {
        Self::base_dir().join("service.pid")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str(&data) {
                return config;
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
