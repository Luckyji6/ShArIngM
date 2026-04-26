use crate::models::{AppMode, TrustedDevice};
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine};
use directories::ProjectDirs;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConfig {
    pub device_id: String,
    pub device_name: String,
    pub identity_seed: String,
    pub mode: AppMode,
    pub trusted_devices: Vec<TrustedDevice>,
    pub autostart_required: bool,
}

impl StoredConfig {
    pub fn new() -> Self {
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self {
            device_id: Uuid::new_v4().to_string(),
            device_name: default_device_name(),
            identity_seed: general_purpose::STANDARD.encode(seed),
            mode: AppMode::Sender,
            trusted_devices: Vec::new(),
            autostart_required: false,
        }
    }
}

pub fn load_or_create() -> Result<(StoredConfig, PathBuf)> {
    let path = config_path()?;
    if path.exists() {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        Ok((config, path))
    } else {
        let config = StoredConfig::new();
        save_to_path(&path, &config)?;
        Ok((config, path))
    }
}

pub fn save_to_path(path: &Path, config: &StoredConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(config)?;
    fs::write(path, raw).with_context(|| format!("failed to write config {}", path.display()))
}

pub fn downloads_dir() -> Result<PathBuf> {
    let dirs = directories::UserDirs::new().context("failed to resolve user directories")?;
    let base = dirs
        .download_dir()
        .map(Path::to_path_buf)
        .or_else(|| Some(dirs.home_dir().join("Downloads")))
        .context("failed to resolve downloads directory")?;
    Ok(base.join("ShArIngM"))
}

fn config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("app", "sharingm", "ShArIngM")
        .context("failed to resolve project directories")?;
    Ok(dirs.config_dir().join("config.json"))
}

fn default_device_name() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "ShArIngM Device".to_string())
}
