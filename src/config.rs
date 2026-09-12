use serde::Deserialize;
use std::path::PathBuf;

fn default_state_path() -> String {
    "~/.local/state/undertow/state.json".to_string()
}

fn default_true() -> bool {
    true
}

fn default_writable_paths() -> Vec<String> {
    vec!["/etc".to_string(), "/usr/bin".to_string(), "/usr/sbin".to_string(), "/etc/systemd/system".to_string()]
}

fn default_suid_paths() -> Vec<String> {
    vec!["/usr/bin".to_string(), "/usr/sbin".to_string(), "/usr/local/bin".to_string(), "/usr/local/sbin".to_string()]
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    #[serde(default = "default_state_path")]
    pub state_path: String,

    #[serde(default = "default_true")]
    pub check_preload: bool,
    #[serde(default = "default_true")]
    pub check_writable: bool,
    #[serde(default = "default_true")]
    pub check_suid: bool,
    #[serde(default = "default_true")]
    pub check_modules: bool,
    #[serde(default = "default_true")]
    pub check_persistence: bool,

    #[serde(default = "default_writable_paths")]
    pub writable_paths: Vec<String>,
    #[serde(default = "default_suid_paths")]
    pub suid_paths: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            state_path: default_state_path(),
            check_preload: true,
            check_writable: true,
            check_suid: true,
            check_modules: true,
            check_persistence: true,
            writable_paths: default_writable_paths(),
            suid_paths: default_suid_paths(),
        }
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok()?;
    let candidates = [config_home.join("undertow").join("config.toml"), PathBuf::from("config.toml")];
    candidates.into_iter().find(|p| p.exists())
}

pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

pub fn load(path: &std::path::Path) -> Result<AppConfig, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    toml::from_str(&raw).map_err(|e| format!("failed to parse {}: {}", path.display(), e))
}
