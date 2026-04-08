use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub debug_mode: bool,
    #[serde(default)]
    pub helper_declined: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            debug_mode: false,
            helper_declined: false,
        }
    }
}

pub struct SettingsStore {
    settings_path: PathBuf,
}

impl SettingsStore {
    pub fn new() -> Result<Self, String> {
        let base =
            dirs::config_dir().ok_or_else(|| "Could not determine config directory".to_string())?;
        let app_dir = base.join("com.openvpngui.app");
        fs::create_dir_all(&app_dir).map_err(|e| format!("Failed to create app dir: {}", e))?;
        Ok(Self {
            settings_path: app_dir.join("settings.json"),
        })
    }

    pub fn get(&self) -> Result<AppSettings, String> {
        if !self.settings_path.exists() {
            return Ok(AppSettings::default());
        }
        let data = fs::read_to_string(&self.settings_path)
            .map_err(|e| format!("Failed to read settings: {}", e))?;
        serde_json::from_str(&data).map_err(|e| format!("Failed to parse settings: {}", e))
    }

    pub fn save(&self, settings: &AppSettings) -> Result<(), String> {
        let data = serde_json::to_string_pretty(settings)
            .map_err(|e| format!("Failed to serialize settings: {}", e))?;
        fs::write(&self.settings_path, data)
            .map_err(|e| format!("Failed to write settings: {}", e))
    }
}
