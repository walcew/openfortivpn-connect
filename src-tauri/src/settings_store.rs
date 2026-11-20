use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Recusa do pedido de instalar o Helper. Chave nova na 0.4.0: a `helper_declined` da 0.3.0
    /// valia para um app que funcionava sem Helper, e agora ele é obrigatório.
    #[serde(default)]
    pub helper_install_declined: bool,
    #[serde(default = "default_true")]
    pub dns_fallback: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            helper_install_declined: false,
            dns_fallback: true,
        }
    }
}

fn default_true() -> bool {
    true
}

pub struct SettingsStore {
    settings_path: PathBuf,
}

impl SettingsStore {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            settings_path: crate::paths::app_dir()?.join("settings.json"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_declined_from_0_3_0_does_not_suppress_the_install_prompt() {
        let old = r#"{"debug_mode":true,"helper_declined":true,"dns_fallback":false}"#;
        let settings: AppSettings = serde_json::from_str(old).unwrap();
        assert!(!settings.helper_install_declined);
        assert!(!settings.dns_fallback);
    }

    #[test]
    fn new_decline_is_kept() {
        let settings: AppSettings = serde_json::from_str(r#"{"helper_install_declined":true}"#).unwrap();
        assert!(settings.helper_install_declined);
    }
}
