use std::fs;
use std::path::PathBuf;

use crate::models::VpnProfile;

pub struct ProfileStore {
    profiles_path: PathBuf,
}

impl ProfileStore {
    pub fn new() -> Result<Self, String> {
        let base = dirs::config_dir()
            .ok_or_else(|| "Could not determine config directory".to_string())?;
        let app_dir = base.join("com.openvpngui.app");
        fs::create_dir_all(&app_dir).map_err(|e| format!("Failed to create app dir: {}", e))?;
        Ok(Self {
            profiles_path: app_dir.join("profiles.json"),
        })
    }

    #[cfg(test)]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            profiles_path: path,
        }
    }

    pub fn get_all(&self) -> Result<Vec<VpnProfile>, String> {
        if !self.profiles_path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read_to_string(&self.profiles_path)
            .map_err(|e| format!("Failed to read profiles: {}", e))?;
        let profiles: Vec<VpnProfile> =
            serde_json::from_str(&data).map_err(|e| format!("Failed to parse profiles: {}", e))?;
        Ok(profiles)
    }

    pub fn get_by_id(&self, id: &str) -> Result<Option<VpnProfile>, String> {
        let profiles = self.get_all()?;
        Ok(profiles.into_iter().find(|p| p.id == id))
    }

    pub fn upsert(&self, mut profile: VpnProfile) -> Result<VpnProfile, String> {
        if profile.id.is_empty() {
            profile.id = uuid::Uuid::new_v4().to_string();
        }
        let mut profiles = self.get_all()?;
        if let Some(existing) = profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing = profile.clone();
        } else {
            profiles.push(profile.clone());
        }
        self.save(&profiles)?;
        Ok(profile)
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        let mut profiles = self.get_all()?;
        profiles.retain(|p| p.id != id);
        self.save(&profiles)
    }

    fn save(&self, profiles: &[VpnProfile]) -> Result<(), String> {
        let data = serde_json::to_string_pretty(profiles)
            .map_err(|e| format!("Failed to serialize profiles: {}", e))?;
        fs::write(&self.profiles_path, data)
            .map_err(|e| format!("Failed to write profiles: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AuthType;
    use std::env;

    #[test]
    fn test_crud_operations() {
        let dir = env::temp_dir().join(format!("openvpngui-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let store = ProfileStore::with_path(dir.join("profiles.json"));

        // Initially empty
        assert!(store.get_all().unwrap().is_empty());

        // Create
        let profile = VpnProfile {
            name: "Test VPN".into(),
            host: "vpn.example.com".into(),
            port: 8443,
            auth_type: AuthType::Saml,
            ..Default::default()
        };
        let saved = store.upsert(profile).unwrap();
        assert!(!saved.id.is_empty());

        // Read
        let all = store.get_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Test VPN");

        // Update
        let mut updated = saved.clone();
        updated.name = "Updated VPN".into();
        store.upsert(updated).unwrap();
        let found = store.get_by_id(&saved.id).unwrap().unwrap();
        assert_eq!(found.name, "Updated VPN");

        // Delete
        store.delete(&saved.id).unwrap();
        assert!(store.get_all().unwrap().is_empty());

        // Cleanup
        fs::remove_dir_all(&dir).ok();
    }
}
