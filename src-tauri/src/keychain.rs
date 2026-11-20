use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const SERVICE: &str = "com.openvpngui.app";

fn account_for(profile_id: &str) -> String {
    format!("vpn-{}", profile_id)
}

/// Com `VPNCONNECT_TEST_HOME`, a senha fica num arquivo por conta em `keychain/`.
fn test_file(account: &str) -> Option<std::path::PathBuf> {
    crate::paths::test_home().map(|home| home.join("keychain").join(account))
}

pub fn set_password(profile_id: &str, password: &str) -> Result<(), String> {
    let account = account_for(profile_id);
    if let Some(file) = test_file(&account) {
        let write = std::fs::create_dir_all(file.parent().unwrap()).and_then(|_| std::fs::write(&file, password));
        return write.map_err(|e| format!("Failed to save password to Keychain: {}", e));
    }
    // Delete first to avoid "duplicate item" errors
    let _ = delete_generic_password(SERVICE, &account);
    set_generic_password(SERVICE, &account, password.as_bytes())
        .map_err(|e| format!("Failed to save password to Keychain: {}", e))
}

pub fn get_password(profile_id: &str) -> Result<Option<String>, String> {
    let account = account_for(profile_id);
    if let Some(file) = test_file(&account) {
        return match std::fs::read_to_string(&file) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            r => r.map(Some).map_err(|e| format!("Failed to retrieve password from Keychain: {}", e)),
        };
    }
    match get_generic_password(SERVICE, &account) {
        Ok(bytes) => {
            let password = String::from_utf8(bytes.to_vec())
                .map_err(|e| format!("Password is not valid UTF-8: {}", e))?;
            Ok(Some(password))
        }
        Err(e) => {
            // errSecItemNotFound = -25300
            if e.code() == -25300 {
                Ok(None)
            } else {
                Err(format!("Failed to retrieve password from Keychain: {}", e))
            }
        }
    }
}

pub fn delete_password(profile_id: &str) -> Result<(), String> {
    let account = account_for(profile_id);
    if let Some(file) = test_file(&account) {
        return match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("Failed to delete password from Keychain: {}", e)),
            _ => Ok(()),
        };
    }
    match delete_generic_password(SERVICE, &account) {
        Ok(()) => Ok(()),
        Err(e) => {
            if e.code() == -25300 {
                Ok(()) // Not found is ok
            } else {
                Err(format!("Failed to delete password from Keychain: {}", e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keychain_operations() {
        let test_id = format!("test-{}", uuid::Uuid::new_v4());

        // Set
        set_password(&test_id, "test-secret-123").unwrap();

        // Get
        let password = get_password(&test_id).unwrap();
        assert_eq!(password, Some("test-secret-123".to_string()));

        // Delete
        delete_password(&test_id).unwrap();
        let password = get_password(&test_id).unwrap();
        assert_eq!(password, None);

        // Delete non-existent is ok
        delete_password(&test_id).unwrap();
    }
}
