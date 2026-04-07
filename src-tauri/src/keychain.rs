use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const SERVICE: &str = "com.openvpngui.app";

fn account_for(profile_id: &str) -> String {
    format!("vpn-{}", profile_id)
}

pub fn set_password(profile_id: &str, password: &str) -> Result<(), String> {
    let account = account_for(profile_id);
    // Delete first to avoid "duplicate item" errors
    let _ = delete_generic_password(SERVICE, &account);
    set_generic_password(SERVICE, &account, password.as_bytes())
        .map_err(|e| format!("Failed to save password to Keychain: {}", e))
}

pub fn get_password(profile_id: &str) -> Result<Option<String>, String> {
    let account = account_for(profile_id);
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
