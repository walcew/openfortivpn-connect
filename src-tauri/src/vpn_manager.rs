use tauri::{AppHandle, Emitter};

use crate::keychain;
use crate::models::{
    AuthType, ConnectionState, ConnectionStatusPayload, TwoFactorType, VpnProfile,
};
use crate::process_manager::ProcessManager;
use crate::profile_store::ProfileStore;

pub struct VpnManager {
    state: ConnectionState,
    profile_store: ProfileStore,
    process_manager: ProcessManager,
    selected_profile_id: Option<String>,
}

impl VpnManager {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            state: ConnectionState::Disconnected,
            profile_store: ProfileStore::new()?,
            process_manager: ProcessManager::new(),
            selected_profile_id: None,
        })
    }

    pub fn get_state(&self) -> &ConnectionState {
        &self.state
    }

    pub fn selected_profile_id(&self) -> Option<&str> {
        self.selected_profile_id.as_deref()
    }

    pub fn set_selected_profile(&mut self, id: &str) {
        self.selected_profile_id = Some(id.to_string());
    }

    /// Update internal state from an event payload (used by the tray listener
    /// to sync state changes emitted by the log monitor).
    pub fn sync_state_from_payload(&mut self, payload: &ConnectionStatusPayload) {
        let new_state = match payload.state.as_str() {
            "Disconnected" => ConnectionState::Disconnected,
            "Connecting" => ConnectionState::Connecting {
                profile_id: payload.profile_id.clone().unwrap_or_default(),
            },
            "WaitingSaml" => ConnectionState::WaitingSaml {
                profile_id: payload.profile_id.clone().unwrap_or_default(),
                url: payload.message.clone().unwrap_or_default(),
            },
            "WaitingOtp" => ConnectionState::WaitingOtp {
                profile_id: payload.profile_id.clone().unwrap_or_default(),
            },
            "WaitingPush" => ConnectionState::WaitingPush {
                profile_id: payload.profile_id.clone().unwrap_or_default(),
            },
            "Connected" => ConnectionState::Connected {
                profile_id: payload.profile_id.clone().unwrap_or_default(),
                ip: payload.ip.clone().unwrap_or_else(|| "unknown".into()),
                since: payload
                    .since
                    .as_deref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .unwrap_or_else(chrono::Utc::now),
            },
            "Disconnecting" => ConnectionState::Disconnecting,
            "Error" => ConnectionState::Error {
                message: payload.message.clone().unwrap_or_default(),
            },
            _ => return,
        };
        self.state = new_state;
    }

    fn set_state(&mut self, state: ConnectionState, app_handle: &AppHandle) {
        self.state = state;
        let payload = ConnectionStatusPayload::from(&self.state);
        let _ = app_handle.emit("connection-status-changed", &payload);
        // NOTE: Do NOT call refresh_tray_menu here — we may be inside a Mutex lock.
        // Tray refresh is driven by listening to the "connection-status-changed" event.
        // update_tray_icon is safe here — it doesn't access the Mutex.
        crate::tray::update_tray_icon(app_handle, &self.state);
    }

    pub fn connect(&mut self, profile_id: &str, app_handle: AppHandle, debug_mode: bool, dns_fallback: bool) -> Result<(), String> {
        // Validate state. Allow reconnect from mid-connect / disconnecting (e.g. Trust &
        // Reconnect after a cert failure) by finishing cleanup first.
        match &self.state {
            ConnectionState::Disconnected | ConnectionState::Error { .. } => {}
            ConnectionState::Connected { .. } => {
                return Err("Already connecting or connected".to_string());
            }
            ConnectionState::Connecting { .. }
            | ConnectionState::WaitingSaml { .. }
            | ConnectionState::WaitingOtp { .. }
            | ConnectionState::WaitingPush { .. }
            | ConnectionState::Disconnecting => {
                self.finish_disconnect(&app_handle);
            }
        }

        // Look up profile
        let profile = self
            .profile_store
            .get_by_id(profile_id)?
            .ok_or_else(|| format!("Profile '{}' not found", profile_id))?;

        let two_factor = if profile.two_factor_enabled && profile.auth_type == AuthType::Password {
            Some(profile.two_factor_type.clone())
        } else {
            None
        };

        // 2FA needs helper >= 0.1.9 (piped stdin + write-stdin). Refuse older helpers.
        if two_factor.is_some() {
            match crate::helper_client::ping() {
                Ok(version) => {
                    if !helper_version_supports_otp(&version) {
                        let msg = format!(
                            "Two-factor authentication requires helper v0.1.9+ (found v{}). Reinstall the helper from Settings.",
                            version
                        );
                        self.set_state(
                            ConnectionState::Error { message: msg.clone() },
                            &app_handle,
                        );
                        return Err(msg);
                    }
                }
                Err(e) => {
                    let msg = format!(
                        "Two-factor authentication requires the helper daemon. Install it from Settings. ({})",
                        e
                    );
                    self.set_state(
                        ConnectionState::Error { message: msg.clone() },
                        &app_handle,
                    );
                    return Err(msg);
                }
            }
        }

        // Set connecting state
        self.set_state(
            ConnectionState::Connecting {
                profile_id: profile_id.to_string(),
            },
            &app_handle,
        );

        // Build args
        let mut args = vec![format!("{}:{}", profile.host, profile.port)];

        match profile.auth_type {
            AuthType::Password => {
                if let Some(ref username) = profile.username {
                    args.push("-u".to_string());
                    args.push(username.clone());
                }
                if let Ok(Some(password)) = keychain::get_password(&profile.id) {
                    args.push("-p".to_string());
                    args.push(password);
                }
            }
            AuthType::Saml => {
                args.push("--saml-login".to_string());
            }
        }

        // Force OTP entry instead of FortiToken Mobile push when TOTP is selected.
        if matches!(two_factor, Some(TwoFactorType::Totp)) {
            args.push("--no-ftm-push".to_string());
        }

        for cert in &profile.trusted_certs {
            args.push(format!("--trusted-cert={}", cert));
        }

        if let Some(ref realm) = profile.realm {
            args.push(format!("--realm={}", realm));
        }

        // Disable openfortivpn's DNS handling: we manage DNS via scutil on macOS
        // because macOS ignores /etc/resolv.conf
        args.push("--set-dns=0".to_string());
        args.push("--pppd-use-peerdns=0".to_string());

        // Enable verbose logging so we can capture DNS server info from debug output
        args.push("-v".to_string());

        args.extend(profile.extra_args.clone());

        // Spawn the process
        match self.process_manager.spawn_vpn(
            args,
            profile_id.to_string(),
            app_handle.clone(),
            debug_mode,
            dns_fallback,
            two_factor,
        ) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_state(ConnectionState::Error { message: e.clone() }, &app_handle);
                Err(e)
            }
        }
    }

    /// Submit a one-time password / 2FA token to the running openfortivpn process.
    pub fn submit_otp(&mut self, code: &str, app_handle: &AppHandle) -> Result<(), String> {
        let trimmed = code.trim();
        if trimmed.is_empty() {
            return Err("OTP code cannot be empty".to_string());
        }
        if trimmed.len() > 128 {
            return Err("OTP code is too long".to_string());
        }

        match &self.state {
            ConnectionState::WaitingOtp { profile_id } => {
                let profile_id = profile_id.clone();
                self.process_manager.write_otp(trimmed)?;
                self.set_state(
                    ConnectionState::Connecting { profile_id },
                    app_handle,
                );
                Ok(())
            }
            _ => Err("Not waiting for an OTP code".to_string()),
        }
    }

    /// Begin disconnecting: sets state to Disconnecting and returns immediately.
    pub fn begin_disconnect(&mut self, app_handle: &AppHandle) {
        self.set_state(ConnectionState::Disconnecting, app_handle);
    }

    /// Perform the heavy disconnect work (kill process, restore routes, DNS).
    pub fn finish_disconnect(&mut self, app_handle: &AppHandle) {
        match self.process_manager.kill_vpn() {
            Ok(()) => {
                self.set_state(ConnectionState::Disconnected, app_handle);
            }
            Err(e) => {
                self.set_state(ConnectionState::Error { message: e.clone() }, app_handle);
            }
        }
    }

    /// Full synchronous disconnect (used by tray menu).
    pub fn disconnect(&mut self, app_handle: AppHandle) -> Result<(), String> {
        self.begin_disconnect(&app_handle);
        self.finish_disconnect(&app_handle);
        Ok(())
    }

    pub fn get_profiles(&self) -> Result<Vec<VpnProfile>, String> {
        self.profile_store.get_all()
    }

    pub fn save_profile(
        &self,
        profile: VpnProfile,
        password: Option<String>,
    ) -> Result<VpnProfile, String> {
        let saved = self.profile_store.upsert(profile)?;
        if let Some(pwd) = password {
            if !pwd.is_empty() {
                keychain::set_password(&saved.id, &pwd)?;
            }
        }
        Ok(saved)
    }

    pub fn delete_profile(&self, profile_id: &str) -> Result<(), String> {
        self.profile_store.delete(profile_id)?;
        let _ = keychain::delete_password(profile_id);
        Ok(())
    }
}

/// Helper v0.1.9+ keeps openfortivpn stdin open and supports `write-stdin` for OTP.
fn helper_version_supports_otp(version: &str) -> bool {
    let mut parts = version
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u32>().ok());
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major, minor, patch) >= (0, 1, 9)
}

#[cfg(test)]
mod tests {
    use super::helper_version_supports_otp;

    #[test]
    fn otp_requires_helper_0_1_9() {
        assert!(!helper_version_supports_otp("0.1.8"));
        assert!(helper_version_supports_otp("0.1.9"));
        assert!(helper_version_supports_otp("0.2.0"));
    }
}
