use tauri::{AppHandle, Emitter};

use crate::keychain;
use crate::models::*;
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
        // Validate state
        match &self.state {
            ConnectionState::Disconnected | ConnectionState::Error { .. } => {}
            _ => return Err("Already connecting or connected".to_string()),
        }

        // Look up profile
        let profile = self
            .profile_store
            .get_by_id(profile_id)?
            .ok_or_else(|| format!("Profile '{}' not found", profile_id))?;

        // Resolve credentials up front: without -u/-p the openfortivpn blocks
        // waiting for input on stdin and the UI would sit on Connecting forever.
        let password_creds = if profile.auth_type == AuthType::Password {
            match Self::resolve_password_creds(&profile) {
                Ok(creds) => Some(creds),
                Err(e) => {
                    self.set_state(ConnectionState::Error { message: e.clone() }, &app_handle);
                    return Err(e);
                }
            }
        } else {
            None
        };

        // Set connecting state
        self.set_state(
            ConnectionState::Connecting {
                profile_id: profile_id.to_string(),
            },
            &app_handle,
        );

        // O openfortivpn não tem opção de ignorar o certificado: quando o perfil
        // pede isso, buscamos o digest sha256 direto do gateway e o passamos como
        // --trusted-cert. Assim a conexão funciona já na primeira tentativa e
        // continua funcionando quando o certificado é renovado.
        let gateway_digest = if profile.ignore_cert_errors {
            match crate::cert_fetcher::fetch_gateway_digest(&profile.host, profile.port) {
                Ok(digest) => {
                    log::info!("Auto-trusting gateway certificate {}", digest);
                    Some(digest)
                }
                Err(e) => {
                    log::warn!("Could not fetch gateway certificate digest: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let args = build_openfortivpn_args(&profile, password_creds, gateway_digest.as_deref());

        // Spawn the process
        match self
            .process_manager
            .spawn_vpn(args, profile_id.to_string(), app_handle.clone(), debug_mode, dns_fallback)
        {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_state(ConnectionState::Error { message: e.clone() }, &app_handle);
                Err(e)
            }
        }
    }

    /// Look up the username and the keychain password of a password-auth profile.
    /// Both are required: openfortivpn prompts on stdin when either is missing,
    /// and the process would just hang with nothing shown to the user.
    fn resolve_password_creds(profile: &VpnProfile) -> Result<(String, String), String> {
        let username = profile
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                format!(
                    "Profile '{}' uses password authentication but has no username. \
                     Edit the profile and fill in the username.",
                    profile.name
                )
            })?;

        let password = keychain::get_password(&profile.id)?
            .filter(|p| !p.is_empty())
            .ok_or_else(|| {
                format!(
                    "No password stored for profile '{}'. \
                     Edit the profile and set the password.",
                    profile.name
                )
            })?;

        Ok((username.to_string(), password))
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

/// Monta os argumentos do openfortivpn. `password_creds` é `Some` na auth por
/// senha e `None` na SAML; `gateway_digest` é o digest já buscado quando o
/// perfil ignora erros de certificado.
fn build_openfortivpn_args(
    profile: &VpnProfile,
    password_creds: Option<(String, String)>,
    gateway_digest: Option<&str>,
) -> Vec<String> {
    let mut args = vec![format!("{}:{}", profile.host, profile.port)];

    if let Some((username, password)) = password_creds {
        args.push("-u".to_string());
        args.push(username);
        args.push("-p".to_string());
        args.push(password);
    } else {
        args.push("--saml-login".to_string());
    }

    let mut trusted_certs = profile.trusted_certs.clone();
    if let Some(digest) = gateway_digest {
        if !trusted_certs.iter().any(|c| c == digest) {
            trusted_certs.push(digest.to_string());
        }
    }

    for cert in &trusted_certs {
        args.push(format!("--trusted-cert={}", cert));
    }

    if let Some(ref realm) = profile.realm {
        args.push(format!("--realm={}", realm));
    }

    // Disable openfortivpn's DNS handling — we manage DNS via scutil on macOS
    // because macOS ignores /etc/resolv.conf
    args.push("--set-dns=0".to_string());
    args.push("--pppd-use-peerdns=0".to_string());

    // Enable verbose logging so we can capture DNS server info from debug output
    args.push("-v".to_string());

    args.extend(profile.extra_args.clone());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_profile(username: Option<&str>) -> VpnProfile {
        VpnProfile {
            name: "Corp".to_string(),
            auth_type: AuthType::Password,
            username: username.map(str::to_string),
            ..VpnProfile::default()
        }
    }

    #[test]
    fn test_password_creds_require_username() {
        for profile in [password_profile(None), password_profile(Some("   "))] {
            let err = VpnManager::resolve_password_creds(&profile).unwrap_err();
            assert!(err.contains("no username"), "unexpected error: {}", err);
        }
    }

    #[test]
    fn test_password_creds_require_stored_password() {
        // The profile id is a fresh uuid, so nothing is stored in the keychain.
        let mut profile = password_profile(Some("john.doe"));
        profile.id = uuid::Uuid::new_v4().to_string();
        let err = VpnManager::resolve_password_creds(&profile).unwrap_err();
        assert!(err.contains("No password stored"), "unexpected error: {}", err);
    }

    fn args_of(profile: &VpnProfile, creds: Option<(&str, &str)>, digest: Option<&str>) -> Vec<String> {
        let creds = creds.map(|(u, p)| (u.to_string(), p.to_string()));
        build_openfortivpn_args(profile, creds, digest)
    }

    fn saml_profile() -> VpnProfile {
        VpnProfile {
            host: "vpn.corp.test".to_string(),
            port: 8443,
            auth_type: AuthType::Saml,
            ..VpnProfile::default()
        }
    }

    #[test]
    fn test_args_password_auth() {
        let args = args_of(&saml_profile(), Some(("john", "s3cret")), None);
        assert_eq!(
            args,
            ["vpn.corp.test:8443", "-u", "john", "-p", "s3cret", "--set-dns=0", "--pppd-use-peerdns=0", "-v"]
        );
    }

    #[test]
    fn test_args_saml_auth() {
        let args = args_of(&saml_profile(), None, None);
        assert_eq!(
            args,
            ["vpn.corp.test:8443", "--saml-login", "--set-dns=0", "--pppd-use-peerdns=0", "-v"]
        );
        assert!(!args.iter().any(|a| a == "-u" || a == "-p"));
    }

    #[test]
    fn test_args_realm() {
        let mut profile = saml_profile();
        profile.realm = Some("corp".to_string());
        assert!(args_of(&profile, None, None).contains(&"--realm=corp".to_string()));
        profile.realm = None;
        assert!(!args_of(&profile, None, None).iter().any(|a| a.starts_with("--realm")));
    }

    #[test]
    fn test_args_trusted_certs() {
        let mut profile = saml_profile();
        profile.trusted_certs = vec!["aaa".to_string(), "bbb".to_string()];
        let args = args_of(&profile, None, None);
        assert!(args.contains(&"--trusted-cert=aaa".to_string()));
        assert!(args.contains(&"--trusted-cert=bbb".to_string()));
    }

    #[test]
    fn test_args_dns_flags_and_verbose_always_present() {
        for args in [args_of(&saml_profile(), None, None), args_of(&saml_profile(), Some(("u", "p")), None)] {
            for flag in ["--set-dns=0", "--pppd-use-peerdns=0", "-v"] {
                assert!(args.contains(&flag.to_string()), "missing {}", flag);
            }
        }
    }

    #[test]
    fn test_args_extra_args_come_last() {
        let mut profile = saml_profile();
        profile.extra_args = vec!["--foo".to_string(), "--bar=1".to_string()];
        let args = args_of(&profile, None, None);
        assert_eq!(&args[args.len() - 2..], ["--foo", "--bar=1"]);
    }

    #[test]
    fn test_args_ignore_cert_adds_gateway_digest() {
        let mut profile = saml_profile();
        profile.ignore_cert_errors = true;
        let args = args_of(&profile, None, Some("deadbeef"));
        assert!(args.contains(&"--trusted-cert=deadbeef".to_string()));
    }

    #[test]
    fn test_args_ignore_cert_does_not_duplicate_known_digest() {
        let mut profile = saml_profile();
        profile.ignore_cert_errors = true;
        profile.trusted_certs = vec!["deadbeef".to_string()];
        let args = args_of(&profile, None, Some("deadbeef"));
        assert_eq!(args.iter().filter(|a| *a == "--trusted-cert=deadbeef").count(), 1);
    }

    #[test]
    fn test_args_ignore_cert_without_digest_keeps_profile_certs() {
        // Falha ao buscar o digest: segue só com os certs do perfil.
        let mut profile = saml_profile();
        profile.ignore_cert_errors = true;
        profile.trusted_certs = vec!["aaa".to_string()];
        let args = args_of(&profile, None, None);
        assert_eq!(args.iter().filter(|a| a.starts_with("--trusted-cert=")).count(), 1);
    }
}
