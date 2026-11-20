use tauri::{AppHandle, Emitter};

use crate::helper_client::Credentials;
use crate::keychain;
use crate::models::*;
use crate::profile_store::ProfileStore;

pub struct VpnManager {
    state: ConnectionState,
    profile_store: ProfileStore,
    selected_profile_id: Option<String>,
}

impl VpnManager {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            state: ConnectionState::Disconnected,
            profile_store: ProfileStore::new()?,
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

    /// Atualiza o estado interno a partir de um payload de estado, vindo dos eventos do Helper.
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
                dns_servers: payload.dns_servers.clone(),
                dns_domains: payload.dns_domains.clone(),
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

    /// Conecta pelo Engine do Helper. O progresso e o resultado chegam depois por eventos de estado.
    pub fn connect(
        &mut self,
        profile_id: &str,
        app_handle: &AppHandle,
        dns_fallback: bool,
        otp: Option<&str>,
    ) -> Result<(), String> {
        match &self.state {
            ConnectionState::Disconnected | ConnectionState::Error { .. } => {}
            _ => return Err("Already connecting or connected".to_string()),
        }
        let profile = self
            .profile_store
            .get_by_id(profile_id)?
            .ok_or_else(|| format!("Profile '{}' not found", profile_id))?;
        check_otp_provided(&profile, otp)?;
        let otp = profile.otp_to_send(otp);
        let fallback_dns = fallback_dns_servers(dns_fallback);
        let result = resolve_credentials(&profile).and_then(|creds| {
            self.set_state(
                ConnectionState::Connecting { profile_id: profile_id.to_string() },
                app_handle,
            );
            if let Some(message) = extra_args_notice(&profile) {
                let payload = LogLinePayload { timestamp: chrono::Utc::now().to_rfc3339(), level: "warn".into(), message };
                let _ = app_handle.emit("log-line", &payload);
            }
            crate::helper_client::connect(
                &crate::helper_client::socket_path(),
                &profile,
                &creds,
                otp,
                &fallback_dns,
            )
            .map_err(String::from)
        });
        if let Err(e) = &result {
            self.set_state(ConnectionState::Error { message: e.clone() }, app_handle);
        }
        result
    }

    /// Limpa os domínios de split DNS digitados: apara, põe em minúsculas e tira o `*.` ou `.`
    /// inicial (o domínio do scutil é o sufixo puro), depois descarta vazios e duplicados.
    /// Rejeita o que a validação de hostname do Helper recusaria.
    fn normalize_dns_domains(domains: &[String]) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        for d in domains {
            let d = d.trim().to_lowercase();
            let d = d.trim_start_matches("*.").trim_start_matches('.').to_string();
            if d.is_empty() || out.contains(&d) {
                continue;
            }
            // Mesma regra do is_valid_hostname do helper.
            let valid = d.len() <= 253
                && !d.starts_with('-')
                && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            if !valid {
                return Err(format!("Invalid DNS domain: {}", d));
            }
            out.push(d);
        }
        Ok(out)
    }

    /// Começa a desconexão: põe o estado em Disconnecting e volta na hora.
    pub fn begin_disconnect(&mut self, app_handle: &AppHandle) {
        self.set_state(ConnectionState::Disconnecting, app_handle);
    }

    /// Pede o `disconnect` ao Engine, que também encerra um login pendente; o estado final chega por evento.
    pub fn finish_disconnect(&mut self, app_handle: &AppHandle) {
        let path = &crate::helper_client::socket_path();
        if let Err(e) = crate::helper_client::disconnect(path) {
            self.set_state(ConnectionState::Error { message: e.into() }, app_handle);
            return;
        }
        // Sem sessão ativa o Helper não emite estado novo e o Disconnecting ficaria
        // preso; um `status` fecha esse caso. Se ainda não caiu, o evento fecha.
        if let Ok(ConnectionState::Disconnected) = crate::helper_client::status(path) {
            self.set_state(ConnectionState::Disconnected, app_handle);
        }
    }

    /// Desconexão completa e síncrona (usada pelo menu da tray).
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
        let profile = VpnProfile {
            dns_match_domains: Self::normalize_dns_domains(&profile.dns_match_domains)?,
            ..profile
        };
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

/// Busca o usuário e a senha (no Keychain) de um Profile com senha. Os dois são
/// obrigatórios: sem eles o login não começa.
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

/// As credenciais do `connect`: usuário e senha do Keychain, ou nenhuma no SAML.
pub(crate) fn resolve_credentials(profile: &VpnProfile) -> Result<Credentials, String> {
    match profile.auth_type {
        AuthType::Password => resolve_password_creds(profile).map(|(username, password)| Credentials::Password { username, password }),
        AuthType::Saml => Ok(Credentials::Saml),
    }
}

/// O DNS do sistema para o fallback, lido antes de a VPN mexer na rede; vazio com ele desligado.
pub(crate) fn fallback_dns_servers(enabled: bool) -> Vec<String> {
    if enabled { crate::dns_manager::get_current_dns_servers() } else { Vec::new() }
}

/// Aviso de uma linha para o Profile salvo com `extra_args`, que o Engine próprio não lê.
pub(crate) fn extra_args_notice(profile: &VpnProfile) -> Option<String> {
    (!profile.extra_args.is_empty()).then(|| {
        format!("Ignoring extra_args of profile '{}': extra options no longer apply since 0.4.0", profile.name)
    })
}

pub(crate) fn check_otp_provided(profile: &VpnProfile, otp: Option<&str>) -> Result<(), String> {
    if profile.needs_otp() && profile.otp_to_send(otp).is_none() {
        return Err("OTP is required for this profile".into());
    }
    Ok(())
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
    fn test_normalize_dns_domains() {
        let input = vec![
            " Corp.Example.com ".to_string(),
            "*.corp.example.com".to_string(),
            ".corp.local".to_string(),
            "".to_string(),
            "   ".to_string(),
        ];
        assert_eq!(
            VpnManager::normalize_dns_domains(&input),
            Ok(vec!["corp.example.com".to_string(), "corp.local".to_string()])
        );
        assert_eq!(VpnManager::normalize_dns_domains(&[]), Ok(vec![]));
        for bad in ["corp_example.com", "-corp.com", "a;b.com"] {
            assert!(VpnManager::normalize_dns_domains(&[bad.to_string()]).is_err());
        }
    }

    #[test]
    fn test_password_creds_require_username() {
        for profile in [password_profile(None), password_profile(Some("   "))] {
            let err = resolve_password_creds(&profile).unwrap_err();
            assert!(err.contains("no username"), "unexpected error: {}", err);
        }
    }

    #[test]
    fn test_password_creds_require_stored_password() {
        // The profile id is a fresh uuid, so nothing is stored in the keychain.
        let mut profile = password_profile(Some("john.doe"));
        profile.id = uuid::Uuid::new_v4().to_string();
        let err = resolve_password_creds(&profile).unwrap_err();
        assert!(err.contains("No password stored"), "unexpected error: {}", err);
    }

    #[test]
    fn extra_args_warn_only_when_present() {
        let mut profile = password_profile(Some("john"));
        assert_eq!(extra_args_notice(&profile), None);
        profile.extra_args = vec!["--foo".to_string()];
        let notice = extra_args_notice(&profile).unwrap();
        assert!(notice.contains("extra_args") && notice.contains("Corp"), "{}", notice);
    }

    #[test]
    fn test_check_otp_provided() {
        let mut profile = password_profile(Some("john"));
        profile.otp_required = true;
        for otp in [None, Some(""), Some("   ")] {
            let err = check_otp_provided(&profile, otp).unwrap_err();
            assert_eq!(err, "OTP is required for this profile");
        }
        assert!(check_otp_provided(&profile, Some(" 123456 ")).is_ok());
        // Sem otp_required, a ausência de OTP é aceita.
        profile.otp_required = false;
        assert!(check_otp_provided(&profile, None).is_ok());
    }
}
