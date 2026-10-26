use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthType {
    Password,
    Saml,
}

impl Default for AuthType {
    fn default() -> Self {
        AuthType::Password
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth_type: AuthType,
    pub username: Option<String>,
    #[serde(default)]
    pub otp_required: bool,
    pub realm: Option<String>,
    pub trusted_certs: Vec<String>,
    #[serde(default)]
    pub ignore_cert_errors: bool,
    pub extra_args: Vec<String>,
}

impl Default for VpnProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            host: String::new(),
            port: 8443,
            auth_type: AuthType::default(),
            username: None,
            otp_required: false,
            realm: None,
            trusted_certs: Vec::new(),
            ignore_cert_errors: false,
            extra_args: Vec::new(),
        }
    }
}

impl VpnProfile {
    /// Profile com senha que exige OTP a cada conexão.
    pub fn needs_otp(&self) -> bool {
        self.auth_type == AuthType::Password && self.otp_required
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting { profile_id: String },
    WaitingSaml { profile_id: String, url: String },
    Connected {
        profile_id: String,
        ip: String,
        since: DateTime<Utc>,
    },
    Disconnecting,
    Error { message: String },
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStatusPayload {
    pub state: String,
    pub profile_id: Option<String>,
    pub ip: Option<String>,
    pub since: Option<String>,
    pub message: Option<String>,
}

impl From<&ConnectionState> for ConnectionStatusPayload {
    fn from(state: &ConnectionState) -> Self {
        match state {
            ConnectionState::Disconnected => ConnectionStatusPayload {
                state: "Disconnected".into(),
                profile_id: None,
                ip: None,
                since: None,
                message: None,
            },
            ConnectionState::Connecting { profile_id } => ConnectionStatusPayload {
                state: "Connecting".into(),
                profile_id: Some(profile_id.clone()),
                ip: None,
                since: None,
                message: None,
            },
            ConnectionState::WaitingSaml { profile_id, url } => ConnectionStatusPayload {
                state: "WaitingSaml".into(),
                profile_id: Some(profile_id.clone()),
                ip: None,
                since: None,
                message: Some(url.clone()),
            },
            ConnectionState::Connected {
                profile_id,
                ip,
                since,
            } => ConnectionStatusPayload {
                state: "Connected".into(),
                profile_id: Some(profile_id.clone()),
                ip: Some(ip.clone()),
                since: Some(since.to_rfc3339()),
                message: None,
            },
            ConnectionState::Disconnecting => ConnectionStatusPayload {
                state: "Disconnecting".into(),
                profile_id: None,
                ip: None,
                since: None,
                message: None,
            },
            ConnectionState::Error { message } => ConnectionStatusPayload {
                state: "Error".into(),
                profile_id: None,
                ip: None,
                since: None,
                message: Some(message.clone()),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLinePayload {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthPayload {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub timestamp: String,
}

/// Emitido pelo tray para a janela principal pedir o OTP de um Profile.
#[derive(Debug, Clone, Serialize)]
pub struct OtpRequestedPayload {
    pub profile_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_otp() {
        let profile = |auth_type, otp_required| VpnProfile {
            auth_type,
            otp_required,
            ..VpnProfile::default()
        };
        assert!(profile(AuthType::Password, true).needs_otp());
        assert!(!profile(AuthType::Password, false).needs_otp());
        assert!(!profile(AuthType::Saml, true).needs_otp());
        assert!(!profile(AuthType::Saml, false).needs_otp());
    }
}
