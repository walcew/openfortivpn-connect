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
    pub realm: Option<String>,
    pub trusted_certs: Vec<String>,
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
            realm: None,
            trusted_certs: Vec::new(),
            extra_args: Vec::new(),
        }
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
