use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd")]
pub enum Request {
    #[serde(rename = "ping")]
    Ping,

    #[serde(rename = "spawn-vpn")]
    SpawnVpn {
        args: Vec<String>,
        log_path: String,
    },

    #[serde(rename = "kill-vpn")]
    KillVpn {
        pid: u32,
        gateway: Option<String>,
    },

    #[serde(rename = "setup-dns")]
    SetupDns {
        servers: Vec<String>,
        suffix: Option<String>,
    },

    #[serde(rename = "teardown-dns")]
    TeardownDns,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Response {
    pub fn success() -> Self {
        Self {
            ok: true,
            error: None,
            pid: None,
            version: None,
        }
    }

    pub fn with_pid(pid: u32) -> Self {
        Self {
            ok: true,
            error: None,
            pid: Some(pid),
            version: None,
        }
    }

    pub fn with_version(version: String) -> Self {
        Self {
            ok: true,
            error: None,
            pid: None,
            version: Some(version),
        }
    }

    pub fn error(msg: String) -> Self {
        Self {
            ok: false,
            error: Some(msg),
            pid: None,
            version: None,
        }
    }
}
