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
        /// IP of the VPN server, used to clear a stale /32 host route left by a
        /// previous session before spawning (pre-connect orphan sweep).
        #[serde(default)]
        vpn_server: Option<String>,
    },

    #[serde(rename = "kill-vpn")]
    KillVpn {
        pid: u32,
        gateway: Option<String>,
        /// IP of the VPN server, used to remove its /32 host route on cleanup.
        #[serde(default)]
        vpn_server: Option<String>,
    },

    #[serde(rename = "setup-dns")]
    SetupDns {
        servers: Vec<String>,
        #[serde(default)]
        suffixes: Vec<String>,
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

// ---- Protocolo v2 ----
//
// JSON por linha, em conexão longa. O cliente se identifica pelo campo `"v": 2`
// na primeira linha; sem ele a conexão segue o protocolo v1 acima (uma requisição,
// uma resposta). Do servidor saem dois tipos de quadro, ambos com `v` e `type`:
// `response` (uma por requisição) e `event` (assíncrono, vindo da sessão).
// Para crescer: novos comandos entram em `RequestV2` e novos eventos em
// `session::Event`, sem mudar o envelope.

pub const VERSION_V2: u32 = 2;

/// Lê só o campo de versão de uma linha, para escolher o protocolo.
#[derive(Debug, Deserialize)]
pub struct VersionProbe {
    pub v: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum RequestV2 {
    Status,
    Disconnect,
}

#[derive(Debug, Serialize)]
pub struct ResponseV2 {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub state: Option<crate::session::State>,
}

/// Envelope de tudo que o servidor escreve numa conexão v2.
#[derive(Debug, Serialize)]
pub struct Frame<T: Serialize> {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: &'static str,
    #[serde(flatten)]
    pub body: T,
}
