use serde::{Deserialize, Serialize};

use crate::fortinet::Profile;
use crate::session::State;

// ---- Protocolo ----
//
// JSON por linha, em conexão longa. Toda requisição leva `"v": 2`. Do servidor saem dois
// tipos de quadro, ambos com `v` e `type`: `response` (uma por requisição) e `event`
// (assíncrono, vindo da sessão).
// Para crescer: novos comandos entram em `Request` e novos eventos em
// `session::Event`, sem mudar o envelope.

pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    Status,
    /// Versão do Helper instalado, para o app decidir se reinstala.
    Version,
    Disconnect,
    /// Cancela um login pendente; sem login pendente é no-op.
    Cancel,
    /// Senha e OTP só no corpo, nunca em argv nem em log.
    Connect {
        profile: Box<Profile>,
        /// Ausente no SAML.
        #[serde(default)]
        password: String,
        /// Código OTP; ausente e com o gateway oferecendo push, o Engine pede o push.
        #[serde(default)]
        otp: Option<String>,
    },
}

impl Request {
    /// Valida a versão e o comando de uma linha já lida como JSON.
    pub fn from_value(value: serde_json::Value) -> Result<Self, String> {
        match value.get("v").and_then(|v| v.as_u64()) {
            Some(v) if v == u64::from(PROTOCOL_VERSION) => {}
            other => return Err(format!("Unsupported protocol version: {:?}", other)),
        }
        serde_json::from_value(value).map_err(|e| format!("Invalid request: {}", e))
    }
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Response {
    pub fn ok(state: Option<State>) -> Self {
        Self { ok: true, error: None, state, version: None }
    }

    pub fn version(version: &str) -> Self {
        Self { ok: true, error: None, state: None, version: Some(version.to_string()) }
    }

    pub fn error(msg: String) -> Self {
        Self { ok: false, error: Some(msg), state: None, version: None }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    Response,
    Event,
}

/// Envelope de tudo que o servidor escreve numa conexão.
#[derive(Debug, Serialize)]
pub struct Frame<T: Serialize> {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: FrameKind,
    #[serde(flatten)]
    pub body: T,
}
