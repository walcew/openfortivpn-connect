//! Cliente do protocolo do Helper, sem Tauri: a GUI (por `gui_events`) e a CLI usam o mesmo.
//!
//! Comandos vão em conexões curtas (uma resposta por comando, erro síncrono);
//! os eventos de estado e de log chegam por uma conexão longa que reabre sozinha
//! se o Helper reiniciar.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::models::*;

/// Socket do Helper; par de `SOCKET_PATH` em helper/src/server.rs.
pub const SOCKET_PATH: &str = "/var/run/vpnconnect-helper.sock";
const TIMEOUT: Duration = Duration::from_secs(5);
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(15);

pub enum Incoming {
    /// `cert_digest` só vem no `disconnected` por certificado não confiável; `cause` só no
    /// `disconnected` de uma sessão que caiu ou expirou.
    State { state: ConnectionState, cert_digest: Option<String>, cause: Option<Cause> },
    /// A sessão expira em `expires_at` (RFC 3339); o Helper avisa uma vez, com antecedência.
    Expiring(String),
    Log(String),
    Bandwidth(Totals),
}

/// `cause` do `disconnected`: por que uma sessão conectada caiu.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cause {
    TunnelDropped,
    Expired,
}

impl Cause {
    /// Valor desconhecido (de um Helper mais novo) vira None: sem notificação.
    fn parse(v: &Value) -> Option<Self> {
        match v.as_str()? {
            "tunnel-dropped" => Some(Self::TunnelDropped),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Totais acumulados da sessão, contados pelo Engine.
#[derive(Clone, Copy)]
pub struct Totals {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Por que um comando ao Helper falhou. Vira `String` (a mesma mensagem) onde a GUI só mostra o erro.
#[derive(Debug)]
pub enum HelperError {
    /// Socket ausente ou inacessível, ou conexão que caiu sem resposta: o Helper não está rodando.
    Unavailable(String),
    /// O Helper recusou o uid: só root e o usuário logado no console usam o socket.
    Unauthorized,
    /// O Helper recebeu o comando e respondeu com erro.
    Refused(String),
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(m) | Self::Refused(m) => f.write_str(m),
            Self::Unauthorized => f.write_str("Helper refused this user: only root and the user logged in at the console can use it"),
        }
    }
}

impl From<HelperError> for String {
    fn from(e: HelperError) -> Self {
        e.to_string()
    }
}

/// Caminho do socket do Helper; com `VPNCONNECT_TEST_HOME`, o `helper.sock` de lá.
pub fn socket_path() -> PathBuf {
    crate::paths::test_home().map_or_else(|| PathBuf::from(SOCKET_PATH), |home| home.join("helper.sock"))
}

/// Como o `connect` se autentica no gateway.
pub enum Credentials {
    Password { username: String, password: String },
    /// Pelo navegador externo, sem usuário nem senha.
    Saml,
}

/// Corpo do `connect`: senha e OTP só viajam aqui, nunca em argv. O OTP já vem normalizado por
/// `VpnProfile::otp_to_send`; sem ele e com o gateway oferecendo push, o Helper pede o push.
/// `dns_fallback_servers` é o DNS do sistema lido antes de conectar (vazio com o fallback
/// desligado); o Helper o usa, com os do Google, só se o gateway não mandar DNS.
pub fn connect_request(profile: &VpnProfile, creds: &Credentials, otp: Option<&str>, dns_fallback_servers: &[String]) -> Value {
    let mut req = json!({
        "v": 2,
        "cmd": "connect",
        "profile": {
            "id": profile.id,
            "host": profile.host,
            "port": profile.port,
            "auth": match creds {
                Credentials::Password { .. } => "password",
                Credentials::Saml => "saml",
            },
            "trusted_certs": profile.trusted_certs,
            "ignore_cert_errors": profile.ignore_cert_errors,
            "dns_match_domains": profile.dns_match_domains,
            "dns_fallback_servers": dns_fallback_servers,
            "realm": profile.realm,
        },
        "otp": otp,
    });
    if let Credentials::Password { username, password } = creds {
        req["profile"]["username"] = json!(username);
        req["password"] = json!(password);
    }
    req
}

fn open(path: &Path) -> Result<UnixStream, String> {
    let stream = UnixStream::connect(path)
        .map_err(|e| format!("Failed to connect to helper socket: {}", e))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;
    Ok(stream)
}

fn send(mut stream: &UnixStream, cmd: &Value) -> Result<(), String> {
    writeln!(stream, "{}", cmd).map_err(|e| format!("Failed to send request: {}", e))
}

/// Uma conexão com o Helper: requests e, depois do primeiro, os eventos da sessão.
pub struct Channel {
    reader: BufReader<UnixStream>,
    /// A linha em leitura; um prazo que vence no meio dela não perde o que já chegou.
    line: String,
}

impl Channel {
    pub fn open(path: &Path) -> Result<Self, HelperError> {
        Ok(Self { reader: BufReader::new(open(path).map_err(HelperError::Unavailable)?), line: String::new() })
    }

    /// Envia `cmd` e devolve a resposta; eventos intercalados são descartados.
    pub fn request(&mut self, cmd: &Value) -> Result<Value, HelperError> {
        send(self.reader.get_ref(), cmd).map_err(HelperError::Unavailable)?;
        loop {
            let frame = self
                .next(TIMEOUT)?
                .ok_or_else(|| HelperError::Unavailable("Timed out waiting for the helper response".into()))?;
            match frame["type"].as_str() {
                Some("response") if frame["ok"] == true => return Ok(frame),
                Some("response") => {
                    return Err(HelperError::Refused(frame["error"].as_str().unwrap_or("Unknown helper error").to_string()))
                }
                // A recusa do uid sai sem envelope (`refuse` em helper/src/server.rs).
                None if frame["ok"] == false => return Err(HelperError::Unauthorized),
                _ => {}
            }
        }
    }

    /// O próximo quadro em até `wait`; `None` se o prazo venceu antes.
    pub fn next(&mut self, wait: Duration) -> Result<Option<Value>, HelperError> {
        use HelperError::Unavailable;
        self.reader
            .get_ref()
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(|e| Unavailable(format!("Failed to set timeout: {}", e)))?;
        match self.reader.read_line(&mut self.line) {
            Ok(0) => Err(Unavailable("Helper closed the connection".into())),
            Ok(_) => {
                let frame = serde_json::from_str(&self.line).map_err(|e| Unavailable(format!("Failed to parse response: {}", e)));
                self.line.clear();
                frame.map(Some)
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Ok(None),
            Err(e) => Err(Unavailable(format!("Failed to read response: {}", e))),
        }
    }
}

/// Envia um comando numa conexão curta e devolve a resposta.
fn request(path: &Path, cmd: &Value) -> Result<Value, HelperError> {
    Channel::open(path)?.request(cmd)
}

pub fn connect(path: &Path, profile: &VpnProfile, creds: &Credentials, otp: Option<&str>, dns_fallback_servers: &[String]) -> Result<(), HelperError> {
    request(path, &connect_request(profile, creds, otp, dns_fallback_servers)).map(|_| ())
}

pub fn disconnect(path: &Path) -> Result<(), HelperError> {
    request(path, &json!({"v": 2, "cmd": "disconnect"})).map(|_| ())
}

/// Versão do Helper instalado; `Err` se ele não está rodando.
pub fn version(path: &Path) -> Result<String, HelperError> {
    let resp = request(path, &json!({"v": 2, "cmd": "version"}))?;
    resp["version"].as_str().map(str::to_string).ok_or_else(|| HelperError::Unavailable("Helper returned no version".into()))
}

/// A resposta do `status` como o Helper a manda (envelope incluso).
pub fn status_frame(path: &Path) -> Result<Value, HelperError> {
    request(path, &json!({"v": 2, "cmd": "status"}))
}

pub fn status(path: &Path) -> Result<ConnectionState, HelperError> {
    parse_state(&status_frame(path)?).ok_or_else(|| HelperError::Unavailable("Helper returned no state".into()))
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Converte o estado do contrato (evento ou resposta de `status`) no
/// `ConnectionState` que a janela e a tray já consomem.
fn parse_state(v: &Value) -> Option<ConnectionState> {
    let text = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    Some(match v["state"].as_str()? {
        // `reason` presente = o Helper desconectou por um motivo (ex.: login recusado).
        "disconnected" => match v["reason"].as_str().filter(|r| !r.is_empty()) {
            Some(reason) => ConnectionState::Error { message: reason.to_string() },
            None => ConnectionState::Disconnected,
        },
        "connecting" => ConnectionState::Connecting { profile_id: text("profile_id") },
        "waiting-saml" => ConnectionState::WaitingSaml { profile_id: text("profile_id"), url: text("url") },
        "waiting-push" => ConnectionState::WaitingPush { profile_id: text("profile_id") },
        "connected" => ConnectionState::Connected {
            profile_id: text("profile_id"),
            ip: v["ip"].as_str().unwrap_or("unknown").to_string(),
            since: v["since"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            dns_servers: str_list(&v["dns_servers"]),
            dns_domains: str_list(&v["dns_suffixes"]),
        },
        _ => return None,
    })
}

pub(crate) fn parse_frame(frame: &Value) -> Option<Incoming> {
    match (frame["type"].as_str()?, frame["event"].as_str()) {
        ("event", Some("state")) | ("response", _) => {
            let cert_digest = frame["cert_digest"].as_str().filter(|d| is_sha256_hex(d)).map(str::to_string);
            let cause = Cause::parse(&frame["cause"]);
            parse_state(frame).map(|state| Incoming::State { state, cert_digest, cause })
        }
        ("event", Some("expiring")) => frame["expires_at"].as_str().map(|t| Incoming::Expiring(t.to_string())),
        ("event", Some("log")) => frame["line"].as_str().map(|l| Incoming::Log(l.to_string())),
        ("event", Some("bandwidth")) => {
            Some(Incoming::Bandwidth(Totals { rx_bytes: frame["rx_bytes"].as_u64()?, tx_bytes: frame["tx_bytes"].as_u64()? }))
        }
        _ => None,
    }
}

/// Uma conexão longa: pede `status` e repassa estados e logs até ela cair.
/// `Err` só quando nem conectou.
fn listen_once(path: &Path, on: &mut impl FnMut(Incoming)) -> Result<(), String> {
    let stream = open(path)?;
    send(&stream, &json!({"v": 2, "cmd": "status"}))?;
    for line in BufReader::new(&stream).lines() {
        let Ok(line) = line else { break };
        if let Some(incoming) = serde_json::from_str(&line).ok().as_ref().and_then(parse_frame) {
            on(incoming);
        }
    }
    Ok(())
}

/// Mantém a conexão de eventos aberta para sempre, reabrindo com espera
/// crescente (1s a 15s) quando o Helper some.
pub fn run_events(path: &Path, mut on: impl FnMut(Incoming)) {
    let mut delay = RECONNECT_MIN;
    loop {
        delay = match listen_once(path, &mut on) {
            Ok(()) => RECONNECT_MIN,
            Err(e) => {
                log::debug!("Helper event channel unavailable: {}", e);
                (delay * 2).min(RECONNECT_MAX)
            }
        };
        std::thread::sleep(delay);
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::mpsc;

    fn temp_socket_path() -> PathBuf {
        std::env::temp_dir().join(format!("ovg-{}.sock", &uuid::Uuid::new_v4().simple().to_string()[..8]))
    }

    /// Helper falso: cada conexão recebe `greeting` (linhas enviadas ao abrir, como o
    /// evento de estado inicial) e depois responde a cada comando com `reply(cmd)`.
    /// Os comandos recebidos vão para o canal devolvido.
    fn fake_helper(
        greeting: Vec<Value>,
        reply: impl Fn(&Value) -> Vec<Value> + Send + 'static,
    ) -> (PathBuf, mpsc::Receiver<Value>) {
        let path = temp_socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                for g in &greeting {
                    writeln!(stream, "{}", g).unwrap();
                }
                let tx = tx.clone();
                let reader = BufReader::new(stream.try_clone().unwrap());
                for line in reader.lines().map_while(Result::ok) {
                    let cmd: Value = serde_json::from_str(&line).unwrap();
                    for frame in reply(&cmd) {
                        writeln!(stream, "{}", frame).unwrap();
                    }
                    tx.send(cmd).unwrap();
                }
            }
        });
        (path, rx)
    }

    fn ok() -> Value {
        json!({"v": 2, "type": "response", "ok": true})
    }

    fn event(body: Value) -> Value {
        let mut frame = json!({"v": 2, "type": "event"});
        frame.as_object_mut().unwrap().extend(body.as_object().unwrap().clone());
        frame
    }

    fn password_creds() -> Credentials {
        Credentials::Password { username: "alice".into(), password: "s3cret".into() }
    }

    fn password_profile() -> VpnProfile {
        VpnProfile {
            id: "p1".into(),
            host: "vpn.example.com".into(),
            port: 443,
            username: Some("alice".into()),
            trusted_certs: vec!["abc".into()],
            dns_match_domains: vec!["corp.example.com".into()],
            ..VpnProfile::default()
        }
    }

    #[test]
    fn connect_sends_the_contract_json_with_credentials_in_the_body() {
        let (path, rx) = fake_helper(vec![], |_| vec![ok()]);
        connect(&path, &password_profile(), &password_creds(), None, &["192.168.0.1".to_string()]).unwrap();
        assert_eq!(
            rx.recv().unwrap(),
            json!({
                "v": 2, "cmd": "connect",
                "profile": {
                    "id": "p1", "host": "vpn.example.com", "port": 443, "auth": "password",
                    "username": "alice", "trusted_certs": ["abc"], "ignore_cert_errors": false,
                    "dns_match_domains": ["corp.example.com"], "dns_fallback_servers": ["192.168.0.1"],
                    "realm": null
                },
                "password": "s3cret", "otp": null
            })
        );
    }

    #[test]
    fn version_asks_the_helper_and_reads_its_answer() {
        let (path, rx) = fake_helper(vec![], |_| vec![json!({"v": 2, "type": "response", "ok": true, "version": "0.4.0"})]);
        assert_eq!(version(&path).unwrap(), "0.4.0");
        assert_eq!(rx.recv().unwrap(), json!({"v": 2, "cmd": "version"}));
    }

    #[test]
    fn version_fails_when_the_helper_is_not_running() {
        assert!(version(&temp_socket_path()).is_err());
    }

    #[test]
    fn connect_carries_the_profile_realm() {
        let (path, rx) = fake_helper(vec![], |_| vec![ok()]);
        let profile = VpnProfile { realm: Some("corp".into()), ..password_profile() };
        connect(&path, &profile, &password_creds(), None, &[]).unwrap();
        assert_eq!(rx.recv().unwrap()["profile"]["realm"], "corp");
    }

    #[test]
    fn only_a_well_formed_digest_is_read_from_the_frame() {
        let frame = |d: &str| json!({"v": 2, "type": "event", "event": "state", "state": "disconnected", "reason": "x", "cert_digest": d});
        let digest = "ab".repeat(32);
        assert!(matches!(parse_frame(&frame(&digest)), Some(Incoming::State { cert_digest: Some(d), .. }) if d == digest));
        assert!(matches!(parse_frame(&frame("not a digest")), Some(Incoming::State { cert_digest: None, .. })));
    }

    #[test]
    fn connect_sends_the_otp_in_the_body() {
        let (path, rx) = fake_helper(vec![], |_| vec![ok()]);
        let mut profile = password_profile();
        profile.otp_required = true;
        connect(&path, &profile, &password_creds(), Some("123456"), &[]).unwrap();
        assert_eq!(rx.recv().unwrap()["otp"], "123456");
    }

    #[test]
    fn helper_error_comes_back_as_err_even_after_events() {
        let (path, _rx) = fake_helper(
            vec![event(json!({"event": "state", "state": "disconnected"}))],
            |_| vec![json!({"v": 2, "type": "response", "ok": false, "error": "Invalid request: nope"})],
        );
        assert_eq!(String::from(disconnect(&path).unwrap_err()), "Invalid request: nope");
    }

    #[test]
    fn status_returns_the_connected_state() {
        let (path, _rx) = fake_helper(vec![], |_| {
            vec![json!({"v": 2, "type": "response", "ok": true, "state": "connected",
                "profile_id": "p1", "ip": "10.0.0.2", "since": "2026-01-01T10:00:00Z",
                "dns_servers": ["10.0.0.1"], "dns_suffixes": ["corp.example.com"], "expires_at": null})]
        });
        match status(&path).unwrap() {
            ConnectionState::Connected { profile_id, ip, dns_servers, dns_domains, since } => {
                assert_eq!((profile_id.as_str(), ip.as_str()), ("p1", "10.0.0.2"));
                assert_eq!(dns_servers, ["10.0.0.1"]);
                assert_eq!(dns_domains, ["corp.example.com"]);
                assert_eq!(since.to_rfc3339(), "2026-01-01T10:00:00+00:00");
            }
            other => panic!("unexpected state: {:?}", other),
        }
    }

    #[test]
    fn parse_state_maps_every_kind() {
        assert!(matches!(parse_state(&json!({"state": "disconnected"})), Some(ConnectionState::Disconnected)));
        assert!(matches!(
            parse_state(&json!({"state": "disconnected", "reason": "Login failed"})),
            Some(ConnectionState::Error { message }) if message == "Login failed"
        ));
        assert!(matches!(
            parse_state(&json!({"state": "connecting", "profile_id": "p1"})),
            Some(ConnectionState::Connecting { profile_id }) if profile_id == "p1"
        ));
        assert!(matches!(
            parse_state(&json!({"state": "waiting-push", "profile_id": "p1"})),
            Some(ConnectionState::WaitingPush { profile_id }) if profile_id == "p1"
        ));
        assert!(parse_state(&json!({"state": "weird"})).is_none());
    }

    #[test]
    fn event_channel_syncs_status_and_forwards_events() {
        let greeting = vec![event(json!({"event": "state", "state": "connecting", "profile_id": "p1"}))];
        let (path, rx) = fake_helper(greeting, |cmd| match cmd["cmd"].as_str() {
            Some("status") => vec![
                json!({"v": 2, "type": "response", "ok": true, "state": "disconnected"}),
                event(json!({"event": "log", "line": "hello"})),
            ],
            _ => vec![],
        });
        let (tx, events) = mpsc::channel();
        let p = path.clone();
        std::thread::spawn(move || run_events(&p, |i| { let _ = tx.send(i); }));

        let next = || events.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(matches!(next(), Incoming::State { state: ConnectionState::Connecting { .. }, .. }));
        // A resposta do `status` pedido ao abrir sincroniza o estado.
        assert!(matches!(next(), Incoming::State { state: ConnectionState::Disconnected, .. }));
        assert!(matches!(next(), Incoming::Log(l) if l == "hello"));
        assert_eq!(rx.recv().unwrap()["cmd"], "status");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn event_channel_reopens_when_the_helper_comes_back() {
        // Helper ausente no início; sobe depois e o canal conecta sozinho.
        let path = temp_socket_path();
        let (tx, events) = mpsc::channel();
        let p = path.clone();
        std::thread::spawn(move || run_events(&p, |i| { let _ = tx.send(i); }));
        std::thread::sleep(Duration::from_millis(300));

        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            writeln!(s, "{}", event(json!({"event": "state", "state": "disconnected"}))).unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(5)).unwrap(),
            Incoming::State { state: ConnectionState::Disconnected, .. }
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn saml_connect_sends_no_username_or_password() {
        let (path, rx) = fake_helper(vec![], |_| vec![ok()]);
        let profile = VpnProfile { auth_type: AuthType::Saml, username: None, ..password_profile() };
        connect(&path, &profile, &Credentials::Saml, None, &[]).unwrap();
        assert_eq!(
            rx.recv().unwrap(),
            json!({
                "v": 2, "cmd": "connect",
                "profile": {
                    "id": "p1", "host": "vpn.example.com", "port": 443, "auth": "saml",
                    "trusted_certs": ["abc"], "ignore_cert_errors": false,
                    "dns_match_domains": ["corp.example.com"], "dns_fallback_servers": [], "realm": null
                },
                "otp": null
            })
        );
    }

    #[test]
    fn waiting_saml_becomes_waiting_saml_with_the_url() {
        let frame = event(json!({"event": "state", "state": "waiting-saml", "profile_id": "p1", "url": "https://vpn/remote/saml/start?redirect=1"}));
        assert!(matches!(
            parse_frame(&frame),
            Some(Incoming::State { state: ConnectionState::WaitingSaml { profile_id, url }, .. })
                if profile_id == "p1" && url == "https://vpn/remote/saml/start?redirect=1"
        ));
    }

    #[test]
    fn cause_and_expiring_are_read_from_the_frames() {
        let frame = event(json!({"event": "state", "state": "disconnected", "reason": "Session expired", "cause": "expired"}));
        assert!(matches!(parse_frame(&frame), Some(Incoming::State { cause: Some(Cause::Expired), .. })));
        let frame = event(json!({"event": "state", "state": "disconnected", "reason": "x", "cause": "something-new"}));
        assert!(matches!(parse_frame(&frame), Some(Incoming::State { cause: None, .. })));
        let frame = event(json!({"event": "expiring", "expires_at": "2026-01-01T10:00:00Z"}));
        assert!(matches!(parse_frame(&frame), Some(Incoming::Expiring(t)) if t == "2026-01-01T10:00:00Z"));
    }
}
