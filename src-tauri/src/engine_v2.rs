//! Cliente do protocolo v2 do Helper, usado só com a feature `engine-v2`.
//!
//! Comandos vão em conexões v2 curtas (uma resposta por comando, erro síncrono);
//! os eventos de estado e de log chegam por uma conexão longa que reabre sozinha
//! se o Helper reiniciar.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::helper_client::SOCKET_PATH;
use crate::models::*;
use crate::vpn_manager::VpnManager;

const TIMEOUT: Duration = Duration::from_secs(5);
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(15);

enum Incoming {
    /// `cert_digest` só vem no `disconnected` por certificado não confiável.
    State { state: ConnectionState, cert_digest: Option<String> },
    Log(String),
}

/// Caminho do socket do Helper.
pub fn socket_path() -> &'static Path {
    Path::new(SOCKET_PATH)
}

/// Recusa o que o Engine ainda não suporta, antes de qualquer tentativa.
// shortcut: só senha (com OTP ou push), SAML evolui no ticket #15
pub fn check_supported(profile: &VpnProfile) -> Result<(), String> {
    if profile.auth_type == AuthType::Saml {
        return Err("SAML authentication is not supported yet by the v2 engine".into());
    }
    Ok(())
}

/// Corpo do `connect`: senha e OTP só viajam aqui, nunca em argv. O OTP já vem
/// normalizado por `VpnProfile::otp_to_send`; sem ele e com o gateway oferecendo
/// push, o Helper pede o push.
/// `dns_fallback_servers` é o DNS do sistema lido antes de conectar (vazio com o fallback
/// desligado); o Helper o usa, com os do Google, só se o gateway não mandar DNS.
fn connect_request(profile: &VpnProfile, username: &str, password: &str, otp: Option<&str>, dns_fallback_servers: &[String]) -> Value {
    json!({
        "v": 2,
        "cmd": "connect",
        "profile": {
            "id": profile.id,
            "host": profile.host,
            "port": profile.port,
            "auth": "password",
            "username": username,
            "trusted_certs": profile.trusted_certs,
            "ignore_cert_errors": profile.ignore_cert_errors,
            // shortcut: o realm do Profile segue fora do contrato; entra quando o Engine o usar no login
            "dns_match_domains": profile.dns_match_domains,
            "dns_fallback_servers": dns_fallback_servers,
        },
        "password": password,
        "otp": otp,
    })
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

/// Envia um comando numa conexão v2 curta e devolve a resposta; eventos
/// intercalados são descartados.
fn request(path: &Path, cmd: &Value) -> Result<Value, String> {
    let stream = open(path)?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;
    send(&stream, cmd)?;
    for line in BufReader::new(&stream).lines() {
        let line = line.map_err(|e| format!("Failed to read response: {}", e))?;
        let frame: Value =
            serde_json::from_str(&line).map_err(|e| format!("Failed to parse response: {}", e))?;
        if frame["type"] == "response" {
            return if frame["ok"] == true {
                Ok(frame)
            } else {
                Err(frame["error"].as_str().unwrap_or("Unknown helper error").to_string())
            };
        }
    }
    Err("Helper closed the connection without a response".into())
}

pub fn connect(path: &Path, profile: &VpnProfile, username: &str, password: &str, otp: Option<&str>, dns_fallback_servers: &[String]) -> Result<(), String> {
    request(path, &connect_request(profile, username, password, otp, dns_fallback_servers)).map(|_| ())
}

pub fn disconnect(path: &Path) -> Result<(), String> {
    request(path, &json!({"v": 2, "cmd": "disconnect"})).map(|_| ())
}

pub fn status(path: &Path) -> Result<ConnectionState, String> {
    let resp = request(path, &json!({"v": 2, "cmd": "status"}))?;
    parse_state(&resp).ok_or_else(|| "Helper returned no state".to_string())
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Converte o estado do contrato v2 (evento ou resposta de `status`) no
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

fn parse_frame(frame: &Value) -> Option<Incoming> {
    match (frame["type"].as_str()?, frame["event"].as_str()) {
        ("event", Some("state")) | ("response", _) => {
            let cert_digest = frame["cert_digest"].as_str().filter(|d| is_sha256_hex(d)).map(str::to_string);
            parse_state(frame).map(|state| Incoming::State { state, cert_digest })
        }
        ("event", Some("log")) => frame["line"].as_str().map(|l| Incoming::Log(l.to_string())),
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
fn run_events(path: &Path, mut on: impl FnMut(Incoming)) {
    let mut delay = RECONNECT_MIN;
    loop {
        delay = match listen_once(path, &mut on) {
            Ok(()) => RECONNECT_MIN,
            Err(e) => {
                log::debug!("Helper v2 event channel unavailable: {}", e);
                (delay * 2).min(RECONNECT_MAX)
            }
        };
        std::thread::sleep(delay);
    }
}

/// No caminho v2 os eventos são a única fonte da verdade do estado. O lock é
/// bloqueante (e não `try_lock`) para que um evento chegando durante um
/// connect/disconnect em andamento espere o comando soltar o manager em vez de se perder.
fn apply_state(manager: &Mutex<VpnManager>, state: &ConnectionState) {
    manager
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .sync_state_from_payload(&ConnectionStatusPayload::from(state));
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Payload do `cert-warning` quando um estado acabou de falhar por certificado não confiável.
/// `connecting` guarda o Profile da tentativa em curso: só a transição `connecting` -> erro
/// abre o diálogo, não o erro antigo repetido no estado inicial de uma reconexão do canal.
fn cert_warning(connecting: &mut Option<String>, state: &ConnectionState, cert_digest: Option<&str>) -> Option<Value> {
    if let ConnectionState::Connecting { profile_id } = state {
        *connecting = Some(profile_id.clone());
        return None;
    }
    let profile_id = connecting.take()?;
    match (state, cert_digest) {
        (ConnectionState::Error { .. }, Some(digest)) => Some(json!({"digest": digest, "profile_id": profile_id})),
        _ => None,
    }
}

/// Liga o canal de eventos ao manager, aos eventos do Tauri e à tray.
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let mut connecting = None;
        run_events(socket_path(), |incoming| match incoming {
            Incoming::State { state, cert_digest } => {
                // Mesmo diálogo "Trust & Reconnect" do caminho do openfortivpn.
                if let Some(payload) = cert_warning(&mut connecting, &state, cert_digest.as_deref()) {
                    let _ = app.emit("cert-warning", payload);
                }
                crate::tray::update_tray_icon(&app, &state);
                let _ = app.emit("connection-status-changed", ConnectionStatusPayload::from(&state));
                apply_state(&app.state::<Mutex<VpnManager>>(), &state);
                // Depois do sync, para o menu refletir o estado novo.
                crate::tray::refresh_tray_menu(&app);
            }
            Incoming::Log(message) => {
                let _ = app.emit(
                    "log-line",
                    // shortcut: o Helper não manda nível, tudo vai como info; evolui se o evento de log ganhar nível
                    LogLinePayload { timestamp: Utc::now().to_rfc3339(), level: "info".into(), message },
                );
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::mpsc;

    fn socket_path() -> PathBuf {
        std::env::temp_dir().join(format!("ovg-{}.sock", &uuid::Uuid::new_v4().simple().to_string()[..8]))
    }

    /// Helper falso: cada conexão recebe `greeting` (linhas enviadas ao abrir, como o
    /// evento de estado inicial) e depois responde a cada comando com `reply(cmd)`.
    /// Os comandos recebidos vão para o canal devolvido.
    fn fake_helper(
        greeting: Vec<Value>,
        reply: impl Fn(&Value) -> Vec<Value> + Send + 'static,
    ) -> (PathBuf, mpsc::Receiver<Value>) {
        let path = socket_path();
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
        connect(&path, &password_profile(), "alice", "s3cret", None, &["192.168.0.1".to_string()]).unwrap();
        assert_eq!(
            rx.recv().unwrap(),
            json!({
                "v": 2, "cmd": "connect",
                "profile": {
                    "id": "p1", "host": "vpn.example.com", "port": 443, "auth": "password",
                    "username": "alice", "trusted_certs": ["abc"], "ignore_cert_errors": false,
                    "dns_match_domains": ["corp.example.com"], "dns_fallback_servers": ["192.168.0.1"]
                },
                "password": "s3cret", "otp": null
            })
        );
    }

    fn error(message: &str) -> ConnectionState {
        ConnectionState::Error { message: message.into() }
    }

    fn connecting(id: &str) -> ConnectionState {
        ConnectionState::Connecting { profile_id: id.into() }
    }

    #[test]
    fn certificate_warning_comes_from_the_cert_digest_field() {
        let digest = "ab".repeat(32);
        let mut pending = None;
        assert!(cert_warning(&mut pending, &connecting("p1"), None).is_none());
        let payload = cert_warning(&mut pending, &error("TLS handshake failed"), Some(&digest)).unwrap();
        assert_eq!(payload, json!({"digest": digest, "profile_id": "p1"}));
    }

    #[test]
    fn digest_text_in_the_reason_does_not_open_the_dialog() {
        let reason = format!("Login failed: sha256 digest {}", "cd".repeat(32));
        let mut pending = None;
        cert_warning(&mut pending, &connecting("p1"), None);
        assert!(cert_warning(&mut pending, &error(&reason), None).is_none());
    }

    #[test]
    fn repeated_old_error_after_a_channel_reconnect_does_not_reopen_the_dialog() {
        let digest = "ab".repeat(32);
        let mut pending = None;
        cert_warning(&mut pending, &connecting("p1"), None);
        assert!(cert_warning(&mut pending, &error("x"), Some(&digest)).is_some());
        // O estado inicial da conexão reaberta repete o erro, sem um connecting antes.
        assert!(cert_warning(&mut pending, &error("x"), Some(&digest)).is_none());
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
        connect(&path, &profile, "alice", "s3cret", Some("123456"), &[]).unwrap();
        assert_eq!(rx.recv().unwrap()["otp"], "123456");
    }

    #[test]
    fn helper_error_comes_back_as_err_even_after_events() {
        let (path, _rx) = fake_helper(
            vec![event(json!({"event": "state", "state": "disconnected"}))],
            |_| vec![json!({"v": 2, "type": "response", "ok": false, "error": "Invalid request: nope"})],
        );
        assert_eq!(disconnect(&path).unwrap_err(), "Invalid request: nope");
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
        let path = socket_path();
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
    fn state_event_during_a_running_command_is_not_lost() {
        let manager = Mutex::new(VpnManager::new().unwrap());
        let held = manager.lock().unwrap(); // connect/disconnect em andamento
        std::thread::scope(|s| {
            let event = s.spawn(|| {
                apply_state(&manager, &ConnectionState::Connecting { profile_id: "p1".into() })
            });
            std::thread::sleep(Duration::from_millis(200));
            assert!(!event.is_finished(), "event must wait for the lock, not give up");
            drop(held);
        });
        assert!(matches!(
            manager.lock().unwrap().get_state(),
            ConnectionState::Connecting { profile_id } if profile_id == "p1"
        ));
    }

    #[test]
    fn saml_is_not_supported_yet_but_otp_is() {
        let mut p = password_profile();
        assert!(check_supported(&p).is_ok());
        p.otp_required = true;
        assert!(check_supported(&p).is_ok());
        p.auth_type = AuthType::Saml;
        assert!(check_supported(&p).unwrap_err().contains("not supported yet"));
    }
}
