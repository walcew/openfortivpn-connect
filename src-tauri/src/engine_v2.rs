//! Cliente do protocolo v2 do Helper.
//!
//! Comandos vão em conexões v2 curtas (uma resposta por comando, erro síncrono);
//! os eventos de estado e de log chegam por uma conexão longa que reabre sozinha
//! se o Helper reiniciar.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
enum Cause {
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
struct Totals {
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Caminho do socket do Helper.
pub fn socket_path() -> &'static Path {
    Path::new(SOCKET_PATH)
}

/// Como o `connect` se autentica no gateway.
pub enum Credentials {
    Password { username: String, password: String },
    /// Pelo navegador externo, sem usuário nem senha.
    Saml,
}

/// Corpo do `connect`: senha e OTP só viajam aqui, nunca em argv. O OTP já vem normalizado por
/// `VpnProfile::otp_to_send`; sem ele e com o gateway oferecendo push, o Helper pede o push.
/// O realm do Profile fica fora do contrato.
/// `dns_fallback_servers` é o DNS do sistema lido antes de conectar (vazio com o fallback
/// desligado); o Helper o usa, com os do Google, só se o gateway não mandar DNS.
fn connect_request(profile: &VpnProfile, creds: &Credentials, otp: Option<&str>, dns_fallback_servers: &[String]) -> Value {
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

pub fn connect(path: &Path, profile: &VpnProfile, creds: &Credentials, otp: Option<&str>, dns_fallback_servers: &[String]) -> Result<(), String> {
    request(path, &connect_request(profile, creds, otp, dns_fallback_servers)).map(|_| ())
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

fn parse_frame(frame: &Value) -> Option<Incoming> {
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

/// Os eventos são a única fonte da verdade do estado. O lock é
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

/// Evento do Tauri que uma transição de estado pede além do próprio estado: `saml-url` na
/// transição `connecting` -> `waiting-saml` e `cert-warning` na `connecting` -> erro por
/// certificado não confiável. `connecting` guarda o Profile da tentativa em curso, então o
/// estado inicial repetido de uma reconexão do canal não reabre a aba nem o diálogo.
fn transition(connecting: &mut Option<String>, state: &ConnectionState, cert_digest: Option<&str>) -> Option<(&'static str, Value)> {
    if let ConnectionState::Connecting { profile_id } = state {
        *connecting = Some(profile_id.clone());
        return None;
    }
    let profile_id = connecting.take()?;
    match (state, cert_digest) {
        // O front abre a URL no navegador padrão e mostra o diálogo "Trust & Reconnect".
        (ConnectionState::WaitingSaml { url, .. }, _) => Some(("saml-url", json!({"url": url}))),
        (ConnectionState::Error { .. }, Some(digest)) => Some(("cert-warning", json!({"digest": digest, "profile_id": profile_id}))),
        _ => None,
    }
}

const RECONNECT_HINT: &str = "Use Connect in the app or the menu bar to reconnect.";
const EXPIRING_HINT: &str = "Reconnect afterwards to keep using the VPN.";

/// Guarda em `connected` se `state` é `connected` e devolve o valor anterior.
fn swap_connected(connected: &mut bool, state: &ConnectionState) -> bool {
    std::mem::replace(connected, matches!(state, ConnectionState::Connected { .. }))
}

/// Notificação (título, corpo) de uma sessão que caiu ou expirou. Só na transição a partir de
/// `connected`: o `disconnected` repetido ao reabrir o canal de eventos não notifica de novo.
fn drop_notice(was_connected: bool, cause: Option<Cause>) -> Option<(&'static str, &'static str)> {
    match cause.filter(|_| was_connected)? {
        Cause::TunnelDropped => Some(("Disconnected: tunnel dropped", RECONNECT_HINT)),
        Cause::Expired => Some(("Session expired", RECONNECT_HINT)),
    }
}

/// Título do aviso de expiração, no horário local.
fn expiring_notice(expires_at: &str) -> Option<String> {
    let at = DateTime::parse_from_rfc3339(expires_at).ok()?.with_timezone(&chrono::Local);
    Some(format!("Session expires at {}", at.format("%H:%M")))
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        log::warn!("Failed to show notification: {}", e);
    }
}

/// Última amostra de banda: os totais e o instante em que chegaram.
struct Sample {
    totals: Totals,
    at: Instant,
}

/// Converte os totais do Helper no payload que o frontend já consome; a velocidade
/// (bytes/s) vem da diferença para a amostra anterior, e a primeira amostra tem velocidade 0.
/// Qualquer estado zera a amostra: os contadores recomeçam a cada sessão, e o Helper manda
/// o estado ao abrir (ou reabrir) o canal, antes de qualquer banda.
fn bandwidth_update(prev: &mut Option<Sample>, incoming: &Incoming, now: Instant) -> Option<BandwidthPayload> {
    let totals = match incoming {
        Incoming::State { .. } => {
            *prev = None;
            return None;
        }
        Incoming::Bandwidth(totals) => *totals,
        Incoming::Log(_) | Incoming::Expiring(_) => return None,
    };
    let speed = |total: u64, before: u64, secs: f64| if secs > 0.0 { total.saturating_sub(before) as f64 / secs } else { 0.0 };
    let (rx_speed, tx_speed) = match prev {
        Some(Sample { totals: before, at }) => {
            let secs = now.duration_since(*at).as_secs_f64();
            (speed(totals.rx_bytes, before.rx_bytes, secs), speed(totals.tx_bytes, before.tx_bytes, secs))
        }
        None => (0.0, 0.0),
    };
    *prev = Some(Sample { totals, at: now });
    Some(BandwidthPayload {
        rx_bytes: totals.rx_bytes,
        tx_bytes: totals.tx_bytes,
        rx_speed,
        tx_speed,
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// Liga o canal de eventos ao manager, aos eventos do Tauri e à tray.
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let mut connecting = None;
        let mut connected = false;
        let mut sample = None;
        run_events(socket_path(), |incoming| {
            if let Some(payload) = bandwidth_update(&mut sample, &incoming, Instant::now()) {
                let _ = app.emit("bandwidth-update", payload);
            }
            match incoming {
                Incoming::State { state, cert_digest, cause } => {
                    if let Some((event, payload)) = transition(&mut connecting, &state, cert_digest.as_deref()) {
                        let _ = app.emit(event, payload);
                    }
                    // Desktop não tem botão de ação na notificação: reconectar é o Connect da janela e da tray.
                    let was_connected = swap_connected(&mut connected, &state);
                    if let Some((title, body)) = drop_notice(was_connected, cause) {
                        notify(&app, title, body);
                    }
                    crate::tray::update_tray_icon(&app, &state);
                    let _ = app.emit("connection-status-changed", ConnectionStatusPayload::from(&state));
                    apply_state(&app.state::<Mutex<VpnManager>>(), &state);
                    // Depois do sync, para o menu refletir o estado novo.
                    crate::tray::refresh_tray_menu(&app);
                }
                Incoming::Bandwidth(_) => {}
                Incoming::Expiring(expires_at) => {
                    if let Some(title) = expiring_notice(&expires_at) {
                        notify(&app, &title, EXPIRING_HINT);
                    }
                }
                Incoming::Log(message) => {
                    let _ = app.emit(
                        "log-line",
                        // shortcut: o Helper não manda nível, tudo vai como info; evolui se o evento de log ganhar nível
                        LogLinePayload { timestamp: Utc::now().to_rfc3339(), level: "info".into(), message },
                    );
                }
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
        assert!(transition(&mut pending, &connecting("p1"), None).is_none());
        let action = transition(&mut pending, &error("TLS handshake failed"), Some(&digest));
        assert_eq!(action, Some(("cert-warning", json!({"digest": digest, "profile_id": "p1"}))));
    }

    #[test]
    fn digest_text_in_the_reason_does_not_open_the_dialog() {
        let reason = format!("Login failed: sha256 digest {}", "cd".repeat(32));
        let mut pending = None;
        transition(&mut pending, &connecting("p1"), None);
        assert!(transition(&mut pending, &error(&reason), None).is_none());
    }

    #[test]
    fn repeated_old_error_after_a_channel_reconnect_does_not_reopen_the_dialog() {
        let digest = "ab".repeat(32);
        let mut pending = None;
        transition(&mut pending, &connecting("p1"), None);
        assert!(transition(&mut pending, &error("x"), Some(&digest)).is_some());
        // O estado inicial da conexão reaberta repete o erro, sem um connecting antes.
        assert!(transition(&mut pending, &error("x"), Some(&digest)).is_none());
    }

    #[test]
    fn only_a_well_formed_digest_is_read_from_the_frame() {
        let frame = |d: &str| json!({"v": 2, "type": "event", "event": "state", "state": "disconnected", "reason": "x", "cert_digest": d});
        let digest = "ab".repeat(32);
        assert!(matches!(parse_frame(&frame(&digest)), Some(Incoming::State { cert_digest: Some(d), .. }) if d == digest));
        assert!(matches!(parse_frame(&frame("not a digest")), Some(Incoming::State { cert_digest: None, .. })));
    }

    fn bandwidth_frame(rx: u64, tx: u64) -> Incoming {
        let frame = json!({"v": 2, "type": "event", "event": "bandwidth", "rx_bytes": rx, "tx_bytes": tx});
        parse_frame(&frame).expect("not a bandwidth event")
    }

    fn state_frame(state: &str) -> Incoming {
        parse_frame(&event(json!({"event": "state", "state": state}))).unwrap()
    }

    #[test]
    fn bandwidth_event_becomes_a_payload_with_the_speed_from_the_previous_sample() {
        let (mut prev, t0) = (None, Instant::now());

        let first = bandwidth_update(&mut prev, &bandwidth_frame(1000, 500), t0).unwrap();
        assert_eq!((first.rx_bytes, first.tx_bytes, first.rx_speed, first.tx_speed), (1000, 500, 0.0, 0.0));

        let second = bandwidth_update(&mut prev, &bandwidth_frame(3000, 500), t0 + Duration::from_secs(2)).unwrap();
        assert_eq!((second.rx_bytes, second.tx_bytes), (3000, 500));
        assert_eq!((second.rx_speed, second.tx_speed), (1000.0, 0.0));
        assert!(DateTime::parse_from_rfc3339(&second.timestamp).is_ok());
    }

    #[test]
    fn a_state_event_resets_the_speed_baseline() {
        // `connecting` de uma sessão nova e o estado enviado ao reabrir o canal seguem o mesmo caminho.
        for state in ["connecting", "connected", "disconnected"] {
            let (mut prev, t0) = (None, Instant::now());
            bandwidth_update(&mut prev, &bandwidth_frame(9_000_000, 9_000_000), t0);

            assert!(bandwidth_update(&mut prev, &state_frame(state), t0 + Duration::from_secs(1)).is_none());
            let first = bandwidth_update(&mut prev, &bandwidth_frame(100, 100), t0 + Duration::from_secs(2)).unwrap();
            assert_eq!((first.rx_speed, first.tx_speed), (0.0, 0.0), "after {}", state);
        }
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
                    "dns_match_domains": ["corp.example.com"], "dns_fallback_servers": []
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
    fn saml_url_opens_only_on_the_transition_from_connecting() {
        let waiting = ConnectionState::WaitingSaml { profile_id: "p1".into(), url: "https://vpn/x".into() };
        let mut pending = None;
        // Estado inicial de uma reconexão do canal, sem connecting antes: não reabre.
        assert!(transition(&mut pending, &waiting, None).is_none());
        transition(&mut pending, &connecting("p1"), None);
        assert_eq!(transition(&mut pending, &waiting, None), Some(("saml-url", json!({"url": "https://vpn/x"}))));
        assert!(transition(&mut pending, &waiting, None).is_none());
    }

    fn connected_state() -> ConnectionState {
        ConnectionState::Connected { profile_id: "p1".into(), ip: "10.0.0.2".into(), since: Utc::now(), dns_servers: vec![], dns_domains: vec![] }
    }

    #[test]
    fn dropped_or_expired_session_notifies_only_on_the_transition_from_connected() {
        // Os estados que o canal entrega em ordem, com o flag carregado entre eles.
        let notices = |states: &[(ConnectionState, Option<Cause>)]| {
            let mut connected = false;
            states.iter().map(|(s, c)| drop_notice(swap_connected(&mut connected, s), *c).map(|n| n.0)).collect::<Vec<_>>()
        };
        for (cause, title) in [(Cause::TunnelDropped, "Disconnected: tunnel dropped"), (Cause::Expired, "Session expired")] {
            // O estado inicial de um canal reaberto repete o disconnected com a causa.
            let seen = notices(&[(connected_state(), None), (error("x"), Some(cause)), (error("x"), Some(cause))]);
            assert_eq!(seen, [None, Some(title), None]);
        }
    }

    #[test]
    fn login_error_and_normal_disconnect_do_not_notify() {
        assert!(drop_notice(true, None).is_none());
        assert!(drop_notice(false, None).is_none());
        // Causa sem ter passado por connected (ex.: canal aberto depois da queda já notificada).
        assert!(drop_notice(false, Some(Cause::Expired)).is_none());
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

    #[test]
    fn expiring_notice_shows_the_local_time() {
        let at = chrono::Local::now() + chrono::Duration::minutes(15);
        let title = expiring_notice(&at.to_rfc3339()).unwrap();
        assert_eq!(title, format!("Session expires at {}", at.format("%H:%M")));
        assert!(expiring_notice("not a time").is_none());
    }
}
