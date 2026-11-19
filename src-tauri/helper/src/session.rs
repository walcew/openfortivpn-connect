use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tokio::sync::{broadcast, Notify};

use crate::fortinet::{Gateway, Profile};
use crate::net::{self, Os};

/// Prazo do logout no disconnect pedido pelo usuário: gateway mudo não segura a desconexão.
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum State {
    Disconnected {
        /// Ausente numa desconexão normal.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Connecting {
        profile_id: String,
    },
    Connected {
        profile_id: String,
        ip: Ipv4Addr,
        since: String,
        dns_servers: Vec<Ipv4Addr>,
        dns_suffixes: Vec<String>,
        expires_at: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    State(State),
    Log { line: String },
}

struct Inner {
    state: State,
    /// Presente enquanto uma sessão roda, do `connect` até o fim do teardown.
    cancel: Option<Arc<Notify>>,
}

/// Dono do estado da VPN e da fonte de eventos do protocolo v2. Cada `connect` roda
/// numa task própria, que conduz o Engine e a camada de rede e emite os eventos.
pub struct Session {
    os: Arc<dyn Os>,
    inner: Mutex<Inner>,
    events: broadcast::Sender<Event>,
}

impl Session {
    pub fn new(os: Arc<dyn Os>) -> Self {
        Self {
            os,
            inner: Mutex::new(Inner { state: State::Disconnected { reason: None }, cancel: None }),
            events: broadcast::channel(256).0,
        }
    }

    pub fn state(&self) -> State {
        self.inner.lock().unwrap().state.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn emit(&self, event: Event) {
        // Sem assinantes o envio falha, o que é esperado.
        let _ = self.events.send(event);
    }

    fn log(&self, line: impl Into<String>) {
        let line = line.into();
        log::info!("{}", line);
        self.emit(Event::Log { line });
    }

    /// Estado e evento mudam sob o mesmo lock, para a ordem dos eventos seguir a do estado.
    fn set_state(inner: &mut Inner, events: &broadcast::Sender<Event>, state: State) {
        inner.state = state.clone();
        let _ = events.send(Event::State(state));
    }

    /// Começa a conexão e volta logo; o progresso chega pelos eventos de estado.
    pub fn connect(self: &Arc<Self>, profile: Profile, password: String) -> Result<(), String> {
        let gateway = Gateway::new(&profile)?;
        let cancel = Arc::new(Notify::new());
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.cancel.is_some() {
                return Err("A session is already active".into());
            }
            inner.cancel = Some(cancel.clone());
            let connecting = State::Connecting { profile_id: profile.id.clone() };
            Self::set_state(&mut inner, &self.events, connecting);
        }
        let session = self.clone();
        tokio::spawn(async move {
            let reason = session.drive(&profile, &gateway, &password, &cancel).await;
            if let Some(r) = &reason {
                session.log(format!("disconnected: {}", r));
            }
            let mut inner = session.inner.lock().unwrap();
            inner.cancel = None;
            Self::set_state(&mut inner, &session.events, State::Disconnected { reason });
        });
        Ok(())
    }

    pub fn disconnect(&self) {
        match &self.inner.lock().unwrap().cancel {
            // notify_one guarda a permissão se a task ainda não estiver esperando.
            Some(cancel) => cancel.notify_one(),
            None => self.emit(Event::Log { line: "disconnect: no active session".into() }),
        }
    }

    /// Conduz a sessão até o fim e devolve o motivo (None = desconexão pedida pelo usuário).
    async fn drive(&self, profile: &Profile, gw: &Gateway, password: &str, cancel: &Notify) -> Option<String> {
        self.log(format!("connecting to {}:{}", profile.host, profile.port));
        let cookie = tokio::select! {
            r = gw.login(&profile.username, password) => match r {
                Ok(c) => c,
                Err(e) => return Some(e),
            },
            _ = cancel.notified() => return None,
        };
        let opened = tokio::select! {
            r = gw.open_tunnel(&cookie) => r,
            _ = cancel.notified() => {
                self.logout(gw, &cookie).await;
                return None;
            }
        };
        let (config, packets, mut tunnel) = match opened {
            Ok(t) => t,
            Err(e) => {
                self.logout(gw, &cookie).await;
                return Some(e);
            }
        };

        if let Err(e) = net::apply(&*self.os, &config, packets) {
            net::teardown(&*self.os, &config);
            drop(tunnel);
            self.logout(gw, &cookie).await;
            return Some(e);
        }
        {
            let mut inner = self.inner.lock().unwrap();
            let connected = State::Connected {
                profile_id: profile.id.clone(),
                ip: config.ip,
                since: rfc3339(Utc::now()),
                dns_servers: config.dns_servers.clone(),
                dns_suffixes: config.dns_suffixes.clone(),
                expires_at: config.expires_at.map(rfc3339),
            };
            Self::set_state(&mut inner, &self.events, connected);
        }

        let reason = tokio::select! {
            r = tunnel.closed() => Some(r),
            _ = cancel.notified() => None,
        };
        drop(tunnel);
        net::teardown(&*self.os, &config);
        if reason.is_none() {
            self.logout(gw, &cookie).await;
        }
        reason
    }

    async fn logout(&self, gw: &Gateway, cookie: &str) {
        match tokio::time::timeout(LOGOUT_TIMEOUT, gw.logout(cookie)).await {
            Ok(Ok(())) => self.log("logged out"),
            Ok(Err(e)) => self.log(format!("logout failed: {}", e)),
            Err(_) => self.log("logout timed out"),
        }
    }
}

fn rfc3339(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use serde_json::{json, Value};

    use crate::net::Route;
    use crate::testing::fake_gateway::*;
    use crate::testing::fake_os::{FakeOs, OsCall};
    use crate::testing::{allow_all, connect, start_with_os, Client};

    fn connect_cmd(gw: &FakeGateway, password: &str) -> Value {
        json!({"v": 2, "cmd": "connect", "profile": gw.profile(), "password": password, "otp": null})
    }

    /// Cliente já com o evento inicial de estado lido.
    async fn client(path: &std::path::PathBuf) -> Client {
        let mut c = connect(path).await;
        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(c.recv_skipping_logs().await["state"], "disconnected");
        assert_eq!(c.recv_skipping_logs().await["type"], "response");
        c
    }

    /// Manda o connect e espera `connecting` e o estado seguinte.
    async fn connect_with(c: &mut Client, gw: &FakeGateway, password: &str) -> Value {
        c.send(connect_cmd(gw, password)).await;
        let mut seen_response = false;
        let mut connecting = false;
        loop {
            let v = c.recv_skipping_logs().await;
            if v["type"] == "response" {
                assert_eq!(v["ok"], true, "{}", v);
                seen_response = true;
            } else if v["state"] == "connecting" {
                assert_eq!(v["profile_id"], PROFILE_ID);
                connecting = true;
            } else {
                assert!(seen_response && connecting, "{}", v);
                return v;
            }
        }
    }

    async fn connected(options: GatewayOptions) -> (FakeGateway, Client, std::sync::Arc<FakeOs>, Value) {
        let gw = FakeGateway::start(options).await;
        let (path, _session, os) = start_with_os(allow_all()).await;
        let mut c = client(&path).await;
        let state = connect_with(&mut c, &gw, PASSWORD).await;
        assert_eq!(state["state"], "connected", "{}", state);
        (gw, c, os, state)
    }

    fn assert_connected_state(state: &Value) {
        assert_eq!(state["profile_id"], PROFILE_ID);
        assert_eq!(state["ip"], ASSIGNED_IP.to_string());
        assert_eq!(state["dns_servers"], json!(XML_DNS.map(|d| d.to_string())));
        assert_eq!(state["dns_suffixes"], json!(DNS_SUFFIXES));
        let since = chrono::DateTime::parse_from_rfc3339(state["since"].as_str().unwrap()).unwrap();
        let expires = chrono::DateTime::parse_from_rfc3339(state["expires_at"].as_str().unwrap()).unwrap();
        assert_eq!((expires - since).num_seconds(), AUTH_TIMEOUT as i64);
    }

    /// As chamadas de SO esperadas num connect, em ordem.
    fn applied_calls(routes: &[Route]) -> Vec<OsCall> {
        let mut calls = vec![
            OsCall::AddGatewayRoute(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            OsCall::Up { ip: ASSIGNED_IP, peer: PEER_IP, mtu: 1354 },
        ];
        calls.extend(routes.iter().map(|r| OsCall::AddRoute(*r)));
        calls.push(OsCall::SetDns { servers: XML_DNS.to_vec(), suffixes: DNS_SUFFIXES.map(String::from).to_vec() });
        calls
    }

    fn route(addr: &str, mask: &str) -> Route {
        Route { addr: addr.parse().unwrap(), mask: mask.parse().unwrap() }
    }

    #[tokio::test]
    async fn password_connect_applies_split_tunnel() {
        let (_gw, _c, os, state) = connected(GatewayOptions::default()).await;
        assert_connected_state(&state);
        let routes: Vec<Route> = SPLIT_ROUTES.iter().map(|(a, m)| route(a, m)).collect();
        assert_eq!(os.calls(), applied_calls(&routes));
    }

    #[tokio::test]
    async fn password_connect_applies_full_tunnel_without_touching_the_default_route() {
        let (_gw, _c, os, state) = connected(GatewayOptions { full_tunnel: true, ..Default::default() }).await;
        assert_connected_state(&state);
        // Duas metades no túnel; nenhuma rota com máscara 0.0.0.0.
        let halves = [route("0.0.0.0", "128.0.0.0"), route("128.0.0.0", "128.0.0.0")];
        assert_eq!(os.calls(), applied_calls(&halves));
    }

    #[tokio::test]
    async fn wrong_password_disconnects_with_a_reason_and_applies_nothing() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(allow_all()).await;
        let mut c = client(&path).await;
        let state = connect_with(&mut c, &gw, "wrong").await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("invalid username or password"), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn untrusted_certificate_is_refused_with_its_digest() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(allow_all()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"]["trusted_certs"] = json!(["00"]);
        c.send(cmd).await;
        let state = loop {
            let v = c.recv_skipping_logs().await;
            if v["state"] == "disconnected" {
                break v;
            }
        };
        assert!(state["reason"].as_str().unwrap().contains(&gw.digest), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn ip_packets_flow_both_ways_and_lcp_echo_is_answered() {
        let (gw, _c, os, _state) = connected(GatewayOptions::default()).await;
        let mut iface = os.take_packets();

        let outbound = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        iface.tx.send(outbound.clone()).await.unwrap();
        assert_eq!(gw.recv_ip().await, outbound);

        let inbound = vec![0x45, 0, 0, 20, 9, 8, 7, 6];
        gw.send_ip(inbound.clone());
        let got = tokio::time::timeout(Duration::from_secs(5), iface.rx.recv()).await.unwrap();
        assert_eq!(got, Some(inbound));

        assert!(gw.echo_replies() >= 1, "gateway echo request was not answered");
    }

    async fn disconnect(c: &mut Client) -> Value {
        c.send(json!({"v": 2, "cmd": "disconnect"})).await;
        loop {
            let v = c.recv_skipping_logs().await;
            if v["type"] == "response" {
                assert_eq!(v["ok"], true);
            } else if v["state"] == "disconnected" {
                return v;
            }
        }
    }

    #[tokio::test]
    async fn disconnect_logs_out_and_tears_everything_down() {
        let (gw, mut c, os, _state) = connected(GatewayOptions::default()).await;
        let state = disconnect(&mut c).await;
        assert_eq!(state, json!({"v": 2, "type": "event", "event": "state", "state": "disconnected"}));
        assert_eq!(gw.logouts(), 1);
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert!(os.calls().contains(&OsCall::Down));
    }

    #[tokio::test]
    async fn mute_gateway_does_not_hold_the_disconnect() {
        let (gw, mut c, os, _state) = connected(GatewayOptions { mute_logout: true, ..Default::default() }).await;
        let started = Instant::now();
        let state = disconnect(&mut c).await;
        assert!(started.elapsed() < Duration::from_millis(2800), "took {:?}", started.elapsed());
        assert!(state.get("reason").is_none());
        assert_eq!(gw.logouts(), 1);
        assert!(os.applied().is_empty());
    }

    #[tokio::test]
    async fn connect_while_active_is_refused() {
        let (gw, mut c, _os, _state) = connected(GatewayOptions::default()).await;
        c.send(connect_cmd(&gw, PASSWORD)).await;
        let r = c.recv_skipping_logs().await;
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("already active"));
    }

    #[tokio::test]
    async fn disconnect_while_connecting_returns_to_disconnected() {
        // Um gateway que aceita o TCP e nunca fala TLS deixa o connect pendurado.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(listener.accept().await.unwrap());
            }
        });
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(allow_all()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"]["port"] = json!(port);
        c.send(cmd).await;
        loop {
            if c.recv_skipping_logs().await["state"] == "connecting" {
                break;
            }
        }
        let state = disconnect(&mut c).await;
        assert!(state.get("reason").is_none(), "{}", state);
        assert!(os.calls().is_empty());

        // E a sessão fica livre para um novo connect.
        assert_eq!(connect_with(&mut c, &gw, PASSWORD).await["state"], "connected");
    }
}
