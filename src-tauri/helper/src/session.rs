use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::task::JoinSet;

use crate::fortinet::{CertTrust, Gateway, LogFn, Login, Profile};
use crate::net::{self, Os, Packets};

const GOOGLE_DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];
/// Prazo do logout no disconnect pedido pelo usuário: gateway mudo não segura a desconexão.
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolução da velocidade que a GUI calcula; mais curto pesa sem ganho visível.
const BANDWIDTH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum State {
    Disconnected {
        /// Ausente numa desconexão normal.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// sha256 hex do certificado recusado, quando a causa é certificado não confiável.
        #[serde(skip_serializing_if = "Option::is_none")]
        cert_digest: Option<String>,
    },
    Connecting {
        profile_id: String,
    },
    /// Push do FortiToken enviado; o usuário aprova no celular.
    WaitingPush {
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
    /// Totais da sessão, em bytes de pacotes IP, a cada intervalo (também sem tráfego, para a GUI ver a velocidade cair a zero).
    Bandwidth { rx_bytes: u64, tx_bytes: u64 },
}

/// Bytes IP que passaram pelo túnel desde o início da sessão (rx = do gateway, tx = para ele).
#[derive(Default)]
struct Traffic {
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
}

/// Repassa os pacotes de `from` para `to`, somando os bytes em `counter`. Termina quando
/// qualquer um dos lados fecha, o que propaga o fechamento para o outro lado do canal.
async fn pump(mut from: mpsc::Receiver<Vec<u8>>, to: mpsc::Sender<Vec<u8>>, counter: Arc<AtomicU64>) {
    loop {
        tokio::select! {
            packet = from.recv() => match packet {
                Some(packet) => {
                    counter.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    if to.send(packet).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            _ = to.closed() => break,
        }
    }
}

/// Troca o canal de pacotes por outro, de mesmo formato, que conta o que passa por ele.
// shortcut: um salto extra por pacote em cada sentido, para não mexer no PPP; mover a contagem para `ppp::run` se pesar.
fn meter(packets: Packets, traffic: &Traffic, tasks: &mut JoinSet<()>) -> Packets {
    let (os_tx, from_os) = mpsc::channel(256);
    let (to_os, os_rx) = mpsc::channel(256);
    tasks.spawn(pump(from_os, packets.tx, traffic.tx.clone()));
    tasks.spawn(pump(packets.rx, to_os, traffic.rx.clone()));
    Packets { tx: os_tx, rx: os_rx }
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
    trust: Arc<CertTrust>,
    inner: Mutex<Inner>,
    /// O que a camada de rede aplicou e ainda não foi desfeito.
    applied: Mutex<net::Applied>,
    events: broadcast::Sender<Event>,
    push_timeout: Option<Duration>,
    bandwidth_interval: Duration,
}

impl Session {
    pub fn new(os: Arc<dyn Os>) -> Self {
        Self::build(os, CertTrust::system())
    }

    /// Só o teste injeta raízes próprias; a produção usa as do sistema.
    #[cfg(test)]
    pub fn with_trust(os: Arc<dyn Os>, trust: CertTrust) -> Self {
        Self::build(os, trust)
    }

    fn build(os: Arc<dyn Os>, trust: CertTrust) -> Self {
        Self {
            os,
            trust: Arc::new(trust),
            inner: Mutex::new(Inner { state: State::Disconnected { reason: None, cert_digest: None }, cancel: None }),
            applied: Mutex::default(),
            events: broadcast::channel(256).0,
            push_timeout: None,
            bandwidth_interval: BANDWIDTH_INTERVAL,
        }
    }

    /// Intervalo curto da banda, só para testes.
    #[cfg(test)]
    pub fn with_bandwidth_interval(mut self, interval: Duration) -> Self {
        self.bandwidth_interval = interval;
        self
    }

    /// Prazo curto do push, só para testes.
    #[cfg(test)]
    pub fn with_push_timeout(mut self, timeout: Duration) -> Self {
        self.push_timeout = Some(timeout);
        self
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
    pub fn connect(self: &Arc<Self>, profile: Profile, password: String, otp: Option<String>) -> Result<(), String> {
        let events = self.events.clone();
        let log: LogFn = Arc::new(move |line| {
            let _ = events.send(Event::Log { line });
        });
        let mut gateway = Gateway::new(&profile, &self.trust, log)?;
        if let Some(timeout) = self.push_timeout {
            gateway = gateway.with_push_timeout(timeout);
        }
        let gateway = Arc::new(gateway);
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
            // A sessão roda numa task supervisionada: um pânico não deixa rede aplicada
            // nem a sessão presa em connecting/connected.
            let s = session.clone();
            let g = gateway.clone();
            let run = tokio::spawn(async move { s.drive(&profile, &g, &password, otp.as_deref(), &cancel).await });
            let reason = match run.await {
                Ok(reason) => reason,
                Err(e) => {
                    session.teardown();
                    Some(format!("Session task failed: {}", e))
                }
            };
            if let Some(r) = &reason {
                session.log(format!("disconnected: {}", r));
            }
            let mut inner = session.inner.lock().unwrap();
            inner.cancel = None;
            // Só a recusa de certificado deste connect põe o digest no estado.
            let cert_digest = reason.as_ref().and_then(|_| gateway.refused_digest());
            Self::set_state(&mut inner, &session.events, State::Disconnected { reason, cert_digest });
        });
        Ok(())
    }

    pub fn disconnect(&self) {
        let cancel = self.inner.lock().unwrap().cancel.clone();
        match cancel {
            // notify_one guarda a permissão se a task ainda não estiver esperando.
            Some(cancel) => cancel.notify_one(),
            None => self.log("disconnect: no active session"),
        }
    }

    /// Desfaz o que estiver aplicado na camada de rede, se houver.
    fn teardown(&self) {
        net::teardown(&*self.os, &self.applied);
    }

    /// Conduz a sessão até o fim e devolve o motivo (None = desconexão pedida pelo usuário).
    async fn drive(&self, profile: &Profile, gw: &Gateway, password: &str, otp: Option<&str>, cancel: &Notify) -> Option<String> {
        self.log(format!("connecting to {}:{}", profile.host, profile.port));
        let cookie = tokio::select! {
            r = self.authenticate(profile, gw, password, otp) => match r {
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
        let (mut config, packets, mut tunnel) = match opened {
            Ok(t) => t,
            Err(e) => {
                self.logout(gw, &cookie).await;
                return Some(e);
            }
        };

        // Regra do v1: o fallback (DNS do sistema + Google) só entra sem DNS do gateway, para
        // resolvedores públicos não pegarem nomes internos do split DNS.
        if config.dns_servers.is_empty() && !profile.dns_fallback_servers.is_empty() {
            for s in profile.dns_fallback_servers.iter().chain(&GOOGLE_DNS) {
                if !config.dns_servers.contains(s) {
                    config.dns_servers.push(*s);
                }
            }
        }
        if !profile.dns_match_domains.is_empty() {
            config.dns_suffixes = profile.dns_match_domains.clone();
        }
        // Ao sair do `drive`, o JoinSet aborta o medidor e o emissor de banda.
        let mut tasks = JoinSet::new();
        let traffic = Traffic::default();
        let packets = meter(packets, &traffic, &mut tasks);
        match net::apply(&*self.os, &config, packets, &self.applied) {
            Ok(None) => {}
            Ok(Some(warning)) => {
                log::warn!("{}", warning);
                self.log(warning);
                // O estado não anuncia DNS que não foi aplicado.
                config.dns_servers.clear();
                config.dns_suffixes.clear();
            }
            Err(e) => {
                self.teardown();
                drop(tunnel);
                self.logout(gw, &cookie).await;
                return Some(e);
            }
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
        let events = self.events.clone();
        let mut ticker = tokio::time::interval(self.bandwidth_interval);
        tasks.spawn(async move {
            loop {
                ticker.tick().await;
                let _ = events.send(Event::Bandwidth {
                    rx_bytes: traffic.rx.load(Ordering::Relaxed),
                    tx_bytes: traffic.tx.load(Ordering::Relaxed),
                });
            }
        });

        let reason = tokio::select! {
            r = tunnel.closed() => Some(r),
            _ = cancel.notified() => None,
        };
        drop(tunnel);
        self.teardown();
        if reason.is_none() {
            self.logout(gw, &cookie).await;
        }
        reason
    }

    /// Login em um ou dois passos. Com o gateway pedindo token: usa o OTP se houver,
    /// senão pede o push (e emite `waiting-push`) quando o gateway o oferece.
    async fn authenticate(&self, profile: &Profile, gw: &Gateway, password: &str, otp: Option<&str>) -> Result<String, String> {
        let challenge = match gw.login(&profile.username, password).await? {
            Login::Cookie(cookie) => return Ok(cookie),
            Login::Challenge(challenge) => challenge,
        };
        let otp = otp.map(str::trim).filter(|o| !o.is_empty());
        if otp.is_none() {
            if !challenge.push {
                return Err("Gateway requires an OTP code but none was provided".into());
            }
            self.log("waiting for push approval");
            let mut inner = self.inner.lock().unwrap();
            Self::set_state(&mut inner, &self.events, State::WaitingPush { profile_id: profile.id.clone() });
        }
        gw.complete_challenge(&profile.username, &challenge, otp).await
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
    use crate::testing::fake_os::{Failure, FakeOs, OsCall};
    use crate::testing::{connect, start_with_bandwidth_interval, start_with_os, start_with_push_timeout, start_with_roots, Client};

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
        connect_with_otp(c, gw, password, None).await
    }

    async fn connect_with_otp(c: &mut Client, gw: &FakeGateway, password: &str, otp: Option<&str>) -> Value {
        let mut cmd = connect_cmd(gw, password);
        cmd["otp"] = json!(otp);
        c.send(cmd).await;
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
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
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
    async fn default_route_from_the_gateway_becomes_the_two_halves() {
        let (_gw, _c, os, _state) = connected(GatewayOptions { default_route_in_split: true, ..Default::default() }).await;
        let mut routes: Vec<Route> = SPLIT_ROUTES.iter().map(|(a, m)| route(a, m)).collect();
        routes.extend([route("0.0.0.0", "128.0.0.0"), route("128.0.0.0", "128.0.0.0")]);
        assert_eq!(os.calls(), applied_calls(&routes));
    }

    #[tokio::test]
    async fn wrong_password_disconnects_with_a_reason_and_applies_nothing() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let state = connect_with(&mut c, &gw, "wrong").await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("invalid username or password"), "{}", state);
        assert!(state.get("cert_digest").is_none(), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn untrusted_certificate_is_refused_with_its_digest() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
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
        assert_eq!(state["cert_digest"], gw.digest);
        assert!(os.calls().is_empty());
    }

    /// Manda o connect e devolve o primeiro estado depois de `connecting`, com as linhas de log vistas.
    async fn connect_logging(c: &mut Client, cmd: Value) -> (Value, Vec<String>) {
        c.send(cmd).await;
        let mut lines = Vec::new();
        loop {
            let v = c.recv().await.expect("server closed the connection");
            if v["event"] == "log" {
                lines.push(v["line"].as_str().unwrap().to_string());
            } else if v["type"] != "response" && v["state"] != "connecting" {
                return (v, lines);
            }
        }
    }

    fn pinless(gw: &FakeGateway) -> Value {
        let mut cmd = connect_cmd(gw, PASSWORD);
        cmd["profile"]["trusted_certs"] = json!([]);
        cmd
    }

    #[tokio::test]
    async fn chain_valid_by_the_roots_connects_without_a_pinned_digest() {
        let gw = FakeGateway::start(GatewayOptions { ca_signed: true, ..Default::default() }).await;
        let (path, _session) = start_with_roots(gw.roots()).await;
        let mut c = client(&path).await;
        let (state, _) = connect_logging(&mut c, pinless(&gw)).await;
        assert_eq!(state["state"], "connected", "{}", state);
    }

    #[tokio::test]
    async fn chain_outside_the_roots_is_refused_with_its_digest() {
        let gw = FakeGateway::start(GatewayOptions { ca_signed: true, ..Default::default() }).await;
        // Raízes do sistema: a CA de teste não está lá.
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let (state, _) = connect_logging(&mut c, pinless(&gw)).await;
        assert_eq!(state["state"], "disconnected");
        let reason = state["reason"].as_str().unwrap();
        assert!(reason.contains(&gw.digest) && reason.contains("UnknownIssuer"), "{}", state);
        assert_eq!(state["cert_digest"], gw.digest);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn chain_valid_for_another_name_is_refused_with_its_digest() {
        let gw = FakeGateway::start(GatewayOptions { ca_signed: true, wrong_name: true, ..Default::default() }).await;
        let (path, _session) = start_with_roots(gw.roots()).await;
        let mut c = client(&path).await;
        let (state, _) = connect_logging(&mut c, pinless(&gw)).await;
        assert_eq!(state["state"], "disconnected");
        let reason = state["reason"].as_str().unwrap();
        assert!(reason.contains(&gw.digest) && reason.to_lowercase().contains("name"), "{}", state);
        assert_eq!(state["cert_digest"], gw.digest);
    }

    #[tokio::test]
    async fn failed_handshake_does_not_count_as_a_digest_change() {
        let good = FakeGateway::start(GatewayOptions::default()).await;
        // Mesmo host, certificado diferente e sem a chave dele: o handshake não termina.
        let mitm = FakeGateway::start(GatewayOptions { mismatched_key: true, ..Default::default() }).await;
        let (path, _session, _os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let auto_trust = |gw: &FakeGateway| {
            let mut cmd = pinless(gw);
            cmd["profile"]["ignore_cert_errors"] = json!(true);
            cmd
        };
        assert_eq!(connect_logging(&mut c, auto_trust(&good)).await.0["state"], "connected");
        disconnect(&mut c).await;

        let (state, lines) = connect_logging(&mut c, auto_trust(&mitm)).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state.get("cert_digest").is_none(), "{}", state);
        assert!(!lines.iter().any(|l| l.contains("changed")), "{:?}", lines);

        // O digest guardado continua o do certificado que provou a chave.
        let (state, lines) = connect_logging(&mut c, auto_trust(&good)).await;
        assert_eq!(state["state"], "connected", "{}", state);
        assert!(!lines.iter().any(|l| l.contains("changed")), "{:?}", lines);
    }

    #[tokio::test]
    async fn auto_trust_connects_with_any_certificate_and_logs_a_digest_change() {
        let (first, second) = (FakeGateway::start(GatewayOptions::default()).await, FakeGateway::start(GatewayOptions::default()).await);
        assert_ne!(first.digest, second.digest);
        let (path, _session, _os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let auto_trust = |gw: &FakeGateway| {
            let mut cmd = pinless(gw);
            cmd["profile"]["ignore_cert_errors"] = json!(true);
            cmd
        };

        let (state, lines) = connect_logging(&mut c, auto_trust(&first)).await;
        assert_eq!(state["state"], "connected", "{}", state);
        assert!(!lines.iter().any(|l| l.contains("changed")), "{:?}", lines);
        disconnect(&mut c).await;

        // Mesmo host (127.0.0.1), outro certificado.
        let (state, lines) = connect_logging(&mut c, auto_trust(&second)).await;
        assert_eq!(state["state"], "connected", "{}", state);
        let change = lines.iter().find(|l| l.contains("changed")).unwrap_or_else(|| panic!("no change log in {:?}", lines));
        assert!(change.contains(&first.digest) && change.contains(&second.digest), "{}", change);
    }

    #[tokio::test]
    async fn auto_trust_of_one_profile_does_not_apply_to_another_host() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, _os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let mut auto = pinless(&gw);
        auto["profile"]["ignore_cert_errors"] = json!(true);
        assert_eq!(connect_logging(&mut c, auto).await.0["state"], "connected");
        disconnect(&mut c).await;

        // Mesmo gateway, mas outro Profile (host diferente) sem auto-trust.
        let mut other = pinless(&gw);
        other["profile"]["host"] = json!("localhost");
        let (state, _) = connect_logging(&mut c, other).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains(&gw.digest), "{}", state);
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

    /// Próximo evento de banda, como (rx, tx).
    async fn next_bandwidth(c: &mut Client) -> (u64, u64) {
        loop {
            let v = c.recv().await.expect("server closed the connection");
            if v["event"] == "bandwidth" {
                assert_eq!(v["type"], "event");
                return (v["rx_bytes"].as_u64().unwrap(), v["tx_bytes"].as_u64().unwrap());
            }
        }
    }

    #[tokio::test]
    async fn bandwidth_stops_counting_the_gateway_once_the_os_side_closes() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_bandwidth_interval(Duration::from_millis(20)).await;
        let mut c = client(&path).await;
        assert_eq!(connect_with(&mut c, &gw, PASSWORD).await["state"], "connected");
        drop(os.take_packets());
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Descarta os eventos acumulados no socket durante a espera.
        while tokio::time::timeout(Duration::from_millis(5), c.recv()).await.is_ok() {}

        gw.send_ip(vec![0x45; 40]);
        for _ in 0..4 {
            assert_eq!(next_bandwidth(&mut c).await, (0, 0));
        }
    }

    #[tokio::test]
    async fn bandwidth_events_carry_the_growing_ip_byte_totals() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_bandwidth_interval(Duration::from_millis(50)).await;
        let mut c = client(&path).await;
        assert_eq!(connect_with(&mut c, &gw, PASSWORD).await["state"], "connected");
        let mut iface = os.take_packets();

        iface.tx.send(vec![0x45; 100]).await.unwrap();
        gw.recv_ip().await;
        gw.send_ip(vec![0x45; 40]);
        assert!(tokio::time::timeout(Duration::from_secs(5), iface.rx.recv()).await.unwrap().is_some());
        // Um tick pode cair entre os dois sentidos; o total final é o que importa.
        loop {
            let (rx, tx) = next_bandwidth(&mut c).await;
            assert!(rx <= 40 && tx <= 100, "{} {}", rx, tx);
            if (rx, tx) == (40, 100) {
                break;
            }
        }

        gw.send_ip(vec![0x45; 60]);
        assert!(tokio::time::timeout(Duration::from_secs(5), iface.rx.recv()).await.unwrap().is_some());
        assert_eq!(next_bandwidth(&mut c).await, (100, 100));
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
    async fn profile_match_domains_replace_the_gateway_suffixes() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"]["dns_match_domains"] = json!(["intra.example"]);
        c.send(cmd).await;
        let state = loop {
            let v = c.recv_skipping_logs().await;
            if v["state"] == "connected" {
                break v;
            }
        };
        // Servidores continuam os do gateway; só os domínios de match vêm do Profile.
        assert_eq!(state["dns_servers"], json!(XML_DNS.map(|d| d.to_string())));
        assert_eq!(state["dns_suffixes"], json!(["intra.example"]));
        assert!(os.calls().contains(&OsCall::SetDns { servers: XML_DNS.to_vec(), suffixes: vec!["intra.example".into()] }));
        disconnect(&mut c).await;
        assert!(os.calls().contains(&OsCall::RemoveDns));
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
    }

    /// Conecta num gateway sem DNS e devolve o estado `connected` e o fake.
    async fn connect_without_gateway_dns(profile: Value) -> (Value, std::sync::Arc<FakeOs>) {
        let gw = FakeGateway::start(GatewayOptions { no_dns: true, ..Default::default() }).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"].as_object_mut().unwrap().extend(profile.as_object().unwrap().clone());
        let (state, _) = connect_logging(&mut c, cmd).await;
        assert_eq!(state["state"], "connected", "{}", state);
        (state, os)
    }

    fn set_dns(servers: &[&str], suffixes: &[&str]) -> OsCall {
        OsCall::SetDns {
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            suffixes: suffixes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn fallback_dns_is_used_only_when_the_gateway_sends_none() {
        let (_, os) = connect_without_gateway_dns(json!({"dns_fallback_servers": ["192.168.0.1"]})).await;
        assert!(os.calls().contains(&set_dns(&["192.168.0.1", "8.8.8.8", "8.8.4.4"], &DNS_SUFFIXES)));
    }

    #[tokio::test]
    async fn fallback_dns_skips_a_system_server_that_is_also_google() {
        let (_, os) = connect_without_gateway_dns(json!({"dns_fallback_servers": ["8.8.8.8"]})).await;
        assert!(os.calls().contains(&set_dns(&["8.8.8.8", "8.8.4.4"], &DNS_SUFFIXES)));
    }

    #[tokio::test]
    async fn fallback_dns_combines_with_the_profile_match_domains() {
        let (state, os) =
            connect_without_gateway_dns(json!({"dns_fallback_servers": ["192.168.0.1"], "dns_match_domains": ["intra.example"]})).await;
        assert!(os.calls().contains(&set_dns(&["192.168.0.1", "8.8.8.8", "8.8.4.4"], &["intra.example"])));
        assert_eq!(state["dns_servers"], json!(["192.168.0.1", "8.8.8.8", "8.8.4.4"]));
        assert_eq!(state["dns_suffixes"], json!(["intra.example"]));
    }

    #[tokio::test]
    async fn no_fallback_servers_means_no_dns_applied() {
        let (state, os) = connect_without_gateway_dns(json!({"dns_fallback_servers": []})).await;
        assert!(!os.calls().iter().any(|c| matches!(c, OsCall::SetDns { .. })), "{:?}", os.calls());
        assert_eq!(state["dns_servers"], json!([]));
    }

    #[tokio::test]
    async fn fallback_dns_does_not_mix_with_the_gateway_dns() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"]["dns_fallback_servers"] = json!(["192.168.0.1"]);
        assert_eq!(connect_logging(&mut c, cmd).await.0["state"], "connected");
        assert!(os.calls().contains(&OsCall::SetDns { servers: XML_DNS.to_vec(), suffixes: DNS_SUFFIXES.map(String::from).to_vec() }));
    }

    #[tokio::test]
    async fn dns_failure_keeps_the_tunnel_up_without_dns() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::failing_set_dns()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"]["dns_match_domains"] = json!(["corp_x.local"]);
        let (state, lines) = connect_logging(&mut c, cmd).await;
        assert_eq!(state["state"], "connected", "{}", state);
        assert_eq!(state["dns_servers"], json!([]));
        assert_eq!(state["dns_suffixes"], json!([]));
        assert!(lines.iter().any(|l| l.contains("DNS setup failed")), "{:?}", lines);
        disconnect(&mut c).await;
        assert!(!os.calls().contains(&OsCall::RemoveDns));
        assert!(os.calls().contains(&OsCall::Down));
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
        assert!(started.elapsed() < Duration::from_millis(2500), "took {:?}", started.elapsed());
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
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
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

    /// Connect contra um gateway que pede token: devolve o primeiro estado depois de `connecting`.
    async fn connect_to_token_gateway(options: GatewayOptions, otp: Option<&str>) -> (FakeGateway, Client, std::sync::Arc<FakeOs>, Value) {
        let gw = FakeGateway::start(options).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let state = connect_with_otp(&mut c, &gw, PASSWORD, otp).await;
        (gw, c, os, state)
    }

    #[tokio::test]
    async fn correct_otp_connects() {
        let (_gw, _c, os, state) = connect_to_token_gateway(GatewayOptions { require_otp: true, ..Default::default() }, Some(OTP)).await;
        assert_eq!(state["state"], "connected", "{}", state);
        assert_connected_state(&state);
        assert!(!os.calls().is_empty());
    }

    #[tokio::test]
    async fn wrong_otp_disconnects_with_a_reason_and_applies_nothing() {
        let (_gw, _c, os, state) = connect_to_token_gateway(GatewayOptions { require_otp: true, ..Default::default() }, Some("000000")).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("invalid or expired OTP"), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn token_requested_without_an_otp_disconnects_with_a_reason() {
        let (_gw, _c, os, state) = connect_to_token_gateway(GatewayOptions { require_otp: true, ..Default::default() }, None).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("requires an OTP"), "{}", state);
        assert!(os.calls().is_empty());
    }

    /// O estado seguinte do cliente, sem logs.
    async fn next_state(c: &mut Client) -> Value {
        c.recv_skipping_logs().await
    }

    #[tokio::test]
    async fn approved_push_waits_and_then_connects() {
        let (_gw, mut c, _os, waiting) = connect_to_token_gateway(GatewayOptions { push: Some(Push::Approve), ..Default::default() }, None).await;
        assert_eq!(waiting, json!({"v": 2, "type": "event", "event": "state", "state": "waiting-push", "profile_id": PROFILE_ID}));
        let started = Instant::now();
        let state = next_state(&mut c).await;
        assert_eq!(state["state"], "connected", "{}", state);
        assert!(started.elapsed() >= PUSH_DELAY / 2, "connected before the gateway approved");
    }

    #[tokio::test]
    async fn denied_push_disconnects_with_a_reason() {
        let (_gw, mut c, os, waiting) = connect_to_token_gateway(GatewayOptions { push: Some(Push::Deny), ..Default::default() }, None).await;
        assert_eq!(waiting["state"], "waiting-push");
        let state = next_state(&mut c).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("push"), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn disconnect_while_waiting_for_push_returns_to_disconnected() {
        let (_gw, mut c, os, waiting) = connect_to_token_gateway(GatewayOptions { push: Some(Push::Approve), ..Default::default() }, None).await;
        assert_eq!(waiting["state"], "waiting-push");
        let state = disconnect(&mut c).await;
        assert!(state.get("reason").is_none(), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn push_that_never_gets_an_answer_expires_with_a_clear_reason() {
        let gw = FakeGateway::start(GatewayOptions { push: Some(Push::Silent), ..Default::default() }).await;
        let (path, _session, os) = start_with_push_timeout(Duration::from_millis(300)).await;
        let mut c = client(&path).await;
        let waiting = connect_with(&mut c, &gw, PASSWORD).await;
        assert_eq!(waiting["state"], "waiting-push");
        let state = next_state(&mut c).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("push notification expired"), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn incomplete_challenge_is_reported_instead_of_a_wrong_otp() {
        let options = GatewayOptions { require_otp: true, incomplete_challenge: true, ..Default::default() };
        let (_gw, _c, os, state) = connect_to_token_gateway(options, Some(OTP)).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("incomplete login challenge"), "{}", state);
        assert!(os.calls().is_empty());
    }

    /// Connect contra um fake de SO que falha no `add_route`: devolve o estado final.
    async fn connect_with_failing_os(failure: Failure) -> (FakeGateway, std::sync::Arc<FakeOs>, Value) {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::failing_add_route(failure)).await;
        let mut c = client(&path).await;
        let state = connect_with(&mut c, &gw, PASSWORD).await;
        (gw, os, state)
    }

    #[tokio::test]
    async fn failed_apply_tears_down_logs_out_and_reports_the_reason() {
        let (gw, os, state) = connect_with_failing_os(Failure::Error).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("fake add_route failure"), "{}", state);
        assert!(os.calls().iter().any(|c| matches!(c, OsCall::AddRoute(_))), "apply did not reach the failure");
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert_eq!(gw.logouts(), 1);
    }

    #[tokio::test]
    async fn failed_gateway_route_is_not_removed_by_the_teardown() {
        // O /32 que não entrou pode ser de outro dono: o teardown só desfaz o que deu certo.
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::failing_add_gateway_route()).await;
        let mut c = client(&path).await;
        let state = connect_with(&mut c, &gw, PASSWORD).await;
        assert!(state["reason"].as_str().unwrap().contains("fake add_gateway_route failure"), "{}", state);
        assert_eq!(os.calls(), [OsCall::AddGatewayRoute(IpAddr::V4(Ipv4Addr::LOCALHOST))]);
        assert_eq!(gw.logouts(), 1);
    }

    #[tokio::test]
    async fn panic_in_the_session_tears_down_and_frees_the_session() {
        let (_gw, os, state) = connect_with_failing_os(Failure::Panic).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("Session task failed"), "{}", state);
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
    }

    #[tokio::test]
    async fn connect_with_an_unsupported_auth_method_is_refused() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"]["auth"] = json!("saml");
        c.send(cmd).await;
        let r = c.recv_skipping_logs().await;
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("saml"), "{}", r);
        assert!(os.calls().is_empty());
    }
}
