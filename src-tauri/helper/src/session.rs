use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::task::JoinSet;

use crate::fortinet::{Auth, CertTrust, Gateway, LogFn, Login, Profile, ECHO_INTERVAL};
use crate::net::{self, Os, Packets};

const GOOGLE_DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];
/// Prazo do logout no disconnect pedido pelo usuário: gateway mudo não segura a desconexão.
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolução da velocidade que a GUI calcula; mais curto pesa sem ganho visível.
const BANDWIDTH_INTERVAL: Duration = Duration::from_secs(1);
/// Janela que agrupa a rajada de avisos de uma troca de rede num único refazer.
const NETWORK_SETTLE: Duration = Duration::from_secs(1);
/// Antecedência do aviso de expiração da sessão.
const EXPIRY_WARNING: Duration = Duration::from_secs(15 * 60);

/// Relógio de parede da sessão; o teste o adianta para simular o sleep do Mac.
type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Como uma sessão terminou.
enum End {
    /// Pedido do usuário (`disconnect` ou `cancel`).
    Stopped,
    /// Falha antes de conectar (login, túnel, camada de rede).
    Failed(String),
    /// Já conectada, caiu ou expirou.
    Lost(String, Cause),
}

/// Por que uma sessão conectada caiu sem o usuário pedir; a GUI oferece reconectar.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cause {
    /// Túnel morto: echo sem resposta, TLS fechado ou PPP encerrado pelo gateway.
    TunnelDropped,
    /// Chegou o `expires_at` (`auth-timeout` do gateway).
    Expired,
}

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
        /// Só quando uma sessão conectada caiu ou expirou; ausente em erro de login e desconexão normal.
        #[serde(skip_serializing_if = "Option::is_none")]
        cause: Option<Cause>,
    },
    Connecting {
        profile_id: String,
    },
    /// Listener SAML de pé; a GUI abre `url` no navegador e o usuário faz o login lá.
    WaitingSaml {
        profile_id: String,
        url: String,
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
    /// A sessão expira em até `EXPIRY_WARNING`; sai uma vez por sessão.
    Expiring { expires_at: String },
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
    /// `disconnect` ou `cancel` já pedido nesta sessão; marcado sob o lock junto com o aviso,
    /// para o `drive` não anunciar `connected` depois de um cancelamento que chegou antes.
    stopping: bool,
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
    /// Troca de rede ou wake durante uma sessão conectada.
    network: Notify,
    push_timeout: Option<Duration>,
    echo_interval: Duration,
    expiry_warning: Duration,
    clock: Clock,
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
        net::recover(&*os);
        Self {
            os,
            trust: Arc::new(trust),
            inner: Mutex::new(Inner { state: State::Disconnected { reason: None, cert_digest: None, cause: None }, cancel: None, stopping: false }),
            applied: Mutex::default(),
            events: broadcast::channel(256).0,
            network: Notify::new(),
            push_timeout: None,
            echo_interval: ECHO_INTERVAL,
            expiry_warning: EXPIRY_WARNING,
            clock: Arc::new(Utc::now),
            bandwidth_interval: BANDWIDTH_INTERVAL,
        }
    }

    /// Intervalo curto da banda, só para testes.
    #[cfg(test)]
    pub fn with_bandwidth_interval(mut self, interval: Duration) -> Self {
        self.bandwidth_interval = interval;
        self
    }

    /// Intervalo curto do LCP echo, só para testes.
    #[cfg(test)]
    pub fn with_echo_interval(mut self, interval: Duration) -> Self {
        self.echo_interval = interval;
        self
    }

    /// Antecedência curta do aviso de expiração, só para testes.
    #[cfg(test)]
    pub fn with_expiry_warning(mut self, warning: Duration) -> Self {
        self.expiry_warning = warning;
        self
    }

    /// Relógio de parede controlado, só para testes.
    #[cfg(test)]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
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
        let gateway = Arc::new(gateway.with_echo_interval(self.echo_interval));
        let cancel = Arc::new(Notify::new());
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.cancel.is_some() {
                return Err("A session is already active".into());
            }
            inner.cancel = Some(cancel.clone());
            inner.stopping = false;
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
            let (reason, cause) = match run.await {
                Ok(End::Stopped) => (None, None),
                Ok(End::Failed(reason)) => (Some(reason), None),
                Ok(End::Lost(reason, cause)) => (Some(reason), Some(cause)),
                Err(e) => {
                    session.teardown();
                    (Some(format!("Session task failed: {}", e)), None)
                }
            };
            if let Some(r) = &reason {
                session.log(format!("disconnected: {}", r));
            }
            let mut inner = session.inner.lock().unwrap();
            inner.cancel = None;
            // Só a recusa de certificado deste connect põe o digest no estado.
            let cert_digest = reason.as_ref().and_then(|_| gateway.refused_digest());
            Self::set_state(&mut inner, &session.events, State::Disconnected { reason, cert_digest, cause });
        });
        Ok(())
    }

    /// Aviso do observador de rede (troca de rota default ou wake). Só conta com o /32 do gateway
    /// aplicado, mesmo antes do `connected`; a rajada é agrupada na sessão.
    pub fn network_changed(&self) {
        if net::has_gateway_route(&self.applied) {
            self.network.notify_one();
        }
    }

    /// Volta quando a rede para de mudar por `NETWORK_SETTLE` depois de um aviso.
    async fn network_settled(&self) {
        self.network.notified().await;
        while tokio::time::timeout(NETWORK_SETTLE, self.network.notified()).await.is_ok() {}
    }

    pub fn disconnect(&self) {
        if !Self::stop(&mut self.inner.lock().unwrap()) {
            self.log("disconnect: no active session");
        }
    }

    /// Cancela um login pendente (SAML, push ou ainda conectando). Conectada ou sem sessão, nada muda.
    pub fn cancel(&self) {
        let stopped = {
            let mut inner = self.inner.lock().unwrap();
            matches!(inner.state, State::Connecting { .. } | State::WaitingSaml { .. } | State::WaitingPush { .. })
                && Self::stop(&mut inner)
        };
        if !stopped {
            self.log("cancel: no pending login");
        }
    }

    /// Avisa a sessão ativa para parar, sob o lock que o chamador segura. false sem sessão.
    fn stop(inner: &mut Inner) -> bool {
        let Some(cancel) = inner.cancel.clone() else { return false };
        inner.stopping = true;
        // notify_one guarda a permissão se a task ainda não estiver esperando.
        cancel.notify_one();
        true
    }

    /// Desfaz o que estiver aplicado na camada de rede, se houver.
    fn teardown(&self) {
        net::teardown(&*self.os, &self.applied);
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    /// Conduz a sessão até o fim e diz como ela terminou.
    async fn drive(&self, profile: &Profile, gw: &Gateway, password: &str, otp: Option<&str>, cancel: &Notify) -> End {
        self.log(format!("connecting to {}:{}", profile.host, profile.port));
        // O `auth-timeout` conta do login: push e SAML podem levar minutos antes do túnel.
        let login_started = self.now();
        let cookie = tokio::select! {
            r = self.authenticate(profile, gw, password, otp) => match r {
                Ok(c) => c,
                Err(e) => return End::Failed(e),
            },
            _ = cancel.notified() => return End::Stopped,
        };
        let opened = tokio::select! {
            r = gw.open_tunnel(&cookie, login_started) => r,
            _ = cancel.notified() => {
                self.logout(gw, &cookie).await;
                return End::Stopped;
            }
        };
        let (mut config, packets, mut tunnel) = match opened {
            Ok(t) => t,
            Err(e) => {
                self.logout(gw, &cookie).await;
                return End::Failed(e);
            }
        };

        // O fallback (DNS do sistema + Google) só entra sem DNS do gateway, para
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
                return End::Failed(e);
            }
        }
        let stopped = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.stopping {
                let connected = State::Connected {
                    profile_id: profile.id.clone(),
                    ip: config.ip,
                    since: rfc3339(self.now()),
                    dns_servers: config.dns_servers.clone(),
                    dns_suffixes: config.dns_suffixes.clone(),
                    expires_at: config.expires_at.map(rfc3339),
                };
                Self::set_state(&mut inner, &self.events, connected);
            }
            inner.stopping
        };
        if stopped {
            drop(tunnel);
            self.teardown();
            self.logout(gw, &cookie).await;
            return End::Stopped;
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

        let expiry = self.expiry(config.expires_at);
        tokio::pin!(expiry);
        let end = loop {
            tokio::select! {
                r = tunnel.closed() => break End::Lost(r, Cause::TunnelDropped),
                _ = &mut expiry => break End::Lost("Session expired".into(), Cause::Expired),
                _ = cancel.notified() => break End::Stopped,
                _ = self.network_settled() => {
                    self.log("network changed: moving the gateway route to the current default and checking the tunnel");
                    if let Err(e) = net::rehome_gateway_route(&*self.os, config.gateway, &self.applied) {
                        self.log(format!("gateway route not restored, the tunnel may drop: {}", e));
                    }
                    tunnel.probe();
                }
            }
        };
        drop(tunnel);
        self.teardown();
        // Sem logout na queda nem na expiração: o gateway não responde ou já encerrou a sessão,
        // e o prazo do logout só atrasaria o `disconnected`.
        if let End::Stopped = end {
            self.logout(gw, &cookie).await;
        }
        end
    }

    /// Emite `expiring` na antecedência do aviso e volta no horário de expiração (nunca, sem
    /// horário). Além de dormir até o próximo prazo, confere o relógio de parede a cada intervalo
    /// de echo: o relógio monotônico para durante o sleep do macOS, e assim o aviso e a expiração
    /// saem no primeiro tick depois de acordar.
    async fn expiry(&self, expires_at: Option<DateTime<Utc>>) {
        let Some(at) = expires_at else { return std::future::pending().await };
        let warn_at = at - chrono::Duration::from_std(self.expiry_warning).unwrap_or_default();
        let mut warned = false;
        let mut tick = tokio::time::interval(self.echo_interval);
        loop {
            let now = self.now();
            if now >= at {
                return;
            }
            if !warned && now >= warn_at {
                warned = true;
                self.emit(Event::Expiring { expires_at: rfc3339(at) });
            }
            let next = if warned { at } else { warn_at };
            tokio::select! {
                _ = tokio::time::sleep((next - now).to_std().unwrap_or_default()) => {}
                _ = tick.tick() => {}
            }
        }
    }

    /// Login em um ou dois passos. Com o gateway pedindo token: usa o OTP se houver,
    /// senão pede o push (e emite `waiting-push`) quando o gateway o oferece.
    async fn authenticate(&self, profile: &Profile, gw: &Gateway, password: &str, otp: Option<&str>) -> Result<String, String> {
        if let Auth::Saml = profile.auth {
            return gw
                .saml_login(|url| {
                    self.log("waiting for SAML login in the browser");
                    let mut inner = self.inner.lock().unwrap();
                    Self::set_state(&mut inner, &self.events, State::WaitingSaml { profile_id: profile.id.clone(), url });
                })
                .await;
        }
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
    use super::{Clock, Session};
    use crate::testing::fake_gateway::*;
    use crate::testing::fake_os::{Failure, FakeOs, OsCall, FIRST_VIA, NEW_VIA};
    use crate::testing::{allow_all, connect, start_session, SAML_PORTS, start_with_bandwidth_interval, start_with_echo_interval, start_with_os, start_with_push_timeout, start_with_roots, Client};

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
        send_connect(c, cmd).await
    }

    async fn send_connect(c: &mut Client, cmd: Value) -> Value {
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
        let (gw, c, os, state, _) = connected_session(crate::fortinet::ECHO_INTERVAL, options).await;
        (gw, c, os, state)
    }

    /// Conectada com o echo neste intervalo; devolve também a sessão, para injetar a troca de rede.
    async fn connected_session(echo: Duration, options: GatewayOptions) -> (FakeGateway, Client, std::sync::Arc<FakeOs>, Value, std::sync::Arc<Session>) {
        let gw = FakeGateway::start(options).await;
        let (path, session, os) = start_with_echo_interval(echo).await;
        let mut c = client(&path).await;
        let state = connect_with(&mut c, &gw, PASSWORD).await;
        assert_eq!(state["state"], "connected", "{}", state);
        (gw, c, os, state, session)
    }

    fn assert_connected_state(state: &Value) {
        assert_eq!(state["profile_id"], PROFILE_ID);
        assert_eq!(state["ip"], ASSIGNED_IP.to_string());
        assert_eq!(state["dns_servers"], json!(XML_DNS.map(|d| d.to_string())));
        assert_eq!(state["dns_suffixes"], json!(DNS_SUFFIXES));
        let since = chrono::DateTime::parse_from_rfc3339(state["since"].as_str().unwrap()).unwrap();
        let expires = chrono::DateTime::parse_from_rfc3339(state["expires_at"].as_str().unwrap()).unwrap();
        // O `auth-timeout` conta do início do login, milissegundos antes do `since`; com os dois
        // truncados em segundos, a diferença pode perder 1 s.
        let ttl = (expires - since).num_seconds();
        assert!(ttl == AUTH_TIMEOUT as i64 || ttl == AUTH_TIMEOUT as i64 - 1, "{}", ttl);
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
        // O runtime do teste tem uma thread só: ceder a vez deixa o medidor ver o fechamento antes do pacote.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        gw.send_ip(vec![0x45; 40]);
        // Dá tempo ao pacote de chegar e descarta os eventos acumulados no socket até lá.
        tokio::time::sleep(Duration::from_millis(100)).await;
        while tokio::time::timeout(Duration::from_millis(5), c.recv()).await.is_ok() {}
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
        // O arquivo de estado da recuperação de crash guarda o /32 e o DNS aplicados.
        assert_eq!(os.saved_state(), Some(json!({"gateway_route": "127.0.0.1", "gateway_via": "192.0.2.1", "dns": true})));
        let state = disconnect(&mut c).await;
        assert_eq!(state, json!({"v": 2, "type": "event", "event": "state", "state": "disconnected"}));
        assert_eq!(gw.logouts(), 1);
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert_eq!(os.saved_state(), None);
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
        assert_eq!(os.saved_state(), None);
    }

    #[tokio::test]
    async fn connect_with_an_unsupported_auth_method_is_refused() {
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let mut cmd = connect_cmd(&gw, PASSWORD);
        cmd["profile"]["auth"] = json!("certificate");
        c.send(cmd).await;
        let r = c.recv_skipping_logs().await;
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("certificate"), "{}", r);
        assert!(os.calls().is_empty());
    }

    // ---- SAML ----

    /// `connect` de um Profile SAML: sem username nem senha.
    fn saml_cmd(gw: &FakeGateway) -> Value {
        let mut profile = gw.profile();
        profile["auth"] = json!("saml");
        profile.as_object_mut().unwrap().remove("username");
        json!({"v": 2, "cmd": "connect", "profile": profile})
    }

    /// Connect SAML: devolve o estado seguinte a `connecting`.
    async fn saml_connect(options: GatewayOptions) -> (FakeGateway, Client, std::sync::Arc<FakeOs>, Value) {
        let gw = FakeGateway::start(options).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let state = send_connect(&mut c, saml_cmd(&gw)).await;
        (gw, c, os, state)
    }

    /// Navegador falso: abre conexões vazias e um pedido sem `id` antes da real, como o
    /// navegador de verdade, e depois `GET /?id=<id>`. Devolve a resposta da real.
    async fn browser(port: u16, id: &str) -> String {
        use tokio::net::TcpStream;
        let addr = ("127.0.0.1", port);
        let _idle = TcpStream::connect(addr).await.unwrap();
        drop(TcpStream::connect(addr).await.unwrap());
        let favicon = local_request(port, "GET /favicon.ico").await;
        assert!(favicon.starts_with("HTTP/1.1 400"), "{}", favicon);
        local_request(port, &format!("GET /?id={}", id)).await
    }

    /// Manda `<método> <alvo> HTTP/1.1` ao listener SAML e devolve a resposta (vazia se ele fechar sem responder).
    async fn local_request(port: u16, line: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = format!("{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept: text/html\r\n\r\n", line, port);
        let _ = s.write_all(req.as_bytes()).await;
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut resp)).await.unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    #[tokio::test]
    async fn saml_login_through_the_browser_connects_without_leaking_the_cookie() {
        let _ports = SAML_PORTS.lock().await;
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        c.send(saml_cmd(&gw)).await;
        let mut frames = Vec::new();
        loop {
            let v = c.recv().await.unwrap();
            frames.push(v.clone());
            if v["state"] == "waiting-saml" {
                let url = format!("https://127.0.0.1:{}/remote/saml/start?redirect=1", gw.port);
                assert_eq!(v, json!({"v": 2, "type": "event", "event": "state", "state": "waiting-saml", "profile_id": PROFILE_ID, "url": url}));
                let resp = browser(gw.sso_port, SAML_ID).await;
                assert!(resp.starts_with("HTTP/1.1 200 OK"), "{}", resp);
                assert!(resp.contains("close this tab"), "{}", resp);
            }
            if v["state"] == "connected" {
                break;
            }
            assert_ne!(v["state"], "disconnected", "{}", v);
        }
        assert!(frames.iter().any(|f| f["state"] == "waiting-saml"));
        assert_connected_state(frames.last().unwrap());
        assert_eq!(os.calls(), applied_calls(&SPLIT_ROUTES.map(|(a, m)| route(a, m))));
        // O listener fecha depois do `id`.
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", gw.sso_port)).await.is_err());
        disconnect(&mut c).await;
        for f in &frames {
            assert!(!f.to_string().contains(COOKIE), "cookie leaked: {}", f);
        }
    }

    #[tokio::test]
    async fn saml_cookie_that_only_comes_from_logincheck_also_connects() {
        let _ports = SAML_PORTS.lock().await;
        let (gw, mut c, _os, waiting) = saml_connect(GatewayOptions { saml_cookie_on_logincheck: true, ..Default::default() }).await;
        assert_eq!(waiting["state"], "waiting-saml");
        browser(gw.sso_port, SAML_ID).await;
        assert_connected_state(&next_state(&mut c).await);
    }

    #[tokio::test]
    async fn requests_other_than_a_valid_id_get_400_and_the_login_goes_on() {
        let _ports = SAML_PORTS.lock().await;
        let (gw, mut c, _os, waiting) = saml_connect(GatewayOptions::default()).await;
        assert_eq!(waiting["state"], "waiting-saml");
        // Como um `<img src="http://127.0.0.1:<porta>/?id=...">` de uma página qualquer.
        for line in [
            "GET /?id=abc;rm%20-rf".to_string(),
            format!("GET /?id={}", "a".repeat(2000)),
            format!("POST /?id={}", SAML_ID),
            format!("GET /other?id={}", SAML_ID),
            "GET /".to_string(),
        ] {
            let resp = local_request(gw.sso_port, &line).await;
            assert!(resp.starts_with("HTTP/1.1 400"), "{}: {}", line, resp);
        }
        assert!(browser(gw.sso_port, SAML_ID).await.starts_with("HTTP/1.1 200 OK"));
        assert_connected_state(&next_state(&mut c).await);
    }

    #[tokio::test]
    async fn connections_above_the_limit_are_closed_without_an_answer() {
        let _ports = SAML_PORTS.lock().await;
        let (gw, mut c, _os, waiting) = saml_connect(GatewayOptions::default()).await;
        assert_eq!(waiting["state"], "waiting-saml");
        let mut idle = Vec::new();
        for _ in 0..16 {
            idle.push(tokio::net::TcpStream::connect(("127.0.0.1", gw.sso_port)).await.unwrap());
        }
        assert_eq!(local_request(gw.sso_port, &format!("GET /?id={}", SAML_ID)).await, "");
        drop(idle);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(browser(gw.sso_port, SAML_ID).await.starts_with("HTTP/1.1 200 OK"));
        assert_connected_state(&next_state(&mut c).await);
    }

    #[tokio::test]
    async fn well_formed_id_refused_by_the_gateway_disconnects_with_a_reason() {
        let _ports = SAML_PORTS.lock().await;
        let (gw, mut c, os, waiting) = saml_connect(GatewayOptions::default()).await;
        assert_eq!(waiting["state"], "waiting-saml");
        assert!(browser(gw.sso_port, "unknown-id").await.starts_with("HTTP/1.1 200 OK"));
        let state = next_state(&mut c).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("no session cookie"), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn disconnect_while_waiting_for_saml_returns_to_disconnected_and_closes_the_listener() {
        let _ports = SAML_PORTS.lock().await;
        let (gw, mut c, os, waiting) = saml_connect(GatewayOptions::default()).await;
        assert_eq!(waiting["state"], "waiting-saml");
        let state = disconnect(&mut c).await;
        assert!(state.get("reason").is_none(), "{}", state);
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", gw.sso_port)).await.is_err());
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn saml_login_times_out_after_the_gateway_remoteauthtimeout() {
        let _ports = SAML_PORTS.lock().await;
        let (_gw, mut c, os, waiting) = saml_connect(GatewayOptions { remoteauthtimeout: Some(1), ..Default::default() }).await;
        assert_eq!(waiting["state"], "waiting-saml");
        let state = next_state(&mut c).await;
        assert_eq!(state["state"], "disconnected");
        assert!(state["reason"].as_str().unwrap().contains("SAML login timed out after 1 s"), "{}", state);
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn cancel_while_waiting_for_saml_returns_to_disconnected_and_closes_the_listener() {
        let _ports = SAML_PORTS.lock().await;
        let (gw, mut c, os, waiting) = saml_connect(GatewayOptions::default()).await;
        assert_eq!(waiting["state"], "waiting-saml");
        c.send(json!({"v": 2, "cmd": "cancel"})).await;
        assert_eq!(c.recv_skipping_logs().await["ok"], true);
        assert_eq!(next_state(&mut c).await, json!({"v": 2, "type": "event", "event": "state", "state": "disconnected"}));
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", gw.sso_port)).await.is_err());
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn cancel_without_a_pending_login_is_a_no_op() {
        let (_gw, mut c, os, _state) = connected(GatewayOptions::default()).await;
        c.send(json!({"v": 2, "cmd": "cancel"})).await;
        assert_eq!(c.recv_skipping_logs().await["ok"], true);
        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(c.recv_skipping_logs().await["state"], "connected");
        assert!(!os.applied().is_empty());
    }

    #[tokio::test]
    async fn busy_sso_port_disconnects_with_a_clear_reason() {
        let _ports = SAML_PORTS.lock().await;
        let gw = FakeGateway::start(GatewayOptions::default()).await;
        let _busy = std::net::TcpListener::bind(("127.0.0.1", gw.sso_port)).unwrap();
        let (path, _session, os) = start_with_os(FakeOs::default()).await;
        let mut c = client(&path).await;
        let state = send_connect(&mut c, saml_cmd(&gw)).await;
        assert_eq!(state["state"], "disconnected");
        let reason = state["reason"].as_str().unwrap();
        assert!(reason.contains(&format!("port {} is already in use", gw.sso_port)) && reason.contains("FortiClient"), "{}", reason);
        assert!(os.calls().is_empty());
    }

    // ---- Túnel morto e expiração ----

    /// Intervalo curto do LCP echo nos testes; a produção usa 10 s.
    const ECHO: Duration = Duration::from_millis(50);

    /// Conecta numa sessão montada por `session` sobre um fake de SO novo.
    async fn connected_on(
        session: impl FnOnce(std::sync::Arc<dyn crate::net::Os>) -> Session,
        options: GatewayOptions,
    ) -> (FakeGateway, Client, std::sync::Arc<FakeOs>, Value) {
        let gw = FakeGateway::start(options).await;
        let os = std::sync::Arc::new(FakeOs::default());
        let (path, _session) = start_session(allow_all(), session(os.clone())).await;
        let mut c = client(&path).await;
        let state = connect_with(&mut c, &gw, PASSWORD).await;
        assert_eq!(state["state"], "connected", "{}", state);
        (gw, c, os, state)
    }

    async fn connected_with_echo(options: GatewayOptions) -> (FakeGateway, Client, std::sync::Arc<FakeOs>, Value) {
        let (gw, c, os, state, _) = connected_session(ECHO, options).await;
        (gw, c, os, state)
    }

    fn assert_dropped(state: &Value, cause: &str, reason: &str) {
        assert_eq!(state["state"], "disconnected", "{}", state);
        assert_eq!(state["cause"], cause, "{}", state);
        assert!(state["reason"].as_str().unwrap().contains(reason), "{}", state);
    }

    #[tokio::test]
    async fn gateway_that_stops_answering_echo_drops_three_intervals_after_its_last_lcp() {
        let (gw, mut c, os, _) = connected_with_echo(GatewayOptions { mute_echo: true, ..Default::default() }).await;
        let started = Instant::now();
        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "tunnel-dropped", "Tunnel dropped: no response from the gateway");
        // O último LCP do gateway é o Echo-Request dele, logo depois do IPCP: echos nos ticks 1 e 2,
        // queda no 3. Sob carga, o Echo-Request do gateway pode chegar depois do tick 1 e adiar a
        // queda em um tick. Os ticks contam do IPCP, antes do `connected` que `started` marca: daí
        // o piso de um intervalo, e não de dois.
        let echoes = gw.echo_requests();
        assert!((2..=3).contains(&echoes), "{} echo requests", echoes);
        assert!(started.elapsed() >= ECHO && started.elapsed() < ECHO * 8, "took {:?}", started.elapsed());
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert_eq!(os.saved_state(), None);
        assert!(os.calls().contains(&OsCall::Down));
        assert_eq!(gw.logouts(), 0);
    }

    #[tokio::test]
    async fn gateway_closing_the_tunnel_tears_down_at_once() {
        // Echo no intervalo de produção (10 s): só o TLS fechado explica a queda dentro do prazo do recv.
        let (gw, mut c, os, _) = connected(GatewayOptions::default()).await;
        gw.close_tunnel();
        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "tunnel-dropped", "Tunnel dropped: connection closed by the gateway");
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert_eq!(gw.logouts(), 0);
    }

    #[tokio::test]
    async fn gateway_terminating_ppp_is_a_dropped_tunnel() {
        let (gw, mut c, os, _) = connected(GatewayOptions::default()).await;
        gw.terminate();
        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "tunnel-dropped", "Tunnel dropped: the gateway terminated the PPP session");
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
    }

    #[tokio::test]
    async fn write_stuck_on_a_half_open_tunnel_is_a_dropped_tunnel() {
        let (gw, mut c, os, _) = connected_with_echo(GatewayOptions::default()).await;
        let iface = os.take_packets();
        gw.stop_reading();
        // Tráfego até o buffer de envio encher e a escrita travar; para quando a sessão cair.
        tokio::spawn(async move { while iface.tx.send(vec![0x45; 1300]).await.is_ok() {} });
        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "tunnel-dropped", "Tunnel dropped: write timed out");
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
    }

    #[tokio::test]
    async fn short_auth_timeout_warns_and_then_expires_the_session() {
        let (gw, mut c, os, connected) = connected(GatewayOptions { auth_timeout: Some(1), ..Default::default() }).await;
        // Faltando menos que a antecedência do aviso, ele sai logo depois do connected.
        let warning = c.recv_skipping_logs().await;
        assert_eq!(warning["event"], "expiring", "{}", warning);
        assert_eq!(warning["expires_at"], connected["expires_at"]);
        assert!(!os.applied().is_empty(), "torn down before the expiry");

        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "expired", "Session expired");
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert_eq!(os.saved_state(), None);
        assert_eq!(gw.logouts(), 0);
    }

    #[tokio::test]
    async fn warning_comes_the_warning_lead_before_the_expiry() {
        let warning = Duration::from_millis(400);
        let options = GatewayOptions { auth_timeout: Some(1), ..Default::default() };
        let (_gw, mut c, _os, _) = connected_on(|os| Session::new(os).with_expiry_warning(warning), options).await;
        let started = Instant::now();
        let event = c.recv_skipping_logs().await;
        assert_eq!(event["event"], "expiring", "{}", event);
        // Expira ~1 s depois do login: o aviso sai ~0,6 s depois dele, não logo no connected.
        assert!(started.elapsed() >= Duration::from_millis(300), "warned after {:?}", started.elapsed());
        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "expired", "Session expired");
        assert!(started.elapsed() <= Duration::from_millis(1500), "expired after {:?}", started.elapsed());
    }

    /// Relógio de parede adiantável: `skew` segundos à frente do real.
    fn skewed_clock() -> (Clock, std::sync::Arc<std::sync::atomic::AtomicI64>) {
        let skew = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
        let s = skew.clone();
        let clock: Clock = std::sync::Arc::new(move || chrono::Utc::now() + chrono::Duration::seconds(s.load(std::sync::atomic::Ordering::SeqCst)));
        (clock, skew)
    }

    #[tokio::test]
    async fn wall_clock_jump_after_sleep_warns_and_expires_on_the_next_echo_tick() {
        use std::sync::atomic::Ordering::SeqCst;
        let (clock, skew) = skewed_clock();
        let session = move |os| Session::new(os).with_echo_interval(ECHO).with_clock(clock);
        let (gw, mut c, os, connected) = connected_on(session, GatewayOptions::default()).await;

        // Mac dormiu até 10 min antes da expiração: o relógio monotônico não andou.
        skew.store(AUTH_TIMEOUT as i64 - 600, SeqCst);
        let warning = c.recv_skipping_logs().await;
        assert_eq!(warning["event"], "expiring", "{}", warning);
        assert_eq!(warning["expires_at"], connected["expires_at"]);

        skew.store(AUTH_TIMEOUT as i64 + 1, SeqCst);
        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "expired", "Session expired");
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert_eq!(gw.logouts(), 0);
    }

    #[tokio::test]
    async fn auth_timeout_counts_from_the_start_of_the_login() {
        use std::sync::atomic::Ordering::SeqCst;
        let (clock, skew) = skewed_clock();
        let gw = FakeGateway::start(GatewayOptions { push: Some(Push::Approve), ..Default::default() }).await;
        let os = std::sync::Arc::new(FakeOs::default());
        let (path, _session) = start_session(allow_all(), Session::new(os.clone()).with_clock(clock)).await;
        let mut c = client(&path).await;
        assert_eq!(connect_with(&mut c, &gw, PASSWORD).await["state"], "waiting-push");
        // Aprovação do push demorou 10 min.
        skew.store(600, SeqCst);
        let state = next_state(&mut c).await;
        assert_eq!(state["state"], "connected", "{}", state);
        let since = chrono::DateTime::parse_from_rfc3339(state["since"].as_str().unwrap()).unwrap();
        let expires = chrono::DateTime::parse_from_rfc3339(state["expires_at"].as_str().unwrap()).unwrap();
        let ttl = (expires - since).num_seconds();
        assert!(ttl == AUTH_TIMEOUT as i64 - 600 || ttl == AUTH_TIMEOUT as i64 - 601, "{}", ttl);
    }

    #[tokio::test]
    async fn healthy_session_stays_connected_past_three_echo_intervals() {
        // Expiração em 8 h (sem aviso agora) e sem expiração (`auth-timeout` 0).
        for auth_timeout in [None, Some(0)] {
            let (gw, mut c, os, state) = connected_with_echo(GatewayOptions { auth_timeout, ..Default::default() }).await;
            assert_eq!(state["expires_at"].is_null(), auth_timeout == Some(0), "{}", state);
            tokio::time::sleep(ECHO * 6).await;
            assert!(gw.echo_requests() >= 4, "only {} echo requests", gw.echo_requests());
            c.send(json!({"v": 2, "cmd": "status"})).await;
            // Nem `expiring` nem `disconnected` antes da resposta.
            let resp = c.recv_skipping_logs().await;
            assert_eq!(resp["type"], "response", "{}", resp);
            assert_eq!(resp["state"], "connected", "{}", resp);
            assert!(!os.applied().is_empty());
        }
    }

    // ---- Troca de rede, wake e recuperação de crash ----

    const GW: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const ECHO_10S: Duration = Duration::from_secs(10);

    /// Chamadas ao SO depois do apply.
    fn calls_after_connect(os: &FakeOs) -> Vec<OsCall> {
        let calls = os.calls();
        let start = calls.iter().position(|c| matches!(c, OsCall::SetDns { .. })).unwrap() + 1;
        calls[start..].to_vec()
    }

    async fn wait_for_echoes(gw: &FakeGateway, n: usize) {
        let started = Instant::now();
        while gw.echo_requests() < n {
            assert!(started.elapsed() < Duration::from_secs(3), "only {} echo requests", gw.echo_requests());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn network_change_moves_the_gateway_route_and_probes_the_tunnel_at_once() {
        // Echo no intervalo de produção (10 s): o echo que chega é o da troca de rede.
        let (gw, _c, os, _, session) = connected_session(ECHO_10S, GatewayOptions::default()).await;
        session.network_changed();
        wait_for_echoes(&gw, 1).await;
        // O /32 é levado ao default novo sem sair da tabela.
        assert_eq!(calls_after_connect(&os), [OsCall::MoveGatewayRoute(GW)]);
        assert_eq!(os.saved_state().unwrap()["gateway_via"], NEW_VIA.to_string());
    }

    #[tokio::test]
    async fn gateway_route_comes_back_on_the_next_change_after_a_failed_move() {
        // Troca de Wi-Fi: a default some antes da nova chegar, e o primeiro refazer falha.
        let (gw, _c, os, _, session) = connected_session(ECHO_10S, GatewayOptions::default()).await;
        os.fail_next_move();
        session.network_changed();
        wait_for_echoes(&gw, 1).await;
        assert!(calls_after_connect(&os).is_empty(), "{:?}", os.calls());
        // O registro continua com o /32 antigo, para o teardown e a recuperação.
        assert_eq!(os.saved_state().unwrap()["gateway_via"], FIRST_VIA.to_string());

        session.network_changed();
        wait_for_echoes(&gw, 2).await;
        assert_eq!(calls_after_connect(&os), [OsCall::MoveGatewayRoute(GW)]);
        assert_eq!(os.saved_state().unwrap()["gateway_via"], NEW_VIA.to_string());
    }

    #[tokio::test]
    async fn burst_of_network_changes_moves_the_route_once() {
        let (gw, mut c, os, _, session) = connected_session(ECHO_10S, GatewayOptions::default()).await;
        for _ in 0..5 {
            session.network_changed();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(super::NETWORK_SETTLE * 2).await;
        assert_eq!(calls_after_connect(&os), [OsCall::MoveGatewayRoute(GW)]);
        assert_eq!(gw.echo_requests(), 1);
        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(c.recv_skipping_logs().await["state"], "connected");
    }

    #[tokio::test]
    async fn network_change_with_a_mute_gateway_drops_the_tunnel() {
        // Echo a cada 600 ms: o refazer (~1 s depois do aviso) vem antes da queda (~1,8 s).
        let options = GatewayOptions { mute_echo: true, ..Default::default() };
        let (_gw, mut c, os, _, session) = connected_session(Duration::from_millis(600), options).await;
        session.network_changed();
        let state = c.recv_skipping_logs().await;
        assert_dropped(&state, "tunnel-dropped", "Tunnel dropped: no response from the gateway");
        assert_eq!(calls_after_connect(&os)[0], OsCall::MoveGatewayRoute(GW), "{:?}", os.calls());
        // O teardown remove o /32 pelo next-hop atual.
        assert!(os.calls().contains(&OsCall::RemoveGatewayRoute(GW, NEW_VIA)), "{:?}", os.calls());
        assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
        assert_eq!(os.saved_state(), None);
    }

    #[tokio::test]
    async fn network_change_while_disconnected_does_nothing() {
        let (_path, session, os) = start_with_os(FakeOs::default()).await;
        session.network_changed();
        tokio::time::sleep(super::NETWORK_SETTLE + Duration::from_millis(200)).await;
        assert!(os.calls().is_empty());
    }

    /// Sobe o Helper sobre um arquivo de estado com este conteúdo e devolve o fake e se o arquivo sobrou.
    async fn start_over_state_file(name: &str, contents: &str) -> (std::sync::Arc<FakeOs>, bool) {
        let file = std::env::temp_dir().join(format!("ovg-crash-{}-{}.json", name, std::process::id()));
        std::fs::write(&file, contents).unwrap();
        let (_path, _session, os) = start_with_os(FakeOs::with_state_file(file.clone())).await;
        (os, file.exists())
    }

    #[tokio::test]
    async fn helper_start_undoes_the_leftovers_of_a_crash() {
        let gw: IpAddr = "203.0.113.5".parse().unwrap();
        let via: IpAddr = "192.168.1.1".parse().unwrap();
        let (os, left) = start_over_state_file("full", r#"{"gateway_route":"203.0.113.5","gateway_via":"192.168.1.1","dns":true}"#).await;
        assert_eq!(os.calls(), [OsCall::RemoveDns, OsCall::RemoveGatewayRoute(gw, via)]);
        assert!(!left);

        let (os, left) = start_over_state_file("route", r#"{"gateway_route":"203.0.113.5","gateway_via":"192.168.1.1","dns":false}"#).await;
        assert_eq!(os.calls(), [OsCall::RemoveGatewayRoute(gw, via)]);
        assert!(!left);

        let (os, left) = start_over_state_file("dns", r#"{"gateway_route":null,"gateway_via":null,"dns":true}"#).await;
        assert_eq!(os.calls(), [OsCall::RemoveDns]);
        assert!(!left);

        // Sem arquivo, nada a desfazer.
        let (_path, _session, os) = start_with_os(FakeOs::default()).await;
        assert!(os.calls().is_empty());
    }

    #[tokio::test]
    async fn state_file_without_the_next_hop_keeps_the_route() {
        // Formato anterior ao next-hop: o /32 do mesmo IP pode ser de outro software.
        let (os, left) = start_over_state_file("old", r#"{"gateway_route":"203.0.113.5","dns":true}"#).await;
        assert_eq!(os.calls(), [OsCall::RemoveDns]);
        assert!(!left);
    }

    #[tokio::test]
    async fn unreadable_state_file_is_discarded_without_touching_the_network() {
        for (name, contents) in [("corrupt", "{\"gateway_ro"), ("bad-ip", r#"{"gateway_route":"not-an-ip","gateway_via":"192.168.1.1","dns":true}"#)] {
            let (os, left) = start_over_state_file(name, contents).await;
            assert!(os.calls().is_empty(), "{}: {:?}", name, os.calls());
            assert!(!left, "{}", name);
        }
    }
}
