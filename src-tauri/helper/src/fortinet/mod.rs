//! Engine Fortinet SSL VPN: login HTTP, `fortisslvpn_xml`, túnel TLS e PPP.
//! O protocolo está descrito em `docs/fortinet-protocol.md`.

mod http;
mod ppp;
mod xml;

pub use http::CertTrust;

/// Emite uma linha como evento de log da sessão.
pub type LogFn = Arc<dyn Fn(String) + Send + Sync>;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::net::{Packets, TunnelConfig};
use crate::validation::is_valid_hostname;

const DEFAULT_MTU: u16 = 1354;
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
/// Prazo da aprovação do push. Que o gateway segure a resposta até a aprovação é inferência
/// (ver `docs/fortinet-protocol.md`); os 60 s são escolha nossa, não do protocolo.
const PUSH_TIMEOUT: Duration = Duration::from_secs(60);
/// Valores do pedido de token que o segundo passo do login devolve ao gateway.
const CHALLENGE_FIELDS: [&str; 6] = ["reqid", "polid", "grp", "portal", "peer", "magic"];

/// Métodos de autenticação que o Engine já fala.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    Password,
}

/// O Profile como chega no `connect`. Só o que o Engine usa; o resto é ignorado.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub id: String,
    pub host: String,
    pub port: u16,
    #[allow(dead_code)] // só existe Password; o match entra com o segundo método
    pub auth: Auth,
    pub username: String,
    #[serde(default)]
    pub trusted_certs: Vec<String>,
    /// Auto-trust: aceita qualquer certificado, só deste host.
    #[serde(default)]
    pub ignore_cert_errors: bool,
    /// Split DNS do Profile: se houver, só estes domínios usam o DNS da VPN, no lugar
    /// dos sufixos do gateway. Vazio mantém os sufixos do gateway.
    #[serde(default)]
    pub dns_match_domains: Vec<String>,
    /// DNS do sistema lido pela GUI antes de conectar (vazio com o fallback desligado ou
    /// sem DNS no sistema). Só valem, com os do Google, se o gateway não mandar servidor.
    #[serde(default)]
    pub dns_fallback_servers: Vec<Ipv4Addr>,
}

/// O gateway pediu o segundo fator (OTP ou push) no primeiro passo do login.
pub struct Challenge {
    fields: Vec<(&'static str, String)>,
    /// O gateway oferece aprovação por push do FortiToken Mobile.
    pub push: bool,
}

/// Resultado do primeiro passo do login.
pub enum Login {
    Cookie(String),
    Challenge(Challenge),
}

/// Pares `chave=valor` do corpo do `logincheck`, separados por vírgula.
// shortcut: valor com vírgula vem truncado, trocar por um parser de verdade se um campo do desafio passar a levar vírgula.
fn parse_pairs(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Endereço e TLS de um gateway.
pub struct Gateway {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls: TlsConnector,
    /// Só o auto-trust registra o digest de cada conexão.
    auto_trust: bool,
    trust: Arc<CertTrust>,
    log: LogFn,
    /// Digest do último certificado que o verificador recusou.
    refused: Arc<Mutex<Option<String>>>,
    push_timeout: Duration,
}

/// A task do túnel; abortá-la (ou soltá-la) fecha a conexão TLS.
pub struct Tunnel(JoinHandle<String>);

impl Tunnel {
    /// Espera o túnel cair e devolve o motivo.
    pub async fn closed(&mut self) -> String {
        (&mut self.0).await.unwrap_or_else(|e| format!("Tunnel task failed: {}", e))
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Gateway {
    pub fn new(profile: &Profile, trust: &Arc<CertTrust>, log: LogFn) -> Result<Self, String> {
        if !is_valid_hostname(&profile.host) {
            return Err(format!("Invalid host: {}", profile.host));
        }
        let server_name = ServerName::try_from(profile.host.clone()).map_err(|e| format!("Invalid host: {}", e))?;
        let refused = Arc::new(Mutex::new(None));
        Ok(Self {
            host: profile.host.clone(),
            port: profile.port,
            server_name,
            tls: TlsConnector::from(Arc::new(http::client_config(profile, trust, refused.clone())?)),
            auto_trust: profile.ignore_cert_errors,
            trust: trust.clone(),
            log,
            refused,
            push_timeout: PUSH_TIMEOUT,
        })
    }

    pub fn with_push_timeout(mut self, timeout: Duration) -> Self {
        self.push_timeout = timeout;
        self
    }

    /// Digest do certificado que o verificador recusou, se foi o caso.
    pub fn refused_digest(&self) -> Option<String> {
        self.refused.lock().unwrap().clone()
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>, String> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| format!("Cannot reach {}:{}: {}", self.host, self.port, e))?;
        let stream = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;
        // Só depois do handshake, que prova a posse da chave: um certificado copiado não vira "troca".
        if self.auto_trust {
            if let Some(cert) = stream.get_ref().1.peer_certificates().and_then(|c| c.first()) {
                if let Some((old, new)) = self.trust.record(&self.host, cert) {
                    let line = format!("gateway certificate of {} changed: sha256 {} -> {}", self.host, old, new);
                    log::warn!("{}", line);
                    (self.log)(line);
                }
            }
        }
        Ok(stream)
    }

    fn host_header(&self) -> String {
        if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }

    /// `host` vai no cabeçalho `Host`: o do gateway, ou `sslvpn` nos passos do túnel.
    async fn request(&self, method: &str, path: &str, host: &str, cookie: Option<&str>, form: Option<&str>) -> Result<http::Response, String> {
        tokio::time::timeout(STEP_TIMEOUT, self.exchange(method, path, host, cookie, form))
            .await
            .map_err(|_| format!("{} {} timed out", method, path))?
    }

    /// Uma troca HTTP sem prazo próprio; quem chama decide quanto esperar.
    async fn exchange(&self, method: &str, path: &str, host: &str, cookie: Option<&str>, form: Option<&str>) -> Result<http::Response, String> {
        let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", method, path, host);
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: SVPNCOOKIE={}\r\n", c));
        }
        if let Some(body) = form {
            req.push_str(&format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            ));
        } else {
            req.push_str("\r\n");
        }
        let mut stream = self.connect().await?;
        stream.write_all(req.as_bytes()).await.map_err(|e| format!("{} {} failed: {}", method, path, e))?;
        http::read_response(&mut stream).await.map_err(|e| format!("{} {} failed: {}", method, path, e))
    }

    /// `POST /remote/logincheck`: devolve o `SVPNCOOKIE` ou o pedido de token do gateway.
    pub async fn login(&self, username: &str, password: &str) -> Result<Login, String> {
        let form = format!(
            "username={}&credential={}&realm=&just_logged_in=1&redir=%2Fremote%2Findex&ajax=1",
            http::form_encode(username),
            http::form_encode(password)
        );
        let resp = self.request("POST", "/remote/logincheck", &self.host_header(), None, Some(&form)).await?;
        if let Some(c) = resp.cookie("SVPNCOOKIE").filter(|c| !c.is_empty()) {
            return Ok(Login::Cookie(c));
        }
        let pairs = parse_pairs(&resp.body);
        let Some((_, tokeninfo)) = pairs.iter().find(|(k, _)| k == "tokeninfo") else {
            return Err("Login failed: invalid username or password".into());
        };
        let fields: Vec<_> = CHALLENGE_FIELDS
            .iter()
            .filter_map(|name| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| (*name, v.clone())))
            .collect();
        // shortcut: só `reqid` é exigido, o gateway real pode omitir os outros; apertar quando houver prova contra ele.
        if !fields.iter().any(|(k, _)| *k == "reqid") {
            return Err("Login failed: incomplete login challenge from the gateway".into());
        }
        Ok(Login::Challenge(Challenge { fields, push: tokeninfo == "ftm_push" }))
    }

    /// Segundo passo do login: reenvia o desafio com o OTP, ou pede o push quando não há OTP.
    /// Com push a chamada espera a aprovação do usuário.
    pub async fn complete_challenge(&self, username: &str, challenge: &Challenge, otp: Option<&str>) -> Result<String, String> {
        let mut form = format!("username={}", http::form_encode(username));
        for (name, value) in &challenge.fields {
            form.push_str(&format!("&{}={}", name, http::form_encode(value)));
        }
        match otp {
            Some(code) => form.push_str(&format!("&code={}", http::form_encode(code))),
            None => form.push_str("&ftm_push=1"),
        }
        form.push_str("&just_logged_in=1&ajax=1");
        let host = self.host_header();
        let resp = match otp {
            Some(_) => self.request("POST", "/remote/logincheck", &host, None, Some(&form)).await?,
            None => tokio::time::timeout(self.push_timeout, self.exchange("POST", "/remote/logincheck", &host, None, Some(&form)))
                .await
                .map_err(|_| "Login failed: push notification expired".to_string())??,
        };
        match resp.cookie("SVPNCOOKIE") {
            Some(c) if !c.is_empty() => Ok(c),
            _ if otp.is_some() => Err("Login failed: invalid or expired OTP code".into()),
            _ => Err("Login failed: push notification was denied or expired".into()),
        }
    }

    /// Lê a config do túnel, abre o `sslvpn-tunnel` e negocia o PPP até o IPCP subir.
    pub async fn open_tunnel(&self, cookie: &str) -> Result<(TunnelConfig, Packets, Tunnel), String> {
        let resp = self.request("GET", "/remote/fortisslvpn_xml", "sslvpn", Some(cookie), None).await?;
        if resp.status != 200 {
            return Err(format!("Gateway refused the tunnel configuration (HTTP {})", resp.status));
        }
        let xml = xml::parse(&resp.body)?;
        let mtu = xml.mtu.unwrap_or(DEFAULT_MTU);

        let mut stream = tokio::time::timeout(STEP_TIMEOUT, self.connect())
            .await
            .map_err(|_| "Tunnel connection timed out".to_string())??;
        let gateway = stream.get_ref().0.peer_addr().map_err(|e| e.to_string())?.ip();
        let req = format!("GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: SVPNCOOKIE={}\r\n\r\n", cookie);
        stream.write_all(req.as_bytes()).await.map_err(|e| format!("Tunnel request failed: {}", e))?;

        let (to_iface, rx) = mpsc::channel(256);
        let (tx, from_iface) = mpsc::channel(256);
        let (up_tx, up_rx) = oneshot::channel();
        let mut tunnel = Tunnel(tokio::spawn(ppp::run(stream, mtu, up_tx, to_iface, from_iface)));
        let up = match tokio::time::timeout(STEP_TIMEOUT, up_rx).await {
            Ok(Ok(up)) => up,
            Ok(Err(_)) => return Err(tunnel.closed().await),
            Err(_) => return Err("PPP negotiation timed out".into()),
        };

        let config = TunnelConfig {
            gateway,
            ip: up.ip,
            peer: up.peer,
            dns_servers: if xml.dns_servers.is_empty() { up.dns_servers } else { xml.dns_servers },
            dns_suffixes: xml.dns_suffixes,
            full_tunnel: xml.routes.is_empty(),
            routes: xml.routes,
            mtu,
            expires_at: xml.auth_timeout.map(|s| chrono::Utc::now() + chrono::Duration::seconds(s as i64)),
        };
        Ok((config, Packets { tx, rx }, tunnel))
    }

    pub async fn logout(&self, cookie: &str) -> Result<(), String> {
        self.request("GET", "/remote/logout", &self.host_header(), Some(cookie), None).await.map(|_| ())
    }
}
