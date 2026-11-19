//! Engine Fortinet SSL VPN: login HTTP, `fortisslvpn_xml`, túnel TLS e PPP.
//! O protocolo está descrito em `docs/fortinet-protocol.md`.

mod http;
mod ppp;
mod xml;

use std::sync::Arc;
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
}

/// Endereço e TLS de um gateway.
pub struct Gateway {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls: TlsConnector,
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
    pub fn new(profile: &Profile) -> Result<Self, String> {
        if !is_valid_hostname(&profile.host) {
            return Err(format!("Invalid host: {}", profile.host));
        }
        let server_name = ServerName::try_from(profile.host.clone()).map_err(|e| format!("Invalid host: {}", e))?;
        Ok(Self {
            host: profile.host.clone(),
            port: profile.port,
            server_name,
            tls: TlsConnector::from(Arc::new(http::client_config(&profile.trusted_certs))),
        })
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>, String> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| format!("Cannot reach {}:{}: {}", self.host, self.port, e))?;
        self.tls
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))
    }

    fn host_header(&self) -> String {
        if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }

    /// `host` vai no cabeçalho `Host`: o do gateway, ou `sslvpn` nos passos do túnel.
    async fn request(&self, method: &str, path: &str, host: &str, cookie: Option<&str>, form: Option<&str>) -> Result<http::Response, String> {
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
        let exchange = async {
            let mut stream = self.connect().await?;
            stream.write_all(req.as_bytes()).await.map_err(|e| format!("{} {} failed: {}", method, path, e))?;
            http::read_response(&mut stream).await.map_err(|e| format!("{} {} failed: {}", method, path, e))
        };
        tokio::time::timeout(STEP_TIMEOUT, exchange)
            .await
            .map_err(|_| format!("{} {} timed out", method, path))?
    }

    /// `POST /remote/logincheck` e devolve o `SVPNCOOKIE`.
    pub async fn login(&self, username: &str, password: &str) -> Result<String, String> {
        let form = format!(
            "username={}&credential={}&realm=&just_logged_in=1&redir=%2Fremote%2Findex&ajax=1",
            http::form_encode(username),
            http::form_encode(password)
        );
        let resp = self.request("POST", "/remote/logincheck", &self.host_header(), None, Some(&form)).await?;
        match resp.cookie("SVPNCOOKIE") {
            Some(c) if !c.is_empty() => Ok(c),
            _ => Err("Login failed: invalid username or password".into()),
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
