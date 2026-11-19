//! Gateway Fortinet falso em loopback, com TLS de certificado gerado no teste.
//! Implementa `logincheck` por senha, `fortisslvpn_xml`, `sslvpn-tunnel` com o lado
//! servidor do PPP (LCP, IPCP e echo) e `logout`. Modos novos (OTP, push, SAML, túnel
//! morto) entram como campos em `GatewayOptions`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

pub const PROFILE_ID: &str = "8d3c1f5e-0000-4000-8000-000000000001";
pub const USERNAME: &str = "alice";
/// Com separadores de formulário, para provar o encoding.
pub const PASSWORD: &str = "s3cr&t =%ok";
pub const COOKIE: &str = "fake-svpn-cookie";
/// IP que o IPCP atribui; o `assigned-addr` do XML é outro de propósito.
pub const ASSIGNED_IP: Ipv4Addr = Ipv4Addr::new(10, 212, 134, 7);
pub const PEER_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 2, 1);
pub const XML_DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(10, 1, 0, 53), Ipv4Addr::new(10, 1, 0, 54)];
pub const IPCP_DNS: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
pub const DNS_SUFFIXES: [&str; 2] = ["corp.example", "lab.example"];
pub const SPLIT_ROUTES: [(&str, &str); 2] = [("10.1.0.0", "255.255.0.0"), ("192.168.50.0", "255.255.255.0")];
pub const AUTH_TIMEOUT: u64 = 28800;

#[derive(Default, Clone)]
pub struct GatewayOptions {
    /// Sem `<split-tunnel-info>` no XML.
    pub full_tunnel: bool,
    /// Aceita o `logout` e nunca responde.
    pub mute_logout: bool,
}

struct Shared {
    options: GatewayOptions,
    logouts: AtomicUsize,
    echo_replies: AtomicUsize,
    from_client: mpsc::UnboundedSender<Vec<u8>>,
    to_client: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

pub struct FakeGateway {
    pub port: u16,
    /// sha256 hex do DER do certificado, como em `trusted_certs`.
    pub digest: String,
    shared: Arc<Shared>,
    from_client: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    to_client: mpsc::UnboundedSender<Vec<u8>>,
}

impl FakeGateway {
    pub async fn start(options: GatewayOptions) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let der = cert.cert.der().clone();
        let digest = Sha256::digest(der.as_ref()).iter().map(|b| format!("{:02x}", b)).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (from_tx, from_rx) = mpsc::unbounded_channel();
        let (to_tx, to_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            options,
            logouts: AtomicUsize::new(0),
            echo_replies: AtomicUsize::new(0),
            from_client: from_tx,
            to_client: Mutex::new(Some(to_rx)),
        });
        let s = shared.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (acceptor, s) = (acceptor.clone(), s.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        handle(tls, s).await;
                    }
                });
            }
        });
        Self { port, digest, shared, from_client: tokio::sync::Mutex::new(from_rx), to_client: to_tx }
    }

    /// O Profile do comando `connect` apontando para este gateway.
    pub fn profile(&self) -> Value {
        json!({
            "id": PROFILE_ID,
            "host": "127.0.0.1",
            "port": self.port,
            "auth": "password",
            "username": USERNAME,
            "trusted_certs": [self.digest],
            "ignore_cert_errors": false,
        })
    }

    pub fn logouts(&self) -> usize {
        self.shared.logouts.load(Ordering::SeqCst)
    }

    pub fn echo_replies(&self) -> usize {
        self.shared.echo_replies.load(Ordering::SeqCst)
    }

    /// Manda um pacote IP ao cliente pelo túnel.
    pub fn send_ip(&self, packet: Vec<u8>) {
        self.to_client.send(packet).unwrap();
    }

    /// Próximo pacote IP que o cliente mandou pelo túnel.
    pub async fn recv_ip(&self) -> Vec<u8> {
        let mut rx = self.from_client.lock().await;
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("no IP packet reached the gateway").unwrap()
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut stream: S, shared: Arc<Shared>) {
    let Some((head, body)) = read_request(&mut stream).await else { return };
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let header = |name: &str| {
        head.lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    let has_cookie = header("cookie").as_deref() == Some(&format!("SVPNCOOKIE={}", COOKIE));

    let response = if request_line.starts_with("POST /remote/logincheck ") {
        let form = parse_form(&body);
        let field = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        let ok = field("username") == Some(USERNAME)
            && field("credential") == Some(PASSWORD)
            && field("realm") == Some("")
            && field("just_logged_in") == Some("1")
            && field("redir") == Some("/remote/index")
            && field("ajax") == Some("1");
        if ok {
            http(&format!("Set-Cookie: SVPNCOOKIE={}; path=/; secure; httponly\r\n", COOKIE), "ret=1,redir=/remote/fortisslvpn_xml")
        } else {
            http("Set-Cookie: SVPNCOOKIE=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n", "ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied")
        }
    } else if request_line.starts_with("GET /remote/fortisslvpn_xml ") && has_cookie && header("host").as_deref() == Some("sslvpn") {
        http("", &xml(&shared.options))
    } else if request_line.starts_with("GET /remote/sslvpn-tunnel ") && has_cookie && header("host").as_deref() == Some("sslvpn") {
        return ppp_server(stream, shared).await;
    } else if request_line.starts_with("GET /remote/logout ") {
        shared.logouts.fetch_add(1, Ordering::SeqCst);
        if shared.options.mute_logout {
            let _ = stream.read(&mut [0u8; 1]).await; // segura a conexão até o cliente desistir
            return;
        }
        http("", "")
    } else {
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_string()
    };
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn http(headers: &str, body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", headers, body.len(), body)
}

fn xml(options: &GatewayOptions) -> String {
    let split = if options.full_tunnel {
        String::new()
    } else {
        let addrs: String = SPLIT_ROUTES.iter().map(|(ip, mask)| format!("<addr ip='{}' mask='{}'/>", ip, mask)).collect();
        format!("<split-tunnel-info>{}</split-tunnel-info>", addrs)
    };
    format!(
        "<?xml version='1.0' encoding='utf-8'?>\n<sslvpn-tunnel ver='2' dtls='1' patch='1'>\
         <dtls-config heartbeat-interval='10' heartbeat-fail-count='10' heartbeat-idle-timeout='10' client-hello-timeout='10'/>\
         <tunnel-method value='ppp'/><tunnel-method value='tun'/>\
         <auth-ses check-src-ip='1' tun-connect-without-reauth='0' tun-user-ses-timeout='30'/>\
         <client-config save-password='off' keep-alive='off' auto-connect='off'/>\
         <ipv4><dns ip='{}'/><dns ip='{}'/><dns-suffix str='{}'/><assigned-addr ipv4='10.212.134.200'/>{}</ipv4>\
         <idle-timeout val='3600'/><auth-timeout val='{}'/></sslvpn-tunnel>",
        XML_DNS[0], XML_DNS[1], DNS_SUFFIXES.join(";"), split, AUTH_TIMEOUT
    )
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8(buf).ok()?;
    let len = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.ok()?;
    Some((head, body))
}

fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    let decode = |s: &str| {
        let mut out = Vec::new();
        let mut bytes = s.bytes();
        while let Some(b) = bytes.next() {
            match b {
                b'+' => out.push(b' '),
                b'%' => {
                    let hex: String = [bytes.next().unwrap(), bytes.next().unwrap()].iter().map(|&c| c as char).collect();
                    out.push(u8::from_str_radix(&hex, 16).unwrap());
                }
                _ => out.push(b),
            }
        }
        String::from_utf8(out).unwrap()
    };
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

// ---- PPP do lado servidor ----

const LCP: u16 = 0xc021;
const IPCP: u16 = 0x8021;
const IP: u16 = 0x0021;

fn ppp_frame(proto: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut ppp = vec![0xff, 0x03];
    ppp.extend_from_slice(&proto.to_be_bytes());
    if proto != IP {
        ppp.extend_from_slice(&[code, id]);
        ppp.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
    }
    ppp.extend_from_slice(data);
    let mut f = Vec::new();
    f.extend_from_slice(&((ppp.len() + 6) as u16).to_be_bytes());
    f.extend_from_slice(&[0x50, 0x50]);
    f.extend_from_slice(&(ppp.len() as u16).to_be_bytes());
    f.extend_from_slice(&ppp);
    f
}

fn opts(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = data[i + 1] as usize;
        out.push((data[i], data[i + 2..i + len].to_vec()));
        i += len;
    }
    out
}

async fn ppp_server<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S, shared: Arc<Shared>) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (frames_tx, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        loop {
            let mut header = [0u8; 6];
            if rd.read_exact(&mut header).await.is_err() {
                return;
            }
            assert_eq!(&header[2..4], &[0x50, 0x50], "bad frame magic from client");
            let len = u16::from_be_bytes([header[4], header[5]]) as usize;
            assert_eq!(u16::from_be_bytes([header[0], header[1]]) as usize, len + 6);
            let mut ppp = vec![0u8; len];
            if rd.read_exact(&mut ppp).await.is_err() || frames_tx.send(ppp).is_err() {
                return;
            }
        }
    });
    let mut to_client = shared.to_client.lock().unwrap().take().expect("one tunnel at a time");

    let assigned: Vec<(u8, Vec<u8>)> = vec![
        (3, ASSIGNED_IP.octets().to_vec()),
        (129, IPCP_DNS.octets().to_vec()),
        (131, IPCP_DNS.octets().to_vec()),
    ];
    let (mut lcp_open, mut ipcp_ours, mut ipcp_theirs, mut echo_sent) = (false, false, false, false);
    let _ = wr.write_all(&ppp_frame(LCP, 1, 1, &[5, 6, 0x11, 0x22, 0x33, 0x44])).await;

    loop {
        let ppp = tokio::select! {
            f = frames.recv() => match f { Some(f) => f, None => break },
            Some(p) = to_client.recv(), if ipcp_ours && ipcp_theirs => {
                let _ = wr.write_all(&ppp_frame(IP, 0, 0, &p)).await;
                continue;
            }
        };
        assert_eq!(&ppp[..2], &[0xff, 0x03], "client frames carry address and control");
        let proto = u16::from_be_bytes([ppp[2], ppp[3]]);
        if proto == IP {
            let _ = shared.from_client.send(ppp[4..].to_vec());
            continue;
        }
        let (code, id) = (ppp[4], ppp[5]);
        let data = &ppp[8..];
        let mut reply = Vec::new();
        match (proto, code) {
            (LCP, 1) => reply.push(ppp_frame(LCP, 2, id, data)),
            (LCP, 2) => {
                lcp_open = true;
                reply.push(ppp_frame(IPCP, 1, 1, &[3, 6, PEER_IP.octets()[0], PEER_IP.octets()[1], PEER_IP.octets()[2], PEER_IP.octets()[3]]));
            }
            (LCP, 10) => {
                shared.echo_replies.fetch_add(1, Ordering::SeqCst);
            }
            (IPCP, 1) if lcp_open => {
                let wanted = opts(data);
                let nak: Vec<u8> = wanted
                    .iter()
                    .filter_map(|(t, v)| assigned.iter().find(|(a, _)| a == t).filter(|(_, av)| av != v))
                    .flat_map(|(t, v)| [*t, (v.len() + 2) as u8].into_iter().chain(v.iter().copied()))
                    .collect();
                if nak.is_empty() {
                    ipcp_ours = true;
                    reply.push(ppp_frame(IPCP, 2, id, data));
                } else {
                    reply.push(ppp_frame(IPCP, 3, id, &nak));
                }
            }
            (IPCP, 2) => ipcp_theirs = true,
            _ => {}
        }
        if ipcp_ours && ipcp_theirs && !echo_sent {
            echo_sent = true;
            reply.push(ppp_frame(LCP, 9, 7, &[0x11, 0x22, 0x33, 0x44, b'p', b'i', b'n', b'g']));
        }
        for f in reply {
            let _ = wr.write_all(&f).await;
        }
    }
    *shared.to_client.lock().unwrap() = Some(to_client);
}
