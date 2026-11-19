//! PPP em modo usuário sobre o stream do `sslvpn-tunnel`: quadros Fortinet, LCP e IPCP.

use std::hash::{BuildHasher, Hasher};
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

const LCP: u16 = 0xc021;
const IPCP: u16 = 0x8021;
const IP: u16 = 0x0021;

const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const PROTO_REJ: u8 = 8;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;

const LCP_MRU: u8 = 1;
const LCP_ACCM: u8 = 2;
const LCP_MAGIC: u8 = 5;
const IPCP_ADDRESS: u8 = 3;
const IPCP_DNS1: u8 = 129;
const IPCP_DNS2: u8 = 131;

/// Echo-Requests seguidos sem nenhum LCP do gateway que contam como túnel morto.
const ECHO_MISSES: u8 = 3;

/// Cabeçalho Fortinet: tamanho total, magic e tamanho do PPP, big-endian.
const FRAME_MAGIC: u16 = 0x5050;
const HEADER_LEN: usize = 6;

/// Resultado do IPCP.
#[derive(Debug)]
pub struct Up {
    pub ip: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
}

type Opts = Vec<(u8, Vec<u8>)>;

enum Action {
    Send(Vec<u8>),
    Deliver(Vec<u8>),
    Close(String),
}

/// Conduz o túnel até ele cair e devolve o motivo. `up` dispara quando o IPCP abre;
/// a partir daí os pacotes IP fluem entre o stream e o canal da interface, e um LCP
/// Echo-Request sai a cada `echo_interval`; `ECHO_MISSES` seguidos sem LCP de volta derrubam o túnel.
pub async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    mtu: u16,
    echo_interval: Duration,
    up: oneshot::Sender<Up>,
    to_iface: mpsc::Sender<Vec<u8>>,
    mut from_iface: mpsc::Receiver<Vec<u8>>,
) -> String {
    let mut ppp = Ppp::new(mtu, up);
    if let Err(e) = stream.write_all(&ppp.lcp.request()).await {
        return format!("Tunnel write failed: {}", e);
    }
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 65536];
    // O primeiro tick sai assim que o IPCP abre; Delay evita rajada de ticks atrasados.
    let mut echo = tokio::time::interval(echo_interval);
    echo.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        // Só `read`, `recv` e `tick` dentro do select: os dois podem ser cancelados sem perder dados.
        tokio::select! {
            r = stream.read(&mut chunk) => {
                match r {
                    Ok(0) => return "Tunnel dropped: connection closed by the gateway".into(),
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) => return format!("Tunnel dropped: read failed: {}", e),
                }
                loop {
                    let payload = match take_frame(&mut buf) {
                        Ok(Some(p)) => p,
                        Ok(None) => break,
                        Err(e) => return e,
                    };
                    for action in ppp.handle(&payload) {
                        match action {
                            Action::Send(f) => if let Err(e) = stream.write_all(&f).await {
                                return format!("Tunnel write failed: {}", e);
                            },
                            // A interface já pode ter sido desfeita no teardown.
                            Action::Deliver(p) => { let _ = to_iface.send(p).await; }
                            Action::Close(reason) => return reason,
                        }
                    }
                }
            }
            Some(packet) = from_iface.recv(), if ppp.up.is_none() => {
                if let Err(e) = stream.write_all(&frame(IP, &packet)).await {
                    return format!("Tunnel write failed: {}", e);
                }
            }
            _ = echo.tick(), if ppp.up.is_none() => {
                if ppp.missed == ECHO_MISSES {
                    return "Tunnel dropped: no response from the gateway".into();
                }
                ppp.missed += 1;
                ppp.echo_id = ppp.echo_id.wrapping_add(1);
                if let Err(e) = stream.write_all(&packet(LCP, ECHO_REQ, ppp.echo_id, &ppp.magic)).await {
                    return format!("Tunnel write failed: {}", e);
                }
            }
        }
    }
}

/// Um protocolo de controle (LCP ou IPCP): o nosso Configure-Request e o estado dos acks.
struct Cp {
    proto: u16,
    opts: Opts,
    id: u8,
    ours_acked: bool,
    theirs_acked: bool,
}

impl Cp {
    fn new(proto: u16, opts: Opts) -> Self {
        Self { proto, opts, id: 0, ours_acked: false, theirs_acked: false }
    }

    fn opened(&self) -> bool {
        self.ours_acked && self.theirs_acked
    }

    fn request(&mut self) -> Vec<u8> {
        self.id = self.id.wrapping_add(1);
        self.ours_acked = false;
        packet(self.proto, CONF_REQ, self.id, &encode_opts(&self.opts))
    }

    fn opt(&self, kind: u8) -> Option<Ipv4Addr> {
        ipv4_opt(&self.opts, kind)
    }

    /// Trata Configure-Request/Ack/Nak/Reject. Devolve as opções do pedido do outro
    /// lado quando ele é aceito.
    fn configure(&mut self, code: u8, id: u8, data: &[u8], accepts: fn(u8) -> bool, out: &mut Vec<Action>) -> Option<Opts> {
        let opts = parse_opts(data)?;
        match code {
            CONF_REQ => {
                let rejected: Opts = opts.iter().filter(|(t, _)| !accepts(*t)).cloned().collect();
                if !rejected.is_empty() {
                    out.push(Action::Send(packet(self.proto, CONF_REJ, id, &encode_opts(&rejected))));
                    return None;
                }
                self.theirs_acked = true;
                out.push(Action::Send(packet(self.proto, CONF_ACK, id, data)));
                return Some(opts);
            }
            CONF_ACK if id == self.id => self.ours_acked = true,
            CONF_NAK if id == self.id => {
                for (kind, value) in opts {
                    if let Some(o) = self.opts.iter_mut().find(|(t, _)| *t == kind) {
                        o.1 = value;
                    }
                }
                out.push(Action::Send(self.request()));
            }
            CONF_REJ if id == self.id => {
                self.opts.retain(|(t, _)| !opts.iter().any(|(r, _)| r == t));
                out.push(Action::Send(self.request()));
            }
            _ => {}
        }
        None
    }
}

struct Ppp {
    magic: [u8; 4],
    lcp: Cp,
    ipcp: Cp,
    ipcp_started: bool,
    peer: Option<Ipv4Addr>,
    /// Some até o IPCP abrir.
    up: Option<oneshot::Sender<Up>>,
    /// Echo-Requests sem nenhum LCP do gateway desde o último; qualquer LCP prova que ele responde.
    missed: u8,
    echo_id: u8,
}

impl Ppp {
    fn new(mtu: u16, up: oneshot::Sender<Up>) -> Self {
        let magic = (std::collections::hash_map::RandomState::new().build_hasher().finish() as u32 | 1).to_be_bytes();
        let lcp = Cp::new(LCP, vec![(LCP_MRU, mtu.to_be_bytes().to_vec()), (LCP_MAGIC, magic.to_vec())]);
        let ipcp = Cp::new(IPCP, vec![(IPCP_ADDRESS, vec![0; 4]), (IPCP_DNS1, vec![0; 4]), (IPCP_DNS2, vec![0; 4])]);
        Self { magic, lcp, ipcp, ipcp_started: false, peer: None, up: Some(up), missed: 0, echo_id: 0 }
    }

    fn handle(&mut self, payload: &[u8]) -> Vec<Action> {
        let mut out = Vec::new();
        // Sem ACFC negociado o quadro deveria trazer FF 03, mas aceitamos sem.
        let p = payload.strip_prefix(&[0xff, 0x03]).unwrap_or(payload);
        if p.len() < 2 {
            return out;
        }
        let (proto, body) = (u16::from_be_bytes([p[0], p[1]]), &p[2..]);
        match proto {
            IP if self.up.is_none() => out.push(Action::Deliver(body.to_vec())),
            LCP => {
                self.missed = 0;
                if let Some((code, id, data)) = parse_cp(body) {
                    self.lcp_packet(code, id, data, &mut out);
                }
            }
            IPCP => {
                if let Some((code, id, data)) = parse_cp(body) {
                    self.ipcp_packet(code, id, data, &mut out);
                }
            }
            // IPv6CP, CCP e afins: recusados para o gateway parar de insistir.
            _ if self.lcp.opened() => {
                let mut data = proto.to_be_bytes().to_vec();
                data.extend_from_slice(body);
                out.push(Action::Send(packet(LCP, PROTO_REJ, 0, &data)));
            }
            _ => {}
        }
        out
    }

    fn lcp_packet(&mut self, code: u8, id: u8, data: &[u8], out: &mut Vec<Action>) {
        match code {
            ECHO_REQ => {
                let mut reply = self.magic.to_vec();
                reply.extend_from_slice(data.get(4..).unwrap_or_default());
                out.push(Action::Send(packet(LCP, ECHO_REP, id, &reply)));
            }
            TERM_REQ => {
                out.push(Action::Send(packet(LCP, TERM_ACK, id, &[])));
                out.push(Action::Close("Gateway terminated the PPP session".into()));
            }
            _ => {
                self.lcp.configure(code, id, data, |t| matches!(t, LCP_MRU | LCP_ACCM | LCP_MAGIC), out);
                if self.lcp.opened() && !self.ipcp_started {
                    self.ipcp_started = true;
                    out.push(Action::Send(self.ipcp.request()));
                }
            }
        }
    }

    fn ipcp_packet(&mut self, code: u8, id: u8, data: &[u8], out: &mut Vec<Action>) {
        if let Some(opts) = self.ipcp.configure(code, id, data, |t| t == IPCP_ADDRESS, out) {
            self.peer = ipv4_opt(&opts, IPCP_ADDRESS);
        }
        if !self.ipcp.opened() || self.up.is_none() {
            return;
        }
        let ip = self.ipcp.opt(IPCP_ADDRESS).unwrap_or(Ipv4Addr::UNSPECIFIED);
        if ip.is_unspecified() {
            out.push(Action::Close("Gateway assigned no IP address".into()));
            return;
        }
        let dns_servers = [IPCP_DNS1, IPCP_DNS2].iter().filter_map(|&k| self.ipcp.opt(k)).filter(|a| !a.is_unspecified()).collect();
        let up = Up { ip, peer: self.peer.unwrap_or(ip), dns_servers };
        let _ = self.up.take().unwrap().send(up);
    }
}

/// Um quadro Fortinet com o PPP sem HDLC, com endereço e controle (FF 03).
fn frame(proto: u16, payload: &[u8]) -> Vec<u8> {
    let ppp_len = payload.len() + 4;
    let mut f = Vec::with_capacity(HEADER_LEN + ppp_len);
    f.extend_from_slice(&((HEADER_LEN + ppp_len) as u16).to_be_bytes());
    f.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
    f.extend_from_slice(&(ppp_len as u16).to_be_bytes());
    f.extend_from_slice(&[0xff, 0x03]);
    f.extend_from_slice(&proto.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn packet(proto: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut p = vec![code, id];
    p.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
    p.extend_from_slice(data);
    frame(proto, &p)
}

/// Tira o próximo quadro completo do buffer e devolve o PPP dele.
fn take_frame(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    // Recusa do túnel vem como resposta HTTP em vez de quadros.
    if buf.starts_with(b"HTTP/") {
        let line = String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == b'\r').unwrap_or(buf.len())]).to_string();
        return Err(format!("Gateway refused the tunnel: {}", line));
    }
    let word = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    let (total, magic, len) = (word(0), word(2), word(4));
    if magic != FRAME_MAGIC as usize || total != len + HEADER_LEN {
        return Err("Malformed tunnel frame".into());
    }
    if buf.len() < total {
        return Ok(None);
    }
    let payload = buf[HEADER_LEN..total].to_vec();
    buf.drain(..total);
    Ok(Some(payload))
}

/// Código, id e dados de um pacote LCP/IPCP.
fn parse_cp(body: &[u8]) -> Option<(u8, u8, &[u8])> {
    let len = u16::from_be_bytes([*body.get(2)?, *body.get(3)?]) as usize;
    Some((body[0], body[1], body.get(4..len)?))
}

fn parse_opts(mut data: &[u8]) -> Option<Opts> {
    let mut opts = Vec::new();
    while !data.is_empty() {
        let len = *data.get(1)? as usize;
        if len < 2 {
            return None;
        }
        opts.push((data[0], data.get(2..len)?.to_vec()));
        data = &data[len..];
    }
    Some(opts)
}

/// Valor IPv4 de uma opção, se ela existir e tiver 4 bytes.
fn ipv4_opt(opts: &Opts, kind: u8) -> Option<Ipv4Addr> {
    let (_, v) = opts.iter().find(|(t, _)| *t == kind)?;
    <[u8; 4]>::try_from(v.as_slice()).ok().map(Ipv4Addr::from)
}

fn encode_opts(opts: &Opts) -> Vec<u8> {
    opts.iter().flat_map(|(t, v)| [*t, (v.len() + 2) as u8].into_iter().chain(v.iter().copied())).collect()
}
