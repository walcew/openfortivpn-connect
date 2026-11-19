//! Camada de rede, independente de protocolo: recebe do Engine a config do túnel e o
//! canal de pacotes IP e os entrega ao sistema (interface, rotas, /32 do gateway, DNS).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use tokio::sync::mpsc;

pub mod system;

pub use system::SystemOs;

/// Rede IPv4 por endereço e máscara, como o gateway as envia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
}

/// O que o Engine negociou e a camada de rede precisa aplicar.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelConfig {
    /// Endereço do gateway, que ganha um /32 pela interface física.
    pub gateway: IpAddr,
    pub ip: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_suffixes: Vec<String>,
    /// Vazio quando `full_tunnel`.
    pub routes: Vec<Route>,
    pub full_tunnel: bool,
    pub mtu: u16,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Canal de pacotes IP visto do lado da interface: `tx` manda para o gateway e `rx`
/// entrega o que chegou dele.
#[derive(Debug)]
pub struct Packets {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
}

/// Operações de SO que a camada de rede usa. A implementação real (utun, `route`,
/// scutil) é o `SystemOs`; os testes usam um fake que registra as chamadas.
/// As remoções não falham: o teardown sempre tenta tudo.
pub trait Os: Send + Sync {
    /// Cria a interface do túnel e assume o canal de pacotes. Rotas dela somem com ela.
    /// Em erro, não deixa interface para trás.
    fn up(&self, ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16, packets: Packets) -> Result<(), String>;
    /// Rota pela interface do túnel.
    fn add_route(&self, route: Route) -> Result<(), String>;
    /// /32 do gateway pela interface física e o default atual.
    fn add_gateway_route(&self, gateway: IpAddr) -> Result<(), String>;
    fn set_dns(&self, servers: &[Ipv4Addr], suffixes: &[String]) -> Result<(), String>;
    fn remove_dns(&self);
    fn remove_gateway_route(&self, gateway: IpAddr);
    fn down(&self);
}

/// Full tunnel em duas metades, para nunca trocar a rota default.
const FULL_TUNNEL: [Route; 2] = [
    Route { addr: Ipv4Addr::new(0, 0, 0, 0), mask: Ipv4Addr::new(128, 0, 0, 0) },
    Route { addr: Ipv4Addr::new(128, 0, 0, 0), mask: Ipv4Addr::new(128, 0, 0, 0) },
];

/// O que já entrou no SO, para o teardown desfazer só isso.
#[derive(Debug, Default)]
pub struct Applied {
    gateway_route: Option<IpAddr>,
    interface: bool,
    dns: bool,
}

/// Aplica a config, marcando em `applied` cada passo que deu certo. Em erro (ou pânico),
/// o chamador faz `teardown` para desfazer o que entrou.
pub fn apply(os: &dyn Os, config: &TunnelConfig, packets: Packets, applied: &Mutex<Applied>) -> Result<(), String> {
    // O /32 entra antes das rotas do túnel para o gateway nunca ser roteado por dentro dele.
    os.add_gateway_route(config.gateway)?;
    applied.lock().unwrap().gateway_route = Some(config.gateway);
    os.up(config.ip, config.peer, config.mtu, packets)?;
    applied.lock().unwrap().interface = true;
    for route in tunnel_routes(config) {
        os.add_route(route)?;
    }
    if !config.dns_servers.is_empty() {
        os.set_dns(&config.dns_servers, &config.dns_suffixes)?;
        applied.lock().unwrap().dns = true;
    }
    Ok(())
}

/// Rotas pelo túnel. Uma default (máscara 0) vinda do gateway vira as duas metades,
/// como no full tunnel: a rota default do sistema nunca é tocada.
fn tunnel_routes(config: &TunnelConfig) -> Vec<Route> {
    if config.full_tunnel {
        return FULL_TUNNEL.to_vec();
    }
    config
        .routes
        .iter()
        .flat_map(|r| if r.mask.is_unspecified() { FULL_TUNNEL.to_vec() } else { vec![*r] })
        .collect()
}

pub fn teardown(os: &dyn Os, applied: &Mutex<Applied>) {
    let applied = std::mem::take(&mut *applied.lock().unwrap());
    if applied.dns {
        os.remove_dns();
    }
    if applied.interface {
        os.down();
    }
    if let Some(gateway) = applied.gateway_route {
        os.remove_gateway_route(gateway);
    }
}
