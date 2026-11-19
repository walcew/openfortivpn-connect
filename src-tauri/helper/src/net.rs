//! Camada de rede, independente de protocolo: recebe do Engine a config do túnel e o
//! canal de pacotes IP e os entrega ao sistema (interface, rotas, /32 do gateway, DNS).

use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub mod system;
pub mod watch;

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
    /// Arquivo de estado da recuperação de crash: o que está aplicado no SO enquanto há sessão.
    fn state_file(&self) -> PathBuf;
}

/// Full tunnel em duas metades, para nunca trocar a rota default.
const FULL_TUNNEL: [Route; 2] = [
    Route { addr: Ipv4Addr::new(0, 0, 0, 0), mask: Ipv4Addr::new(128, 0, 0, 0) },
    Route { addr: Ipv4Addr::new(128, 0, 0, 0), mask: Ipv4Addr::new(128, 0, 0, 0) },
];

/// O que já entrou no SO, para o teardown desfazer só isso. O /32 e o DNS vão também para o
/// arquivo de estado; a interface não, porque o utun some com o processo.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Applied {
    gateway_route: Option<IpAddr>,
    #[serde(skip)]
    interface: bool,
    dns: bool,
}

/// Muda `applied` e grava o arquivo de estado. Falha ao gravar não derruba a sessão: só perde a
/// recuperação de crash, e o log diz isso.
fn record(os: &dyn Os, applied: &Mutex<Applied>, change: impl FnOnce(&mut Applied)) {
    let mut applied = applied.lock().unwrap();
    change(&mut applied);
    if let Err(e) = save_state(&os.state_file(), &applied) {
        log::warn!("crash recovery state not saved: {}", e);
    }
}

/// Grava de forma atômica (temporário + rename), só para root (0700 no diretório, 0600 no arquivo).
fn save_state(path: &Path, applied: &Applied) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    file.write_all(&serde_json::to_vec(applied)?)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

/// Ao iniciar o Helper: desfaz o que uma sessão anterior deixou no arquivo de estado (crash ou
/// `kill -9`) e apaga o arquivo. Sem arquivo, nada.
pub fn recover(os: &dyn Os) {
    let path = os.state_file();
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => return log::warn!("crash recovery state unreadable: {}: {}", path.display(), e),
    };
    match serde_json::from_slice::<Applied>(&data) {
        Ok(applied) => {
            log::info!("undoing leftovers of a previous session: {:?}", applied);
            teardown(os, &Mutex::new(applied));
        }
        Err(e) => {
            log::warn!("crash recovery state invalid, discarding: {}", e);
            remove_state(&path);
        }
    }
}

fn remove_state(path: &Path) {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("crash recovery state not removed: {}: {}", path.display(), e);
        }
    }
}

/// Aplica a config, marcando em `applied` cada passo que deu certo. Em erro (ou pânico),
/// o chamador faz `teardown` para desfazer o que entrou. A falha do DNS não é fatal, como no
/// v1: o túnel sobe sem DNS e `Ok(Some(aviso))` diz por quê.
pub fn apply(os: &dyn Os, config: &TunnelConfig, packets: Packets, applied: &Mutex<Applied>) -> Result<Option<String>, String> {
    // O /32 entra antes das rotas do túnel para o gateway nunca ser roteado por dentro dele.
    os.add_gateway_route(config.gateway)?;
    record(os, applied, |a| a.gateway_route = Some(config.gateway));
    os.up(config.ip, config.peer, config.mtu, packets)?;
    applied.lock().unwrap().interface = true;
    for route in tunnel_routes(config) {
        os.add_route(route)?;
    }
    if !config.dns_servers.is_empty() {
        match os.set_dns(&config.dns_servers, &config.dns_suffixes) {
            Ok(()) => record(os, applied, |a| a.dns = true),
            Err(e) => return Ok(Some(format!("DNS setup failed, tunnel stays up without DNS: {}", e))),
        }
    }
    Ok(None)
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
    remove_state(&os.state_file());
}

/// Depois de uma troca de rede: o /32 do gateway sai do default antigo e entra pelo atual. Se não
/// entrar (default sem gateway IP), fica sem /32 e a detecção de túnel morto decide.
pub fn rehome_gateway_route(os: &dyn Os, applied: &Mutex<Applied>) -> Result<(), String> {
    let Some(gateway) = applied.lock().unwrap().gateway_route else { return Ok(()) };
    os.remove_gateway_route(gateway);
    os.add_gateway_route(gateway).inspect_err(|_| record(os, applied, |a| a.gateway_route = None))
}
