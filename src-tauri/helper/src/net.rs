//! Camada de rede, independente de protocolo: recebe do Engine a config do túnel e o
//! canal de pacotes IP e os entrega ao sistema (interface, rotas, /32 do gateway, DNS).

use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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
    /// /32 do gateway pelo default atual; devolve o next-hop usado.
    fn add_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String>;
    /// Leva o /32 do gateway para o default atual sem removê-lo antes (o tráfego do gateway nunca
    /// cai no túnel); cria se ele não existir. Devolve o next-hop usado.
    fn move_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String>;
    fn set_dns(&self, servers: &[Ipv4Addr], suffixes: &[String]) -> Result<(), String>;
    fn remove_dns(&self);
    /// Remove o /32 só se ele ainda sai por `via`: outro software pode ter um /32 do mesmo IP.
    fn remove_gateway_route(&self, gateway: IpAddr, via: IpAddr);
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
    /// Next-hop do /32; ausente em arquivos de estado antigos.
    #[serde(default)]
    gateway_via: Option<IpAddr>,
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
        private_dir(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    // Um temporário que já existia mantém o modo antigo.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
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

/// Cria o diretório 0700, ou o corrige se já existe com outro modo. Recusa diretório de outro dono
/// ou que não é diretório (symlink incluído): o arquivo guarda o que o root vai remover no boot.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    // SAFETY: geteuid não falha nem toca memória.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::other(format!("{} is not a directory owned by this user", dir.display())));
    }
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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
    let via = os.add_gateway_route(config.gateway)?;
    record(os, applied, |a| (a.gateway_route, a.gateway_via) = (Some(config.gateway), Some(via)));
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
    match (applied.gateway_route, applied.gateway_via) {
        (Some(gateway), Some(via)) => os.remove_gateway_route(gateway, via),
        (Some(gateway), None) => log::warn!("host route to {} left in place: its next hop was not recorded", gateway),
        _ => {}
    }
    remove_state(&os.state_file());
}

/// Há /32 do gateway aplicado, logo uma troca de rede precisa refazê-lo.
pub fn has_gateway_route(applied: &Mutex<Applied>) -> bool {
    applied.lock().unwrap().gateway_route.is_some()
}

/// Depois de uma troca de rede: leva o /32 do `gateway` da sessão para o default atual. Se falhar
/// (na troca de Wi-Fi a default some antes da nova chegar), o registro fica como estava e o próximo
/// evento tenta de novo; até lá a detecção de túnel morto decide.
// shortcut: só IPv4, como o resto da camada de rede; evoluir junto com o suporte a gateway IPv6.
pub fn rehome_gateway_route(os: &dyn Os, gateway: IpAddr, applied: &Mutex<Applied>) -> Result<(), String> {
    let via = os.move_gateway_route(gateway)?;
    record(os, applied, |a| (a.gateway_route, a.gateway_via) = (Some(gateway), Some(via)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ovg-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn state_dir_and_file_are_private() {
        let dir = temp_dir("state-dir");
        let file = dir.join("session-state.json");
        save_state(&file, &Applied::default()).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn existing_state_dir_with_a_loose_mode_is_tightened() {
        let dir = temp_dir("loose-dir");
        fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
        save_state(&dir.join("session-state.json"), &Applied::default()).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_dir_that_is_a_symlink_is_refused() {
        let target = temp_dir("link-target");
        let link = temp_dir("link");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = save_state(&link.join("session-state.json"), &Applied::default()).unwrap_err();
        assert!(err.to_string().contains("not a directory owned by this user"), "{}", err);
        fs::remove_file(&link).unwrap();
        fs::remove_dir_all(&target).unwrap();
    }
}
