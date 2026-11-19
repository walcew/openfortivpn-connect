//! Camada de SO real no macOS: utun pelo socket de controle do kernel, rotas com
//! `/sbin/route`, endereço com `/sbin/ifconfig` e DNS com scutil.

use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Mutex;

use tokio::io::unix::AsyncFd;
use tokio::task::{block_in_place, JoinHandle};

use super::{Os, Packets, Route};
use crate::validation;

const IFCONFIG: &str = "/sbin/ifconfig";
const ROUTE: &str = "/sbin/route";
const SCUTIL: &str = "/usr/sbin/scutil";
const DSCACHEUTIL: &str = "/usr/bin/dscacheutil";
const KILLALL: &str = "/usr/bin/killall";
/// No diretório de suporte de root, com o nome do Helper instalado pelo app.
const STATE_FILE: &str = "/Library/Application Support/com.openvpngui.helper/session-state.json";
const DNS_KEY: &str = "State:/Network/Service/OpenFortiVPN/DNS";
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
/// Cabeçalho do utun: a família do protocolo em ordem de rede.
const AF_INET_HEADER: [u8; 4] = (libc::AF_INET as u32).to_be_bytes();

/// Interface do túnel ativa: o nome e a task que liga o fd ao canal de pacotes.
struct Utun {
    name: String,
    bridge: JoinHandle<()>,
}

#[derive(Default)]
pub struct SystemOs {
    utun: Mutex<Option<Utun>>,
}

// Os comandos rodam em `block_in_place`: o trait é síncrono e é chamado de dentro da task
// da sessão, e assim um comando lento não prende a worker thread do runtime.
impl Os for SystemOs {
    fn up(&self, ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16, packets: Packets) -> Result<(), String> {
        let (fd, name) = open_utun()?;
        let fd = AsyncFd::new(File::from(fd)).map_err(|e| format!("utun AsyncFd: {}", e))?;
        // A task é dona do fd: abortá-la fecha o fd, e o kernel remove a interface e as rotas dela.
        let bridge = tokio::spawn(bridge_packets(fd, packets));
        *self.utun.lock().unwrap() = Some(Utun { name: name.clone(), bridge });
        log::info!("{} created", name);
        let configured = block_in_place(|| run(IFCONFIG, &ifconfig_args(&name, ip, peer, mtu)));
        if configured.is_err() {
            self.down();
        }
        configured
    }

    fn add_route(&self, route: Route) -> Result<(), String> {
        let name = match &*self.utun.lock().unwrap() {
            Some(u) => u.name.clone(),
            None => return Err("add_route: tunnel interface is not up".into()),
        };
        block_in_place(|| run(ROUTE, &route_args(&name, route)))
    }

    fn add_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String> {
        let gateway = ipv4(gateway)?;
        block_in_place(|| {
            let via = default_gateway()?;
            add_host_route(gateway, via).map(|()| IpAddr::V4(via))
        })
    }

    fn move_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String> {
        let gateway = ipv4(gateway)?;
        block_in_place(|| {
            let via = default_gateway()?;
            match run(ROUTE, &gateway_route_args("change", gateway, via)) {
                Err(e) if e.contains("not in table") => add_host_route(gateway, via),
                r => r,
            }
            .map(|()| IpAddr::V4(via))
        })
    }

    fn set_dns(&self, servers: &[Ipv4Addr], suffixes: &[String]) -> Result<(), String> {
        let servers: Vec<String> = servers.iter().map(Ipv4Addr::to_string).collect();
        block_in_place(|| {
            write_dns_config(&servers, suffixes)?;
            flush_dns_cache();
            Ok(())
        })
    }

    fn remove_dns(&self) {
        block_in_place(|| {
            match remove_dns_config() {
                Ok(status) if status.success() => {}
                Ok(status) => log::warn!("scutil exited with status: {}", status),
                Err(e) => log::warn!("{}", e),
            }
            flush_dns_cache();
        })
    }

    fn remove_gateway_route(&self, gateway: IpAddr, via: IpAddr) {
        let (Ok(gateway), Ok(via)) = (ipv4(gateway), ipv4(via)) else { return };
        let removed = block_in_place(|| {
            let out = output(ROUTE, &["-n", "get", &gateway.to_string()].map(String::from))?;
            if !is_host_route_via(&out, gateway, via) {
                return Err(format!("host route to {} via {} is gone or changed owner, left in place", gateway, via));
            }
            run(ROUTE, &gateway_route_args("delete", gateway, via))
        });
        if let Err(e) = removed {
            log::warn!("{}", e);
        }
    }

    fn state_file(&self) -> PathBuf {
        PathBuf::from(STATE_FILE)
    }

    fn down(&self) {
        if let Some(utun) = self.utun.lock().unwrap().take() {
            utun.bridge.abort();
            log::info!("{} closed", utun.name);
        }
    }
}

// shortcut: só IPv4 (rota e default via `route -n get default`), evoluir quando houver gateway IPv6.
fn ipv4(ip: IpAddr) -> Result<Ipv4Addr, String> {
    match ip {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(ip) => Err(format!("IPv6 VPN gateway not supported: {}", ip)),
    }
}

/// Cria um utun com o número escolhido pelo kernel e devolve o fd (não bloqueante) e o nome.
fn open_utun() -> Result<(OwnedFd, String), String> {
    let err = |what: &str| format!("utun {}: {}", what, std::io::Error::last_os_error());
    // SAFETY: chamadas libc com structs zeradas do tamanho certo; o fd é possuído pelo OwnedFd.
    unsafe {
        let raw = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if raw < 0 {
            return Err(err("socket"));
        }
        let fd = OwnedFd::from_raw_fd(raw);
        // O Helper roda comandos como root: o fd do túnel não vaza para eles.
        if libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            return Err(err("FD_CLOEXEC"));
        }

        let mut info: libc::ctl_info = std::mem::zeroed();
        for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.bytes()) {
            *dst = src as libc::c_char;
        }
        if libc::ioctl(raw, libc::CTLIOCGINFO, &mut info) < 0 {
            return Err(err("CTLIOCGINFO"));
        }

        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0, // 0: o kernel escolhe o próximo utunN livre
            sc_reserved: [0; 5],
        };
        let len = std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t;
        if libc::connect(raw, &addr as *const _ as *const libc::sockaddr, len) < 0 {
            return Err(err("connect"));
        }

        let mut name = [0u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        if libc::getsockopt(
            raw,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        ) < 0
        {
            return Err(err("UTUN_OPT_IFNAME"));
        }
        let name = CStr::from_bytes_until_nul(&name)
            .map_err(|_| "utun name is not NUL-terminated".to_string())?
            .to_string_lossy()
            .into_owned();

        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags < 0 || libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(err("O_NONBLOCK"));
        }
        Ok((fd, name))
    }
}

/// Liga o utun ao canal de pacotes até um dos lados fechar.
async fn bridge_packets(fd: AsyncFd<File>, mut packets: Packets) {
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = fd.async_io(tokio::io::Interest::READABLE, |mut f| f.read(&mut buf)) => match r {
                Ok(n) => {
                    if let Some(packet) = unframe(&buf[..n]) {
                        if packets.tx.send(packet.to_vec()).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("utun read: {}", e);
                    return;
                }
            },
            p = packets.rx.recv() => {
                let Some(packet) = p else { return };
                let frame = frame(&packet);
                if let Err(e) = fd.async_io(tokio::io::Interest::WRITABLE, |mut f| f.write(&frame)).await {
                    log::warn!("utun write: {}", e);
                    return;
                }
            }
        }
    }
}

/// Pacote IPv4 do túnel para o utun.
fn frame(packet: &[u8]) -> Vec<u8> {
    [&AF_INET_HEADER[..], packet].concat()
}

/// Pacote IPv4 lido do utun; outras famílias (IPv6) não vão para o túnel.
fn unframe(frame: &[u8]) -> Option<&[u8]> {
    match frame.split_at_checked(4) {
        Some((header, packet)) if header == AF_INET_HEADER && !packet.is_empty() => Some(packet),
        _ => None,
    }
}

// shortcut: recusa quando a default não tem gateway IP (só de interface, ou saindo por outra VPN);
// evoluir se aparecer caso real.
fn default_gateway() -> Result<Ipv4Addr, String> {
    let out = output(ROUTE, &["-n", "get", "default"].map(String::from))?;
    parse_default_gateway(&out).ok_or_else(|| "no IPv4 default gateway to reach the VPN gateway".into())
}

fn add_host_route(gateway: Ipv4Addr, via: Ipv4Addr) -> Result<(), String> {
    run(ROUTE, &gateway_route_args("add", gateway, via)).map_err(|e| {
        // Resíduo de uma sessão anterior é limpo pela recuperação de crash, não aqui:
        // apagar o /32 antes do add poderia tirar uma rota de outro software.
        if e.contains("File exists") {
            format!("a host route to the VPN gateway {} already exists: {}", gateway, e)
        } else {
            e
        }
    })
}

/// Se a saída de `route -n get <gateway>` é um /32 para ele saindo por `via`.
fn is_host_route_via(out: &str, gateway: Ipv4Addr, via: Ipv4Addr) -> bool {
    let field = |name: &str| out.lines().find_map(|l| l.trim().strip_prefix(name)).map(str::trim);
    field("destination:") == Some(&gateway.to_string()) && parse_default_gateway(out) == Some(via)
}

fn ifconfig_args(name: &str, ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16) -> Vec<String> {
    let mtu = mtu.to_string();
    [name, "inet", &ip.to_string(), &peer.to_string(), "mtu", &mtu, "up"].map(String::from).to_vec()
}

fn route_args(name: &str, route: Route) -> Vec<String> {
    let (addr, mask) = (route.addr.to_string(), route.mask.to_string());
    ["-n", "add", "-net", &addr, "-netmask", &mask, "-interface", name].map(String::from).to_vec()
}

/// Sempre com o next-hop: no `delete`, ele restringe a remoção ao /32 que sai por ele.
fn gateway_route_args(action: &str, gateway: Ipv4Addr, via: Ipv4Addr) -> Vec<String> {
    ["-n", action, "-host", &gateway.to_string(), &via.to_string()].map(String::from).to_vec()
}

/// Gateway IPv4 da saída de `route -n get default`; None se a default não tiver gateway IP.
fn parse_default_gateway(out: &str) -> Option<Ipv4Addr> {
    out.lines().find_map(|l| l.trim().strip_prefix("gateway:")).and_then(|g| g.trim().parse().ok())
}

/// Roda o comando e devolve o stdout, ou um erro com o stderr.
fn output(cmd: &str, args: &[String]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("{}: {}", cmd, e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{} {} failed: {}", cmd, args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run(cmd: &str, args: &[String]) -> Result<(), String> {
    output(cmd, args).map(|_| ())
}

/// Roda o scutil com a entrada dada; o erro é só de não conseguir rodá-lo.
fn scutil(input: &str) -> Result<ExitStatus, String> {
    Command::new(SCUTIL)
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            // O stdin é fechado ao sair do bloco para o scutil processar a entrada.
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(input.as_bytes())?;
            }
            child.wait()
        })
        .map_err(|e| format!("Failed to run scutil: {}", e))
}

/// Split DNS via scutil: os servidores respondem só pelos sufixos (ou por tudo, sem sufixos).
pub fn write_dns_config(servers: &[String], suffixes: &[String]) -> Result<(), String> {
    if servers.is_empty() {
        return Err("No DNS servers provided".to_string());
    }
    for server in servers {
        if !validation::is_valid_ipv4(server) {
            return Err(format!("Invalid DNS server IP: {}", server));
        }
    }
    // Cada sufixo vai cru para o scutil: rejeita o que não for hostname (ex.: com ';').
    for s in suffixes {
        if !validation::is_valid_hostname(s) {
            return Err(format!("Invalid DNS suffix: {}", s));
        }
    }
    log::info!("Setting up DNS with servers: {} suffixes: {:?}", servers.join(" "), suffixes);
    let status = scutil(&scutil_dns_input(servers, suffixes))?;
    if !status.success() {
        return Err(format!("scutil exited with status: {}", status));
    }
    Ok(())
}

/// Remove a chave de DNS; quem chama decide o que fazer com o status do scutil.
pub fn remove_dns_config() -> Result<ExitStatus, String> {
    log::info!("Tearing down DNS configuration");
    scutil(&format!("remove {}\nquit\n", DNS_KEY))
}

fn scutil_dns_input(servers: &[String], suffixes: &[String]) -> String {
    let servers = servers.join(" ");
    if suffixes.is_empty() {
        format!(
            "d.init\nd.add ServerAddresses * {servers}\nd.add SupplementalMatchDomains * \"\"\nset {DNS_KEY}\nquit\n"
        )
    } else {
        let domains = suffixes.join(" ");
        format!(
            "d.init\nd.add ServerAddresses * {servers}\nd.add SupplementalMatchDomains * {domains}\nd.add SearchDomains * {domains}\nset {DNS_KEY}\nquit\n"
        )
    }
}

pub fn flush_dns_cache() {
    let _ = Command::new(DSCACHEUTIL).arg("-flushcache").output();
    let _ = Command::new(KILLALL).args(["-HUP", "mDNSResponder"]).output();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn utun_frames_carry_af_inet_header() {
        let packet = [0x45, 0, 0, 20];
        let framed = frame(&packet);
        assert_eq!(framed, [0, 0, 0, 2, 0x45, 0, 0, 20]);
        assert_eq!(unframe(&framed), Some(&packet[..]));
    }

    #[test]
    fn unframe_drops_ipv6_and_short_frames() {
        assert_eq!(unframe(&[0, 0, 0, 30, 0x60, 0]), None);
        assert_eq!(unframe(&[0, 0, 0, 2]), None);
        assert_eq!(unframe(&[0, 0]), None);
    }

    #[test]
    fn ifconfig_sets_point_to_point_address_and_mtu() {
        let args = ifconfig_args("utun7", Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 1354);
        assert_eq!(args, strings(&["utun7", "inet", "10.0.0.2", "10.0.0.1", "mtu", "1354", "up"]));
    }

    #[test]
    fn tunnel_routes_go_through_the_interface() {
        let route = Route { addr: Ipv4Addr::new(128, 0, 0, 0), mask: Ipv4Addr::new(128, 0, 0, 0) };
        let args = route_args("utun7", route);
        assert_eq!(args, strings(&["-n", "add", "-net", "128.0.0.0", "-netmask", "128.0.0.0", "-interface", "utun7"]));
    }

    #[test]
    fn gateway_route_is_a_host_route_via_default_gateway() {
        let gw = Ipv4Addr::new(203, 0, 113, 5);
        let add = gateway_route_args("add", gw, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(add, strings(&["-n", "add", "-host", "203.0.113.5", "192.168.1.1"]));
        let via = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(gateway_route_args("change", gw, via), strings(&["-n", "change", "-host", "203.0.113.5", "10.0.0.1"]));
        assert_eq!(gateway_route_args("delete", gw, via), strings(&["-n", "delete", "-host", "203.0.113.5", "10.0.0.1"]));
    }

    #[test]
    fn recognizes_our_host_route_by_destination_and_next_hop() {
        let (gw, via) = (Ipv4Addr::new(203, 0, 113, 5), Ipv4Addr::new(192, 168, 1, 1));
        let host = "   route to: 203.0.113.5\ndestination: 203.0.113.5\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n";
        assert!(is_host_route_via(host, gw, via));
        // Outro next-hop: o /32 é de outro software ou já foi trocado.
        assert!(!is_host_route_via(host, gw, Ipv4Addr::new(10, 0, 0, 1)));
        // Sem /32, o `get` devolve a rota que cobre o IP (a metade do túnel ou a default).
        let half = "   route to: 203.0.113.5\ndestination: 0.0.0.0\n       mask: 128.0.0.0\n  interface: utun4\n";
        assert!(!is_host_route_via(half, gw, via));
        let default = "   route to: 203.0.113.5\ndestination: default\n    gateway: 192.168.1.1\n";
        assert!(!is_host_route_via(default, gw, via));
    }

    #[test]
    fn parses_default_gateway_from_route_get() {
        let out = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_default_gateway(out), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_default_gateway("   route to: default\n  interface: utun3\n"), None);
        assert_eq!(parse_default_gateway("    gateway: link#14\n"), None);
    }

    #[test]
    fn scutil_input_scopes_servers_to_suffixes() {
        let input = scutil_dns_input(&strings(&["10.0.0.53"]), &strings(&["corp.example.com"]));
        assert!(input.contains("d.add ServerAddresses * 10.0.0.53\n"));
        assert!(input.contains("d.add SupplementalMatchDomains * corp.example.com\n"));
        assert!(input.contains("set State:/Network/Service/OpenFortiVPN/DNS\n"));
    }

    #[test]
    fn scutil_input_without_suffixes_matches_every_domain() {
        let input = scutil_dns_input(&strings(&["10.0.0.53", "10.0.0.54"]), &[]);
        assert!(input.contains("d.add ServerAddresses * 10.0.0.53 10.0.0.54\n"));
        assert!(input.contains("d.add SupplementalMatchDomains * \"\"\n"));
        assert!(!input.contains("SearchDomains"));
    }

    #[test]
    fn dns_config_rejects_invalid_servers() {
        let err = write_dns_config(&strings(&["10.0.0.53; quit"]), &[]).unwrap_err();
        assert!(err.contains("Invalid DNS server IP"), "{}", err);
        assert!(write_dns_config(&[], &[]).unwrap_err().contains("No DNS servers"));
    }

    #[test]
    fn dns_config_rejects_unsafe_suffixes() {
        let err = write_dns_config(&strings(&["10.0.0.53"]), &strings(&["evil;quit"])).unwrap_err();
        assert!(err.contains("Invalid DNS suffix"));
    }
}
