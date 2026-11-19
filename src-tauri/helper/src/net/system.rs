//! Camada de SO real no macOS: utun pelo socket de controle do kernel, rotas com
//! `/sbin/route`, endereço com `/sbin/ifconfig` e DNS com scutil.

use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

use super::{Os, Packets, Route};
use crate::validation;

const IFCONFIG: &str = "/sbin/ifconfig";
const ROUTE: &str = "/sbin/route";
const SCUTIL: &str = "/usr/sbin/scutil";
const DNS_KEY: &str = "State:/Network/Service/OpenFortiVPN/DNS";
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
/// Cabeçalho do utun: a família do protocolo em ordem de rede.
const AF_INET_HEADER: [u8; 4] = (libc::AF_INET as u32).to_be_bytes();

/// Interface do túnel ativa: o nome e a task que liga o fd ao canal de pacotes.
struct Utun {
    name: String,
    pump: JoinHandle<()>,
}

#[derive(Default)]
pub struct SystemOs {
    utun: Mutex<Option<Utun>>,
}

impl Os for SystemOs {
    fn up(&self, ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16, packets: Packets) -> Result<(), String> {
        let (fd, name) = open_utun()?;
        let fd = AsyncFd::new(File::from(fd)).map_err(|e| format!("utun AsyncFd: {}", e))?;
        // A task é dona do fd: abortá-la fecha o fd, e o kernel remove a interface e as rotas dela.
        let pump = tokio::spawn(pump(fd, packets));
        *self.utun.lock().unwrap() = Some(Utun { name: name.clone(), pump });
        log::info!("{} created", name);
        run(IFCONFIG, &ifconfig_args(&name, ip, peer, mtu))
    }

    fn add_route(&self, route: Route) -> Result<(), String> {
        let name = match &*self.utun.lock().unwrap() {
            Some(u) => u.name.clone(),
            None => return Err("add_route: tunnel interface is not up".into()),
        };
        run(ROUTE, &route_args(&name, route))
    }

    fn add_gateway_route(&self, gateway: IpAddr) -> Result<(), String> {
        let gateway = ipv4(gateway)?;
        let out = output(ROUTE, &["-n", "get", "default"])?;
        let via = parse_default_gateway(&out).ok_or("no IPv4 default gateway to reach the VPN gateway")?;
        // Um /32 que sobrou de uma sessão anterior faria o add falhar com "File exists".
        let _ = output(ROUTE, &gateway_route_args("delete", gateway, None));
        run(ROUTE, &gateway_route_args("add", gateway, Some(via)))
    }

    fn set_dns(&self, servers: &[Ipv4Addr], suffixes: &[String]) -> Result<(), String> {
        let servers: Vec<String> = servers.iter().map(Ipv4Addr::to_string).collect();
        set_dns(&servers, suffixes)?;
        flush_dns_cache();
        Ok(())
    }

    fn remove_dns(&self) {
        if let Err(e) = remove_dns() {
            log::warn!("{}", e);
        }
        flush_dns_cache();
    }

    fn remove_gateway_route(&self, gateway: IpAddr) {
        if let Ok(gateway) = ipv4(gateway) {
            if let Err(e) = run(ROUTE, &gateway_route_args("delete", gateway, None)) {
                log::warn!("{}", e);
            }
        }
    }

    fn down(&self) {
        if let Some(utun) = self.utun.lock().unwrap().take() {
            utun.pump.abort();
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
async fn pump(fd: AsyncFd<File>, mut packets: Packets) {
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

fn ifconfig_args(name: &str, ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16) -> Vec<String> {
    let mtu = mtu.to_string();
    [name, "inet", &ip.to_string(), &peer.to_string(), "mtu", &mtu, "up"].map(String::from).to_vec()
}

fn route_args(name: &str, route: Route) -> Vec<String> {
    let (addr, mask) = (route.addr.to_string(), route.mask.to_string());
    ["-n", "add", "-net", &addr, "-netmask", &mask, "-interface", name].map(String::from).to_vec()
}

fn gateway_route_args(action: &str, gateway: Ipv4Addr, via: Option<Ipv4Addr>) -> Vec<String> {
    let mut args: Vec<String> = ["-n", action, "-host", &gateway.to_string()].map(String::from).to_vec();
    args.extend(via.map(|v| v.to_string()));
    args
}

/// Gateway IPv4 da saída de `route -n get default`; None se a default não tiver gateway IP.
fn parse_default_gateway(out: &str) -> Option<Ipv4Addr> {
    out.lines().find_map(|l| l.trim().strip_prefix("gateway:")).and_then(|g| g.trim().parse().ok())
}

/// Roda o comando e devolve o stdout, ou um erro com o stderr.
fn output<S: AsRef<std::ffi::OsStr>>(cmd: &str, args: &[S]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("{}: {}", cmd, e))?;
    if !out.status.success() {
        let args: Vec<_> = args.iter().map(|a| a.as_ref().to_string_lossy()).collect();
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{} {} failed: {}", cmd, args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run(cmd: &str, args: &[String]) -> Result<(), String> {
    output(cmd, args).map(|_| ())
}

fn scutil(input: &str) -> Result<(), String> {
    let status = Command::new(SCUTIL)
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            // O stdin é fechado ao sair do bloco para o scutil processar a entrada.
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(input.as_bytes())?;
            }
            child.wait()
        })
        .map_err(|e| format!("Failed to run scutil: {}", e))?;
    if !status.success() {
        return Err(format!("scutil exited with status: {}", status));
    }
    Ok(())
}

/// Split DNS via scutil: os servidores respondem só pelos sufixos (ou por tudo, sem sufixos).
pub fn set_dns(servers: &[String], suffixes: &[String]) -> Result<(), String> {
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
    scutil(&scutil_dns_input(servers, suffixes))
}

pub fn remove_dns() -> Result<(), String> {
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

fn flush_dns_cache() {
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").output();
    let _ = Command::new("/usr/bin/killall").args(["-HUP", "mDNSResponder"]).output();
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
        let add = gateway_route_args("add", gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(add, strings(&["-n", "add", "-host", "203.0.113.5", "192.168.1.1"]));
        assert_eq!(gateway_route_args("delete", gw, None), strings(&["-n", "delete", "-host", "203.0.113.5"]));
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
    fn set_dns_rejects_unsafe_suffixes() {
        let err = set_dns(&strings(&["10.0.0.53"]), &strings(&["evil;quit"])).unwrap_err();
        assert!(err.contains("Invalid DNS suffix"));
    }
}
