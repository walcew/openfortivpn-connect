//! Observa trocas de rede e o wake do sleep e avisa quem chamou. Sem runloop de app no daemon:
//! a troca de rota default vem do route socket (`PF_ROUTE`) lido pelo tokio, e o wake vem do
//! relógio monotônico, que no macOS não anda durante o sleep, ficando atrás do relógio de parede.

use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::{Duration, Instant, SystemTime};

use tokio::io::unix::AsyncFd;

/// De quanto em quanto o relógio é conferido; o wake é notado até esse tempo depois.
const WAKE_CHECK: Duration = Duration::from_secs(5);

/// Avisa `changed` a cada troca de rota default IPv4 e a cada wake. Avisos chegam em rajada:
/// quem recebe agrupa.
pub async fn run(changed: impl Fn()) {
    let routes = async {
        match open_route_socket() {
            Ok(fd) => watch_routes(fd, &changed).await,
            Err(e) => log::error!("network change watch disabled: {}", e),
        }
        std::future::pending::<()>().await
    };
    tokio::join!(routes, watch_wakes(&changed));
}

async fn watch_routes(fd: AsyncFd<File>, changed: &impl Fn()) {
    let mut buf = vec![0u8; 2048];
    loop {
        match fd.async_io(tokio::io::Interest::READABLE, |mut f| f.read(&mut buf)).await {
            Ok(n) if is_default_route_change(&buf[..n]) => changed(),
            Ok(_) => {}
            Err(e) => return log::error!("route socket read: {}", e),
        }
    }
}

async fn watch_wakes(changed: &impl Fn()) {
    let (mut mono, mut wall) = (Instant::now(), SystemTime::now());
    loop {
        tokio::time::sleep(WAKE_CHECK).await;
        let (m, w) = (Instant::now(), SystemTime::now());
        let slept = w.duration_since(wall).unwrap_or_default().saturating_sub(m - mono);
        if slept > WAKE_CHECK {
            log::info!("woke up after about {} s asleep", slept.as_secs());
            changed();
        }
        (mono, wall) = (m, w);
    }
}

fn open_route_socket() -> Result<AsyncFd<File>, String> {
    let err = |what: &str| format!("route socket {}: {}", what, std::io::Error::last_os_error());
    // SAFETY: chamadas libc sem ponteiros; o fd é possuído pelo OwnedFd.
    unsafe {
        let raw = libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET);
        if raw < 0 {
            return Err(err("socket"));
        }
        let fd = OwnedFd::from_raw_fd(raw);
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) < 0
            || flags < 0
            || libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
        {
            return Err(err("fcntl"));
        }
        AsyncFd::new(File::from(fd)).map_err(|e| format!("route socket AsyncFd: {}", e))
    }
}

/// Se a mensagem do route socket adiciona, remove ou muda uma rota default IPv4 (destino 0.0.0.0,
/// máscara zero). As nossas rotas ficam de fora: o /32 é de host e as metades do full tunnel têm
/// máscara 128.0.0.0.
fn is_default_route_change(msg: &[u8]) -> bool {
    let header = std::mem::size_of::<libc::rt_msghdr>();
    if msg.len() < header || msg[2] != libc::RTM_VERSION as u8 {
        return false;
    }
    let int = |at: usize| i32::from_ne_bytes(msg[at..at + 4].try_into().unwrap());
    // rt_msghdr: rtm_type no byte 3, rtm_flags no 8, rtm_addrs no 12.
    let (kind, flags, addrs) = (msg[3] as i32, int(8), int(12));
    if ![libc::RTM_ADD, libc::RTM_DELETE, libc::RTM_CHANGE].contains(&kind)
        || flags & libc::RTF_HOST != 0
        || addrs & libc::RTA_DST == 0
    {
        return false;
    }
    let mut dst = None;
    let mut mask = None;
    let mut rest = &msg[header..];
    // Os sockaddr seguem na ordem dos bits de rtm_addrs, cada um alinhado a 4 bytes.
    for bit in 0..8 {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let Some(&len) = rest.first() else { return false };
        let size = if len == 0 { 4 } else { (len as usize + 3) & !3 };
        let Some(sa) = rest.get(..(len as usize).max(1)) else { return false };
        match 1 << bit {
            libc::RTA_DST => dst = Some(sa),
            libc::RTA_NETMASK => mask = Some(sa),
            _ => {}
        }
        rest = rest.get(size..).unwrap_or_default();
    }
    // sockaddr_in: sa_len, sa_family, porta (2), endereço (4). A máscara vem aparada no último
    // byte não nulo, ou com sa_len 0 para a default.
    let addr_is_zero = |sa: &[u8]| sa.get(4..).unwrap_or_default().iter().all(|b| *b == 0);
    matches!(dst, Some(d) if d.len() >= 8 && d[1] == libc::AF_INET as u8 && addr_is_zero(d))
        && mask.is_none_or(addr_is_zero)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mensagem de rota com os sockaddr dados (já no tamanho da mensagem, alinhados).
    fn message(kind: i32, flags: i32, addrs: i32, sockaddrs: &[&[u8]]) -> Vec<u8> {
        let mut msg = vec![0u8; std::mem::size_of::<libc::rt_msghdr>()];
        msg[2] = libc::RTM_VERSION as u8;
        msg[3] = kind as u8;
        msg[8..12].copy_from_slice(&flags.to_ne_bytes());
        msg[12..16].copy_from_slice(&addrs.to_ne_bytes());
        for sa in sockaddrs {
            msg.extend_from_slice(sa);
        }
        msg
    }

    fn sockaddr_in(addr: [u8; 4]) -> Vec<u8> {
        let mut sa = vec![16, libc::AF_INET as u8, 0, 0];
        sa.extend_from_slice(&addr);
        sa.extend_from_slice(&[0; 8]);
        sa
    }

    const DST_GW_MASK: i32 = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;

    #[test]
    fn default_route_added_or_deleted_is_a_change() {
        let gw = sockaddr_in([192, 168, 1, 1]);
        // Máscara da default como o kernel manda: sa_len 0, ocupando 4 bytes.
        let empty_mask = [0u8, 0, 0, 0];
        for kind in [libc::RTM_ADD, libc::RTM_DELETE, libc::RTM_CHANGE] {
            let msg = message(kind, libc::RTF_GATEWAY | libc::RTF_STATIC, DST_GW_MASK, &[&sockaddr_in([0; 4]), &gw, &empty_mask]);
            assert!(is_default_route_change(&msg));
        }
        let no_mask = message(libc::RTM_ADD, libc::RTF_GATEWAY, libc::RTA_DST | libc::RTA_GATEWAY, &[&sockaddr_in([0; 4]), &gw]);
        assert!(is_default_route_change(&no_mask));
    }

    #[test]
    fn our_own_routes_are_not_a_change() {
        let iface = [20u8, libc::AF_LINK as u8, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // Metade 0.0.0.0/1 do full tunnel: máscara aparada em 128.
        let half = [5u8, 0, 0, 0, 128, 0, 0, 0];
        let msg = message(libc::RTM_ADD, libc::RTF_STATIC, DST_GW_MASK, &[&sockaddr_in([0; 4]), &iface, &half]);
        assert!(!is_default_route_change(&msg));
        // /32 do gateway.
        let host = message(libc::RTM_ADD, libc::RTF_HOST | libc::RTF_GATEWAY, libc::RTA_DST | libc::RTA_GATEWAY, &[&sockaddr_in([203, 0, 113, 5]), &sockaddr_in([192, 168, 1, 1])]);
        assert!(!is_default_route_change(&host));
    }

    #[test]
    fn other_messages_are_ignored() {
        let default = [&sockaddr_in([0; 4])[..]];
        assert!(!is_default_route_change(&message(libc::RTM_GET, 0, libc::RTA_DST, &default)));
        assert!(!is_default_route_change(&message(libc::RTM_ADD, 0, libc::RTA_DST, &[&sockaddr_in([10, 0, 0, 0])])));
        let mut old_version = message(libc::RTM_ADD, 0, libc::RTA_DST, &default);
        old_version[2] = 4;
        assert!(!is_default_route_change(&old_version));
        // Truncada: sem o sockaddr anunciado, ou menor que o cabeçalho.
        assert!(!is_default_route_change(&message(libc::RTM_ADD, 0, libc::RTA_DST, &[])));
        assert!(!is_default_route_change(&[0; 8]));
    }
}
