use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use crate::protocol::{Request, Response};
use crate::validation;

fn stdin_handles() -> &'static Mutex<HashMap<u32, ChildStdin>> {
    static HANDLES: OnceLock<Mutex<HashMap<u32, ChildStdin>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn handle(request: Request) -> Response {
    match request {
        Request::Ping => handle_ping(),
        Request::SpawnVpn {
            args,
            log_path,
            vpn_server,
        } => handle_spawn_vpn(args, log_path, vpn_server),
        Request::KillVpn {
            pid,
            gateway,
            vpn_server,
        } => handle_kill_vpn(pid, gateway, vpn_server),
        Request::SetupDns { servers, suffixes } => handle_setup_dns(servers, suffixes),
        Request::TeardownDns => handle_teardown_dns(),
        Request::WriteStdin { pid, data } => handle_write_stdin(pid, data),
    }
}

fn handle_ping() -> Response {
    Response::with_version(env!("CARGO_PKG_VERSION").to_string())
}

fn handle_spawn_vpn(args: Vec<String>, log_path: String, vpn_server: Option<String>) -> Response {
    // Validate args
    if let Err(e) = validation::validate_vpn_args(&args) {
        return Response::error(e);
    }

    // Validate log path
    if !validation::is_valid_log_path(&log_path) {
        return Response::error(format!("Invalid log path: {}", log_path));
    }

    // Validate VPN server IP if provided
    if let Some(ref s) = vpn_server {
        if !validation::is_valid_ipv4(s) {
            return Response::error(format!("Invalid VPN server: {}", s));
        }
    }

    // Pre-connect orphan sweep: a previous session that died during sleep can
    // leave a zombie pppd, a downed ppp interface and (most importantly) a
    // stale /32 host route to the server pointing at an old gateway. That route
    // makes the new connection fail instantly with "Can't assign requested
    // address". Clear it here (without touching the default route; the OS
    // reconverges that once the dead ppp interface is gone).
    cleanup_network(None, vpn_server.as_deref());

    // Open log file for appending
    let log_file = match OpenOptions::new().create(true).append(true).open(&log_path) {
        Ok(f) => f,
        Err(e) => return Response::error(format!("Failed to open log file: {}", e)),
    };

    let log_file_stderr = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => return Response::error(format!("Failed to clone log file handle: {}", e)),
    };

    // Spawn openfortivpn with a piped stdin so the app can submit OTP / 2FA codes.
    match Command::new(validation::OPENFORTIVPN_PATH)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(log_file)
        .stderr(log_file_stderr)
        .spawn()
    {
        Ok(mut child) => {
            let pid = child.id();
            if let Some(stdin) = child.stdin.take() {
                if let Ok(mut map) = stdin_handles().lock() {
                    map.insert(pid, stdin);
                }
            }
            // Reap the child when it exits and drop its stdin handle.
            std::thread::spawn(move || {
                let _ = child.wait();
                if let Ok(mut map) = stdin_handles().lock() {
                    map.remove(&pid);
                }
                log::info!("openfortivpn PID {} exited", pid);
            });
            log::info!("Spawned openfortivpn with PID {}", pid);
            Response::with_pid(pid)
        }
        Err(e) => Response::error(format!("Failed to spawn openfortivpn: {}", e)),
    }
}

fn handle_write_stdin(pid: u32, data: String) -> Response {
    if !validation::is_openfortivpn_pid(pid) {
        return Response::error(format!(
            "PID {} is not an openfortivpn process",
            pid
        ));
    }

    // OTP / token codes are short; reject oversized payloads.
    if data.len() > 128 {
        return Response::error("Stdin payload too large".to_string());
    }

    // Reject control characters other than newline/tab (defense in depth).
    if data
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Response::error("Stdin payload contains invalid characters".to_string());
    }

    let mut map = match stdin_handles().lock() {
        Ok(m) => m,
        Err(e) => return Response::error(format!("Failed to lock stdin handles: {}", e)),
    };

    let stdin = match map.get_mut(&pid) {
        Some(s) => s,
        None => {
            return Response::error(format!(
                "No stdin handle for PID {} (process may have exited)",
                pid
            ))
        }
    };

    let mut payload = data;
    if !payload.ends_with('\n') {
        payload.push('\n');
    }

    match stdin.write_all(payload.as_bytes()).and_then(|_| stdin.flush()) {
        Ok(()) => {
            log::info!("Wrote {} bytes to openfortivpn PID {} stdin", payload.len(), pid);
            Response::success()
        }
        Err(e) => Response::error(format!("Failed to write to stdin: {}", e)),
    }
}

fn handle_kill_vpn(pid: u32, gateway: Option<String>, vpn_server: Option<String>) -> Response {
    // Validate gateway if provided
    if let Some(ref gw) = gateway {
        if !validation::is_valid_gateway(gw) {
            return Response::error(format!("Invalid gateway: {}", gw));
        }
    }

    // Validate VPN server IP if provided
    if let Some(ref s) = vpn_server {
        if !validation::is_valid_ipv4(s) {
            return Response::error(format!("Invalid VPN server: {}", s));
        }
    }

    // Validate that the PID is actually openfortivpn
    if !validation::is_openfortivpn_pid(pid) {
        return Response::error(format!(
            "PID {} is not an openfortivpn process",
            pid
        ));
    }

    log::info!("Killing openfortivpn PID {}", pid);

    // Drop stdin handle early so the process is not blocked on a closed reader later.
    if let Ok(mut map) = stdin_handles().lock() {
        map.remove(&pid);
    }

    // 1. SIGINT for clean shutdown
    let _ = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .output();

    // 2. Wait, then SIGKILL if still alive
    std::thread::sleep(std::time::Duration::from_secs(2));
    let still_alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if still_alive {
        let _ = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();
    }

    // 3. Full network cleanup (pppd, ppp interfaces, host route, default, DNS)
    cleanup_network(gateway.as_deref(), vpn_server.as_deref());

    log::info!("VPN cleanup complete for PID {}", pid);
    Response::success()
}

/// Tear down leftover VPN networking state. Shared by the disconnect path and
/// the pre-connect orphan sweep.
///
/// - Kills any `pppd`: SIGTERM first for a clean exit, then SIGKILL. A `pppd`
///   whose peer vanished during sleep ignores SIGTERM and only dies on SIGKILL.
/// - Brings down ppp interfaces.
/// - Removes the `/32` host route to the VPN server (`vpn_server`), which
///   otherwise survives a network change and breaks reconnection.
/// - Restores the original default route when `gateway` is given (disconnect);
///   skipped on the pre-connect sweep, where the OS reconverges the default.
/// - Removes the VPN DNS config and flushes the resolver cache.
fn cleanup_network(gateway: Option<&str>, vpn_server: Option<&str>) {
    // Kill pppd: escalate to SIGKILL for ones that ignore SIGTERM.
    let _ = Command::new("killall").args(["pppd"]).output();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let _ = Command::new("killall").args(["-KILL", "pppd"]).output();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Bring down ppp interfaces
    for iface in ["ppp0", "ppp1", "ppp2"] {
        let _ = Command::new("ifconfig").args([iface, "down"]).output();
    }

    // Remove the stale /32 host route to the VPN server
    if let Some(server) = vpn_server {
        let _ = Command::new("/sbin/route").args(["delete", server]).output();
    }

    // Restore original default route
    if let Some(gw) = gateway {
        let _ = Command::new("/sbin/route").args(["delete", "default"]).output();
        let _ = Command::new("/sbin/route").args(["add", "default", gw]).output();
    }

    // Remove VPN DNS config
    let _ = Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(b"remove State:/Network/Service/OpenFortiVPN/DNS\nquit\n")?;
            }
            child.wait()
        });

    // Flush DNS cache
    let _ = Command::new("/usr/bin/dscacheutil")
        .args(["-flushcache"])
        .output();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .output();
}

fn handle_setup_dns(servers: Vec<String>, suffixes: Vec<String>) -> Response {
    // Validate servers
    if servers.is_empty() {
        return Response::error("No DNS servers provided".to_string());
    }
    for server in &servers {
        if !validation::is_valid_ipv4(server) {
            return Response::error(format!("Invalid DNS server IP: {}", server));
        }
    }

    // Validate each suffix individually (rejecting e.g. strings containing ';')
    for s in &suffixes {
        if !validation::is_valid_hostname(s) {
            return Response::error(format!("Invalid DNS suffix: {}", s));
        }
    }

    let servers_str = servers.join(" ");

    let scutil_input = if suffixes.is_empty() {
        format!(
            "d.init\n\
             d.add ServerAddresses * {servers}\n\
             d.add SupplementalMatchDomains * \"\"\n\
             set State:/Network/Service/OpenFortiVPN/DNS\n\
             quit\n",
            servers = servers_str,
        )
    } else {
        let domains = suffixes.join(" ");
        format!(
            "d.init\n\
             d.add ServerAddresses * {servers}\n\
             d.add SupplementalMatchDomains * {domains}\n\
             d.add SearchDomains * {domains}\n\
             set State:/Network/Service/OpenFortiVPN/DNS\n\
             quit\n",
            servers = servers_str,
            domains = domains,
        )
    };

    log::info!(
        "Setting up DNS with servers: {} suffixes: {:?}",
        servers_str,
        suffixes
    );

    let result = Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(scutil_input.as_bytes())?;
                // stdin is dropped here, closing the pipe so scutil processes input
            }
            child.wait()
        });

    match result {
        Ok(status) if status.success() => {
            log::info!("DNS configured successfully");
            Response::success()
        }
        Ok(status) => Response::error(format!("scutil exited with status: {}", status)),
        Err(e) => Response::error(format!("Failed to run scutil: {}", e)),
    }
}

fn handle_teardown_dns() -> Response {
    log::info!("Tearing down DNS configuration");

    let result = Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(b"remove State:/Network/Service/OpenFortiVPN/DNS\nquit\n")?;
            }
            child.wait()
        });

    match result {
        Ok(_) => {
            log::info!("DNS configuration removed");
            Response::success()
        }
        Err(e) => Response::error(format!("Failed to teardown DNS: {}", e)),
    }
}
