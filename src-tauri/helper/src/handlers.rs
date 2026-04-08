use std::fs::OpenOptions;
use std::process::Command;

use crate::protocol::{Request, Response};
use crate::validation;

pub fn handle(request: Request) -> Response {
    match request {
        Request::Ping => handle_ping(),
        Request::SpawnVpn { args, log_path } => handle_spawn_vpn(args, log_path),
        Request::KillVpn { pid, gateway } => handle_kill_vpn(pid, gateway),
        Request::SetupDns { servers, suffix } => handle_setup_dns(servers, suffix),
        Request::TeardownDns => handle_teardown_dns(),
    }
}

fn handle_ping() -> Response {
    Response::with_version(env!("CARGO_PKG_VERSION").to_string())
}

fn handle_spawn_vpn(args: Vec<String>, log_path: String) -> Response {
    // Validate args
    if let Err(e) = validation::validate_vpn_args(&args) {
        return Response::error(e);
    }

    // Validate log path
    if !validation::is_valid_log_path(&log_path) {
        return Response::error(format!("Invalid log path: {}", log_path));
    }

    // Open log file for appending
    let log_file = match OpenOptions::new().create(true).append(true).open(&log_path) {
        Ok(f) => f,
        Err(e) => return Response::error(format!("Failed to open log file: {}", e)),
    };

    let log_file_stderr = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => return Response::error(format!("Failed to clone log file handle: {}", e)),
    };

    // Spawn openfortivpn directly (no shell, no quoting needed)
    match Command::new(validation::OPENFORTIVPN_PATH)
        .args(&args)
        .stdout(log_file)
        .stderr(log_file_stderr)
        .spawn()
    {
        Ok(child) => {
            let pid = child.id();
            log::info!("Spawned openfortivpn with PID {}", pid);
            Response::with_pid(pid)
        }
        Err(e) => Response::error(format!("Failed to spawn openfortivpn: {}", e)),
    }
}

fn handle_kill_vpn(pid: u32, gateway: Option<String>) -> Response {
    // Validate gateway if provided
    if let Some(ref gw) = gateway {
        if !validation::is_valid_gateway(gw) {
            return Response::error(format!("Invalid gateway: {}", gw));
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

    // 3. Kill orphaned pppd
    let _ = Command::new("killall")
        .args(["pppd"])
        .output();

    std::thread::sleep(std::time::Duration::from_secs(1));

    // 4. Bring down ppp interfaces
    let _ = Command::new("ifconfig")
        .args(["ppp0", "down"])
        .output();
    let _ = Command::new("ifconfig")
        .args(["ppp1", "down"])
        .output();

    // 5. Restore original default route
    if let Some(ref gw) = gateway {
        let _ = Command::new("/sbin/route")
            .args(["delete", "default"])
            .output();
        let _ = Command::new("/sbin/route")
            .args(["add", "default", gw])
            .output();
    }

    // 6. Remove VPN DNS config
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

    // 7. Flush DNS cache
    let _ = Command::new("/usr/bin/dscacheutil")
        .args(["-flushcache"])
        .output();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .output();

    log::info!("VPN cleanup complete for PID {}", pid);
    Response::success()
}

fn handle_setup_dns(servers: Vec<String>, suffix: Option<String>) -> Response {
    // Validate servers
    if servers.is_empty() {
        return Response::error("No DNS servers provided".to_string());
    }
    for server in &servers {
        if !validation::is_valid_ipv4(server) {
            return Response::error(format!("Invalid DNS server IP: {}", server));
        }
    }

    // Validate suffix if provided
    if let Some(ref s) = suffix {
        if !validation::is_valid_hostname(s) {
            return Response::error(format!("Invalid DNS suffix: {}", s));
        }
    }

    let servers_str = servers.join(" ");

    let domain_line = if let Some(ref s) = suffix {
        format!("d.add DomainName {}\n", s)
    } else {
        String::new()
    };

    let scutil_input = format!(
        "d.init\n\
         d.add ServerAddresses * {servers}\n\
         {domain}\
         d.add SupplementalMatchDomains * \"\"\n\
         set State:/Network/Service/OpenFortiVPN/DNS\n\
         quit\n",
        servers = servers_str,
        domain = domain_line,
    );

    log::info!("Setting up DNS with servers: {}", servers_str);

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
