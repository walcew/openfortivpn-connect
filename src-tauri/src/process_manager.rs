use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use tauri::{AppHandle, Emitter};
use tauri::async_runtime::JoinHandle;

use crate::dns_manager::{self, DnsInfo};
use crate::helper_client;
use crate::models::{
    BandwidthPayload, ConnectionState, ConnectionStatusPayload, LogLinePayload, TwoFactorType,
};

pub struct ProcessManager {
    pid: Option<u32>,
    log_file_path: Option<PathBuf>,
    stop_flag: Arc<AtomicBool>,
    monitor_handle: Option<JoinHandle<()>>,
    /// Original default gateway saved before connecting, to restore on disconnect
    original_gateway: Option<String>,
    /// Resolved IP of the VPN server, used to clear its stale host route on cleanup
    vpn_server_ip: Option<String>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            pid: None,
            log_file_path: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            monitor_handle: None,
            original_gateway: None,
            vpn_server_ip: None,
        }
    }

    pub fn spawn_vpn(
        &mut self,
        args: Vec<String>,
        profile_id: String,
        app_handle: AppHandle,
        debug_mode: bool,
        dns_fallback: bool,
        two_factor: Option<TwoFactorType>,
        auto_reconnect: bool,
    ) -> Result<(), String> {
        // Resolve the VPN server IP from "host:port" (args[0]) so the helper can
        // clear any stale host route to it left by a previous session.
        self.vpn_server_ip = args.first().and_then(|hp| resolve_server_ip(hp));
        log::info!("Resolved VPN server IP: {:?}", self.vpn_server_ip);

        // Capture the current default gateway before connecting
        self.original_gateway = get_default_gateway();
        log::info!(
            "Saved original default gateway: {:?}",
            self.original_gateway
        );

        // Capture current system DNS servers before VPN modifies them
        let fallback_dns = if dns_fallback {
            let servers = dns_manager::get_current_dns_servers();
            log::info!("Captured fallback DNS servers: {:?}", servers);
            servers
        } else {
            Vec::new()
        };

        let log_id = uuid::Uuid::new_v4();
        let log_path = PathBuf::from(format!(
            "{}{}.log",
            openvpngui_common::VPN_LOG_PREFIX,
            log_id
        ));

        // Create the log file so the monitor can start reading
        File::create(&log_path)
            .map_err(|e| format!("Failed to create log file: {}", e))?;

        let server_ip = self.vpn_server_ip.as_deref();
        let require_helper = two_factor.is_some();
        let pid = match helper_client::spawn_vpn(&args, log_path.to_str().unwrap(), server_ip) {
            Ok(pid) => {
                log::info!("Spawned openfortivpn via helper daemon");
                pid
            }
            Err(e) if !require_helper && helper_client::is_connection_error(&e) => {
                log::info!("Helper unavailable ({}), falling back to osascript", e);
                self.spawn_vpn_osascript(&args, &log_path, server_ip)?
            }
            Err(e) => return Err(e),
        };

        log::info!("openfortivpn started with PID {}", pid);

        self.pid = Some(pid);
        self.log_file_path = Some(log_path.clone());
        self.stop_flag = Arc::new(AtomicBool::new(false));

        let stop_flag = self.stop_flag.clone();
        let handle = tauri::async_runtime::spawn(async move {
            start_log_monitor(
                log_path,
                profile_id,
                pid,
                app_handle,
                stop_flag,
                debug_mode,
                fallback_dns,
                two_factor,
                auto_reconnect,
            )
            .await;
        });
        self.monitor_handle = Some(handle);

        Ok(())
    }

    /// Write an OTP / 2FA code to the running openfortivpn stdin via the helper.
    pub fn write_otp(&self, code: &str) -> Result<(), String> {
        let pid = self
            .pid
            .ok_or_else(|| "No VPN process running".to_string())?;
        helper_client::write_stdin(pid, code)
    }

    /// Fallback: spawn openfortivpn via osascript with admin privileges.
    fn spawn_vpn_osascript(
        &self,
        args: &[String],
        log_path: &PathBuf,
        vpn_server: Option<&str>,
    ) -> Result<u32, String> {
        let quoted_args: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
        let ovpn_args = quoted_args.join(" ");
        // Pre-connect orphan sweep (same admin prompt): kill a zombie pppd and
        // remove the stale host route to the server before spawning.
        let host_route_cleanup = match vpn_server {
            Some(ip) => format!("/sbin/route delete {} 2>/dev/null;", shell_quote(ip)),
            None => String::new(),
        };
        let cmd = format!(
            "killall pppd 2>/dev/null; sleep 1; killall -KILL pppd 2>/dev/null; \
             ifconfig ppp0 down 2>/dev/null; ifconfig ppp1 down 2>/dev/null; \
             {host_route_cleanup} \
             {openfortivpn} {ovpn_args} >> {log} 2>&1 & echo $!",
            openfortivpn = openvpngui_common::OPENFORTIVPN_INSTALL_PATH,
            host_route_cleanup = host_route_cleanup,
            ovpn_args = ovpn_args,
            log = log_path.display()
        );

        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            applescript_escape(&cmd)
        );

        let output = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .map_err(|e| format!("Failed to run osascript: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("User canceled") || stderr.contains("-128") {
                return Err("Authentication cancelled by user".to_string());
            }
            return Err(format!("osascript failed: {}", stderr));
        }

        let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let pid: u32 = pid_str
            .parse()
            .map_err(|_| format!("Failed to parse PID from osascript output: '{}'", pid_str))?;

        Ok(pid)
    }

    pub fn kill_vpn(&mut self) -> Result<(), String> {
        // Stop the log monitor
        self.stop_flag.store(true, Ordering::Relaxed);

        if let Some(handle) = self.monitor_handle.take() {
            handle.abort();
        }

        if let Some(pid) = self.pid.take() {
            log::info!(
                "Killing openfortivpn PID {}, restoring gateway {:?}",
                pid,
                self.original_gateway
            );

            match helper_client::kill_vpn(
                pid,
                self.original_gateway.as_deref(),
                self.vpn_server_ip.as_deref(),
            ) {
                Ok(()) => {
                    log::info!("Killed openfortivpn via helper daemon");
                }
                Err(e) if helper_client::is_connection_error(&e) => {
                    log::info!("Helper unavailable ({}), falling back to osascript", e);
                    self.kill_vpn_osascript(pid)?;
                }
                Err(e) => return Err(e),
            }
        } else {
            // No PID but still clean up DNS just in case
            let _ = dns_manager::teardown_dns();
        }

        self.original_gateway = None;
        self.vpn_server_ip = None;

        // Cleanup log file
        if let Some(path) = self.log_file_path.take() {
            let _ = fs::remove_file(&path);
        }

        Ok(())
    }

    /// Fallback: kill openfortivpn via osascript with admin privileges.
    fn kill_vpn_osascript(&self, pid: u32) -> Result<(), String> {
        let gateway_restore = if let Some(ref gw) = self.original_gateway {
            format!(
                "/sbin/route delete default 2>/dev/null; \
                 /sbin/route add default {} 2>/dev/null;",
                gw
            )
        } else {
            String::new()
        };

        // Remove the stale /32 host route to the VPN server, if known.
        let host_route_cleanup = if let Some(ref ip) = self.vpn_server_ip {
            format!("/sbin/route delete {} 2>/dev/null;", shell_quote(ip))
        } else {
            String::new()
        };

        let cmd = format!(
            "kill -INT {pid} 2>/dev/null; \
             sleep 2; \
             kill -0 {pid} 2>/dev/null && kill -9 {pid} 2>/dev/null; \
             killall pppd 2>/dev/null; \
             sleep 1; \
             killall -KILL pppd 2>/dev/null; \
             ifconfig ppp0 down 2>/dev/null; \
             ifconfig ppp1 down 2>/dev/null; \
             {host_route_cleanup} \
             {gateway_restore} \
             echo 'remove State:/Network/Service/OpenFortiVPN/DNS' | /usr/sbin/scutil; \
             /usr/bin/dscacheutil -flushcache; \
             /usr/bin/killall -HUP mDNSResponder 2>/dev/null; \
             true",
            pid = pid,
            host_route_cleanup = host_route_cleanup,
            gateway_restore = gateway_restore,
        );

        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            applescript_escape(&cmd)
        );

        let output = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .map_err(|e| format!("Failed to disconnect: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("User canceled") || stderr.contains("-128") {
                return Err("Disconnect cancelled by user".to_string());
            }
            log::warn!("Disconnect command returned error: {}", stderr);
        }

        Ok(())
    }
}

async fn start_log_monitor(
    log_path: PathBuf,
    profile_id: String,
    pid: u32,
    app_handle: AppHandle,
    stop_flag: Arc<AtomicBool>,
    debug_mode: bool,
    fallback_dns: Vec<String>,
    two_factor: Option<TwoFactorType>,
    auto_reconnect: bool,
) {
    use std::io::Read;

    // Wait a moment for the log file to start receiving data
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let mut file = match OpenOptions::new().read(true).open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            log::error!("Failed to open log file for monitoring: {}", e);
            return;
        }
    };

    let mut pending = Vec::<u8>::new();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut dns_suffixes: Vec<String> = Vec::new();
    let mut vpn_local_ip: Option<String> = None;
    let vpn_peer_ip: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut otp_prompted = false;
    let mut push_signaled = false;
    let mut cert_warned = false;
    // True after Tunnel is up (or a terminal error). Used to distinguish
    // "died before connect" from "session ended after connect".
    let mut reached_terminal = false;
    let mut last_error: Option<String> = None;
    let tunnel_up = Arc::new(AtomicBool::new(false));
    let monitors_started = Arc::new(AtomicBool::new(false));
    let need_2fa_reset = Arc::new(AtomicBool::new(false));

    while !stop_flag.load(Ordering::Relaxed) {
        if need_2fa_reset.swap(false, Ordering::Relaxed) {
            otp_prompted = false;
            push_signaled = false;
        }

        let mut chunk = [0u8; 512];
        match file.read(&mut chunk) {
            Ok(0) => {
                // Process gone: drain late lines, then update UI.
                if !is_process_alive(pid) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
                    let mut drain = [0u8; 4096];
                    if let Ok(n) = file.read(&mut drain) {
                        if n > 0 {
                            pending.extend_from_slice(&drain[..n]);
                            continue;
                        }
                    }
                    while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                        let line_bytes: Vec<u8> = pending.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line_bytes);
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        handle_log_line(
                            trimmed,
                            &profile_id,
                            &app_handle,
                            debug_mode,
                            &mut dns_servers,
                            &mut dns_suffixes,
                            &mut vpn_local_ip,
                            &fallback_dns,
                            &stop_flag,
                            two_factor.as_ref(),
                            &mut otp_prompted,
                            &mut push_signaled,
                            &mut cert_warned,
                            &mut reached_terminal,
                            &mut last_error,
                            &tunnel_up,
                            &monitors_started,
                            &need_2fa_reset,
                            &vpn_peer_ip,
                            pid,
                            auto_reconnect,
                        );
                    }
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    if reached_terminal {
                        // Session had been up (or already reported down): show Disconnected.
                        emit_disconnected(
                            &app_handle,
                            Some("VPN session ended".into()),
                        );
                        let _ = dns_manager::teardown_dns();
                        stop_flag.store(true, Ordering::Relaxed);
                        break;
                    }
                    let message = last_error.unwrap_or_else(|| {
                        if otp_prompted {
                            "Authentication failed after OTP. Check the code and try again."
                                .into()
                        } else if push_signaled {
                            "Push authentication failed or was denied.".into()
                        } else {
                            "VPN process exited before the tunnel came up".into()
                        }
                    });
                    emit_connection_error(&app_handle, &message);
                    stop_flag.store(true, Ordering::Relaxed);
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                continue;
            }
            Ok(n) => {
                pending.extend_from_slice(&chunk[..n]);

                while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                    let line_bytes: Vec<u8> = pending.drain(..=pos).collect();
                    let line = String::from_utf8_lossy(&line_bytes);
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    handle_log_line(
                        trimmed,
                        &profile_id,
                        &app_handle,
                        debug_mode,
                        &mut dns_servers,
                        &mut dns_suffixes,
                        &mut vpn_local_ip,
                        &fallback_dns,
                        &stop_flag,
                        two_factor.as_ref(),
                        &mut otp_prompted,
                        &mut push_signaled,
                        &mut cert_warned,
                        &mut reached_terminal,
                        &mut last_error,
                        &tunnel_up,
                        &monitors_started,
                        &need_2fa_reset,
                        &vpn_peer_ip,
                        pid,
                        auto_reconnect,
                    );
                }

            }
            Err(e) => {
                log::error!("Error reading log file: {}", e);
                let _ = file.seek(SeekFrom::Current(0));
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }
}

fn handle_log_line(
    trimmed: &str,
    profile_id: &str,
    app_handle: &AppHandle,
    debug_mode: bool,
    dns_servers: &mut Vec<String>,
    dns_suffixes: &mut Vec<String>,
    vpn_local_ip: &mut Option<String>,
    fallback_dns: &[String],
    stop_flag: &Arc<AtomicBool>,
    two_factor: Option<&TwoFactorType>,
    otp_prompted: &mut bool,
    push_signaled: &mut bool,
    cert_warned: &mut bool,
    reached_terminal: &mut bool,
    last_error: &mut Option<String>,
    tunnel_up: &Arc<AtomicBool>,
    monitors_started: &Arc<AtomicBool>,
    need_2fa_reset: &Arc<AtomicBool>,
    vpn_peer_ip: &Arc<Mutex<Option<String>>>,
    pid: u32,
    auto_reconnect: bool,
) {
    let level = if trimmed.contains("ERROR") || trimmed.contains("error") {
        "error"
    } else if trimmed.contains("WARN") || trimmed.contains("warn") {
        "warn"
    } else {
        "info"
    };

    if level == "error" {
        // Prefer actionable lines (trusted-cert / validation) over indented cert details.
        if trimmed.contains("trusted-cert")
            || trimmed.contains("certificate validation failed")
            || trimmed.contains("ERROR:")
        {
            let cleaned = trimmed
                .trim_start_matches("ERROR:")
                .trim()
                .to_string();
            let is_bare_digest = cleaned.len() == 64
                && cleaned.chars().all(|c| c.is_ascii_hexdigit());
            if !cleaned.is_empty()
                && !is_bare_digest
                && !cleaned.starts_with("--trusted-cert")
                && !cleaned.starts_with("subject:")
                && !cleaned.starts_with("issuer:")
                && !cleaned.starts_with("C=")
                && !cleaned.starts_with("ST=")
                && !cleaned.starts_with("O=")
                && !cleaned.starts_with("CN=")
                && !cleaned.starts_with("L=")
                && !cleaned.starts_with("sha256")
            {
                *last_error = Some(cleaned);
            }
        }
    }

    let is_important = level != "info"
        || trimmed.contains("Tunnel is up")
        || trimmed.contains("Tunnel is down")
        || trimmed.contains("Connected to")
        || trimmed.contains("saml")
        || trimmed.contains("SAML")
        || trimmed.contains("certificate")
        || trimmed.contains("Authenticated")
        || trimmed.contains("Disconnecting")
        || trimmed.contains("Connected to gateway");

    if debug_mode || is_important {
        let _ = app_handle.emit(
            "log-line",
            LogLinePayload {
                timestamp: Utc::now().to_rfc3339(),
                level: level.to_string(),
                message: trimmed.to_string(),
            },
        );
    }

    if let Some(dns_info) = dns_manager::parse_dns_from_log(trimmed) {
        match dns_info {
            DnsInfo::Server(s) => {
                if !dns_servers.contains(&s) {
                    dns_servers.push(s);
                }
            }
            DnsInfo::SearchDomains(ds) => {
                for d in ds {
                    if !dns_suffixes.contains(&d) {
                        dns_suffixes.push(d);
                    }
                }
            }
        }
    }

    if vpn_local_ip.is_none() {
        if let Some(ip) = extract_vpn_ip_from_log(trimmed) {
            log::info!("Captured VPN local IP from log: {}", ip);
            *vpn_local_ip = Some(ip);
        }
    }
    if let Some(peer) = extract_vpn_peer_from_log(trimmed) {
        if let Ok(mut slot) = vpn_peer_ip.lock() {
            if slot.as_ref() != Some(&peer) {
                log::info!("Captured VPN peer IP from log: {}", peer);
                *slot = Some(peer);
            }
        }
    }

    if trimmed.contains("Tunnel is up and running") {
        // Build final DNS server list. Fallback (DHCP + Google) is only
        // used when the VPN itself did not provide any DNS servers;
        // otherwise mixing public resolvers with the VPN's split-DNS
        // causes public IPs to be cached for internal hostnames, which
        // the VPN's firewall then blocks (hairpin/split-DNS enforcement).
        let mut all_dns = dns_servers.clone();
        if all_dns.is_empty() && !fallback_dns.is_empty() {
            for s in fallback_dns {
                if !all_dns.contains(s) {
                    all_dns.push(s.clone());
                }
            }
            for google in &["8.8.8.8", "8.8.4.4"] {
                let g = google.to_string();
                if !all_dns.contains(&g) {
                    all_dns.push(g);
                }
            }
            log::info!("DNS with fallback (VPN provided none): {:?}", all_dns);
        }

        if !all_dns.is_empty() {
            if let Err(e) = dns_manager::setup_dns(&all_dns, dns_suffixes) {
                log::error!("Failed to setup DNS: {}", e);
            }
        }

        let ip = vpn_local_ip
            .clone()
            .or_else(|| extract_ip(trimmed))
            .or_else(get_ppp_interface_ip)
            .unwrap_or_else(|| "unknown".to_string());
        crate::tray::update_tray_icon(
            app_handle,
            &ConnectionState::Connected {
                profile_id: profile_id.to_string(),
                ip: ip.clone(),
                since: Utc::now(),
            },
        );
        let bw_ip = ip.clone();

        *reached_terminal = true;
        tunnel_up.store(true, Ordering::Relaxed);
        let _ = app_handle.emit(
            "connection-status-changed",
            ConnectionStatusPayload {
                state: "Connected".into(),
                profile_id: Some(profile_id.to_string()),
                ip: Some(ip),
                since: Some(Utc::now().to_rfc3339()),
                message: None,
            },
        );

        // Start bandwidth + health monitors once per VPN session.
        if monitors_started
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let health_ip = vpn_local_ip.clone().unwrap_or_else(|| bw_ip.clone());
            let bw_app_handle = app_handle.clone();
            let bw_stop_flag = stop_flag.clone();
            let bw_ip_monitor = bw_ip;
            tauri::async_runtime::spawn(async move {
                start_bandwidth_monitor(bw_app_handle, bw_stop_flag, bw_ip_monitor).await;
            });

            let health_app = app_handle.clone();
            let health_stop = stop_flag.clone();
            let health_tunnel = tunnel_up.clone();
            let health_2fa = need_2fa_reset.clone();
            let health_peer = vpn_peer_ip.clone();
            let health_profile = profile_id.to_string();
            tauri::async_runtime::spawn(async move {
                start_connection_health_monitor(
                    health_app,
                    health_stop,
                    health_tunnel,
                    health_2fa,
                    health_peer,
                    pid,
                    health_profile,
                    health_ip,
                    auto_reconnect,
                )
                .await;
            });
        }
    } else if trimmed.contains("Tunnel is down") {
        *reached_terminal = true;
        tunnel_up.store(false, Ordering::Relaxed);
        *otp_prompted = false;
        *push_signaled = false;
        if auto_reconnect {
            // With --persistent, openfortivpn stays alive and retries.
            crate::tray::update_tray_icon(
                app_handle,
                &ConnectionState::Connecting {
                    profile_id: profile_id.to_string(),
                },
            );
            let _ = app_handle.emit(
                "connection-status-changed",
                ConnectionStatusPayload {
                    state: "Connecting".into(),
                    profile_id: Some(profile_id.to_string()),
                    ip: None,
                    since: None,
                    message: Some("Reconnecting...".into()),
                },
            );
        } else {
            emit_disconnected(app_handle, Some("Tunnel is down".into()));
            let _ = dns_manager::teardown_dns();
            stop_flag.store(true, Ordering::Relaxed);
        }
    } else if trimmed.contains("/remote/saml/start")
        || (trimmed.contains("http") && trimmed.contains("saml"))
    {
        if let Some(url) = extract_url(trimmed) {
            crate::tray::update_tray_icon(
                app_handle,
                &ConnectionState::WaitingSaml {
                    profile_id: profile_id.to_string(),
                    url: url.clone(),
                },
            );
            let _ = app_handle.emit("saml-url", serde_json::json!({ "url": url }));
            let _ = app_handle.emit(
                "connection-status-changed",
                ConnectionStatusPayload {
                    state: "WaitingSaml".into(),
                    profile_id: Some(profile_id.to_string()),
                    ip: None,
                    since: None,
                    message: Some(url),
                },
            );
        }
    } else if !*cert_warned {
        if let Some(digest) = extract_trusted_cert_hint(trimmed) {
            *cert_warned = true;
            let _ = app_handle.emit(
                "cert-warning",
                serde_json::json!({
                    "digest": digest,
                    "profile_id": profile_id
                }),
            );
            focus_main_window(app_handle);
        }
    }

    // After gateway login, OTP/push is next. Driven by profile 2FA setting, not
    // by matching FortiGate prompt wording.
    if trimmed.contains("Connected to gateway") {
        match two_factor {
            Some(TwoFactorType::Totp) if !*otp_prompted => {
                *otp_prompted = true;
                emit_waiting_otp(app_handle, profile_id);
            }
            Some(TwoFactorType::Push) if !*push_signaled => {
                *push_signaled = true;
                emit_waiting_push(app_handle, profile_id);
            }
            _ => {}
        }
    }

    // Auth failure after OTP/password: leave Connecting immediately.
    if trimmed.contains("Could not authenticate to gateway")
        || trimmed.contains("No OTP specified")
        || trimmed.contains("No token specified")
    {
        let cleaned = trimmed
            .trim_start_matches("ERROR:")
            .trim()
            .to_string();
        *last_error = Some(cleaned.clone());
        *reached_terminal = true;
        emit_connection_error(app_handle, &cleaned);
        stop_flag.store(true, Ordering::Relaxed);
    }
}

fn is_process_alive(pid: u32) -> bool {
    process_state(pid).is_some()
}

/// True when the process exists but is stopped (SIGSTOP / traced), state `T`.
/// Still listed by `ps`, so a plain alive check would miss a frozen VPN.
fn is_process_stopped(pid: u32) -> bool {
    matches!(process_state(pid), Some(s) if is_stopped_state(&s))
}

fn process_state(pid: u32) -> Option<String> {
    // Use `ps` instead of `kill -0`: openfortivpn runs as root via the helper, and
    // an unprivileged `kill -0` returns EPERM even when the process is alive.
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "state="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if state.is_empty() {
        None
    } else {
        Some(state)
    }
}

fn is_stopped_state(state: &str) -> bool {
    state.chars().next() == Some('T')
}

fn emit_connection_error(app_handle: &AppHandle, message: &str) {
    log::error!("VPN connection failed: {}", message);
    crate::tray::update_tray_icon(
        app_handle,
        &ConnectionState::Error {
            message: message.to_string(),
        },
    );
    let _ = app_handle.emit(
        "connection-status-changed",
        ConnectionStatusPayload {
            state: "Error".into(),
            profile_id: None,
            ip: None,
            since: None,
            message: Some(message.to_string()),
        },
    );
    focus_main_window(app_handle);
}

fn emit_disconnected(app_handle: &AppHandle, message: Option<String>) {
    log::info!(
        "VPN disconnected{}",
        message
            .as_deref()
            .map(|m| format!(": {}", m))
            .unwrap_or_default()
    );
    crate::tray::update_tray_icon(app_handle, &ConnectionState::Disconnected);
    let _ = app_handle.emit(
        "connection-status-changed",
        ConnectionStatusPayload {
            state: "Disconnected".into(),
            profile_id: None,
            ip: None,
            since: None,
            message,
        },
    );
}

/// Poll process, ppp interface, and PPP peer reachability while connected.
/// Peer IP comes from ifconfig (`inet local --> peer`), never hardcoded.
/// If ICMP to the peer never succeeds, probing is disabled (peer may block ping)
/// and we fall back to process + interface checks only.
async fn start_connection_health_monitor(
    app_handle: AppHandle,
    stop_flag: Arc<AtomicBool>,
    tunnel_up: Arc<AtomicBool>,
    need_2fa_reset: Arc<AtomicBool>,
    vpn_peer_ip: Arc<Mutex<Option<String>>>,
    pid: u32,
    profile_id: String,
    vpn_ip: String,
    auto_reconnect: bool,
) {
    let mut missing_iface = 0u32;
    let mut probe_fails = 0u32;
    let mut probe_ever_ok = false;
    let mut probe_skipped = false;
    let mut probe_misses_before_ok = 0u32;
    log::info!(
        "Connection health monitor started (pid={}, ip={}, auto_reconnect={})",
        pid,
        vpn_ip,
        auto_reconnect
    );

    while !stop_flag.load(Ordering::Relaxed) {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        if !is_process_alive(pid) {
            log::warn!("VPN process {} is no longer alive", pid);
            emit_disconnected(&app_handle, Some("VPN process ended".into()));
            let _ = dns_manager::teardown_dns();
            stop_flag.store(true, Ordering::Relaxed);
            break;
        }
        if is_process_stopped(pid) {
            log::warn!("VPN process {} is stopped (SIGSTOP/traced)", pid);
            emit_disconnected(&app_handle, Some("VPN process suspended".into()));
            let _ = dns_manager::teardown_dns();
            stop_flag.store(true, Ordering::Relaxed);
            break;
        }

        if !tunnel_up.load(Ordering::Relaxed) {
            missing_iface = 0;
            probe_fails = 0;
            continue;
        }

        if vpn_ip == "unknown" {
            continue;
        }

        let Some((_iface, ifconfig_peer)) = find_ppp_link(&vpn_ip) else {
            missing_iface += 1;
            // ~15s without the VPN IP on a ppp interface.
            if missing_iface >= 3 {
                mark_tunnel_unhealthy(
                    &app_handle,
                    &stop_flag,
                    &tunnel_up,
                    &need_2fa_reset,
                    &profile_id,
                    auto_reconnect,
                    "Tunnel lost (interface gone)",
                );
                if !auto_reconnect {
                    break;
                }
                missing_iface = 0;
            }
            continue;
        };
        missing_iface = 0;

        let peer = ifconfig_peer.or_else(|| {
            vpn_peer_ip
                .lock()
                .ok()
                .and_then(|g| g.clone())
        });
        let Some(peer) = peer else {
            // No peer address available; interface presence is enough.
            continue;
        };

        if probe_skipped {
            continue;
        }

        if probe_host_reachable(&peer).await {
            if !probe_ever_ok {
                log::info!("Tunnel probe OK via PPP peer {}", peer);
            }
            probe_ever_ok = true;
            probe_fails = 0;
            probe_misses_before_ok = 0;
            continue;
        }

        if !probe_ever_ok {
            // Never got a successful ping: peer may block ICMP. Stop probing
            // after ~30s so we do not false-disconnect.
            probe_misses_before_ok += 1;
            if probe_misses_before_ok >= 6 {
                log::info!(
                    "PPP peer {} never answered ping; disabling reachability probe",
                    peer
                );
                probe_skipped = true;
            }
            continue;
        }

        probe_fails += 1;
        log::warn!(
            "Tunnel probe failed to PPP peer {} ({}/3)",
            peer,
            probe_fails
        );
        if probe_fails < 3 {
            continue;
        }

        mark_tunnel_unhealthy(
            &app_handle,
            &stop_flag,
            &tunnel_up,
            &need_2fa_reset,
            &profile_id,
            auto_reconnect,
            "Tunnel lost (peer unreachable)",
        );
        if !auto_reconnect {
            break;
        }
        probe_fails = 0;
        probe_ever_ok = false;
        probe_misses_before_ok = 0;
    }

    log::info!("Connection health monitor stopped");
}

fn mark_tunnel_unhealthy(
    app_handle: &AppHandle,
    stop_flag: &Arc<AtomicBool>,
    tunnel_up: &Arc<AtomicBool>,
    need_2fa_reset: &Arc<AtomicBool>,
    profile_id: &str,
    auto_reconnect: bool,
    reason: &str,
) {
    tunnel_up.store(false, Ordering::Relaxed);
    if auto_reconnect {
        log::warn!("{}; marking reconnecting", reason);
        need_2fa_reset.store(true, Ordering::Relaxed);
        crate::tray::update_tray_icon(
            app_handle,
            &ConnectionState::Connecting {
                profile_id: profile_id.to_string(),
            },
        );
        let _ = app_handle.emit(
            "connection-status-changed",
            ConnectionStatusPayload {
                state: "Connecting".into(),
                profile_id: Some(profile_id.to_string()),
                ip: None,
                since: None,
                message: Some("Reconnecting...".into()),
            },
        );
    } else {
        log::warn!("{}; marking disconnected", reason);
        emit_disconnected(app_handle, Some(reason.into()));
        let _ = dns_manager::teardown_dns();
        stop_flag.store(true, Ordering::Relaxed);
    }
}

/// ICMP echo to a dynamically discovered PPP peer. macOS: -W is ms wait per reply.
async fn probe_host_reachable(ip: &str) -> bool {
    if !is_valid_vpn_ip(ip) {
        return false;
    }
    let ip = ip.to_string();
    tokio::task::spawn_blocking(move || {
        Command::new("ping")
            .args(["-c", "1", "-W", "2000", "-t", "3", &ip])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Extract a trusted-cert digest from openfortivpn error output.
/// Handles both `--trusted-cert <hex>` lines and bare 64-char hex digest lines.
fn extract_trusted_cert_hint(line: &str) -> Option<String> {
    if let Some(idx) = line.find("--trusted-cert") {
        return extract_cert_digest(&line[idx..]);
    }
    if line.contains("trusted-cert") {
        if let Some(digest) = extract_cert_digest(line) {
            return Some(digest);
        }
    }
    let trimmed = line.trim();
    let trimmed = trimmed.strip_prefix("ERROR:").unwrap_or(trimmed).trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(trimmed.to_string());
    }
    None
}

fn emit_waiting_otp(app_handle: &AppHandle, profile_id: &str) {
    log::info!("Detected OTP / 2FA prompt for profile {}", profile_id);
    crate::tray::update_tray_icon(
        app_handle,
        &ConnectionState::WaitingOtp {
            profile_id: profile_id.to_string(),
        },
    );
    let _ = app_handle.emit(
        "connection-status-changed",
        ConnectionStatusPayload {
            state: "WaitingOtp".into(),
            profile_id: Some(profile_id.to_string()),
            ip: None,
            since: None,
            message: Some("Enter your authentication code".into()),
        },
    );
    let _ = app_handle.emit("otp-required", serde_json::json!({ "profile_id": profile_id }));
    focus_main_window(app_handle);
}

fn emit_waiting_push(app_handle: &AppHandle, profile_id: &str) {
    log::info!("Detected FTM push wait for profile {}", profile_id);
    crate::tray::update_tray_icon(
        app_handle,
        &ConnectionState::WaitingPush {
            profile_id: profile_id.to_string(),
        },
    );
    let _ = app_handle.emit(
        "connection-status-changed",
        ConnectionStatusPayload {
            state: "WaitingPush".into(),
            profile_id: Some(profile_id.to_string()),
            ip: None,
            since: None,
            message: Some("Approve the push notification on your phone".into()),
        },
    );
    focus_main_window(app_handle);
}

fn focus_main_window(app_handle: &AppHandle) {
    use tauri::Manager;
    if let Some(window) = app_handle.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.unminimize();
    }
}

fn extract_ip(line: &str) -> Option<String> {
    // Look for IP-like patterns (e.g., "10.0.1.45")
    for word in line.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        let parts: Vec<&str> = word.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            // Skip common non-VPN IPs
            if !word.starts_with("127.") && !word.starts_with("0.") {
                return Some(word.to_string());
            }
        }
    }
    None
}

fn is_valid_vpn_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| p.parse::<u8>().is_ok())
        && !s.starts_with("127.")
        && !s.starts_with("0.")
}

/// Extract VPN local IP from openfortivpn verbose log lines.
/// Matches patterns like:
///   "Got addresses: [10.0.1.45], peer [192.168.1.1]"
///   "local  IP address 10.0.1.45"
///   "local IP is 10.0.1.45"
fn extract_vpn_ip_from_log(line: &str) -> Option<String> {
    // Pattern 1: "Got addresses: [10.x.x.x], peer [y.y.y.y]"
    if line.contains("Got addresses") {
        if let Some(start) = line.find('[') {
            if let Some(end) = line[start..].find(']') {
                let candidate = &line[start + 1..start + end];
                if is_valid_vpn_ip(candidate) {
                    return Some(candidate.to_string());
                }
            }
        }
    }

    // Pattern 2: "local  IP address X.X.X.X" (pppd output)
    if line.contains("local") && line.contains("IP address") {
        for word in line.split_whitespace().rev() {
            let cleaned = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            if is_valid_vpn_ip(cleaned) {
                return Some(cleaned.to_string());
            }
        }
    }

    // Pattern 3: "local IP is X.X.X.X"
    if line.contains("local IP is") {
        for word in line.split_whitespace().rev() {
            let cleaned = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            if is_valid_vpn_ip(cleaned) {
                return Some(cleaned.to_string());
            }
        }
    }

    None
}

/// Fallback: query ppp interface IP via ifconfig when log parsing fails.
fn get_ppp_interface_ip() -> Option<String> {
    for iface in &["ppp0", "ppp1", "ppp2"] {
        if let Ok(output) = Command::new("ifconfig").arg(iface).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("inet ") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 && is_valid_vpn_ip(parts[1]) {
                            return Some(parts[1].to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_url(line: &str) -> Option<String> {
    // Find URL starting with http
    for word in line.split_whitespace() {
        let word = word.trim_matches(|c: char| c == '\'' || c == '"' || c == '(' || c == ')');
        if word.starts_with("http://") || word.starts_with("https://") {
            return Some(word.to_string());
        }
    }
    None
}

fn extract_cert_digest(line: &str) -> Option<String> {
    // Look for SHA256 hex digest (64 hex chars)
    for word in line.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_ascii_hexdigit());
        if word.len() == 64 && word.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(word.to_string());
        }
    }
    // Also check colon-separated format
    for word in line.split_whitespace() {
        let stripped: String = word.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if stripped.len() == 64 {
            return Some(stripped);
        }
    }
    None
}

/// Start polling the ppp interface for bandwidth statistics.
/// Runs until stop_flag is set. Emits "bandwidth-update" events.
async fn start_bandwidth_monitor(
    app_handle: AppHandle,
    stop_flag: Arc<AtomicBool>,
    vpn_ip: String,
) {
    // Wait for the ppp interface to be fully ready
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let iface = match detect_ppp_interface(&vpn_ip) {
        Some(i) => i,
        None => {
            log::warn!("Could not detect ppp interface for IP {}", vpn_ip);
            return;
        }
    };
    log::info!("Bandwidth monitor starting on interface: {}", iface);

    let mut prev_rx: Option<u64> = None;
    let mut prev_tx: Option<u64> = None;
    let mut prev_time: Option<std::time::Instant> = None;

    while !stop_flag.load(Ordering::Relaxed) {
        if let Some((rx_bytes, tx_bytes)) = read_interface_bytes(&iface) {
            let now = std::time::Instant::now();

            let (rx_speed, tx_speed) = if let (Some(p_rx), Some(p_tx), Some(p_time)) =
                (prev_rx, prev_tx, prev_time)
            {
                let elapsed = now.duration_since(p_time).as_secs_f64();
                if elapsed > 0.0 {
                    let rx_delta = rx_bytes.saturating_sub(p_rx) as f64;
                    let tx_delta = tx_bytes.saturating_sub(p_tx) as f64;
                    (rx_delta / elapsed, tx_delta / elapsed)
                } else {
                    (0.0, 0.0)
                }
            } else {
                (0.0, 0.0)
            };

            prev_rx = Some(rx_bytes);
            prev_tx = Some(tx_bytes);
            prev_time = Some(now);

            let _ = app_handle.emit(
                "bandwidth-update",
                BandwidthPayload {
                    rx_bytes,
                    tx_bytes,
                    rx_speed,
                    tx_speed,
                    timestamp: Utc::now().to_rfc3339(),
                },
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    log::info!("Bandwidth monitor stopped");
}

/// Detect the ppp interface that has the given VPN IP assigned.
fn detect_ppp_interface(vpn_ip: &str) -> Option<String> {
    find_ppp_link(vpn_ip).map(|(iface, _)| iface)
}

/// Find the ppp interface for `vpn_ip` and its point-to-point peer, if any.
/// Peer comes from macOS ifconfig: `inet 10.x.x.x --> 10.y.y.y`.
fn find_ppp_link(vpn_ip: &str) -> Option<(String, Option<String>)> {
    let output = Command::new("ifconfig").output().ok()?;
    parse_ppp_link_from_ifconfig(&String::from_utf8_lossy(&output.stdout), vpn_ip)
}

fn parse_ppp_link_from_ifconfig(stdout: &str, vpn_ip: &str) -> Option<(String, Option<String>)> {
    let mut current_iface: Option<String> = None;
    for line in stdout.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') {
            if let Some(name) = line.split(':').next() {
                if name.starts_with("ppp") {
                    current_iface = Some(name.to_string());
                } else {
                    current_iface = None;
                }
            }
            continue;
        }
        let Some(ref iface) = current_iface else {
            continue;
        };
        if let Some((local, peer)) = parse_ppp_inet_line(line) {
            if local == vpn_ip {
                log::info!(
                    "Found VPN IP {} on interface {} (peer={:?})",
                    vpn_ip,
                    iface,
                    peer
                );
                return Some((iface.clone(), peer));
            }
        }
    }
    None
}

/// Parse `inet <local> --> <peer> ...` (macOS ppp) or bare `inet <local>`.
fn parse_ppp_inet_line(line: &str) -> Option<(String, Option<String>)> {
    let trimmed = line.trim();
    if !trimmed.starts_with("inet ") {
        return None;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let local = parts.get(1)?.to_string();
    if !is_valid_vpn_ip(&local) {
        return None;
    }
    let peer = if parts.get(2) == Some(&"-->") {
        parts.get(3).and_then(|p| {
            if is_valid_vpn_ip(p) {
                Some(p.to_string())
            } else {
                None
            }
        })
    } else {
        None
    };
    Some((local, peer))
}

/// Peer from openfortivpn verbose log: `Got addresses: [local], peer [peer]`.
fn extract_vpn_peer_from_log(line: &str) -> Option<String> {
    if !line.contains("Got addresses") || !line.contains("peer") {
        return None;
    }
    let peer_idx = line.find("peer")?;
    let after = &line[peer_idx..];
    let start = after.find('[')?;
    let end = after[start..].find(']')?;
    let candidate = &after[start + 1..start + end];
    if is_valid_vpn_ip(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

/// Read cumulative RX and TX bytes from a network interface using netstat.
/// Parses `netstat -I <iface> -b` output on macOS. Looks for the <Link> row
/// which contains total cumulative bytes.
fn read_interface_bytes(iface: &str) -> Option<(u64, u64)> {
    let output = Command::new("netstat")
        .args(["-I", iface, "-b"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();

    // Parse header to find Ibytes and Obytes column indices
    let header = lines.next()?;
    let header_cols: Vec<&str> = header.split_whitespace().collect();
    let ibytes_idx = header_cols.iter().position(|&c| c == "Ibytes")?;
    let obytes_idx = header_cols.iter().position(|&c| c == "Obytes")?;

    // Find the <Link> row (cumulative totals, no address field = one fewer column)
    for line in lines {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        // Match interface name, ignoring trailing asterisk (inactive marker)
        let name = cols[0].trim_end_matches('*');
        if name != iface {
            continue;
        }
        // The <Link> row has no Address column, so it has one fewer field
        // than the header. Adjust indices by -1 for this row.
        if cols.iter().any(|c| c.contains("<Link")) {
            let adj_ibytes = ibytes_idx.checked_sub(1)?;
            let adj_obytes = obytes_idx.checked_sub(1)?;
            if cols.len() > adj_obytes {
                let ibytes = cols[adj_ibytes].parse::<u64>().ok()?;
                let obytes = cols[adj_obytes].parse::<u64>().ok()?;
                return Some((ibytes, obytes));
            }
        }
    }
    None
}

/// Get the current default gateway (before VPN modifies routes).
/// Parses `route -n get default` output on macOS.
fn get_default_gateway() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("gateway:") {
            let gw = trimmed.strip_prefix("gateway:")?.trim();
            if !gw.is_empty() {
                return Some(gw.to_string());
            }
        }
    }
    None
}

/// Resolve the VPN server IP from a `"host:port"` argument (args[0]).
/// Returns the first IPv4 address, or the host itself if it's already an IPv4
/// literal. Used to clear the server's stale `/32` host route on cleanup.
fn resolve_server_ip(host_port: &str) -> Option<String> {
    // Strip the ":port" suffix (the host may be a bare hostname or IPv4).
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);

    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host.to_string());
    }

    use std::net::ToSocketAddrs;
    (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            std::net::IpAddr::V6(_) => None,
        })
}

/// Escape a string for inclusion in an AppleScript double-quoted string.
/// AppleScript only recognizes `\\` and `\"` as escape sequences.
/// Shell metacharacters like `$`, `` ` ``, `&` are left as-is because
/// `do shell script` passes the string to `/bin/sh` which interprets them.
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// Wrap a user-supplied value in single quotes for shell safety.
/// Inside single quotes, the shell interprets nothing — only `'` needs handling.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_server_ip_passes_through_ipv4_literal() {
        assert_eq!(
            resolve_server_ip("201.49.152.75:10443"),
            Some("201.49.152.75".to_string())
        );
        // Bare IPv4 without a port also works.
        assert_eq!(
            resolve_server_ip("10.0.0.1"),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn resolve_server_ip_rejects_garbage() {
        // A non-resolvable, non-IP host yields None rather than a bogus route.
        assert_eq!(resolve_server_ip("not_a_host:10443"), None);
    }

    #[test]
    fn parse_ppp_inet_line_with_peer() {
        let (local, peer) =
            parse_ppp_inet_line("\tinet 10.212.134.200 --> 10.212.134.199 netmask 0xfffffff0")
                .unwrap();
        assert_eq!(local, "10.212.134.200");
        assert_eq!(peer.as_deref(), Some("10.212.134.199"));
    }

    #[test]
    fn parse_ppp_inet_line_without_peer() {
        let (local, peer) = parse_ppp_inet_line("inet 10.0.1.45 netmask 0xffffff00").unwrap();
        assert_eq!(local, "10.0.1.45");
        assert!(peer.is_none());
    }

    #[test]
    fn parse_ppp_link_from_ifconfig_finds_peer() {
        let stdout = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1354
	inet 10.212.134.200 --> 10.212.134.199 netmask 0xfffffff0
";
        let (iface, peer) = parse_ppp_link_from_ifconfig(stdout, "10.212.134.200").unwrap();
        assert_eq!(iface, "ppp0");
        assert_eq!(peer.as_deref(), Some("10.212.134.199"));
    }

    #[test]
    fn extract_vpn_peer_from_got_addresses() {
        let line = "INFO:   Got addresses: [10.0.1.45], peer [192.168.1.1]";
        assert_eq!(
            extract_vpn_peer_from_log(line).as_deref(),
            Some("192.168.1.1")
        );
    }

    #[test]
    fn stopped_state_detects_sigstop() {
        assert!(is_stopped_state("T"));
        assert!(is_stopped_state("Ts"));
        assert!(is_stopped_state("T+"));
        assert!(!is_stopped_state("S"));
        assert!(!is_stopped_state("Ss+"));
        assert!(!is_stopped_state("R"));
        assert!(!is_stopped_state(""));
    }

}
