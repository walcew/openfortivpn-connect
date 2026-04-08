use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::Utc;
use tauri::{AppHandle, Emitter};
use tauri::async_runtime::JoinHandle;

use crate::dns_manager::{self, DnsInfo};
use crate::helper_client;
use crate::models::{ConnectionState, ConnectionStatusPayload, LogLinePayload};

pub struct ProcessManager {
    pid: Option<u32>,
    log_file_path: Option<PathBuf>,
    stop_flag: Arc<AtomicBool>,
    monitor_handle: Option<JoinHandle<()>>,
    /// Original default gateway saved before connecting, to restore on disconnect
    original_gateway: Option<String>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            pid: None,
            log_file_path: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            monitor_handle: None,
            original_gateway: None,
        }
    }

    pub fn spawn_vpn(
        &mut self,
        args: Vec<String>,
        profile_id: String,
        app_handle: AppHandle,
        debug_mode: bool,
    ) -> Result<(), String> {
        // Capture the current default gateway before connecting
        self.original_gateway = get_default_gateway();
        log::info!(
            "Saved original default gateway: {:?}",
            self.original_gateway
        );

        let log_id = uuid::Uuid::new_v4();
        let log_path = PathBuf::from(format!("/tmp/openvpngui-{}.log", log_id));

        // Create the log file so the monitor can start reading
        File::create(&log_path)
            .map_err(|e| format!("Failed to create log file: {}", e))?;

        let pid = match helper_client::spawn_vpn(&args, log_path.to_str().unwrap()) {
            Ok(pid) => {
                log::info!("Spawned openfortivpn via helper daemon");
                pid
            }
            Err(e) if helper_client::is_connection_error(&e) => {
                log::info!("Helper unavailable ({}), falling back to osascript", e);
                self.spawn_vpn_osascript(&args, &log_path)?
            }
            Err(e) => return Err(e),
        };

        log::info!("openfortivpn started with PID {}", pid);

        self.pid = Some(pid);
        self.log_file_path = Some(log_path.clone());
        self.stop_flag = Arc::new(AtomicBool::new(false));

        let stop_flag = self.stop_flag.clone();
        let handle = tauri::async_runtime::spawn(async move {
            start_log_monitor(log_path, profile_id, app_handle, stop_flag, debug_mode).await;
        });
        self.monitor_handle = Some(handle);

        Ok(())
    }

    /// Fallback: spawn openfortivpn via osascript with admin privileges.
    fn spawn_vpn_osascript(&self, args: &[String], log_path: &PathBuf) -> Result<u32, String> {
        let quoted_args: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
        let ovpn_args = quoted_args.join(" ");
        let cmd = format!(
            "/opt/homebrew/bin/openfortivpn {} >> {} 2>&1 & echo $!",
            ovpn_args,
            log_path.display()
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

            match helper_client::kill_vpn(pid, self.original_gateway.as_deref()) {
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

        let cmd = format!(
            "kill -INT {pid} 2>/dev/null; \
             sleep 2; \
             kill -0 {pid} 2>/dev/null && kill -9 {pid} 2>/dev/null; \
             killall pppd 2>/dev/null; \
             sleep 1; \
             ifconfig ppp0 down 2>/dev/null; \
             ifconfig ppp1 down 2>/dev/null; \
             {gateway_restore} \
             echo 'remove State:/Network/Service/OpenFortiVPN/DNS' | /usr/sbin/scutil; \
             /usr/bin/dscacheutil -flushcache; \
             /usr/bin/killall -HUP mDNSResponder 2>/dev/null; \
             true",
            pid = pid,
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

    pub fn is_running(&self) -> bool {
        self.pid.is_some()
    }
}

async fn start_log_monitor(
    log_path: PathBuf,
    profile_id: String,
    app_handle: AppHandle,
    stop_flag: Arc<AtomicBool>,
    debug_mode: bool,
) {
    // Wait a moment for the log file to start receiving data
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let file = match OpenOptions::new().read(true).open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            log::error!("Failed to open log file for monitoring: {}", e);
            return;
        }
    };

    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut dns_suffix: Option<String> = None;

    while !stop_flag.load(Ordering::Relaxed) {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data, wait and retry
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                continue;
            }
            Ok(_) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }

                // Determine log level
                let level = if trimmed.contains("ERROR") || trimmed.contains("error") {
                    "error"
                } else if trimmed.contains("WARN") || trimmed.contains("warn") {
                    "warn"
                } else {
                    "info"
                };

                // Check if this is an important line that should always be shown
                let is_important = level != "info"
                    || trimmed.contains("Tunnel is up")
                    || trimmed.contains("Tunnel is down")
                    || trimmed.contains("Connected to")
                    || trimmed.contains("saml")
                    || trimmed.contains("SAML")
                    || trimmed.contains("certificate")
                    || trimmed.contains("Authenticated")
                    || trimmed.contains("Disconnecting");

                // Only emit verbose info lines when debug mode is enabled
                if debug_mode || is_important {
                    let _ = app_handle.emit(
                        "log-line",
                        LogLinePayload {
                            timestamp: Utc::now().to_rfc3339(),
                            level: level.to_string(),
                            message: trimmed.clone(),
                        },
                    );
                }

                // Collect DNS info from log lines before tunnel comes up
                if let Some(dns_info) = dns_manager::parse_dns_from_log(&trimmed) {
                    match dns_info {
                        DnsInfo::Server(s) => {
                            if !dns_servers.contains(&s) {
                                dns_servers.push(s);
                            }
                        }
                        DnsInfo::SearchDomain(d) => {
                            dns_suffix = Some(d);
                        }
                    }
                }

                // Detect state changes
                if trimmed.contains("Tunnel is up and running") {
                    // Configure macOS DNS via scutil
                    if !dns_servers.is_empty() {
                        if let Err(e) = dns_manager::setup_dns(&dns_servers, dns_suffix.as_deref()) {
                            log::error!("Failed to setup DNS: {}", e);
                        }
                    }

                    let ip = extract_ip(&trimmed).unwrap_or_else(|| "unknown".to_string());
                    crate::tray::update_tray_icon(
                        &app_handle,
                        &ConnectionState::Connected {
                            profile_id: profile_id.clone(),
                            ip: ip.clone(),
                            since: Utc::now(),
                        },
                    );
                    let _ = app_handle.emit(
                        "connection-status-changed",
                        ConnectionStatusPayload {
                            state: "Connected".into(),
                            profile_id: Some(profile_id.clone()),
                            ip: Some(ip),
                            since: Some(Utc::now().to_rfc3339()),
                            message: None,
                        },
                    );
                } else if trimmed.contains("Tunnel is down") {
                    crate::tray::update_tray_icon(&app_handle, &ConnectionState::Disconnected);
                    let _ = app_handle.emit(
                        "connection-status-changed",
                        ConnectionStatusPayload {
                            state: "Disconnected".into(),
                            profile_id: None,
                            ip: None,
                            since: None,
                            message: None,
                        },
                    );
                    break;
                } else if trimmed.contains("/remote/saml/start") || trimmed.contains("http") && trimmed.contains("saml") {
                    if let Some(url) = extract_url(&trimmed) {
                        crate::tray::update_tray_icon(
                            &app_handle,
                            &ConnectionState::WaitingSaml {
                                profile_id: profile_id.clone(),
                                url: url.clone(),
                            },
                        );
                        let _ = app_handle.emit(
                            "saml-url",
                            serde_json::json!({ "url": url }),
                        );
                        let _ = app_handle.emit(
                            "connection-status-changed",
                            ConnectionStatusPayload {
                                state: "WaitingSaml".into(),
                                profile_id: Some(profile_id.clone()),
                                ip: None,
                                since: None,
                                message: Some(url),
                            },
                        );
                    }
                } else if trimmed.contains("certificate") && trimmed.contains("digest") {
                    // Try to extract cert digest for trusted cert flow
                    if let Some(digest) = extract_cert_digest(&trimmed) {
                        let _ = app_handle.emit(
                            "cert-warning",
                            serde_json::json!({
                                "digest": digest,
                                "profile_id": profile_id.clone()
                            }),
                        );
                    }
                }
            }
            Err(e) => {
                log::error!("Error reading log file: {}", e);
                // Try to recover by seeking to current position
                let _ = reader.get_mut().seek(SeekFrom::Current(0));
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
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
