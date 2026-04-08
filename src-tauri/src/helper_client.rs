use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::Deserialize;

const SOCKET_PATH: &str = "/var/run/openvpngui-helper.sock";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub error: Option<String>,
    pub pid: Option<u32>,
    pub version: Option<String>,
}

fn send_request(json: &str) -> Result<HelperResponse, String> {
    let stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("Failed to connect to helper socket: {}", e))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    let mut stream_ref = &stream;
    write!(stream_ref, "{}\n", json)
        .map_err(|e| format!("Failed to send request: {}", e))?;
    stream_ref
        .flush()
        .map_err(|e| format!("Failed to flush: {}", e))?;

    // Shutdown write half so the server knows we're done sending
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("Failed to shutdown write: {}", e))?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let response: HelperResponse = serde_json::from_str(line.trim())
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "Unknown helper error".to_string()));
    }

    Ok(response)
}

/// Check if the helper daemon is reachable.
pub fn is_available() -> bool {
    ping().is_ok()
}

/// Ping the helper and return its version.
pub fn ping() -> Result<String, String> {
    let resp = send_request(r#"{"cmd":"ping"}"#)?;
    Ok(resp.version.unwrap_or_else(|| "unknown".to_string()))
}

/// Spawn openfortivpn via the helper. Returns the PID.
pub fn spawn_vpn(args: &[String], log_path: &str) -> Result<u32, String> {
    let request = serde_json::json!({
        "cmd": "spawn-vpn",
        "args": args,
        "log_path": log_path,
    });
    let resp = send_request(&request.to_string())?;
    resp.pid
        .ok_or_else(|| "Helper did not return PID".to_string())
}

/// Kill openfortivpn and perform full cleanup via the helper.
pub fn kill_vpn(pid: u32, gateway: Option<&str>) -> Result<(), String> {
    let request = serde_json::json!({
        "cmd": "kill-vpn",
        "pid": pid,
        "gateway": gateway,
    });
    send_request(&request.to_string())?;
    Ok(())
}

/// Configure macOS DNS via the helper.
pub fn setup_dns(servers: &[String], suffix: Option<&str>) -> Result<(), String> {
    let request = serde_json::json!({
        "cmd": "setup-dns",
        "servers": servers,
        "suffix": suffix,
    });
    send_request(&request.to_string())?;
    Ok(())
}

/// Remove VPN DNS configuration via the helper.
pub fn teardown_dns() -> Result<(), String> {
    send_request(r#"{"cmd":"teardown-dns"}"#)?;
    Ok(())
}
