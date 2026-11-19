use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::Deserialize;

pub const SOCKET_PATH: &str = "/var/run/openvpngui-helper.sock";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub error: Option<String>,
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

/// Ping the helper and return its version.
pub fn ping() -> Result<String, String> {
    let resp = send_request(r#"{"cmd":"ping"}"#)?;
    Ok(resp.version.unwrap_or_else(|| "unknown".to_string()))
}
