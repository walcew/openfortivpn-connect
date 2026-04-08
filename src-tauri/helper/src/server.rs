use std::fs;
use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::handlers;
use crate::protocol::Request;

pub const SOCKET_PATH: &str = "/var/run/openvpngui-helper.sock";

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Remove stale socket file if it exists
    let socket_path = Path::new(SOCKET_PATH);
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set socket permissions: world read/write so unprivileged Tauri app can connect.
    // This is safe because the protocol validates all commands.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666))?;
    }

    log::info!("Listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        log::error!("Connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // Read exactly one line (one JSON request per connection)
    buf_reader.read_line(&mut line).await?;
    let trimmed = line.trim();

    if trimmed.is_empty() {
        return Ok(());
    }

    log::debug!("Received: {}", trimmed);

    let response = match serde_json::from_str::<Request>(trimmed) {
        Ok(request) => {
            // Run handler in blocking task since some handlers do I/O
            tokio::task::spawn_blocking(move || handlers::handle(request))
                .await
                .unwrap_or_else(|e| {
                    crate::protocol::Response::error(format!("Handler panicked: {}", e))
                })
        }
        Err(e) => crate::protocol::Response::error(format!("Invalid request: {}", e)),
    };

    let response_json = serde_json::to_string(&response)?;
    log::debug!("Responding: {}", response_json);

    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    Ok(())
}
