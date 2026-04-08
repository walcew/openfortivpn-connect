mod handlers;
mod protocol;
mod server;
mod validation;

use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!(
        "openvpngui-helper v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Run server with graceful shutdown on SIGTERM/SIGINT
    tokio::select! {
        result = server::run() => {
            if let Err(e) = result {
                log::error!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown_signal() => {
            log::info!("Shutdown signal received, cleaning up");
            // Remove socket file on clean shutdown
            let socket_path = Path::new(server::SOCKET_PATH);
            if socket_path.exists() {
                let _ = fs::remove_file(socket_path);
            }
        }
    }

    log::info!("openvpngui-helper stopped");
}

async fn shutdown_signal() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => log::info!("Received SIGTERM"),
        _ = sigint.recv() => log::info!("Received SIGINT"),
    }
}
