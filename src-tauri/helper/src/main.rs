mod handlers;
mod protocol;
mod server;
mod validation;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!(
        "openvpngui-helper v{} starting",
        env!("CARGO_PKG_VERSION")
    );
    // TODO: will be filled in Task 5
}
