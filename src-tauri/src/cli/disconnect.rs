//! `vpnconnect disconnect`: encerra a sessão conectada ou o login pendente, venha de onde vier.
//! Sem sessão, não é erro: sai com 0 e avisa na stderr.

use std::time::{Duration, Instant};

use serde_json::json;

use super::{status, CliError, Out};
use crate::helper_client::{self, Channel};

/// Quanto esperar pelo `disconnected` depois de pedir o `disconnect`.
const WAIT: Duration = Duration::from_secs(30);

pub fn run(out: &Out) -> Result<(), CliError> {
    let mut channel = Channel::open(&helper_client::socket_path())?;
    let current = channel.request(&helper_client::status_request())?;
    if current["state"] == "disconnected" {
        eprintln!("No active session");
        status::print(out, current);
        return Ok(());
    }
    channel.request(&json!({"v": 2, "cmd": "disconnect"}))?;
    let deadline = Instant::now() + WAIT;
    while let Some(frame) = channel.next(deadline.saturating_duration_since(Instant::now()))? {
        if frame["event"] == "state" && frame["state"] == "disconnected" {
            status::print(out, frame);
            return Ok(());
        }
    }
    // O `disconnected` pode ter saído antes da resposta ao `disconnect`, e aí foi descartado.
    let current = channel.request(&helper_client::status_request())?;
    if current["state"] == "disconnected" {
        status::print(out, current);
        return Ok(());
    }
    Err(CliError::refused("TIMEOUT", format!("The session is still {} after {} s", current["state"], WAIT.as_secs())))
}
