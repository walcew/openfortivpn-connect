//! `vpnconnect watch`: os eventos do Helper em NDJSON até Ctrl-C (que sai com 130, pelo tratador
//! de `cli::main`). Se o socket cai ou não existe, emite `reconnecting` e tenta de novo, como
//! a GUI; só a recusa do uid desiste, porque tentar de novo não adianta.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use super::{status, CliError};
use crate::helper_client::{self, Channel, HelperError};

/// Quanto esperar por um quadro antes de olhar de novo; só evita um prazo infinito no socket.
const IDLE: Duration = Duration::from_secs(3600);

pub fn run() -> Result<(), CliError> {
    let socket = helper_client::socket_path();
    let mut delay = helper_client::RECONNECT_MIN;
    loop {
        if let HelperError::Unauthorized = stream(&socket, &mut delay)? {
            return Err(HelperError::Unauthorized.into());
        }
        emit(&json!({"event": "reconnecting", "in_ms": delay.as_millis() as u64}))?;
        std::thread::sleep(delay);
        delay = helper_client::next_delay(delay);
    }
}

/// Abre o socket e emite os eventos até ele cair; devolve o motivo. O `delay` volta ao mínimo
/// a cada evento, então só falhas seguidas o fazem crescer. `Err` só se a stdout fechou.
fn stream(socket: &Path, delay: &mut Duration) -> Result<HelperError, CliError> {
    let mut channel = match Channel::open(socket) {
        Ok(c) => c,
        Err(e) => return Ok(e),
    };
    // O Helper começa pelo estado atual depois do primeiro request; o `status` é só esse gatilho.
    if let Err(e) = channel.send(&helper_client::status_request()) {
        return Ok(e);
    }
    loop {
        let mut frame = match channel.next(IDLE) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(e) => return Ok(e),
        };
        if helper_client::is_uid_refusal(&frame) {
            return Ok(HelperError::Unauthorized);
        }
        // A resposta ao `status` repete o estado que o evento já trouxe.
        if frame["type"] != "event" {
            continue;
        }
        if let Some(fields) = frame.as_object_mut() {
            fields.remove("v");
            fields.remove("type");
        }
        if frame["event"] == "state" {
            frame["profile"] = status::profile(frame["profile_id"].as_str());
        }
        emit(&frame)?;
        *delay = helper_client::RECONNECT_MIN;
    }
}

/// Uma linha de JSON na stdout, já enviada: quem lê reage a ela sem esperar a próxima.
fn emit(line: &Value) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|e| CliError::cli(format!("Cannot write to stdout: {e}")))
}
