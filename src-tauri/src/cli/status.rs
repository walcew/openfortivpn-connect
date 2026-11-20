//! `vpnconnect status`: o estado da sessão no Helper, o mesmo que a GUI vê.

use serde_json::{json, Value};

use super::{output, CliError, Out};
use crate::helper_client;
use crate::profile_store::ProfileStore;

pub fn run(out: &Out) -> Result<(), CliError> {
    print(out, helper_client::status_frame(&helper_client::socket_path())?);
    Ok(())
}

/// Imprime um estado do Helper (resposta do `status` ou evento `state`) no formato do `status`.
pub fn print(out: &Out, mut state: Value) {
    // Sai só o estado: o envelope (`v`, `type`, `ok`, `event`) é do protocolo.
    if let Some(fields) = state.as_object_mut() {
        for envelope in ["v", "type", "ok", "event"] {
            fields.remove(envelope);
        }
    }
    state["profile"] = profile(state["profile_id"].as_str());
    out.emit(&state, || print_human(&state));
}

/// O Profile da sessão, como a GUI o acha: pelo `profile_id` que o Helper manda nos estados de
/// uma sessão ativa. Sem sessão não há `profile_id`, e o Profile é null.
pub(super) fn profile(id: Option<&str>) -> Value {
    let Some(id) = id else { return Value::Null };
    // Um profiles.json ilegível não derruba o status: o Profile só fica sem nome.
    let name = ProfileStore::new().and_then(|s| s.get_by_id(id)).ok().flatten().map(|p| p.name);
    json!({"id": id, "name": name})
}

fn print_human(state: &Value) {
    let profile = &state["profile"];
    let profile = match profile["name"].as_str() {
        Some(name) => Value::from(format!("{name} ({})", profile["id"].as_str().unwrap_or_default())),
        None => profile["id"].clone(),
    };
    let rows = [
        ("State", &state["state"]),
        ("Profile", &profile),
        ("IP", &state["ip"]),
        ("Since", &state["since"]),
        ("Expires", &state["expires_at"]),
        ("DNS servers", &state["dns_servers"]),
        ("DNS suffixes", &state["dns_suffixes"]),
        ("Login URL", &state["url"]),
        ("Reason", &state["reason"]),
        ("Cause", &state["cause"]),
        ("Certificate", &state["cert_digest"]),
    ];
    for (label, value) in rows {
        if let Some(text) = output::text(value) {
            println!("{:<13} {text}", format!("{label}:"));
        }
    }
}
