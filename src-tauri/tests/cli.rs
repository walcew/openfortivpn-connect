//! A CLI `vpnconnect` de ponta a ponta: roda o executável real do app com argumentos e
//! `VPNCONNECT_TEST_HOME` (só no build de debug), que troca o diretório de config, o Keychain
//! e o socket do Helper pelos de um diretório temporário, diante de um Helper falso. Confere
//! stdout, stderr, código de saída e os requests que chegaram ao socket.

mod fake_helper;

use std::path::PathBuf;
use std::process::{Command, Output};

use fake_helper::{unauthorized, FakeHelper};
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_openvpngui");

/// O diretório de teste de um caso, apagado no fim.
struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        // Curto: o caminho do socket do Unix tem limite de ~100 bytes.
        let dir = std::env::temp_dir().join(format!("vpnc-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("helper.sock")
    }

    fn profiles(&self, profiles: Value) {
        std::fs::write(self.0.join("profiles.json"), profiles.to_string()).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN).args(args).env("VPNCONNECT_TEST_HOME", &self.0).output().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A stdout de um `--json`: exatamente uma linha de JSON.
fn json_out(out: &Output) -> Value {
    let stdout = text(&out.stdout);
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    serde_json::from_str(&stdout).unwrap()
}

fn profile(id: &str, name: &str) -> Value {
    json!({"id": id, "name": name, "host": "vpn.example.com", "port": 443, "auth_type": "Password",
           "username": "alice", "realm": null, "trusted_certs": [], "extra_args": []})
}

fn connected() -> Value {
    json!({"state": "connected", "profile_id": "p1", "ip": "10.0.0.2", "since": "2026-01-01T10:00:00Z",
           "dns_servers": ["10.0.0.1"], "dns_suffixes": ["corp.example.com"], "expires_at": "2026-01-01T18:00:00Z"})
}

#[test]
fn version_shows_the_app_version() {
    let out = Home::new().run(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out.stdout).trim(), format!("vpnconnect {}", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_exits_zero() {
    let out = Home::new().run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("status"), "{}", text(&out.stdout));
}

#[test]
fn status_json_is_the_helper_state_plus_the_profile() {
    let home = Home::new();
    home.profiles(json!([profile("p1", "Corp")]));
    let helper = FakeHelper::with_state(&home.socket(), connected());

    let out = home.run(&["status", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mut expected = connected();
    expected["profile"] = json!({"id": "p1", "name": "Corp"});
    assert_eq!(json_out(&out), expected);
    assert_eq!(helper.requests(), [json!({"v": 2, "cmd": "status"})]);
}

#[test]
fn status_json_while_disconnected_has_no_profile() {
    let home = Home::new();
    let state = json!({"state": "disconnected", "reason": "Session expired", "cause": "expired"});
    let _helper = FakeHelper::with_state(&home.socket(), state.clone());

    let out = home.run(&["--json", "status"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mut expected = state;
    expected["profile"] = Value::Null;
    assert_eq!(json_out(&out), expected);
}

#[test]
fn status_json_keeps_the_id_of_a_profile_that_no_longer_exists() {
    let home = Home::new();
    let _helper = FakeHelper::with_state(&home.socket(), connected());
    let out = home.run(&["status", "--json"]);
    assert_eq!(json_out(&out)["profile"], json!({"id": "p1", "name": null}));
}

#[test]
fn status_text_shows_state_ip_since_expiry_dns_and_profile() {
    let home = Home::new();
    home.profiles(json!([profile("p1", "Corp")]));
    let _helper = FakeHelper::with_state(&home.socket(), connected());

    let out = home.run(&["status"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for expected in ["connected", "Corp", "10.0.0.2", "2026-01-01T10:00:00Z", "2026-01-01T18:00:00Z", "10.0.0.1", "corp.example.com"] {
        assert!(stdout.contains(expected), "missing {expected} in:\n{stdout}");
    }
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
}

#[test]
fn status_text_shows_why_the_session_went_down() {
    let home = Home::new();
    let _helper = FakeHelper::with_state(&home.socket(), json!({"state": "disconnected", "reason": "Tunnel dropped", "cause": "tunnel-dropped"}));
    let stdout = text(&home.run(&["status"]).stdout);
    for expected in ["disconnected", "Tunnel dropped", "tunnel-dropped"] {
        assert!(stdout.contains(expected), "missing {expected} in:\n{stdout}");
    }
}

#[test]
fn status_without_a_helper_fails_with_255_and_a_structured_error() {
    let out = Home::new().run(&["status", "--json"]);
    assert_eq!(out.status.code(), Some(255));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    let err: Value = serde_json::from_str(text(&out.stderr).trim()).unwrap();
    assert_eq!(err["error"]["code"], "HELPER_UNAVAILABLE");
    assert!(err["error"]["message"].as_str().unwrap().contains("Helper"), "{err}");
}

#[test]
fn status_without_a_helper_prints_only_the_message_without_json() {
    let out = Home::new().run(&["status"]);
    assert_eq!(out.status.code(), Some(255));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("Helper") && !stderr.contains("{"), "{stderr}");
}

#[test]
fn status_refused_by_the_helper_fails_with_255() {
    let home = Home::new();
    let _helper = FakeHelper::start(&home.socket(), json!({"state": "disconnected"}), |_| vec![unauthorized()]);
    let out = home.run(&["status", "--json"]);
    assert_eq!(out.status.code(), Some(255));
    let err: Value = serde_json::from_str(text(&out.stderr).trim()).unwrap();
    assert_eq!(err["error"]["code"], "HELPER_UNAUTHORIZED");
}

#[test]
fn unknown_argument_fails_with_255_and_the_envelope_under_json() {
    let out = Home::new().run(&["statu", "--json"]);
    assert_eq!(out.status.code(), Some(255));
    let err: Value = serde_json::from_str(text(&out.stderr).trim()).unwrap();
    assert_eq!(err["error"]["code"], "CLI_ERROR");
}
