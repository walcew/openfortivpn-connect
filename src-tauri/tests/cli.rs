//! A CLI `vpnconnect` de ponta a ponta: roda o executável real do app com argumentos e
//! `VPNCONNECT_TEST_HOME` (só no build de debug), que troca o diretório de config, o Keychain
//! e o socket do Helper pelos de um diretório temporário, diante de um Helper falso. Confere
//! stdout, stderr, código de saída e os requests que chegaram ao socket.

mod fake_helper;

use std::path::PathBuf;
use std::process::{Command, Output};

use fake_helper::{event, hang_up, refusal, response, state, unauthorized, FakeHelper};
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

    fn settings(&self, settings: Value) {
        std::fs::write(self.0.join("settings.json"), settings.to_string()).unwrap();
    }

    /// A senha do Profile no Keychain em arquivo do test home.
    fn password(&self, id: &str, password: &str) {
        std::fs::create_dir_all(self.0.join("keychain")).unwrap();
        std::fs::write(self.0.join("keychain").join(format!("vpn-{id}")), password).unwrap();
    }

    /// As URLs que a CLI mandou abrir no navegador (no test home, o `open` só as registra).
    fn opened_urls(&self) -> Vec<String> {
        std::fs::read_to_string(self.0.join("opened-urls")).unwrap_or_default().lines().map(str::to_string).collect()
    }

    /// O que a CLI gravou em `profiles.json`; array vazio se o arquivo não existe.
    fn stored_profiles(&self) -> Value {
        std::fs::read_to_string(self.0.join("profiles.json")).map_or(json!([]), |s| serde_json::from_str(&s).unwrap())
    }

    fn stored_settings(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.0.join("settings.json")).unwrap()).unwrap()
    }

    /// A senha do Profile no Keychain em arquivo, se houver.
    fn stored_password(&self, id: &str) -> Option<String> {
        std::fs::read_to_string(self.0.join("keychain").join(format!("vpn-{id}"))).ok()
    }

    /// Roda com `input` na stdin.
    fn run_with_stdin(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write;
        let mut child = self.command(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args).env("VPNCONNECT_TEST_HOME", &self.0);
        cmd
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

/// O erro `--json` da stderr.
fn json_err(out: &Output) -> Value {
    serde_json::from_str(text(&out.stderr).lines().last().unwrap_or_default()).unwrap_or_else(|_| panic!("stderr: {}", text(&out.stderr)))
}

fn connected_event() -> Value {
    state(connected())
}

/// Home com o Profile `p1` "Corp" (senha "s3cret") e o `profiles` extra.
fn home_with_corp(extra: &[Value]) -> Home {
    let home = Home::new();
    let mut profiles = vec![profile("p1", "Corp")];
    profiles.extend_from_slice(extra);
    home.profiles(json!(profiles));
    home.password("p1", "s3cret");
    home
}

#[test]
fn connect_with_password_waits_for_connected_and_prints_the_status() {
    let home = home_with_corp(&[]);
    home.settings(json!({"dns_fallback": false}));
    let helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "connecting", "profile_id": "p1"})), connected_event()]);

    let out = home.run(&["connect", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mut expected = connected();
    expected["profile"] = json!({"id": "p1", "name": "Corp"});
    assert_eq!(json_out(&out), expected);
    let connect = helper.requests().into_iter().find(|r| r["cmd"] == "connect").unwrap();
    assert_eq!(connect["password"], "s3cret");
    assert_eq!(connect["profile"]["username"], "alice");
    assert_eq!(connect["profile"]["dns_fallback_servers"], json!([]));
    assert_eq!(connect["otp"], Value::Null);
    // Conectado, o fim do processo não derruba a sessão.
    assert!(!helper.commands().contains(&"disconnect".to_string()), "{:?}", helper.commands());
}

fn otp_profile(id: &str, name: &str) -> Value {
    let mut p = profile(id, name);
    p["otp_required"] = json!(true);
    p
}

fn saml_profile(id: &str, name: &str) -> Value {
    let mut p = profile(id, name);
    p["auth_type"] = json!("Saml");
    p["username"] = Value::Null;
    p
}

fn connect_request(helper: &FakeHelper) -> Value {
    helper.requests().into_iter().find(|r| r["cmd"] == "connect").expect("no connect request")
}

#[test]
fn connect_without_the_required_otp_fails_before_talking_to_the_helper() {
    let home = home_with_corp(&[otp_profile("p2", "Token")]);
    home.password("p2", "s3cret");
    let helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);

    let out = home.run(&["connect", "Token", "--json"]);

    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert_eq!(json_err(&out)["error"]["code"], "OTP_REQUIRED");
    assert!(helper.requests().is_empty(), "{:?}", helper.requests());
}

#[test]
fn connect_sends_the_otp() {
    let home = home_with_corp(&[otp_profile("p2", "Token")]);
    home.password("p2", "s3cret");
    let helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);

    let out = home.run(&["connect", "Token", "--otp", " 123456 "]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(connect_request(&helper)["otp"], "123456");
}

#[test]
fn connect_waiting_for_push_says_so_on_stderr() {
    let home = home_with_corp(&[]);
    let _helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "waiting-push", "profile_id": "p1"})), connected_event()]);

    let out = home.run(&["connect", "Corp"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("approve the FortiToken push on your phone"), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("10.0.0.2"), "{}", text(&out.stdout));
}

const SAML_URL: &str = "https://vpn.example.com/remote/saml/start?redirect=1";

fn saml_helper(home: &Home) -> FakeHelper {
    FakeHelper::idle(&home.socket(), vec![state(json!({"state": "waiting-saml", "profile_id": "p3", "url": SAML_URL})), connected_event()])
}

#[test]
fn connect_saml_opens_the_browser_and_prints_the_url() {
    let home = home_with_corp(&[saml_profile("p3", "Sso")]);
    let helper = saml_helper(&home);

    let out = home.run(&["connect", "Sso", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains(SAML_URL), "{}", text(&out.stderr));
    assert_eq!(home.opened_urls(), [SAML_URL]);
    let connect = connect_request(&helper);
    assert_eq!(connect["profile"]["auth"], "saml");
    assert!(connect.get("password").is_none(), "{connect}");
}

#[test]
fn connect_saml_with_no_browser_only_prints_the_url() {
    let home = home_with_corp(&[saml_profile("p3", "Sso")]);
    let _helper = saml_helper(&home);

    let out = home.run(&["connect", "Sso", "--no-browser"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains(SAML_URL), "{}", text(&out.stderr));
    assert!(home.opened_urls().is_empty(), "{:?}", home.opened_urls());
}

#[test]
fn connect_with_an_untrusted_certificate_fails_with_the_digest() {
    let home = home_with_corp(&[]);
    let digest = "ab".repeat(32);
    let reason = format!("TLS handshake failed: untrusted certificate (sha256 {digest})");
    let _helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "disconnected", "reason": reason, "cert_digest": digest}))]);

    let out = home.run(&["connect", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(1));
    let err = json_err(&out);
    assert_eq!(err["error"]["code"], "CERT_UNTRUSTED");
    assert_eq!(err["error"]["cert_digest"], digest);
}

#[test]
fn connect_with_a_wrong_password_fails_with_login_failed() {
    let home = home_with_corp(&[]);
    let _helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "disconnected", "reason": "Login failed: invalid username or password"}))]);

    let out = home.run(&["connect", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(1));
    let err = json_err(&out);
    assert_eq!(err["error"]["code"], "LOGIN_FAILED");
    assert!(err["error"]["message"].as_str().unwrap().contains("invalid username or password"), "{err}");
}

#[test]
fn connect_failing_for_another_reason_fails_with_connect_failed() {
    let home = home_with_corp(&[]);
    let _helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "disconnected", "reason": "Failed to apply route"}))]);
    let out = home.run(&["connect", "Corp", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_err(&out)["error"]["code"], "CONNECT_FAILED");
}

#[test]
fn connect_cancelled_by_another_client_fails_with_connect_cancelled() {
    let home = home_with_corp(&[]);
    let _helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "connecting", "profile_id": "p1"})), state(json!({"state": "disconnected"}))]);
    let out = home.run(&["connect", "Corp", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_err(&out)["error"]["code"], "CONNECT_CANCELLED");
}

#[test]
fn connect_timeout_cancels_the_login() {
    let home = home_with_corp(&[]);
    let helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "connecting", "profile_id": "p1"}))]);

    let out = home.run(&["connect", "Corp", "--timeout", "1", "--json"]);

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_err(&out)["error"]["code"], "TIMEOUT");
    assert_eq!(helper.commands().last().map(String::as_str), Some("disconnect"), "{:?}", helper.commands());
}

#[test]
fn ctrl_c_during_connect_cancels_the_login_and_exits_130() {
    let home = home_with_corp(&[]);
    let helper = FakeHelper::idle(&home.socket(), vec![state(json!({"state": "connecting", "profile_id": "p1"}))]);
    let child = home.command(&["connect", "Corp"]).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();

    helper.wait_for("connect");
    // SAFETY: SIGINT ao filho que este teste criou.
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let out = child.wait_with_output().unwrap();

    assert_eq!(out.status.code(), Some(130), "{}", text(&out.stderr));
    assert_eq!(helper.commands().last().map(String::as_str), Some("disconnect"), "{:?}", helper.commands());
}

#[test]
fn connect_with_a_session_already_active_is_refused() {
    let home = home_with_corp(&[]);
    let helper = FakeHelper::with_state(&home.socket(), connected());

    let out = home.run(&["connect", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_err(&out)["error"]["code"], "SESSION_ACTIVE");
    assert!(!helper.commands().contains(&"connect".to_string()), "{:?}", helper.commands());
}

#[test]
fn connect_refused_by_the_helper_fails_with_1() {
    let home = home_with_corp(&[]);
    let idle = json!({"state": "disconnected"});
    let _helper = FakeHelper::start(&home.socket(), idle.clone(), move |req| match req["cmd"].as_str() {
        Some("status") => vec![response(idle.clone())],
        Some("version") => vec![response(json!({"version": env!("CARGO_PKG_VERSION")}))],
        _ => vec![refusal("Invalid profile: bad host")],
    });

    let out = home.run(&["connect", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(1));
    let err = json_err(&out);
    assert_eq!(err["error"]["code"], "HELPER_REFUSED");
    assert!(err["error"]["message"].as_str().unwrap().contains("bad host"), "{err}");
}

#[test]
fn connect_without_a_helper_fails_with_255_and_points_to_helper_install() {
    let out = home_with_corp(&[]).run(&["connect", "Corp", "--json"]);
    assert_eq!(out.status.code(), Some(255));
    let err = json_err(&out);
    assert_eq!(err["error"]["code"], "HELPER_NOT_INSTALLED");
    assert!(err["error"]["message"].as_str().unwrap().contains("vpnconnect helper install"), "{err}");
}

#[test]
fn connect_with_an_outdated_helper_fails_with_255_and_points_to_helper_install() {
    let home = home_with_corp(&[]);
    let helper = FakeHelper::start(&home.socket(), json!({"state": "disconnected"}), |_| vec![response(json!({"version": "0.3.0"}))]);

    let out = home.run(&["connect", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(255));
    let err = json_err(&out);
    assert_eq!(err["error"]["code"], "HELPER_OUTDATED");
    assert!(err["error"]["message"].as_str().unwrap().contains("vpnconnect helper install"), "{err}");
    assert_eq!(helper.commands(), ["version"]);
}

#[test]
fn connect_sends_the_system_dns_when_the_fallback_is_on() {
    let home = home_with_corp(&[]);
    home.settings(json!({"dns_fallback": true}));
    let helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);

    assert_eq!(home.run(&["connect", "Corp"]).status.code(), Some(0));

    // O DNS do sistema varia por máquina: confere que veio o que o `scutil --dns` mostra.
    let scutil = text(&Command::new("scutil").arg("--dns").output().unwrap().stdout);
    let servers = connect_request(&helper)["profile"]["dns_fallback_servers"].clone();
    for server in servers.as_array().unwrap() {
        assert!(scutil.contains(server.as_str().unwrap()), "{server} not in scutil --dns");
    }
}

#[test]
fn connect_warns_about_extra_args_on_stderr() {
    let mut legacy = profile("p4", "Legacy");
    legacy["extra_args"] = json!(["--set-dns=0"]);
    let home = home_with_corp(&[legacy]);
    home.password("p4", "s3cret");
    let _helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);

    let out = home.run(&["connect", "Legacy", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("extra_args"), "{}", text(&out.stderr));
    json_out(&out);
}

#[test]
fn connect_without_a_stored_password_is_refused() {
    let home = Home::new();
    home.profiles(json!([profile("p1", "Corp")]));
    let helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);
    let out = home.run(&["connect", "Corp", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_err(&out)["error"]["code"], "CREDENTIALS_MISSING");
    assert!(helper.requests().is_empty());
}

#[test]
fn connect_targets_a_profile_by_id() {
    let home = home_with_corp(&[]);
    let helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);
    assert_eq!(home.run(&["connect", "p1"]).status.code(), Some(0));
    assert_eq!(connect_request(&helper)["profile"]["id"], "p1");
}

#[test]
fn connect_refuses_a_partial_name() {
    let home = home_with_corp(&[]);
    let _helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);
    let out = home.run(&["connect", "Cor", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_err(&out)["error"]["code"], "PROFILE_NOT_FOUND");
}

#[test]
fn connect_refuses_an_ambiguous_name() {
    let home = home_with_corp(&[profile("p5", "Corp")]);
    let helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);
    let out = home.run(&["connect", "Corp", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_err(&out)["error"]["code"], "PROFILE_AMBIGUOUS");
    assert!(helper.requests().is_empty());
}

#[test]
fn password_is_never_accepted_as_an_argument() {
    let home = home_with_corp(&[]);
    let out = home.run(&["connect", "Corp", "--password", "s3cret", "--json"]);
    assert_eq!(out.status.code(), Some(255));
    assert_eq!(json_err(&out)["error"]["code"], "CLI_ERROR");
}

/// Helper com a sessão em `current` que, no `disconnect`, responde e emite `disconnected`.
fn session_helper(home: &Home, current: Value) -> FakeHelper {
    FakeHelper::start(&home.socket(), current.clone(), move |req| match req["cmd"].as_str() {
        Some("status") => vec![response(current.clone())],
        Some("disconnect") => vec![response(json!({})), state(json!({"state": "disconnected"}))],
        _ => vec![response(json!({}))],
    })
}

#[test]
fn disconnect_ends_a_connected_session() {
    let home = Home::new();
    let helper = session_helper(&home, connected());

    let out = home.run(&["disconnect", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(json_out(&out), json!({"state": "disconnected", "profile": null}));
    assert_eq!(helper.commands(), ["status", "disconnect"]);
}

#[test]
fn disconnect_cancels_a_pending_login() {
    let home = Home::new();
    let helper = session_helper(&home, json!({"state": "waiting-saml", "profile_id": "p1", "url": SAML_URL}));

    let out = home.run(&["disconnect"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("disconnected"), "{}", text(&out.stdout));
    assert_eq!(helper.commands(), ["status", "disconnect"]);
}

#[test]
fn disconnect_without_a_session_exits_0_with_a_notice() {
    let home = Home::new();
    let helper = FakeHelper::with_state(&home.socket(), json!({"state": "disconnected"}));

    let out = home.run(&["disconnect", "--json"]);

    assert_eq!(out.status.code(), Some(0));
    assert_eq!(json_out(&out), json!({"state": "disconnected", "profile": null}));
    assert!(text(&out.stderr).contains("No active session"), "{}", text(&out.stderr));
    assert_eq!(helper.commands(), ["status"]);
}

#[test]
fn disconnect_without_a_helper_fails_with_255() {
    let out = Home::new().run(&["disconnect", "--json"]);
    assert_eq!(out.status.code(), Some(255));
    assert_eq!(json_err(&out)["error"]["code"], "HELPER_UNAVAILABLE");
}

/// Um `vpnconnect watch` em andamento: as linhas da stdout chegam por um canal, com prazo, para
/// um teste que falha não ficar preso. O filho morre junto com o teste.
struct Watch {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Watch {
    fn spawn(home: &Home, args: &[&str]) -> Self {
        let mut child = home.command(args).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in stdout.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    /// A próxima linha da stdout, como JSON.
    fn next(&self) -> Value {
        let line = self.lines.recv_timeout(std::time::Duration::from_secs(10)).expect("no line on stdout in 10 s");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"))
    }

    /// Ctrl-C no filho e o código de saída dele.
    fn interrupt(mut self) -> Option<i32> {
        // SAFETY: SIGINT ao filho que este teste criou.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGINT) };
        self.child.wait().unwrap().code()
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn watch_streams_each_helper_event_as_one_json_line_with_or_without_json() {
    for args in [&["watch"][..], &["watch", "--json"][..]] {
        let home = Home::new();
        home.profiles(json!([profile("p1", "Corp")]));
        let _helper = FakeHelper::start(&home.socket(), connected(), |req| match req["cmd"].as_str() {
            Some("status") => vec![
                response(connected()),
                event(json!({"event": "log", "line": "Tunnel is up"})),
                event(json!({"event": "bandwidth", "rx_bytes": 10, "tx_bytes": 20})),
                event(json!({"event": "expiring", "expires_at": "2026-01-01T18:00:00Z"})),
            ],
            _ => vec![response(json!({}))],
        });

        let watch = Watch::spawn(&home, args);

        let mut state = connected();
        state["event"] = json!("state");
        state["profile"] = json!({"id": "p1", "name": "Corp"});
        assert_eq!(watch.next(), state, "{args:?}");
        assert_eq!(watch.next(), json!({"event": "log", "line": "Tunnel is up"}));
        assert_eq!(watch.next(), json!({"event": "bandwidth", "rx_bytes": 10, "tx_bytes": 20}));
        assert_eq!(watch.next(), json!({"event": "expiring", "expires_at": "2026-01-01T18:00:00Z"}));
        assert_eq!(watch.interrupt(), Some(130));
    }
}

#[test]
fn watch_reconnects_when_the_helper_closes_the_socket_and_emits_the_current_state_again() {
    let home = Home::new();
    let sessions = std::sync::atomic::AtomicUsize::new(0);
    let _helper = FakeHelper::start(&home.socket(), json!({"state": "disconnected"}), move |req| {
        if req["cmd"] != "status" {
            return vec![response(json!({}))];
        }
        // A primeira conexão cai depois de um log; a segunda segue aberta.
        match sessions.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
            0 => vec![response(json!({})), event(json!({"event": "log", "line": "before"})), hang_up()],
            _ => vec![response(json!({})), event(json!({"event": "log", "line": "after"}))],
        }
    });

    let watch = Watch::spawn(&home, &["watch"]);

    assert_eq!(watch.next(), json!({"event": "state", "state": "disconnected", "profile": null}));
    assert_eq!(watch.next(), json!({"event": "log", "line": "before"}));
    assert_eq!(watch.next(), json!({"event": "reconnecting", "in_ms": 1000}));
    assert_eq!(watch.next(), json!({"event": "state", "state": "disconnected", "profile": null}));
    assert_eq!(watch.next(), json!({"event": "log", "line": "after"}));
}

#[test]
fn watch_without_a_helper_keeps_trying_and_streams_once_it_is_up() {
    let home = Home::new();
    let watch = Watch::spawn(&home, &["watch", "--json"]);

    assert_eq!(watch.next(), json!({"event": "reconnecting", "in_ms": 1000}));
    let _helper = FakeHelper::with_state(&home.socket(), json!({"state": "disconnected"}));

    assert_eq!(watch.next(), json!({"event": "state", "state": "disconnected", "profile": null}));
}

#[test]
fn watch_refused_by_the_helper_fails_with_255_without_retrying() {
    let home = Home::new();
    let _helper = FakeHelper::start(&home.socket(), json!({"state": "disconnected"}), |_| vec![unauthorized()]);

    let out = home.run(&["watch", "--json"]);

    assert_eq!(out.status.code(), Some(255));
    assert_eq!(json_err(&out)["error"]["code"], "HELPER_UNAUTHORIZED");
    assert!(!text(&out.stdout).contains("reconnecting"), "{}", text(&out.stdout));
}

// --- profile e settings ---

const DIGEST: &str = "aa11bb22cc33dd44ee55ff6600770088aa11bb22cc33dd44ee55ff6600770088";

fn assert_refused(out: &Output, exit: i32, code: &str) {
    assert_eq!(out.status.code(), Some(exit), "stderr: {}", text(&out.stderr));
    assert_eq!(json_err(out)["error"]["code"], code);
}

/// O Profile `p1` completo, como a GUI o grava, para conferir o que a CLI preserva.
fn full_profile() -> Value {
    json!({"id": "p1", "name": "Corp", "host": "vpn.example.com", "port": 443, "auth_type": "Password",
           "username": "alice", "otp_required": true, "realm": "corp", "trusted_certs": [DIGEST],
           "ignore_cert_errors": true, "dns_match_domains": ["corp.example.com"], "extra_args": ["--set-dns=0"]})
}

#[test]
fn profile_ls_lists_the_profiles_as_a_json_array_and_as_a_table() {
    let home = home_with_corp(&[profile("p2", "Other")]);

    let out = home.run(&["profile", "ls", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let list = json_out(&out);
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(list[0]["id"], "p1");
    assert_eq!(list[0]["has_password"], true);
    assert_eq!(list[1]["has_password"], false);

    let out = home.run(&["profile", "ls"]);
    let table = text(&out.stdout);
    assert!(table.lines().next().unwrap().contains("NAME"), "{table}");
    assert!(table.contains("Corp") && table.contains("Other") && table.contains("vpn.example.com"), "{table}");
}

#[test]
fn profile_ls_without_profiles_is_an_empty_array() {
    let out = Home::new().run(&["profile", "ls", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(json_out(&out), json!([]));
}

#[test]
fn profile_show_prints_every_field_but_never_the_password_or_extra_args() {
    let home = Home::new();
    home.profiles(json!([full_profile()]));
    home.password("p1", "s3cret");

    let out = home.run(&["profile", "show", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(json_out(&out), json!({
        "id": "p1", "name": "Corp", "host": "vpn.example.com", "port": 443, "auth": "password",
        "username": "alice", "realm": "corp", "otp_required": true, "auto_trust": true,
        "trusted_certs": [DIGEST], "dns_domains": ["corp.example.com"], "has_password": true,
    }));
    let human = home.run(&["profile", "show", "p1"]);
    let human = text(&human.stdout);
    assert!(human.contains("vpn.example.com") && human.contains(DIGEST), "{human}");
    assert!(!human.contains("s3cret") && !human.contains("set-dns"), "{human}");
}

#[test]
fn profile_targets_by_id_or_exact_name_only() {
    let home = home_with_corp(&[profile("p2", "Corp")]);
    assert_refused(&home.run(&["profile", "show", "Corp", "--json"]), 1, "PROFILE_AMBIGUOUS");
    assert_refused(&home.run(&["profile", "show", "Cor", "--json"]), 1, "PROFILE_NOT_FOUND");
    assert_refused(&home.run(&["profile", "edit", "Cor", "--port", "1", "--json"]), 1, "PROFILE_NOT_FOUND");
    assert_refused(&home.run(&["profile", "rm", "Cor", "--json"]), 1, "PROFILE_NOT_FOUND");
    assert_eq!(home.run(&["profile", "show", "p2"]).status.code(), Some(0));
    assert_eq!(home.stored_profiles().as_array().unwrap().len(), 2);
}

#[test]
fn profile_add_creates_the_profile_the_gui_would() {
    let home = Home::new();

    let out = home.run(&[
        "profile", "add", "--name", "Corp", "--host", "vpn.example.com", "--port", "443", "--username", "alice",
        "--realm", "corp", "--otp-required", "--auto-trust", "--dns-domain", "*.Corp.Example.com", "--dns-domain", "intra.local", "--json",
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let shown = json_out(&out);
    let stored = home.stored_profiles();
    assert_eq!(stored.as_array().unwrap().len(), 1);
    let id = stored[0]["id"].as_str().unwrap();
    assert!(!id.is_empty());
    assert_eq!(shown["id"], id);
    assert_eq!(shown["has_password"], false);
    assert_eq!(stored[0], json!({
        "id": id, "name": "Corp", "host": "vpn.example.com", "port": 443, "auth_type": "Password",
        "username": "alice", "otp_required": true, "realm": "corp", "trusted_certs": [],
        "ignore_cert_errors": true, "dns_match_domains": ["corp.example.com", "intra.local"], "extra_args": [],
    }));
}

#[test]
fn profile_add_defaults_to_the_gui_new_profile() {
    let home = Home::new();
    let out = home.run(&["profile", "add", "--name", "Plain", "--host", "h.example.com"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let p = &home.stored_profiles()[0];
    assert_eq!((p["port"].clone(), p["auth_type"].clone(), p["otp_required"].clone()), (json!(8443), json!("Password"), json!(false)));
    assert_eq!((p["username"].clone(), p["realm"].clone(), p["ignore_cert_errors"].clone()), (Value::Null, Value::Null, json!(false)));
}

#[test]
fn profile_add_saml_never_requires_otp() {
    let home = Home::new();
    let out = home.run(&["profile", "add", "--name", "Sso", "--host", "h", "--auth", "saml", "--otp-required"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(home.stored_profiles()[0]["auth_type"], "Saml");
    assert_eq!(home.stored_profiles()[0]["otp_required"], false);
}

#[test]
fn profile_add_needs_name_and_host_and_refuses_blank_ones() {
    let home = Home::new();
    assert_refused(&home.run(&["profile", "add", "--host", "h", "--json"]), 255, "CLI_ERROR");
    assert_refused(&home.run(&["profile", "add", "--name", "x", "--json"]), 255, "CLI_ERROR");
    assert_refused(&home.run(&["profile", "add", "--name", " ", "--host", "h", "--json"]), 255, "INVALID_ARGUMENT");
    assert_refused(&home.run(&["profile", "add", "--name", "x", "--host", "h", "--port", "0", "--json"]), 255, "INVALID_ARGUMENT");
    assert_refused(&home.run(&["profile", "add", "--name", "x", "--host", "h", "--auth", "kerberos", "--json"]), 255, "CLI_ERROR");
    assert_eq!(home.stored_profiles(), json!([]));
}

#[test]
fn profile_add_refuses_a_name_already_in_use() {
    let home = home_with_corp(&[]);
    let before = home.stored_profiles();
    assert_refused(&home.run(&["profile", "add", "--name", "Corp", "--host", "h", "--json"]), 1, "PROFILE_NAME_TAKEN");
    assert_eq!(home.stored_profiles(), before);
}

#[test]
fn invalid_dns_domains_are_refused_and_nothing_is_saved() {
    let home = Home::new();
    assert_refused(&home.run(&["profile", "add", "--name", "x", "--host", "h", "--dns-domain", "ok.example.com", "--dns-domain", "bad_domain!", "--json"]), 1, "INVALID_DNS_DOMAIN");
    assert!(!home.0.join("profiles.json").exists());

    home.profiles(json!([full_profile()]));
    let before = std::fs::read(home.0.join("profiles.json")).unwrap();
    assert_refused(&home.run(&["profile", "edit", "Corp", "--port", "1234", "--dns-domain=-bad.example.com", "--json"]), 1, "INVALID_DNS_DOMAIN");
    assert_eq!(std::fs::read(home.0.join("profiles.json")).unwrap(), before);
}

#[test]
fn profile_edit_changes_only_what_was_passed() {
    let home = Home::new();
    home.profiles(json!([full_profile()]));

    let out = home.run(&["profile", "edit", "Corp", "--port", "8443", "--no-otp-required", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mut expected = full_profile();
    expected["port"] = json!(8443);
    expected["otp_required"] = json!(false);
    assert_eq!(home.stored_profiles(), json!([expected]));
    assert_eq!(json_out(&out)["port"], 8443);
}

#[test]
fn profile_edit_renames_and_swaps_the_dns_domains() {
    let home = home_with_corp(&[profile("p2", "Other")]);
    home.run(&["profile", "edit", "p1", "--name", "Renamed", "--dns-domain", "a.example.com", "--dns-domain", "b.example.com"]);
    let p = &home.stored_profiles()[0];
    assert_eq!((p["name"].clone(), p["dns_match_domains"].clone()), (json!("Renamed"), json!(["a.example.com", "b.example.com"])));

    assert_refused(&home.run(&["profile", "edit", "p1", "--name", "Other", "--json"]), 1, "PROFILE_NAME_TAKEN");
    // Manter o próprio nome não é conflito.
    assert_eq!(home.run(&["profile", "edit", "p1", "--name", "Renamed"]).status.code(), Some(0));
}

#[test]
fn profile_edit_clears_dns_domains_and_blank_username_and_realm() {
    let home = Home::new();
    home.profiles(json!([full_profile()]));

    let out = home.run(&["profile", "edit", "Corp", "--clear-dns-domains", "--username", "", "--realm", ""]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let p = &home.stored_profiles()[0];
    assert_eq!((p["dns_match_domains"].clone(), p["username"].clone(), p["realm"].clone()), (json!([]), Value::Null, Value::Null));
    assert_refused(&home.run(&["profile", "edit", "Corp", "--clear-dns-domains", "--dns-domain", "a.example.com", "--json"]), 255, "CLI_ERROR");
}

#[test]
fn profile_edit_to_saml_drops_the_otp_requirement() {
    let home = Home::new();
    home.profiles(json!([full_profile()]));
    home.run(&["profile", "edit", "Corp", "--auth", "saml"]);
    let p = &home.stored_profiles()[0];
    assert_eq!((p["auth_type"].clone(), p["otp_required"].clone()), (json!("Saml"), json!(false)));
}

#[test]
fn profile_rm_deletes_the_profile_and_its_password_only() {
    let home = home_with_corp(&[profile("p2", "Other")]);
    home.password("p2", "keep-me");

    let out = home.run(&["profile", "rm", "Corp", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(json_out(&out)["id"], "p1");
    let left = home.stored_profiles();
    assert_eq!(left.as_array().unwrap().len(), 1);
    assert_eq!(left[0]["id"], "p2");
    assert_eq!(home.stored_password("p1"), None);
    assert_eq!(home.stored_password("p2").as_deref(), Some("keep-me"));
}

#[test]
fn set_password_reads_stdin_and_strips_one_trailing_newline() {
    let home = Home::new();
    home.profiles(json!([profile("p1", "Corp")]));

    let out = home.run_with_stdin(&["profile", "set-password", "Corp", "--password-stdin", "--json"], "s3 cret\n");

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(home.stored_password("p1").as_deref(), Some("s3 cret"));
    assert_eq!(json_out(&out)["has_password"], true);
    assert!(!text(&out.stdout).contains("s3 cret") && !text(&out.stderr).contains("s3 cret"));
}

#[test]
fn set_password_refuses_an_empty_password_and_keeps_the_old_one() {
    let home = home_with_corp(&[]);
    for input in ["", "\n"] {
        let out = home.run_with_stdin(&["profile", "set-password", "Corp", "--password-stdin", "--json"], input);
        assert_refused(&out, 255, "INVALID_ARGUMENT");
    }
    assert_eq!(home.stored_password("p1").as_deref(), Some("s3cret"));
}

#[test]
fn set_password_needs_the_stdin_flag_and_has_no_password_argument() {
    let home = home_with_corp(&[]);
    assert_refused(&home.run_with_stdin(&["profile", "set-password", "Corp", "--json"], "new\n"), 255, "CLI_ERROR");
    assert_refused(&home.run_with_stdin(&["profile", "set-password", "Corp", "--password", "new", "--json"], ""), 255, "CLI_ERROR");
    assert_refused(&home.run(&["profile", "add", "--name", "x", "--host", "h", "--password", "new", "--json"]), 255, "CLI_ERROR");
    assert_eq!(home.stored_password("p1").as_deref(), Some("s3cret"));
    assert!(home.stored_profiles().as_array().unwrap().len() == 1);
}

#[test]
fn clear_password_removes_it() {
    let home = home_with_corp(&[]);
    let out = home.run(&["profile", "clear-password", "Corp", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(json_out(&out)["has_password"], false);
    assert_eq!(home.stored_password("p1"), None);
    // Sem senha salva também não é erro.
    assert_eq!(home.run(&["profile", "clear-password", "Corp"]).status.code(), Some(0));
}

#[test]
fn trust_and_untrust_are_idempotent_and_normalize_the_digest() {
    let home = home_with_corp(&[]);
    let colons = DIGEST.to_uppercase().as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":");

    for digest in [DIGEST.to_uppercase(), colons, DIGEST.to_string()] {
        let out = home.run(&["profile", "trust", "Corp", &digest, "--json"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(json_out(&out)["trusted_certs"], json!([DIGEST]));
    }
    assert_eq!(home.stored_profiles()[0]["trusted_certs"], json!([DIGEST]));

    let other = "ab".repeat(32);
    home.run(&["profile", "trust", "Corp", &other]);
    assert_eq!(home.run(&["profile", "untrust", "Corp", DIGEST]).status.code(), Some(0));
    assert_eq!(home.run(&["profile", "untrust", "Corp", DIGEST]).status.code(), Some(0));
    assert_eq!(home.stored_profiles()[0]["trusted_certs"], json!([other]));
}

#[test]
fn trust_refuses_a_malformed_digest_and_changes_nothing() {
    let home = home_with_corp(&[]);
    let before = home.stored_profiles();
    for bad in ["abc", &"z".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
        assert_refused(&home.run(&["profile", "trust", "Corp", bad, "--json"]), 1, "INVALID_CERT_DIGEST");
        assert_refused(&home.run(&["profile", "untrust", "Corp", bad, "--json"]), 1, "INVALID_CERT_DIGEST");
    }
    assert_eq!(home.stored_profiles(), before);
}

#[test]
fn settings_show_defaults_and_set_dns_fallback_keeps_the_other_fields() {
    let home = Home::new();
    let out = home.run(&["settings", "show", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(json_out(&out)["dns_fallback"], true);
    assert!(text(&home.run(&["settings", "show"]).stdout).contains("dns-fallback"));

    home.settings(json!({"helper_install_declined": true, "dns_fallback": true}));
    let out = home.run(&["settings", "set", "dns-fallback", "off", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(json_out(&out)["dns_fallback"], false);
    assert_eq!(home.stored_settings(), json!({"helper_install_declined": true, "dns_fallback": false}));

    home.run(&["settings", "set", "dns-fallback", "on"]);
    assert_eq!(home.stored_settings()["dns_fallback"], true);
}

#[test]
fn settings_set_refuses_an_unknown_key_or_value() {
    let home = Home::new();
    assert_refused(&home.run(&["settings", "set", "dns-fallback", "maybe", "--json"]), 255, "CLI_ERROR");
    assert_refused(&home.run(&["settings", "set", "debug-mode", "on", "--json"]), 255, "CLI_ERROR");
    assert!(!home.0.join("settings.json").exists());
}

#[test]
fn a_profile_created_by_the_cli_connects() {
    let home = Home::new();
    home.run(&["profile", "add", "--name", "Fresh", "--host", "fresh.example.com", "--username", "bob", "--dns-domain", "corp.example.com"]);
    home.run_with_stdin(&["profile", "set-password", "Fresh", "--password-stdin"], "pw\n");
    let helper = FakeHelper::idle(&home.socket(), vec![connected_event()]);

    let out = home.run(&["connect", "Fresh", "--json"]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let request = connect_request(&helper);
    assert_eq!(request["profile"]["host"], "fresh.example.com");
    assert_eq!(request["profile"]["dns_match_domains"], json!(["corp.example.com"]));
    assert_eq!(request["password"], "pw");
}
