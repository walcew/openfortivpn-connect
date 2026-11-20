//! A CLI `vpnconnect` de ponta a ponta: roda o executável real do app com argumentos e
//! `VPNCONNECT_TEST_HOME` (só no build de debug), que troca o diretório de config, o Keychain
//! e o socket do Helper pelos de um diretório temporário, diante de um Helper falso. Confere
//! stdout, stderr, código de saída e os requests que chegaram ao socket.

mod fake_helper;

use std::path::PathBuf;
use std::process::{Command, Output};

use fake_helper::{refusal, response, state, unauthorized, FakeHelper};
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
