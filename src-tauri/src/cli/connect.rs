//! `vpnconnect connect`: as checagens da GUI, o `connect` ao Helper e a espera pelos eventos até
//! a sessão subir ou falhar. Conectada, a sessão vive no Helper e não depende deste processo.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{status, target, CliError, Out};
use crate::helper_client::{self, Channel, HelperError};
use crate::settings_store::SettingsStore;
use crate::{helper_installer, paths, vpn_manager};

const INSTALL_HINT: &str = "run `vpnconnect helper install`";

pub fn run(out: &Out, target: &str, otp: Option<&str>, timeout: u64, no_browser: bool) -> Result<(), CliError> {
    let profile = target::resolve(target)?;
    vpn_manager::check_otp_provided(&profile, otp)
        .map_err(|m| CliError::refused("OTP_REQUIRED", format!("{m}: pass the code with --otp")))?;
    if let Some(notice) = vpn_manager::extra_args_notice(&profile) {
        eprintln!("warning: {notice}");
    }
    let creds = vpn_manager::resolve_credentials(&profile).map_err(|m| CliError::refused("CREDENTIALS_MISSING", m))?;
    let socket = helper_client::socket_path();
    check_helper(&socket)?;
    let settings = SettingsStore::new().and_then(|s| s.get()).unwrap_or_default();
    let dns_fallback_servers = vpn_manager::fallback_dns_servers(settings.dns_fallback);

    let mut channel = Channel::open(&socket)?;
    // Como a GUI: só conecta sem sessão, para não trocar uma sessão que o usuário abriu.
    let current = channel.request(&helper_client::status_request())?;
    if current["state"] != "disconnected" {
        return Err(session_active(&format!("state {}", current["state"])));
    }
    disconnect_on_interrupt(socket.clone());
    let request = helper_client::connect_request(&profile, &creds, profile.otp_to_send(otp), &dns_fallback_servers);
    channel.request(&request).map_err(|e| match e {
        HelperError::Refused(m) if m.contains("already active") => session_active(&m),
        e => e.into(),
    })?;

    let deadline = Instant::now() + Duration::from_secs(timeout);
    loop {
        let Some(frame) = channel.next(deadline.saturating_duration_since(Instant::now()))? else {
            let _ = helper_client::disconnect(&socket);
            return Err(CliError::refused("TIMEOUT", format!("The session did not come up in {timeout} s: login cancelled")));
        };
        if frame["event"] != "state" {
            continue;
        }
        match frame["state"].as_str() {
            Some("connected") => {
                status::print(out, frame);
                return Ok(());
            }
            Some("disconnected") => return Err(failure(&frame)),
            Some("waiting-saml") => {
                let url = frame["url"].as_str().unwrap_or_default();
                eprintln!("Log in through the browser: {url}");
                if !no_browser {
                    open_browser(url);
                }
            }
            Some("waiting-push") => eprintln!("Waiting for you to approve the FortiToken push on your phone..."),
            _ => {}
        }
    }
}

fn session_active(detail: &str) -> CliError {
    CliError::refused("SESSION_ACTIVE", format!("A session is already active ({detail}): run `vpnconnect disconnect` first"))
}

/// O Helper responde e está na versão do app, o mesmo critério do `check_helper_status` da GUI.
fn check_helper(socket: &Path) -> Result<(), CliError> {
    let version = helper_client::version(socket).map_err(|e| match e {
        // Socket ausente: para quem usa a CLI, a saída é a mesma de um Helper nunca instalado.
        HelperError::Unavailable(m) => {
            CliError::failure("HELPER_NOT_INSTALLED", format!("The Helper is not installed or not running ({m}): {INSTALL_HINT}"))
        }
        e => e.into(),
    })?;
    let app = env!("CARGO_PKG_VERSION");
    if helper_installer::needs_update(Some(&version), app) {
        return Err(CliError::failure("HELPER_OUTDATED", format!("The Helper is {version} and the app is {app}: {INSTALL_HINT}")));
    }
    Ok(())
}

/// O `disconnected` que encerrou a tentativa, no código da tabela.
fn failure(frame: &Value) -> CliError {
    let reason = frame["reason"].as_str().filter(|r| !r.is_empty());
    if let Some(digest) = frame["cert_digest"].as_str() {
        let message = format!(
            "{}. Only a human may trust it, after checking the digest: `vpnconnect profile trust <profile> {digest}`",
            reason.unwrap_or("The gateway certificate is not trusted")
        );
        return CliError { cert_digest: Some(digest.to_string()), ..CliError::refused("CERT_UNTRUSTED", message) };
    }
    match reason {
        // shortcut: o prefixo é o texto das recusas de login em helper/src/fortinet; troca por um campo se o protocolo ganhar um.
        Some(r) if r.starts_with("Login failed") => CliError::refused("LOGIN_FAILED", r),
        Some(r) => CliError::refused("CONNECT_FAILED", r),
        None => CliError::refused("CONNECT_CANCELLED", "The login was cancelled before the session came up"),
    }
}

/// Abre a URL do login SAML no navegador padrão. No test home só a registra em `opened-urls`:
/// teste nunca abre navegador.
fn open_browser(url: &str) {
    // A URL vem do Helper; `open` só recebe http(s), nunca um caminho ou uma opção.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        eprintln!("warning: not opening a login URL that is not http(s)");
        return;
    }
    if let Some(home) = paths::test_home() {
        use std::io::Write;
        let file = std::fs::OpenOptions::new().create(true).append(true).open(home.join("opened-urls"));
        let _ = file.and_then(|mut f| writeln!(f, "{url}"));
        return;
    }
    if let Err(e) = std::process::Command::new("open").arg(url).status() {
        eprintln!("warning: could not open the browser: {e}");
    }
}

/// Ctrl-C com o login pendente manda `disconnect` ao Helper e sai com 130. O SIGINT fica
/// bloqueado neste processo e uma thread o espera com `sigwait`, onde dá para falar com o socket.
fn disconnect_on_interrupt(socket: PathBuf) {
    // SAFETY: só manipula a máscara de sinais; as threads criadas depois herdam o bloqueio.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    };
    std::thread::spawn(move || {
        let mut sig = 0;
        // SAFETY: `set` é um sigset válido e `sig` recebe o sinal.
        unsafe { libc::sigwait(&set, &mut sig) };
        let _ = helper_client::disconnect(&socket);
        eprintln!("Interrupted: login cancelled");
        std::process::exit(super::output::EXIT_INTERRUPTED);
    });
}
