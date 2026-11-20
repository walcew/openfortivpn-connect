//! A CLI `vpnconnect`: um modo do executável do app (ADR 0003). Com argumentos, `main.rs`
//! roda [`main`] e o Tauri nem inicializa; sem argumentos, abre a GUI.
//!
//! Comando novo: a variante em [`args::Cmd`] e um módulo aqui que recebe o [`Out`], fala com o
//! Helper por `helper_client` e imprime por [`Out::emit`]. Erros voltam como [`CliError`], que
//! leva o código de saída da tabela em [`output`].

mod args;
mod connect;
mod disconnect;
mod output;
mod profile;
mod settings;
mod status;
mod target;
mod watch;

use std::process::ExitCode;

use clap::Parser;

use args::{Cli, Cmd};
pub use output::{CliError, Out};

/// O executável foi chamado como CLI: há argumentos além do nome. O `-psn_…` que o macOS antigo
/// passava ao abrir um app pelo Finder não conta.
pub fn wants_cli() -> bool {
    std::env::args_os().nth(1).is_some_and(|a| !a.to_string_lossy().starts_with("-psn_"))
}

pub fn main() -> ExitCode {
    interrupt_exits_130();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return output::usage_error(e),
    };
    let out = Out { json: cli.json };
    let result = match cli.cmd {
        Cmd::Status => status::run(&out),
        Cmd::Connect { profile, otp, timeout, no_browser } => connect::run(&out, &profile, otp.as_deref(), timeout, no_browser),
        Cmd::Disconnect => disconnect::run(&out),
        Cmd::Watch => watch::run(),
        Cmd::Profile(cmd) => profile::run(&out, cmd),
        Cmd::Settings(cmd) => settings::run(&out, cmd),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => out.fail(e),
    }
}

/// Ctrl-C sai com 130 em qualquer ponto. Comando que precisa desfazer algo antes (ex.: cancelar
/// um login pendente) troca este tratador pelo seu.
fn interrupt_exits_130() {
    extern "C" fn on_interrupt(_: libc::c_int) {
        // SAFETY: `_exit` é async-signal-safe.
        unsafe { libc::_exit(output::EXIT_INTERRUPTED) }
    }
    // SAFETY: troca o tratador de SIGINT por uma função `extern "C"` que só chama `_exit`.
    unsafe {
        libc::signal(libc::SIGINT, on_interrupt as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
}
