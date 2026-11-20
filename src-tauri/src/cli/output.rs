//! O contrato de saída, o das CLIs `nuvemteam`/`nuvemworks` sem `--dry-run` nem i18n:
//!
//! | saída | quando | `code` no `--json` |
//! |---|---|---|
//! | 0 | sucesso | — |
//! | 1 | recusa do Helper, do gateway ou da checagem antes de conectar; diálogo de administrador recusado ou falho no `helper install`/`uninstall` | `HELPER_REFUSED`, `PROFILE_NOT_FOUND`, `PROFILE_AMBIGUOUS`, `PROFILE_NAME_TAKEN`, `INVALID_DNS_DOMAIN`, `INVALID_CERT_DIGEST`, `OTP_REQUIRED`, `CREDENTIALS_MISSING`, `SESSION_ACTIVE`, `CERT_UNTRUSTED`, `LOGIN_FAILED`, `CONNECT_FAILED`, `CONNECT_CANCELLED`, `TIMEOUT`, `HELPER_INSTALL_CANCELLED`, `HELPER_INSTALL_FAILED` |
//! | 255 | falha da CLI: argumento, falha interna (IO, saída fechada), Helper inacessível | `INVALID_ARGUMENT`, `CLI_ERROR`, `HELPER_UNAVAILABLE`, `HELPER_UNAUTHORIZED`, `HELPER_NOT_INSTALLED`, `HELPER_OUTDATED` |
//! | 130 | Ctrl-C | — |
//!
//! Com `--json`, a stdout leva só o JSON do resultado, numa linha, e o erro sai na stderr como
//! `{"error":{"code","message"}}`, mais `cert_digest` no `CERT_UNTRUSTED`. Sem ele, a stderr
//! leva só a mensagem.

use std::process::ExitCode;

use serde_json::{json, Value};

use crate::helper_client::HelperError;

pub const EXIT_REFUSED: u8 = 1;
pub const EXIT_FAILURE: u8 = 255;
pub const EXIT_INTERRUPTED: i32 = 130;

/// Uma falha do comando, com o código estável e a saída da tabela.
#[derive(Debug)]
pub struct CliError {
    pub exit: u8,
    pub code: &'static str,
    pub message: String,
    /// sha256 do certificado recusado, só no `CERT_UNTRUSTED`.
    pub cert_digest: Option<String>,
}

impl CliError {
    pub fn failure(code: &'static str, message: impl Into<String>) -> Self {
        Self { exit: EXIT_FAILURE, code, message: message.into(), cert_digest: None }
    }

    pub fn refused(code: &'static str, message: impl Into<String>) -> Self {
        Self { exit: EXIT_REFUSED, code, message: message.into(), cert_digest: None }
    }
}

impl From<HelperError> for CliError {
    fn from(e: HelperError) -> Self {
        match e {
            HelperError::Unavailable(m) => Self::failure("HELPER_UNAVAILABLE", format!("Helper unavailable: {m}")),
            HelperError::Unauthorized => Self::failure("HELPER_UNAUTHORIZED", e.to_string()),
            HelperError::Refused(m) => Self::refused("HELPER_REFUSED", m),
        }
    }
}

/// O formato da saída: o único ponto que decide entre JSON e texto.
pub struct Out {
    pub json: bool,
}

impl Out {
    /// O resultado: `value` em uma linha com `--json`, senão o que `human` imprimir.
    pub fn emit(&self, value: &Value, human: impl FnOnce()) {
        if self.json {
            println!("{value}");
        } else {
            human();
        }
    }

    /// Escreve o erro na stderr e devolve o código de saída dele.
    pub fn fail(&self, e: CliError) -> ExitCode {
        if self.json {
            let mut error = json!({"code": e.code, "message": e.message});
            if let Some(digest) = e.cert_digest {
                error["cert_digest"] = json!(digest);
            }
            eprintln!("{}", json!({ "error": error }));
        } else {
            eprintln!("{}", e.message);
        }
        ExitCode::from(e.exit)
    }
}

/// A linha de comando não fechou: `--help` e `--version` saem com 0; o resto é 255, com o
/// envelope se a linha pedia `--json`.
pub fn usage_error(e: clap::Error) -> ExitCode {
    if e.exit_code() == 0 {
        let _ = e.print();
        return ExitCode::SUCCESS;
    }
    if std::env::args_os().any(|a| a == "--json") {
        eprintln!("{}", json!({"error": {"code": "INVALID_ARGUMENT", "message": e.render().to_string().trim()}}));
    } else {
        let _ = e.print();
    }
    ExitCode::from(EXIT_FAILURE)
}
