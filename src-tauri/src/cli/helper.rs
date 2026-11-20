//! `vpnconnect helper`: o Helper instalado e o instalador da GUI. `install` e `uninstall` abrem o
//! diálogo de administrador do macOS, e quem digita a senha é a pessoa.

use std::path::PathBuf;

use serde_json::json;

use super::args::HelperCmd;
use super::{CliError, Out};
use crate::helper_installer::{self, AdminError, HelperStatus};
use crate::paths;

pub fn run(out: &Out, cmd: HelperCmd) -> Result<(), CliError> {
    match cmd {
        HelperCmd::Status => print(out, &helper_installer::check_status()),
        HelperCmd::Install => {
            refuse_in_test_mode()?;
            helper_installer::install(&resource_dir()?).map_err(admin_error)?;
            print(out, &helper_installer::check_status());
        }
        HelperCmd::Uninstall => {
            refuse_in_test_mode()?;
            helper_installer::uninstall().map_err(admin_error)?;
            print(out, &helper_installer::check_status());
        }
    }
    Ok(())
}

/// O status do Helper, no JSON ou um campo por linha. Também é o resultado de `install` e `uninstall`.
fn print(out: &Out, status: &HelperStatus) {
    out.emit(&json!(status), || {
        println!("{:<13} {}", "installed:", status.installed);
        println!("{:<13} {}", "running:", status.running);
        println!("{:<13} {}", "version:", status.version.as_deref().unwrap_or("-"));
        println!("{:<13} {}", "needs_update:", status.needs_update);
    });
}

/// No build de teste o osascript nunca roda: o teste não pode pedir senha de administrador.
fn refuse_in_test_mode() -> Result<(), CliError> {
    if paths::test_home().is_some() {
        return Err(CliError::cli("helper install and uninstall are not available in test mode"));
    }
    Ok(())
}

/// Os resources do bundle, onde o app guarda o Helper: `Contents/Resources`, como o Tauri acha
/// (`${exe_dir}/../Resources`). Canonicaliza o executável: o symlink `vpnconnect` no PATH não pode
/// ser usado como base.
fn resource_dir() -> Result<PathBuf, CliError> {
    let exe = std::env::current_exe().and_then(|exe| exe.canonicalize()).map_err(|e| {
        CliError::refused("HELPER_INSTALL_FAILED", format!("Could not find the app bundle: {e}"))
    })?;
    let dir = exe.parent().map(|dir| dir.join("../Resources"));
    dir.ok_or_else(|| CliError::refused("HELPER_INSTALL_FAILED", "Could not find the app bundle"))
}

/// A recusa do diálogo sai com `HELPER_INSTALL_CANCELLED`; outra falha com `HELPER_INSTALL_FAILED`.
/// `uninstall` usa os mesmos códigos: a mensagem diz qual dos dois falhou.
fn admin_error(e: AdminError) -> CliError {
    match e {
        AdminError::Cancelled(m) => CliError::refused("HELPER_INSTALL_CANCELLED", m),
        AdminError::Failed(m) => CliError::refused("HELPER_INSTALL_FAILED", m),
    }
}
