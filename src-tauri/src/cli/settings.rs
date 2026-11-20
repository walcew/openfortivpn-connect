//! `vpnconnect settings`: o mesmo `settings.json` da GUI; trocar um campo preserva os outros.

use super::args::{SettingCmd, SettingsCmd, Toggle};
use super::{CliError, Out};
use crate::settings_store::SettingsStore;

pub fn run(out: &Out, cmd: SettingsCmd) -> Result<(), CliError> {
    let store = SettingsStore::new().map_err(CliError::cli)?;
    let mut settings = store.get().map_err(CliError::cli)?;
    if let SettingsCmd::Set(SettingCmd::DnsFallback { value }) = cmd {
        settings.dns_fallback = matches!(value, Toggle::On);
        store.save(&settings).map_err(CliError::cli)?;
    }
    out.emit(&serde_json::json!(settings), || {
        println!("dns-fallback: {}", if settings.dns_fallback { "on" } else { "off" });
    });
    Ok(())
}
