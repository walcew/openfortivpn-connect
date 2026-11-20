//! A mira de um Profile na linha de comando: o id ou o nome exato. Nome parcial ou repetido é
//! recusado, para nunca agir no Profile errado.

use super::CliError;
use crate::models::VpnProfile;
use crate::profile_store::ProfileStore;

pub fn resolve(target: &str) -> Result<VpnProfile, CliError> {
    let profiles = ProfileStore::new().and_then(|s| s.get_all()).map_err(|e| CliError::failure("CLI_ERROR", e))?;
    if let Some(p) = profiles.iter().find(|p| p.id == target) {
        return Ok(p.clone());
    }
    let mut named = profiles.into_iter().filter(|p| p.name == target);
    match (named.next(), named.next()) {
        (Some(p), None) => Ok(p),
        (Some(_), Some(_)) => Err(CliError::refused(
            "PROFILE_AMBIGUOUS",
            format!("More than one Profile is named '{target}': use its id instead"),
        )),
        (None, _) => Err(CliError::refused(
            "PROFILE_NOT_FOUND",
            format!("No Profile has the id or the exact name '{target}' (partial names are not accepted)"),
        )),
    }
}
