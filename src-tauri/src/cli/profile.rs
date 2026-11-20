//! `vpnconnect profile`: os Profiles e o que a GUI faz com eles. Grava pelo `VpnManager` e pelo
//! Keychain, os mesmos da GUI, então a validação e o formato em disco são os dela.

use std::io::{IsTerminal, Read};

use serde_json::{json, Value};

use super::args::{Auth, Fields, ProfileCmd};
use super::{target, CliError, Out};
use crate::keychain;
use crate::models::{AuthType, VpnProfile};
use crate::vpn_manager::VpnManager;

fn cli_error(e: String) -> CliError {
    CliError::failure("CLI_ERROR", e)
}

pub fn run(out: &Out, cmd: ProfileCmd) -> Result<(), CliError> {
    let mgr = VpnManager::new().map_err(cli_error)?;
    match cmd {
        ProfileCmd::Ls => {
            let views = mgr.get_profiles().map_err(cli_error)?.iter().map(view).collect::<Result<Vec<_>, _>>()?;
            out.emit(&Value::Array(views.clone()), || print_table(&views));
        }
        ProfileCmd::Show { profile } => print(out, &target::resolve(&profile)?)?,
        ProfileCmd::Add { name, host, fields } => {
            let mut p = VpnProfile::default();
            apply(&mut p, Some(name), Some(host), &fields)?;
            ensure_name_free(&mgr, &p)?;
            save(out, &mgr, p)?;
        }
        ProfileCmd::Edit { profile, name, host, fields } => {
            let mut p = target::resolve(&profile)?;
            let renamed = name.as_ref().is_some_and(|n| n.trim() != p.name);
            apply(&mut p, name, host, &fields)?;
            if renamed {
                ensure_name_free(&mgr, &p)?;
            }
            save(out, &mgr, p)?;
        }
        ProfileCmd::Rm { profile } => {
            let p = target::resolve(&profile)?;
            mgr.delete_profile(&p.id).map_err(cli_error)?;
            let removed = json!({"id": p.id, "name": p.name, "removed": true});
            out.emit(&removed, || println!("Removed Profile '{}' ({})", p.name, p.id));
        }
        ProfileCmd::SetPassword { profile, .. } => {
            let p = target::resolve(&profile)?;
            keychain::set_password(&p.id, &read_password()?).map_err(cli_error)?;
            print(out, &p)?;
        }
        ProfileCmd::ClearPassword { profile } => {
            let p = target::resolve(&profile)?;
            keychain::delete_password(&p.id).map_err(cli_error)?;
            print(out, &p)?;
        }
        ProfileCmd::Trust { profile, digest } => {
            let (mut p, digest) = (target::resolve(&profile)?, digest_of(&digest)?);
            if !p.trusted_certs.contains(&digest) {
                p.trusted_certs.push(digest);
            }
            save(out, &mgr, p)?;
        }
        ProfileCmd::Untrust { profile, digest } => {
            let (mut p, digest) = (target::resolve(&profile)?, digest_of(&digest)?);
            p.trusted_certs.retain(|d| *d != digest);
            save(out, &mgr, p)?;
        }
    }
    Ok(())
}

/// Aplica as flags passadas, e só elas, ao Profile.
fn apply(p: &mut VpnProfile, name: Option<String>, host: Option<String>, f: &Fields) -> Result<(), CliError> {
    let required = |flag: &str, value: String| match value.trim() {
        "" => Err(CliError::failure("INVALID_ARGUMENT", format!("--{flag} cannot be empty"))),
        v => Ok(v.to_string()),
    };
    if let Some(name) = name {
        p.name = required("name", name)?;
    }
    if let Some(host) = host {
        p.host = required("host", host)?;
    }
    if let Some(port) = f.port {
        if port == 0 {
            return Err(CliError::failure("INVALID_ARGUMENT", "--port must be between 1 and 65535"));
        }
        p.port = port;
    }
    if let Some(auth) = f.auth {
        p.auth_type = match auth {
            Auth::Password => AuthType::Password,
            Auth::Saml => AuthType::Saml,
        };
    }
    // Vazio limpa o campo, como o editor da GUI.
    let optional = |v: &String| Some(v.trim().to_string()).filter(|v| !v.is_empty());
    if let Some(u) = &f.username {
        p.username = optional(u);
    }
    if let Some(r) = &f.realm {
        p.realm = optional(r);
    }
    if f.otp_required || f.no_otp_required {
        p.otp_required = f.otp_required;
    }
    // O editor da GUI não oferece OTP para SAML.
    if p.auth_type == AuthType::Saml {
        p.otp_required = false;
    }
    if f.auto_trust || f.no_auto_trust {
        p.ignore_cert_errors = f.auto_trust;
    }
    if f.clear_dns_domains {
        p.dns_match_domains.clear();
    } else if !f.dns_domains.is_empty() {
        p.dns_match_domains = f.dns_domains.clone();
    }
    Ok(())
}

/// Nome repetido deixaria a mira por nome exato ambígua.
fn ensure_name_free(mgr: &VpnManager, p: &VpnProfile) -> Result<(), CliError> {
    if mgr.get_profiles().map_err(cli_error)?.iter().any(|o| o.id != p.id && o.name == p.name) {
        return Err(CliError::refused("PROFILE_NAME_TAKEN", format!("Another Profile is already named '{}'", p.name)));
    }
    Ok(())
}

/// Valida os domínios de DNS como a GUI e grava o Profile pelo mesmo caminho dela.
fn save(out: &Out, mgr: &VpnManager, mut p: VpnProfile) -> Result<(), CliError> {
    p.dns_match_domains =
        VpnManager::normalize_dns_domains(&p.dns_match_domains).map_err(|m| CliError::refused("INVALID_DNS_DOMAIN", m))?;
    print(out, &mgr.save_profile(p, None).map_err(cli_error)?)
}

/// O digest como o editor da GUI o guarda: sem `:`, em minúsculas, 64 hex.
fn digest_of(input: &str) -> Result<String, CliError> {
    let digest = input.replace(':', "").trim().to_lowercase();
    if digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(digest);
    }
    Err(CliError::refused("INVALID_CERT_DIGEST", "The digest must be a sha256: 64 hex characters (':' separators allowed)"))
}

/// A senha da stdin, sem o `\n` final. Nunca pergunta: com um terminal na stdin, falha.
fn read_password() -> Result<String, CliError> {
    let usage = |m: &str| CliError::failure("INVALID_ARGUMENT", m);
    if std::io::stdin().is_terminal() {
        return Err(usage("stdin is a terminal: pipe the password in, this command never prompts"));
    }
    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password).map_err(|e| usage(&format!("Cannot read the password from stdin: {e}")))?;
    if password.strip_suffix('\n').unwrap_or(&password).is_empty() {
        return Err(usage("The password on stdin is empty"));
    }
    Ok(password.strip_suffix('\n').unwrap_or(&password).to_string())
}

/// O Profile como a CLI o mostra: sem `extra_args`, nunca com a senha, só se ela existe.
fn view(p: &VpnProfile) -> Result<Value, CliError> {
    let has_password = keychain::get_password(&p.id).map_err(cli_error)?.is_some_and(|s| !s.is_empty());
    Ok(json!({
        "id": p.id, "name": p.name, "host": p.host, "port": p.port,
        "auth": if p.auth_type == AuthType::Saml { "saml" } else { "password" },
        "username": p.username, "realm": p.realm, "otp_required": p.otp_required,
        "auto_trust": p.ignore_cert_errors, "trusted_certs": p.trusted_certs,
        "dns_domains": p.dns_match_domains, "has_password": has_password,
    }))
}

fn print(out: &Out, p: &VpnProfile) -> Result<(), CliError> {
    let v = view(p)?;
    out.emit(&v, || {
        for key in ["id", "name", "host", "port", "auth", "username", "realm", "otp_required", "auto_trust", "trusted_certs", "dns_domains", "has_password"] {
            let text = match &v[key] {
                Value::Null => continue,
                Value::String(s) => s.clone(),
                Value::Array(items) => items.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "),
                other => other.to_string(),
            };
            if text.is_empty() {
                continue;
            }
            println!("{:<14} {text}", format!("{key}:"));
        }
    });
    Ok(())
}

fn print_table(views: &[Value]) {
    let width = views.iter().map(|v| v["name"].as_str().unwrap_or_default().len()).max().unwrap_or(0).max(4);
    println!("{:<36}  {:<width$}  {:<8}  HOST", "ID", "NAME", "AUTH");
    for v in views {
        let field = |k: &str| v[k].as_str().unwrap_or_default().to_string();
        println!("{:<36}  {:<width$}  {:<8}  {}:{}", field("id"), field("name"), field("auth"), field("host"), v["port"]);
    }
}
