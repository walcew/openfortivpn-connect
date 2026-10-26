use std::path::Path;
use std::process::Command;

use tauri::{AppHandle, Manager};

use crate::helper_client;
use crate::process_manager::{applescript_escape, shell_quote};

const HELPER_INSTALL_PATH: &str = "/Library/PrivilegedHelperTools/com.openvpngui.helper";
const PLIST_INSTALL_PATH: &str = "/Library/LaunchDaemons/com.openvpngui.helper.plist";
// Par de OPENFORTIVPN_PATH em helper/src/validation.rs; o fallback sem Helper usa este.
pub(crate) const OPENFORTIVPN_INSTALL_PATH: &str = "/Library/PrivilegedHelperTools/openfortivpn";

const PLIST_CONTENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openvpngui.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/PrivilegedHelperTools/com.openvpngui.helper</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/openvpngui-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/openvpngui-helper.log</string>
</dict>
</plist>
"#;

#[derive(Debug, Clone, serde::Serialize)]
pub struct HelperStatus {
    pub installed: bool,
    pub running: bool,
    pub version: Option<String>,
    pub needs_update: bool,
}

/// Check the current status of the helper daemon.
pub fn check_status() -> HelperStatus {
    let openfortivpn_installed = Path::new(OPENFORTIVPN_INSTALL_PATH).exists();
    let installed = Path::new(HELPER_INSTALL_PATH).exists()
        && Path::new(PLIST_INSTALL_PATH).exists();

    let (running, version) = match helper_client::ping() {
        Ok(v) => (true, Some(v)),
        Err(_) => (false, None),
    };

    let update_needed = needs_update(
        version.as_deref(),
        env!("CARGO_PKG_VERSION"),
        openfortivpn_installed,
    );

    HelperStatus {
        installed,
        running,
        version,
        needs_update: update_needed,
    }
}

/// Um Helper ativo precisa ser reinstalado quando a versão difere da do app ou
/// quando falta o Bundled openfortivpn que ele executa.
fn needs_update(
    installed_version: Option<&str>,
    expected_version: &str,
    openfortivpn_installed: bool,
) -> bool {
    installed_version.is_some_and(|v| v != expected_version || !openfortivpn_installed)
}

/// AppleScript que roda `cmd` como root. Segunda camada do escape: os valores
/// variáveis de `cmd` já vêm com shell_quote; aqui só `\\` e `"` do AppleScript.
fn admin_script(cmd: &str) -> String {
    format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(cmd)
    )
}

/// Install the helper daemon using osascript (one-time admin password).
/// The helper and openfortivpn binaries are read from the app bundle's resources.
pub fn install(app_handle: &AppHandle) -> Result<(), String> {
    // Locate the helper binary in the app bundle resources
    let resource_dir = app_handle
        .path()
        .resource_dir()
        .map_err(|e| format!("Failed to get resource dir: {}", e))?;
    let bundled_helper = resource_dir.join("openvpngui-helper");
    let bundled_openfortivpn = resource_dir.join("openfortivpn");

    if !bundled_helper.exists() {
        return Err(format!(
            "Helper binary not found in bundle at {:?}",
            bundled_helper
        ));
    }
    if !bundled_openfortivpn.exists() {
        return Err(format!(
            "openfortivpn binary not found in bundle at {:?}",
            bundled_openfortivpn
        ));
    }

    // set -e: qualquer passo que falhe (ex.: cp do openfortivpn) faz o osascript falhar.
    let cmd = format!(
        "set -e; \
         launchctl unload -w {plist_path} 2>/dev/null || true; \
         mkdir -p /Library/PrivilegedHelperTools; \
         cp {helper_src} {helper_dst}; \
         chmod 755 {helper_dst}; \
         chown root:wheel {helper_dst}; \
         rm -f {openfortivpn_dst}; \
         cp {openfortivpn_src} {openfortivpn_dst}; \
         chmod 755 {openfortivpn_dst}; \
         chown root:wheel {openfortivpn_dst}; \
         echo {plist_content} > {plist_path}; \
         chmod 644 {plist_path}; \
         chown root:wheel {plist_path}; \
         launchctl load -w {plist_path}",
        helper_src = shell_quote(&bundled_helper.to_string_lossy()),
        helper_dst = HELPER_INSTALL_PATH,
        openfortivpn_src = shell_quote(&bundled_openfortivpn.to_string_lossy()),
        openfortivpn_dst = OPENFORTIVPN_INSTALL_PATH,
        plist_path = PLIST_INSTALL_PATH,
        plist_content = shell_quote(PLIST_CONTENT),
    );
    let script = admin_script(&cmd);

    log::info!("Installing helper daemon via osascript");

    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("Failed to run osascript: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") || stderr.contains("-128") {
            return Err("Installation cancelled by user".to_string());
        }
        return Err(format!("Installation failed: {}", stderr));
    }

    // Wait briefly for the daemon to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify the helper is responding
    match helper_client::ping() {
        Ok(version) => {
            log::info!("Helper daemon installed and running (v{})", version);
            Ok(())
        }
        Err(e) => Err(format!(
            "Helper installed but not responding: {}. Check /var/log/openvpngui-helper.log",
            e
        )),
    }
}

/// Uninstall the helper daemon.
pub fn uninstall() -> Result<(), String> {
    let script = admin_script(&format!(
        "set -e; \
         launchctl unload -w {plist} 2>/dev/null || true; \
         rm -f {helper}; \
         rm -f {openfortivpn}; \
         rm -f {plist}; \
         rm -f /var/run/openvpngui-helper.sock",
        helper = HELPER_INSTALL_PATH,
        openfortivpn = OPENFORTIVPN_INSTALL_PATH,
        plist = PLIST_INSTALL_PATH,
    ));

    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("Failed to run osascript: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") || stderr.contains("-128") {
            return Err("Uninstall cancelled by user".to_string());
        }
        return Err(format!("Uninstall failed: {}", stderr));
    }

    log::info!("Helper daemon uninstalled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{admin_script, needs_update, shell_quote};

    /// Roda o AppleScript de verdade, sem o privilégio de admin, e devolve o stdout.
    fn run_without_admin(script: &str) -> String {
        let script = script
            .strip_suffix(" with administrator privileges")
            .expect("admin suffix");
        let out = std::process::Command::new("osascript")
            .args(["-e", script])
            .output()
            .expect("osascript");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim_end_matches('\n').to_string()
    }

    #[test]
    fn bundle_paths_survive_both_escape_layers() {
        for path in [
            "/Applications/OpenFortiVpn Connect.app/x",
            "/tmp/it's/x",
            "/tmp/say \"hi\"/x",
            "/tmp/back\\slash/x",
            "/tmp/'; touch /tmp/pwned; '\"\\$(id)`id`/x",
        ] {
            let script = admin_script(&format!("printf %s {}", shell_quote(path)));
            assert_eq!(run_without_admin(&script), path);
        }
    }

    #[test]
    fn admin_script_escapes_applescript_quotes_and_backslashes() {
        assert_eq!(
            admin_script(r#"echo "a\b""#),
            r#"do shell script "echo \"a\\b\"" with administrator privileges"#
        );
    }

    #[test]
    fn failing_step_fails_the_whole_command() {
        let script = admin_script("set -e; false; echo reached");
        let script = script.strip_suffix(" with administrator privileges").unwrap();
        let out = std::process::Command::new("osascript").args(["-e", script]).output().unwrap();
        assert!(!out.status.success());
    }

    #[test]
    fn up_to_date_with_openfortivpn_needs_no_update() {
        assert!(!needs_update(Some("0.2.0"), "0.2.0", true));
    }

    #[test]
    fn version_mismatch_needs_update() {
        assert!(needs_update(Some("0.1.9"), "0.2.0", true));
    }

    #[test]
    fn missing_openfortivpn_needs_update_even_when_version_matches() {
        assert!(needs_update(Some("0.2.0"), "0.2.0", false));
    }

    #[test]
    fn helper_not_running_is_not_an_update() {
        assert!(!needs_update(None, "0.2.0", false));
    }
}
