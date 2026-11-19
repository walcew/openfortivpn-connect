use std::path::Path;
use std::process::Command;

use tauri::{AppHandle, Manager};

use crate::helper_client;

const HELPER_INSTALL_PATH: &str = "/Library/PrivilegedHelperTools/com.vpnconnect.helper";
const PLIST_INSTALL_PATH: &str = "/Library/LaunchDaemons/com.vpnconnect.helper.plist";

// Artefatos da 0.3.0 (label, binário, plist, socket e log do Helper antigo, o openfortivpn
// bundlado e a chave de DNS dele), removidos no mesmo passo que instala o Helper novo.
const LEGACY_LABEL: &str = "com.openvpngui.helper";
const LEGACY_PLIST_PATH: &str = "/Library/LaunchDaemons/com.openvpngui.helper.plist";
const LEGACY_FILES: [&str; 5] = [
    "/Library/PrivilegedHelperTools/com.openvpngui.helper",
    "/Library/PrivilegedHelperTools/openfortivpn",
    "/var/run/openvpngui-helper.sock",
    "/var/log/openvpngui-helper.log",
    "/tmp/openvpngui-*.log",
];
const LEGACY_DNS_KEY: &str = "State:/Network/Service/OpenFortiVPN/DNS";

const PLIST_CONTENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vpnconnect.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/PrivilegedHelperTools/com.vpnconnect.helper</string>
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
    <string>/var/log/vpnconnect-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/vpnconnect-helper.log</string>
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
    let installed = Path::new(HELPER_INSTALL_PATH).exists()
        && Path::new(PLIST_INSTALL_PATH).exists();

    let (running, version) = match helper_client::version(helper_client::socket_path()) {
        Ok(v) => (true, Some(v)),
        Err(_) => (false, None),
    };

    let update_needed = needs_update(version.as_deref(), env!("CARGO_PKG_VERSION"));

    HelperStatus {
        installed,
        running,
        version,
        needs_update: update_needed,
    }
}

/// Um Helper ativo precisa ser reinstalado quando a versão difere da do app.
fn needs_update(installed_version: Option<&str>, expected_version: &str) -> bool {
    installed_version.is_some_and(|v| v != expected_version)
}

/// Escape a string for inclusion in an AppleScript double-quoted string.
/// AppleScript only recognizes `\\` and `\"` as escape sequences.
/// Shell metacharacters like `$`, `` ` ``, `&` are left as-is because
/// `do shell script` passes the string to `/bin/sh` which interprets them.
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Wrap a user-supplied value in single quotes for shell safety.
/// Inside single quotes, the shell interprets nothing — only `'` needs handling.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// AppleScript que roda `cmd` como root. Segunda camada do escape: os valores
/// variáveis de `cmd` já vêm com shell_quote; aqui só `\\` e `"` do AppleScript.
fn admin_script(cmd: &str) -> String {
    format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(cmd)
    )
}

/// Comandos de shell que removem o Helper da 0.3.0. Tolerantes: numa instalação nova nada disso
/// existe, e o passo não pode derrubar o `set -e` do chamador.
fn legacy_cleanup_cmd() -> String {
    // Com uma sessão da 0.3.0 ativa, o openfortivpn e o pppd ficam órfãos: mesmos comandos do
    // `kill-vpn` antigo (SIGTERM e depois SIGKILL no pppd, que ignora SIGTERM quando o peer sumiu).
    // Só se o Helper antigo existe, para não matar o pppd de outra VPN numa instalação nova.
    // O unload derruba o Helper antigo e os filhos dele; o `remove` cobre o label carregado sem plist.
    let mut cmd = format!(
        "if [ -e {plist} ]; then \
           pkill -x openfortivpn || true; sleep 1; \
           killall pppd 2>/dev/null || true; sleep 1; \
           killall -KILL pppd 2>/dev/null || true; \
           for i in ppp0 ppp1 ppp2; do /sbin/ifconfig $i down 2>/dev/null || true; done; \
         fi; \
         launchctl unload -w {plist} 2>/dev/null || true; \
         launchctl remove {label} 2>/dev/null || true; \
         echo {remove_dns} | /usr/sbin/scutil || true; ",
        plist = shell_quote(LEGACY_PLIST_PATH),
        label = LEGACY_LABEL,
        remove_dns = shell_quote(&format!("remove {}", LEGACY_DNS_KEY)),
    );
    // Sem aspas: o glob do /tmp precisa expandir.
    cmd.push_str(&format!("rm -f {} {}", LEGACY_FILES.join(" "), LEGACY_PLIST_PATH));
    cmd
}

/// Script único de instalação: remove o Helper antigo e instala o novo. `set -e`: qualquer
/// passo que falhe faz o osascript falhar.
fn install_cmd(bundled_helper: &str) -> String {
    format!(
        "set -e; \
         {legacy}; \
         launchctl unload -w {plist_path} 2>/dev/null || true; \
         mkdir -p /Library/PrivilegedHelperTools; \
         cp {helper_src} {helper_dst}; \
         chmod 755 {helper_dst}; \
         chown root:wheel {helper_dst}; \
         echo {plist_content} > {plist_path}; \
         chmod 644 {plist_path}; \
         chown root:wheel {plist_path}; \
         launchctl load -w {plist_path}",
        legacy = legacy_cleanup_cmd(),
        helper_src = shell_quote(bundled_helper),
        helper_dst = HELPER_INSTALL_PATH,
        plist_path = PLIST_INSTALL_PATH,
        plist_content = shell_quote(PLIST_CONTENT),
    )
}

/// Install the helper daemon using osascript (one-time admin password).
/// The helper binary is read from the app bundle's resources.
pub fn install(app_handle: &AppHandle) -> Result<(), String> {
    let resource_dir = app_handle
        .path()
        .resource_dir()
        .map_err(|e| format!("Failed to get resource dir: {}", e))?;
    let bundled_helper = resource_dir.join("openvpngui-helper");

    if !bundled_helper.exists() {
        return Err(format!(
            "Helper binary not found in bundle at {:?}",
            bundled_helper
        ));
    }

    let script = admin_script(&install_cmd(&bundled_helper.to_string_lossy()));

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
    match helper_client::version(helper_client::socket_path()) {
        Ok(version) => {
            log::info!("Helper daemon installed and running (v{})", version);
            Ok(())
        }
        Err(e) => Err(format!(
            "Helper installed but not responding: {}. Check /var/log/vpnconnect-helper.log",
            e
        )),
    }
}

/// Uninstall the helper daemon (e qualquer resto da 0.3.0).
pub fn uninstall() -> Result<(), String> {
    let script = admin_script(&format!(
        "set -e; \
         {legacy}; \
         launchctl unload -w {plist} 2>/dev/null || true; \
         rm -f {helper}; \
         rm -f {plist}; \
         rm -f {socket}",
        legacy = legacy_cleanup_cmd(),
        helper = HELPER_INSTALL_PATH,
        plist = PLIST_INSTALL_PATH,
        socket = helper_client::SOCKET_PATH,
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
    use super::*;

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
    fn up_to_date_helper_needs_no_update() {
        assert!(!needs_update(Some("0.4.0"), "0.4.0"));
    }

    #[test]
    fn version_mismatch_needs_update() {
        assert!(needs_update(Some("0.3.0"), "0.4.0"));
    }

    #[test]
    fn helper_not_running_is_not_an_update() {
        assert!(!needs_update(None, "0.4.0"));
    }

    #[test]
    fn install_is_one_admin_script_that_removes_the_old_helper_before_the_new_one_loads() {
        let cmd = install_cmd("/Applications/App.app/Contents/Resources/openvpngui-helper");
        let at = |needle: &str| cmd.find(needle).unwrap_or_else(|| panic!("missing {needle} in {cmd}"));
        let kill_openfortivpn = at("pkill -x openfortivpn");
        let kill_pppd = at("killall -KILL pppd");
        let down_ppp = at("/sbin/ifconfig $i down");
        let old_unload = at("launchctl unload -w '/Library/LaunchDaemons/com.openvpngui.helper.plist'");
        let old_remove = at("launchctl remove com.openvpngui.helper");
        let old_dns = at("remove State:/Network/Service/OpenFortiVPN/DNS");
        let old_files = at("rm -f /Library/PrivilegedHelperTools/com.openvpngui.helper /Library/PrivilegedHelperTools/openfortivpn /var/run/openvpngui-helper.sock");
        let new_copy = at("cp '/Applications/App.app/Contents/Resources/openvpngui-helper' /Library/PrivilegedHelperTools/com.vpnconnect.helper");
        let new_load = at("launchctl load -w /Library/LaunchDaemons/com.vpnconnect.helper.plist");
        assert!(kill_openfortivpn < kill_pppd && kill_pppd < down_ppp && down_ppp < old_unload);
        assert!(old_unload < old_remove && old_remove < old_dns && old_dns < old_files);
        assert!(old_files < new_copy && new_copy < new_load);
        assert!(cmd.starts_with("set -e; "));
        assert!(cmd.contains(&format!("{}.plist", "/Library/LaunchDaemons/com.openvpngui.helper")), "old plist is removed too");
    }

    #[test]
    fn install_and_legacy_cleanup_are_valid_shell() {
        // `-n` só confere a sintaxe: rodar o script tocaria nos caminhos reais do Mac.
        for cmd in [legacy_cleanup_cmd(), install_cmd("/tmp/it's/helper")] {
            let out = std::process::Command::new("/bin/sh").args(["-n", "-c", &cmd]).output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        }
    }

    #[test]
    fn no_new_artifact_carries_the_old_names() {
        for new in [HELPER_INSTALL_PATH, PLIST_INSTALL_PATH, helper_client::SOCKET_PATH, PLIST_CONTENT] {
            assert!(!new.contains("openvpngui") && !new.to_lowercase().contains("openfortivpn"), "{new}");
        }
    }
}
