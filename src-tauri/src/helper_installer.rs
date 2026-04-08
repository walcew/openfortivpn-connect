use std::path::Path;
use std::process::Command;

use tauri::{AppHandle, Manager};

use crate::helper_client;

const HELPER_INSTALL_PATH: &str = "/Library/PrivilegedHelperTools/com.openvpngui.helper";
const PLIST_INSTALL_PATH: &str = "/Library/LaunchDaemons/com.openvpngui.helper.plist";

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
    let installed = Path::new(HELPER_INSTALL_PATH).exists()
        && Path::new(PLIST_INSTALL_PATH).exists();

    let (running, version) = match helper_client::ping() {
        Ok(v) => (true, Some(v)),
        Err(_) => (false, None),
    };

    let needs_update = version
        .as_deref()
        .map(|v| v != env!("CARGO_PKG_VERSION"))
        .unwrap_or(false);

    HelperStatus {
        installed,
        running,
        version,
        needs_update,
    }
}

/// Install the helper daemon using osascript (one-time admin password).
/// The helper binary is read from the app bundle's resources.
pub fn install(app_handle: &AppHandle) -> Result<(), String> {
    // Locate the helper binary in the app bundle resources
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

    // Build the installation script
    let helper_src = bundled_helper.to_string_lossy();
    let plist_escaped = PLIST_CONTENT
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\'', "'\\''");

    let script = format!(
        "do shell script \"\
            launchctl unload -w {plist_path} 2>/dev/null; \
            mkdir -p /Library/PrivilegedHelperTools; \
            cp '{helper_src}' {helper_dst}; \
            chmod 755 {helper_dst}; \
            chown root:wheel {helper_dst}; \
            echo '{plist_content}' > {plist_path}; \
            chmod 644 {plist_path}; \
            chown root:wheel {plist_path}; \
            launchctl load -w {plist_path}\
        \" with administrator privileges",
        helper_src = helper_src,
        helper_dst = HELPER_INSTALL_PATH,
        plist_path = PLIST_INSTALL_PATH,
        plist_content = plist_escaped,
    );

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
    let script = format!(
        "do shell script \"\
            launchctl unload -w {plist} 2>/dev/null; \
            rm -f {helper}; \
            rm -f {plist}; \
            rm -f /var/run/openvpngui-helper.sock\
        \" with administrator privileges",
        helper = HELPER_INSTALL_PATH,
        plist = PLIST_INSTALL_PATH,
    );

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
