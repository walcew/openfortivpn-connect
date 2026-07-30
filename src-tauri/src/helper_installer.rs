use std::path::Path;
use std::process::Command;

use openvpngui_common::{
    helper_plist_xml, HELPER_BINARY_NAME, HELPER_INSTALL_PATH, HELPER_LOG_PATH, HELPER_PLIST_PATH,
    HELPER_SOCKET_PATH, OPENFORTIVPN_BINARY_NAME, OPENFORTIVPN_INSTALL_PATH,
    PRIVILEGED_HELPER_TOOLS_DIR,
};
use tauri::{AppHandle, Manager};

use crate::helper_client;

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
        && Path::new(OPENFORTIVPN_INSTALL_PATH).exists()
        && Path::new(HELPER_PLIST_PATH).exists();

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
/// The helper and openfortivpn binaries are read from the app bundle's resources.
pub fn install(app_handle: &AppHandle) -> Result<(), String> {
    let resource_dir = app_handle
        .path()
        .resource_dir()
        .map_err(|e| format!("Failed to get resource dir: {}", e))?;
    let bundled_helper = resource_dir.join(HELPER_BINARY_NAME);
    let bundled_openfortivpn = resource_dir.join(OPENFORTIVPN_BINARY_NAME);

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

    let helper_src = bundled_helper.to_string_lossy();
    let openfortivpn_src = bundled_openfortivpn.to_string_lossy();
    let plist_escaped = helper_plist_xml()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\'', "'\\''");

    let script = format!(
        "do shell script \"\
            launchctl unload -w {plist_path} 2>/dev/null; \
            mkdir -p {helper_tools_dir}; \
            cp '{helper_src}' {helper_dst}; \
            chmod 755 {helper_dst}; \
            chown root:wheel {helper_dst}; \
            cp '{openfortivpn_src}' {openfortivpn_dst}; \
            chmod 755 {openfortivpn_dst}; \
            chown root:wheel {openfortivpn_dst}; \
            echo '{plist_content}' > {plist_path}; \
            chmod 644 {plist_path}; \
            chown root:wheel {plist_path}; \
            launchctl load -w {plist_path}\
        \" with administrator privileges",
        helper_tools_dir = PRIVILEGED_HELPER_TOOLS_DIR,
        helper_src = helper_src,
        helper_dst = HELPER_INSTALL_PATH,
        openfortivpn_src = openfortivpn_src,
        openfortivpn_dst = OPENFORTIVPN_INSTALL_PATH,
        plist_path = HELPER_PLIST_PATH,
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

    std::thread::sleep(std::time::Duration::from_secs(2));

    match helper_client::ping() {
        Ok(version) => {
            log::info!("Helper daemon installed and running (v{})", version);
            Ok(())
        }
        Err(e) => Err(format!(
            "Helper installed but not responding: {}. Check {}",
            e, HELPER_LOG_PATH
        )),
    }
}

/// Uninstall the helper daemon.
pub fn uninstall() -> Result<(), String> {
    let script = format!(
        "do shell script \"\
            launchctl unload -w {plist} 2>/dev/null; \
            rm -f {helper}; \
            rm -f {openfortivpn}; \
            rm -f {plist}; \
            rm -f {socket}\
        \" with administrator privileges",
        helper = HELPER_INSTALL_PATH,
        openfortivpn = OPENFORTIVPN_INSTALL_PATH,
        plist = HELPER_PLIST_PATH,
        socket = HELPER_SOCKET_PATH,
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
