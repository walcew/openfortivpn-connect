//! Project identity and shared paths.
//!
//! Edit points (only these):
//! 1. App/helper version → `[workspace.package].version` in `src-tauri/Cargo.toml`
//! 2. Everything below in this file
//!
//! `build.rs` mirrors these into tauri.conf.json, frontend constants, package.json,
//! Cargo.toml metadata, and `project.env` (for CI).

/// Marketing / window title (also mirrored into generated frontend constants).
pub const PRODUCT_NAME: &str = "OpenFortiVpn Connect";
pub const APP_WINDOW_TITLE: &str = "OPENFORTIVPN CONNECT";
pub const PACKAGE_DESCRIPTION: &str = "OpenFortiVpn Connect - A macOS VPN client";

/// GitHub identity.
pub const REPOSITORY_SLUG: &str = "walcew/openfortivpn-connect";
pub const REPOSITORY_URL: &str = "https://github.com/walcew/openfortivpn-connect";

/// npm / Cargo package names.
pub const NPM_PACKAGE_NAME: &str = "openvpngui";
pub const APP_CRATE_NAME: &str = "openvpngui";
pub const HELPER_CRATE_NAME: &str = "openvpngui-helper";

/// Homebrew release dispatch.
pub const HOMEBREW_CASK: &str = "openfortivpn-connect";
pub const HOMEBREW_TAP_REPO: &str = "walcew/homebrew-tap";
/// Pattern sent to the tap updater (`{version}` / `{arch}` placeholders).
pub const DMG_ASSET_PATTERN: &str = "OpenFortiVpn.Connect_{version}_{arch}.dmg";

/// macOS app bundle identifier (CFBundleIdentifier / Tauri `identifier`).
pub const APP_BUNDLE_IDENTIFIER: &str = "com.openfortivpn-connect.desktop";

/// Config-dir + Keychain service name (historical; keep stable for existing installs).
pub const APP_ID: &str = "com.openvpngui.app";

/// Privileged helper launchd label and installed binary name.
pub const HELPER_LABEL: &str = "com.openvpngui.helper";
pub const HELPER_BINARY_NAME: &str = "openvpngui-helper";
pub const PRIVILEGED_HELPER_TOOLS_DIR: &str = "/Library/PrivilegedHelperTools";
pub const HELPER_INSTALL_PATH: &str = "/Library/PrivilegedHelperTools/com.openvpngui.helper";
pub const HELPER_PLIST_PATH: &str = "/Library/LaunchDaemons/com.openvpngui.helper.plist";
pub const HELPER_LOG_PATH: &str = "/var/log/openvpngui-helper.log";
pub const HELPER_SOCKET_PATH: &str = "/var/run/openvpngui-helper.sock";

/// Bundled openfortivpn installed next to the helper.
pub const OPENFORTIVPN_BINARY_NAME: &str = "openfortivpn";
pub const OPENFORTIVPN_INSTALL_PATH: &str = "/Library/PrivilegedHelperTools/openfortivpn";

/// VPN process log files must live under this prefix.
pub const VPN_LOG_PREFIX: &str = "/tmp/openvpngui-";

/// Oldest helper version that supports piped stdin / OTP write-stdin.
pub const MIN_HELPER_OTP_VERSION: &str = "0.1.9";

/// LaunchDaemon plist body for helper install.
pub fn helper_plist_xml() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{helper}</string>
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
    <string>{log}</string>
    <key>StandardOutPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        label = HELPER_LABEL,
        helper = HELPER_INSTALL_PATH,
        log = HELPER_LOG_PATH,
    )
}
