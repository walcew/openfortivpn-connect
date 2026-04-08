use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{CheckMenuItemBuilder, MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Listener, Manager};

use crate::models::{ConnectionState, ConnectionStatusPayload, VpnProfile};
use crate::vpn_manager::VpnManager;

const TRAY_ICON_DISCONNECTED: &[u8] = include_bytes!("../icons/tray/disconnected@2x.png");
const TRAY_ICON_CONNECTED: &[u8] = include_bytes!("../icons/tray/connected@2x.png");

/// Build and register the system tray. Call once during app setup.
pub fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let menu = build_tray_menu(app.handle())?;

    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(TRAY_ICON_DISCONNECTED)?)
        .icon_as_template(true)
        .menu(&menu)
        .on_menu_event(handle_menu_event)
        .build(app)?;

    // Listen for connection state changes to update VpnManager state and refresh tray.
    // The log monitor emits these events but cannot update VpnManager.state directly
    // (no access to the Mutex). This listener bridges that gap.
    let handle = app.handle().clone();
    app.listen("connection-status-changed", move |event| {
        let h = handle.clone();
        let payload_str = event.payload().to_string();
        std::thread::spawn(move || {
            // Parse the payload to sync VpnManager.state
            if let Ok(payload) = serde_json::from_str::<ConnectionStatusPayload>(&payload_str) {
                // Try to update VpnManager.state — retry a few times if locked
                for _ in 0..10 {
                    let mgr_state = h.state::<Mutex<VpnManager>>();
                    if let Ok(mut mgr) = mgr_state.try_lock() {
                        mgr.sync_state_from_payload(&payload);
                        drop(mgr);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
            refresh_tray_menu(&h);
        });
    });

    Ok(())
}

/// Rebuild and replace the tray menu. Call whenever profiles or connection state change.
pub fn refresh_tray_menu(app: &AppHandle) {
    match build_tray_menu(app) {
        Ok(menu) => {
            if let Some(tray) = app.tray_by_id("main") {
                let _ = tray.set_menu(Some(menu));
            }
        }
        Err(e) => {
            log::error!("Failed to refresh tray menu: {}", e);
        }
    }
}

/// Update the tray icon to reflect the current connection state.
pub fn update_tray_icon(app: &AppHandle, state: &ConnectionState) {
    let icon_bytes = match state {
        ConnectionState::Connected { .. } => TRAY_ICON_CONNECTED,
        _ => TRAY_ICON_DISCONNECTED,
    };
    if let Some(tray) = app.tray_by_id("main") {
        if let Ok(icon) = Image::from_bytes(icon_bytes) {
            let _ = tray.set_icon(Some(icon));
            // Re-apply template flag — set_icon() resets it on macOS
            let _ = tray.set_icon_as_template(true);
        }
    }
}

fn build_tray_menu(app: &AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    // Use try_lock to avoid deadlock: if the Mutex is held (e.g. during
    // connect/disconnect), skip this refresh — the next event will catch up.
    let mgr_state = app.state::<Mutex<VpnManager>>();
    let guard = match mgr_state.try_lock() {
        Ok(g) => g,
        Err(_) => {
            // Mutex is busy, build a minimal placeholder menu
            let busy = MenuItemBuilder::with_id("status", "Working...")
                .enabled(false)
                .build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            return MenuBuilder::new(app)
                .item(&busy)
                .separator()
                .item(&quit)
                .build();
        }
    };
    let state = guard.get_state().clone();
    let profiles = guard.get_profiles().unwrap_or_default();
    let selected_id = guard.selected_profile_id().map(|s| s.to_string());
    drop(guard);

    let is_connected = matches!(state, ConnectionState::Connected { .. });
    let is_busy = matches!(
        state,
        ConnectionState::Connecting { .. }
            | ConnectionState::WaitingSaml { .. }
            | ConnectionState::Disconnecting
    );

    let mut builder = MenuBuilder::new(app);

    // --- Status line ---
    let status_text = match &state {
        ConnectionState::Disconnected => "Disconnected".to_string(),
        ConnectionState::Connecting { .. } => "Connecting...".to_string(),
        ConnectionState::WaitingSaml { .. } => "Waiting SAML...".to_string(),
        ConnectionState::Connected { ip, .. } => format!("Connected ({})", ip),
        ConnectionState::Disconnecting => "Disconnecting...".to_string(),
        ConnectionState::Error { message } => format!("Error: {}", truncate(message, 30)),
    };
    let status_item = MenuItemBuilder::with_id("status", &status_text)
        .enabled(false)
        .build(app)?;
    builder = builder.item(&status_item).separator();

    // --- Profile submenu (radio-style with check marks) ---
    if !profiles.is_empty() {
        let mut profiles_sub = SubmenuBuilder::with_id(app, "profiles_sub", "Profiles");

        for profile in &profiles {
            let is_selected = selected_id.as_deref() == Some(&profile.id);
            let label = format_profile_label(profile);
            let item = CheckMenuItemBuilder::with_id(
                format!("profile:{}", profile.id),
                &label,
            )
            .checked(is_selected)
            .enabled(!is_busy)
            .build(app)?;
            profiles_sub = profiles_sub.item(&item);
        }

        let profiles_menu = profiles_sub.build()?;
        builder = builder.item(&profiles_menu).separator();
    }

    // --- Connect / Disconnect ---
    if is_connected || is_busy {
        let disconnect_item = MenuItemBuilder::with_id("disconnect", "Disconnect")
            .enabled(!matches!(state, ConnectionState::Disconnecting))
            .build(app)?;
        builder = builder.item(&disconnect_item);
    } else {
        let has_selection = selected_id.is_some();
        let connect_item = MenuItemBuilder::with_id("connect", "Connect")
            .enabled(has_selection && !is_busy)
            .build(app)?;
        builder = builder.item(&connect_item);
    }

    builder = builder.separator();

    // --- Open app / Quit ---
    let open_item = MenuItemBuilder::with_id("show", "Open App").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    builder = builder.item(&open_item).item(&quit_item);

    builder.build()
}

fn handle_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    let id = event.id().as_ref().to_string();

    match id.as_str() {
        "show" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        "quit" => {
            let app = app.clone();
            std::thread::spawn(move || {
                let should_disconnect = {
                    let mgr_state = app.state::<Mutex<VpnManager>>();
                    let mgr = mgr_state.lock().unwrap();
                    !matches!(mgr.get_state(), ConnectionState::Disconnected)
                };
                if should_disconnect {
                    let mgr_state = app.state::<Mutex<VpnManager>>();
                    let mut mgr = mgr_state.lock().unwrap();
                    let _ = mgr.disconnect(app.clone());
                }
                app.exit(0);
            });
        }
        "connect" => {
            let app = app.clone();
            std::thread::spawn(move || {
                let profile_id = {
                    let mgr_state = app.state::<Mutex<VpnManager>>();
                    let mgr = mgr_state.lock().unwrap();
                    mgr.selected_profile_id().map(|s| s.to_string())
                };
                if let Some(profile_id) = profile_id {
                    let settings = crate::settings_store::SettingsStore::new()
                        .and_then(|s| s.get())
                        .unwrap_or_default();
                    let mgr_state = app.state::<Mutex<VpnManager>>();
                    let mut mgr = mgr_state.lock().unwrap();
                    let _ = mgr.connect(&profile_id, app.clone(), settings.debug_mode, settings.dns_fallback);
                    drop(mgr);
                }
                // Refresh after lock is released
                refresh_tray_menu(&app);
            });
        }
        "disconnect" => {
            let app = app.clone();
            std::thread::spawn(move || {
                {
                    let mgr_state = app.state::<Mutex<VpnManager>>();
                    let mut mgr = mgr_state.lock().unwrap();
                    let _ = mgr.disconnect(app.clone());
                }
                // Refresh after lock is released
                refresh_tray_menu(&app);
            });
        }
        _ if id.starts_with("profile:") => {
            let profile_id = id.strip_prefix("profile:").unwrap();
            let mgr_state = app.state::<Mutex<VpnManager>>();
            if let Ok(mut mgr) = mgr_state.lock() {
                mgr.set_selected_profile(profile_id);
            }
            refresh_tray_menu(app);
        }
        _ => {}
    }
}

fn format_profile_label(profile: &VpnProfile) -> String {
    let auth = match profile.auth_type {
        crate::models::AuthType::Saml => "SAML",
        crate::models::AuthType::Password => "Pass",
    };
    format!("{} ({})", profile.name, auth)
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
