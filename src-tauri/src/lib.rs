mod commands;
mod dns_manager;
mod keychain;
mod models;
mod process_manager;
mod profile_store;
mod settings_store;
pub mod tray;
mod vpn_manager;
mod helper_client;
mod helper_installer;

use std::sync::Mutex;

use tauri::{Manager, RunEvent, WindowEvent};

use vpn_manager::VpnManager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let vpn_manager = VpnManager::new().expect("Failed to initialize VPN manager");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Mutex::new(vpn_manager))
        .invoke_handler(tauri::generate_handler![
            commands::get_profiles,
            commands::save_profile,
            commands::delete_profile,
            commands::connect,
            commands::disconnect,
            commands::get_status,
            commands::get_settings,
            commands::save_settings,
            commands::check_helper_status,
            commands::install_helper,
            commands::uninstall_helper,
        ])
        .setup(|app| {
            tray::setup_tray(app)?;

            #[cfg(target_os = "macos")]
            {
                let window = app.get_webview_window("main").unwrap();
                use window_vibrancy::{
                    apply_vibrancy, NSVisualEffectMaterial, NSVisualEffectState,
                };
                apply_vibrancy(
                    &window,
                    NSVisualEffectMaterial::HudWindow,
                    Some(NSVisualEffectState::Active),
                    Some(12.0),
                )
                .expect("Failed to apply vibrancy");
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            #[cfg(target_os = "macos")]
            if let RunEvent::Reopen { has_visible_windows, .. } = event {
                if !has_visible_windows {
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
        });
}
