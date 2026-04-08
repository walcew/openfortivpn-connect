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

use tauri::WindowEvent;

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
        ])
        .setup(|app| {
            tray::setup_tray(app)?;

            #[cfg(target_os = "macos")]
            {
                use tauri::Manager;
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
