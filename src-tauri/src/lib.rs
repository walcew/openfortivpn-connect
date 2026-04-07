mod commands;
mod dns_manager;
mod keychain;
mod models;
mod process_manager;
mod profile_store;
pub mod tray;
mod vpn_manager;

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
        ])
        .setup(|app| {
            tray::setup_tray(app)?;
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
