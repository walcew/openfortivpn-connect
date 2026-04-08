use std::sync::Mutex;

use tauri::State;

use crate::helper_installer;
use crate::models::*;
use crate::settings_store::{AppSettings, SettingsStore};
use crate::vpn_manager::VpnManager;

#[tauri::command]
pub fn get_profiles(manager: State<'_, Mutex<VpnManager>>) -> Result<Vec<VpnProfile>, String> {
    let mgr = manager.lock().map_err(|e| e.to_string())?;
    mgr.get_profiles()
}

#[tauri::command]
pub fn save_profile(
    manager: State<'_, Mutex<VpnManager>>,
    app_handle: tauri::AppHandle,
    profile: VpnProfile,
    password: Option<String>,
) -> Result<VpnProfile, String> {
    let result = {
        let mgr = manager.lock().map_err(|e| e.to_string())?;
        mgr.save_profile(profile, password)?
    };
    crate::tray::refresh_tray_menu(&app_handle);
    Ok(result)
}

#[tauri::command]
pub fn delete_profile(
    manager: State<'_, Mutex<VpnManager>>,
    app_handle: tauri::AppHandle,
    profile_id: String,
) -> Result<(), String> {
    {
        let mgr = manager.lock().map_err(|e| e.to_string())?;
        mgr.delete_profile(&profile_id)?;
    }
    crate::tray::refresh_tray_menu(&app_handle);
    Ok(())
}

#[tauri::command]
pub fn connect(
    manager: State<'_, Mutex<VpnManager>>,
    app_handle: tauri::AppHandle,
    profile_id: String,
) -> Result<(), String> {
    let settings = SettingsStore::new()
        .and_then(|s| s.get())
        .unwrap_or_default();

    let mut mgr = manager.lock().map_err(|e| e.to_string())?;
    mgr.set_selected_profile(&profile_id);
    mgr.connect(&profile_id, app_handle, settings.debug_mode, settings.dns_fallback)
}

#[tauri::command]
pub fn disconnect(
    manager: State<'_, Mutex<VpnManager>>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    let mut mgr = manager.lock().map_err(|e| e.to_string())?;
    mgr.disconnect(app_handle)
}

#[tauri::command]
pub fn get_status(
    manager: State<'_, Mutex<VpnManager>>,
) -> Result<ConnectionStatusPayload, String> {
    let mgr = manager.lock().map_err(|e| e.to_string())?;
    Ok(ConnectionStatusPayload::from(mgr.get_state()))
}

#[tauri::command]
pub fn get_settings() -> Result<AppSettings, String> {
    let store = SettingsStore::new()?;
    store.get()
}

#[tauri::command]
pub fn save_settings(settings: AppSettings) -> Result<(), String> {
    let store = SettingsStore::new()?;
    store.save(&settings)
}

#[tauri::command]
pub fn check_helper_status() -> Result<helper_installer::HelperStatus, String> {
    Ok(helper_installer::check_status())
}

#[tauri::command]
pub fn install_helper(app_handle: tauri::AppHandle) -> Result<(), String> {
    helper_installer::install(&app_handle)
}

#[tauri::command]
pub fn uninstall_helper() -> Result<(), String> {
    helper_installer::uninstall()
}
