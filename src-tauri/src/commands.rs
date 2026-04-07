use std::sync::Mutex;

use tauri::State;

use crate::models::*;
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
    let mut mgr = manager.lock().map_err(|e| e.to_string())?;
    mgr.set_selected_profile(&profile_id);
    mgr.connect(&profile_id, app_handle)
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
