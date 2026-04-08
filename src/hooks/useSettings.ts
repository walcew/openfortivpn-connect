import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

export interface AppSettings {
  debug_mode: boolean;
  helper_declined: boolean;
  dns_fallback: boolean;
}

export function useSettings() {
  const [settings, setSettings] = useState<AppSettings>({ debug_mode: false, helper_declined: false, dns_fallback: false });
  const [loading, setLoading] = useState(true);

  const fetchSettings = useCallback(async () => {
    try {
      const result = await invoke<AppSettings>("get_settings");
      setSettings(result);
    } catch (e) {
      console.error("Failed to fetch settings:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  const updateSettings = async (newSettings: AppSettings) => {
    await invoke("save_settings", { settings: newSettings });
    setSettings(newSettings);
  };

  return { settings, loading, updateSettings };
}
