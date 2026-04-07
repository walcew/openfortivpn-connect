import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { VpnProfile } from "../types";

export function useProfiles() {
  const [profiles, setProfiles] = useState<VpnProfile[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchProfiles = useCallback(async () => {
    try {
      setLoading(true);
      const result = await invoke<VpnProfile[]>("get_profiles");
      setProfiles(result);
    } catch (e) {
      console.error("Failed to fetch profiles:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProfiles();
  }, [fetchProfiles]);

  const saveProfile = async (profile: VpnProfile, password?: string) => {
    const saved = await invoke<VpnProfile>("save_profile", {
      profile,
      password: password || null,
    });
    await fetchProfiles();
    return saved;
  };

  const deleteProfile = async (profileId: string) => {
    await invoke("delete_profile", { profileId });
    await fetchProfiles();
  };

  return { profiles, loading, saveProfile, deleteProfile, refetch: fetchProfiles };
}
