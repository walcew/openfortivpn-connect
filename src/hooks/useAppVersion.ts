import { useState, useEffect } from "react";
import { getVersion } from "@tauri-apps/api/app";

export function useAppVersion() {
  const [version, setVersion] = useState("");

  useEffect(() => {
    getVersion().then(setVersion);
  }, []);

  return version;
}
