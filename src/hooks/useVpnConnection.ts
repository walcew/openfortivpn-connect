import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { ConnectionStatus, LogLine, BandwidthData } from "../types";

const INITIAL_STATUS: ConnectionStatus = {
  state: "Disconnected",
  profile_id: null,
  ip: null,
  since: null,
  message: null,
};

export function useVpnConnection() {
  const [status, setStatus] = useState<ConnectionStatus>(INITIAL_STATUS);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const logsRef = useRef<LogLine[]>([]);
  const [bandwidth, setBandwidth] = useState<BandwidthData[]>([]);
  const bandwidthRef = useRef<BandwidthData[]>([]);

  useEffect(() => {
    const unlistenStatus = listen<ConnectionStatus>(
      "connection-status-changed",
      (event) => {
        setStatus(event.payload);
      },
    );

    const unlistenLog = listen<LogLine>("log-line", (event) => {
      logsRef.current = [...logsRef.current, event.payload];
      setLogs([...logsRef.current]);
    });

    const unlistenSaml = listen<{ url: string }>(
      "saml-url",
      async (event) => {
        try {
          await openUrl(event.payload.url);
        } catch (e) {
          console.error("Failed to open SAML URL:", e);
        }
      },
    );

    const unlistenBandwidth = listen<BandwidthData>(
      "bandwidth-update",
      (event) => {
        bandwidthRef.current = [
          ...bandwidthRef.current.slice(-59),
          event.payload,
        ];
        setBandwidth([...bandwidthRef.current]);
      },
    );

    // Fetch initial status
    invoke<ConnectionStatus>("get_status")
      .then(setStatus)
      .catch(console.error);

    return () => {
      unlistenStatus.then((fn) => fn());
      unlistenLog.then((fn) => fn());
      unlistenSaml.then((fn) => fn());
      unlistenBandwidth.then((fn) => fn());
    };
  }, []);

  // Reset bandwidth data on disconnect
  useEffect(() => {
    if (status.state !== "Connected") {
      bandwidthRef.current = [];
      setBandwidth([]);
    }
  }, [status.state]);

  const connect = useCallback(async (profileId: string) => {
    try {
      await invoke("connect", { profileId });
    } catch (e) {
      console.error("Connect failed:", e);
      throw e;
    }
  }, []);

  const disconnect = useCallback(async () => {
    try {
      await invoke("disconnect");
    } catch (e) {
      console.error("Disconnect failed:", e);
      throw e;
    }
  }, []);

  const clearLogs = useCallback(() => {
    logsRef.current = [];
    setLogs([]);
  }, []);

  return { status, logs, bandwidth, connect, disconnect, clearLogs };
}
