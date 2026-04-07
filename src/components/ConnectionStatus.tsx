import { useEffect, useState } from "react";
import type { ConnectionStatus as ConnectionStatusType } from "../types";

interface Props {
  status: ConnectionStatusType;
  profileName: string;
  selectedProfileId: string | null;
  onConnect: () => void;
  onDisconnect: () => void;
}

const STATUS_CONFIG: Record<
  ConnectionStatusType["state"],
  { color: string; bg: string; label: string }
> = {
  Disconnected: { color: "bg-gray-400", bg: "bg-gray-800", label: "Disconnected" },
  Connecting: { color: "bg-yellow-400", bg: "bg-yellow-900/30", label: "Connecting..." },
  WaitingSaml: { color: "bg-yellow-400", bg: "bg-yellow-900/30", label: "Waiting for SAML login..." },
  Connected: { color: "bg-green-400", bg: "bg-green-900/30", label: "Connected" },
  Disconnecting: { color: "bg-orange-400", bg: "bg-orange-900/30", label: "Disconnecting..." },
  Error: { color: "bg-red-400", bg: "bg-red-900/30", label: "Error" },
};

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h, m, s].map((v) => String(v).padStart(2, "0")).join(":");
}

export function ConnectionStatus({
  status,
  profileName,
  selectedProfileId,
  onConnect,
  onDisconnect,
}: Props) {
  const [duration, setDuration] = useState(0);
  const config = STATUS_CONFIG[status.state];

  useEffect(() => {
    if (status.state !== "Connected" || !status.since) {
      setDuration(0);
      return;
    }
    const start = new Date(status.since).getTime();
    const tick = () => setDuration(Math.floor((Date.now() - start) / 1000));
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [status.state, status.since]);

  const isConnected = status.state === "Connected";
  const isBusy = status.state === "Connecting" || status.state === "WaitingSaml" || status.state === "Disconnecting";

  return (
    <div className={`rounded-lg p-4 ${config.bg}`}>
      <div className="flex items-center gap-2 mb-2">
        <span className={`w-3 h-3 rounded-full ${config.color} ${isBusy ? "animate-pulse" : ""}`} />
        <span className="text-sm font-medium text-gray-200">{config.label}</span>
      </div>

      {isConnected && (
        <div className="text-sm text-gray-400 mb-2 ml-5">
          <div>{profileName}</div>
          {status.ip && <div>IP: {status.ip}</div>}
          <div>{formatDuration(duration)}</div>
        </div>
      )}

      {status.state === "Error" && status.message && (
        <div className="text-sm text-red-400 mb-2 ml-5 break-words">
          {status.message}
        </div>
      )}

      <div className="mt-2">
        {isConnected || isBusy ? (
          <button
            onClick={onDisconnect}
            disabled={status.state === "Disconnecting"}
            className="w-full py-2 px-4 bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
          >
            {status.state === "Disconnecting" ? "Disconnecting..." : "Disconnect"}
          </button>
        ) : (
          <button
            onClick={onConnect}
            disabled={!selectedProfileId}
            className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
          >
            Connect
          </button>
        )}
      </div>
    </div>
  );
}
