import { useEffect, useState } from "react";
import type { ConnectionStatus as ConnectionStatusType, BandwidthData } from "../types";
import { BandwidthChart } from "./BandwidthChart";

interface Props {
  status: ConnectionStatusType;
  profileName: string;
  selectedProfileId: string | null;
  bandwidth: BandwidthData[];
  onConnect: () => void;
  onDisconnect: () => void;
}

const STATUS_CONFIG: Record<
  ConnectionStatusType["state"],
  { color: string; bg: string; label: string }
> = {
  Disconnected: { color: "bg-gray-400", bg: "bg-black/40 border border-white/10", label: "Disconnected" },
  Connecting: { color: "bg-yellow-400", bg: "bg-black/40 border border-yellow-500/20", label: "Connecting..." },
  WaitingSaml: { color: "bg-yellow-400", bg: "bg-black/40 border border-yellow-500/20", label: "Waiting for SAML login..." },
  Connected: { color: "bg-green-400", bg: "bg-black/40 border border-green-500/20", label: "Connected" },
  Disconnecting: { color: "bg-orange-400", bg: "bg-black/40 border border-orange-500/20", label: "Disconnecting..." },
  Error: { color: "bg-red-400", bg: "bg-black/40 border border-red-500/20", label: "Error" },
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
  bandwidth,
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
    <div className={`rounded-xl p-4 ${config.bg}`}>
      <div className="flex items-center gap-2 mb-2">
        <span className={`w-3 h-3 rounded-full ${config.color} ${isBusy ? "animate-pulse" : ""}`} />
        <span className="text-sm font-medium text-white/80">{config.label}</span>
      </div>

      {isConnected && (
        <div className="text-sm text-white/50 mb-2 ml-5">
          <div>{profileName}</div>
          {status.ip && <div>IP: {status.ip}</div>}
          <div>{formatDuration(duration)}</div>
          {bandwidth.length > 1 && <BandwidthChart data={bandwidth} />}
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
            className="w-full py-2.5 px-4 bg-red-500/80 hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {status.state === "Disconnecting" && (
              <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            )}
            {status.state === "Disconnecting" ? "Disconnecting..." : "Disconnect"}
          </button>
        ) : (
          <button
            onClick={onConnect}
            disabled={!selectedProfileId}
            className="w-full py-2.5 px-4 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
          >
            Connect
          </button>
        )}
      </div>
    </div>
  );
}
