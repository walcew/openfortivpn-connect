import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useProfiles } from "./hooks/useProfiles";
import { useVpnConnection } from "./hooks/useVpnConnection";
import { ConnectionStatus } from "./components/ConnectionStatus";
import { ProfileList } from "./components/ProfileList";
import { ProfileEditor } from "./components/ProfileEditor";
import { LogViewer } from "./components/LogViewer";
import { CertDialog } from "./components/CertDialog";
import type { VpnProfile, CertWarningPayload } from "./types";

type EditingState = null | "new" | VpnProfile;

function App() {
  const { profiles, saveProfile, deleteProfile, refetch } = useProfiles();
  const { status, logs, connect, disconnect, clearLogs } = useVpnConnection();

  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [editing, setEditing] = useState<EditingState>(null);
  const [showLogs, setShowLogs] = useState(false);
  const [certWarning, setCertWarning] = useState<CertWarningPayload | null>(null);

  // Listen for cert warnings
  useEffect(() => {
    const unlisten = listen<CertWarningPayload>("cert-warning", (event) => {
      setCertWarning(event.payload);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const handleAcceptCert = async () => {
    if (!certWarning) return;
    const profile = profiles.find((p) => p.id === certWarning.profile_id);
    if (profile) {
      const updated = {
        ...profile,
        trusted_certs: [...profile.trusted_certs, certWarning.digest],
      };
      await invoke("save_profile", { profile: updated, password: null });
      await refetch();
      setCertWarning(null);
      // Reconnect with the trusted cert
      try {
        await disconnect();
        await connect(profile.id);
      } catch {
        // handled by status events
      }
    }
  };

  const handleRejectCert = async () => {
    setCertWarning(null);
    try {
      await disconnect();
    } catch {
      // handled by status events
    }
  };

  const activeProfileId = status.profile_id;
  const selectedProfile = profiles.find((p) => p.id === selectedProfileId);
  const profileName = selectedProfile?.name ?? "";

  const handleConnect = async () => {
    if (!selectedProfileId) return;
    try {
      await connect(selectedProfileId);
    } catch {
      // Error is handled via status events
    }
  };

  const handleDisconnect = async () => {
    try {
      await disconnect();
    } catch {
      // Error is handled via status events
    }
  };

  const handleSave = async (profile: VpnProfile, password?: string) => {
    await saveProfile(profile, password);
    setEditing(null);
  };

  const handleDelete = async (id: string) => {
    await deleteProfile(id);
    if (selectedProfileId === id) {
      setSelectedProfileId(null);
    }
    setEditing(null);
  };

  return (
    <div className="h-screen bg-gray-900 text-white flex flex-col select-none">
      {/* Header */}
      <div className="px-4 pt-3 pb-2">
        <h1 className="text-sm font-bold text-gray-400 tracking-wider uppercase">
          OpenFortiVPN
        </h1>
      </div>

      {/* Connection Status */}
      <div className="px-4 pb-3">
        <ConnectionStatus
          status={status}
          profileName={profileName}
          selectedProfileId={selectedProfileId}
          onConnect={handleConnect}
          onDisconnect={handleDisconnect}
        />
      </div>

      {/* Main content */}
      <div className="flex-1 px-4 overflow-y-auto min-h-0">
        {editing !== null ? (
          <ProfileEditor
            profile={editing === "new" ? null : editing}
            onSave={handleSave}
            onCancel={() => setEditing(null)}
            onDelete={editing !== "new" ? handleDelete : undefined}
          />
        ) : (
          <ProfileList
            profiles={profiles}
            selectedProfileId={selectedProfileId}
            activeProfileId={activeProfileId}
            onSelect={setSelectedProfileId}
            onEdit={(profile) => setEditing(profile)}
            onNew={() => setEditing("new")}
          />
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-gray-800 flex items-center justify-between">
        <button
          onClick={() => setShowLogs(!showLogs)}
          className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          Logs
          {logs.length > 0 && (
            <span className="bg-gray-700 text-gray-400 px-1.5 py-0.5 rounded-full text-xs">
              {logs.length}
            </span>
          )}
        </button>
        <span className="text-xs text-gray-600">v0.1.0</span>
      </div>

      {/* Log Viewer overlay */}
      <LogViewer
        logs={logs}
        isOpen={showLogs}
        onClose={() => setShowLogs(false)}
        onClear={clearLogs}
      />

      {/* Cert Warning dialog */}
      {certWarning && (
        <CertDialog
          digest={certWarning.digest}
          onAccept={handleAcceptCert}
          onReject={handleRejectCert}
        />
      )}
    </div>
  );
}

export default App;
