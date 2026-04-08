import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useSettings } from "../hooks/useSettings";

interface HelperStatus {
  installed: boolean;
  running: boolean;
  version: string | null;
  needs_update: boolean;
}

interface Props {
  onBack: () => void;
}

export function Settings({ onBack }: Props) {
  const { settings, loading, updateSettings } = useSettings();
  const [helperStatus, setHelperStatus] = useState<HelperStatus | null>(null);
  const [installing, setInstalling] = useState(false);
  const [installError, setInstallError] = useState<string | null>(null);

  useEffect(() => {
    invoke<HelperStatus>("check_helper_status").then(setHelperStatus).catch(console.error);
  }, []);

  const handleToggleDebug = () => {
    updateSettings({ ...settings, debug_mode: !settings.debug_mode });
  };

  const handleInstallHelper = async () => {
    setInstalling(true);
    setInstallError(null);
    try {
      await invoke("install_helper");
      const status = await invoke<HelperStatus>("check_helper_status");
      setHelperStatus(status);
    } catch (e) {
      setInstallError(String(e));
    } finally {
      setInstalling(false);
    }
  };

  return (
    <div className="flex-1 px-4 overflow-y-auto animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <button
          onClick={onBack}
          className="text-white/40 hover:text-white/80 transition-colors p-1"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </button>
        <h2 className="text-sm font-semibold text-white/80 uppercase tracking-wide">Settings</h2>
      </div>

      {!loading && (
        <div className="space-y-3">
          {/* Debug Mode Card */}
          <div className="bg-white/5 border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium text-white/90">Debug Mode</div>
                <div className="text-xs text-white/40 mt-0.5">
                  Enable verbose logging for troubleshooting
                </div>
              </div>
              <button
                onClick={handleToggleDebug}
                className={`relative w-10 h-6 rounded-full transition-colors ${
                  settings.debug_mode ? "bg-blue-500" : "bg-white/15"
                }`}
              >
                <span
                  className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${
                    settings.debug_mode ? "translate-x-4" : ""
                  }`}
                />
              </button>
            </div>
          </div>

          {/* Helper Status Card */}
          {helperStatus && (
            <div className="bg-white/5 border border-white/10 rounded-xl p-4">
              <div className="text-sm font-medium text-white/90 mb-2">Componente Auxiliar</div>
              <div className="text-xs text-white/40 mb-3">
                Permite conectar e desconectar sem digitar a senha do sistema.
              </div>

              {/* Status indicator */}
              <div className="flex items-center gap-2 mb-3">
                <div
                  className={`w-2 h-2 rounded-full ${
                    helperStatus.running ? "bg-green-400" : "bg-red-400"
                  }`}
                />
                <span className="text-xs text-white/60">
                  {helperStatus.running
                    ? `Ativo (v${helperStatus.version})`
                    : helperStatus.installed
                      ? "Instalado mas nao esta rodando"
                      : "Nao instalado"}
                </span>
              </div>

              {/* Error */}
              {installError && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-2 mb-3">
                  <p className="text-xs text-red-400">{installError}</p>
                </div>
              )}

              {/* Install/Reinstall button */}
              <button
                onClick={handleInstallHelper}
                disabled={installing}
                className="w-full px-3 py-2 text-xs text-white/80 font-medium bg-white/10 hover:bg-white/15 rounded-lg transition-colors disabled:opacity-50"
              >
                {installing
                  ? "Instalando..."
                  : helperStatus.needs_update
                    ? "Atualizar"
                    : helperStatus.installed
                      ? "Reinstalar"
                      : "Instalar"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
