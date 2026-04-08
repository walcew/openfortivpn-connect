import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  onInstalled: () => void;
  onDeclined: () => void;
}

export function HelperInstallDialog({ onInstalled, onDeclined }: Props) {
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleInstall = async () => {
    setInstalling(true);
    setError(null);
    try {
      await invoke("install_helper");
      onInstalled();
    } catch (e) {
      setError(String(e));
      setInstalling(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-neutral-900 border border-white/10 rounded-2xl p-6 mx-4 max-w-sm w-full shadow-2xl">
        {/* Icon */}
        <div className="flex justify-center mb-4">
          <div className="w-12 h-12 rounded-full bg-blue-500/20 flex items-center justify-center">
            <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
        </div>

        {/* Title */}
        <h3 className="text-base font-semibold text-white text-center mb-2">
          Install Helper Component
        </h3>

        {/* Description */}
        <p className="text-sm text-white/50 text-center mb-5 leading-relaxed">
          To connect and disconnect without repeatedly asking for your password, we need to
          install a helper component. This requires your administrator password{" "}
          <span className="text-white/70 font-medium">only once</span>.
        </p>

        {/* Error */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4">
            <p className="text-xs text-red-400">{error}</p>
          </div>
        )}

        {/* Buttons */}
        <div className="flex gap-3">
          <button
            onClick={onDeclined}
            disabled={installing}
            className="flex-1 px-4 py-2.5 text-sm text-white/50 hover:text-white/80 bg-white/5 hover:bg-white/10 rounded-xl transition-colors disabled:opacity-50"
          >
            Not now
          </button>
          <button
            onClick={handleInstall}
            disabled={installing}
            className="flex-1 px-4 py-2.5 text-sm text-white font-medium bg-blue-500 hover:bg-blue-600 rounded-xl transition-colors disabled:opacity-50"
          >
            {installing ? "Installing..." : "Install"}
          </button>
        </div>
      </div>
    </div>
  );
}
