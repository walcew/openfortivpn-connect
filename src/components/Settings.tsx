import { useSettings } from "../hooks/useSettings";

interface Props {
  onBack: () => void;
}

export function Settings({ onBack }: Props) {
  const { settings, loading, updateSettings } = useSettings();

  const handleToggleDebug = () => {
    updateSettings({ ...settings, debug_mode: !settings.debug_mode });
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

      {/* Settings Card */}
      {!loading && (
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
      )}
    </div>
  );
}
