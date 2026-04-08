import type { VpnProfile } from "../types";

interface Props {
  profiles: VpnProfile[];
  selectedProfileId: string | null;
  activeProfileId: string | null;
  onSelect: (id: string) => void;
  onEdit: (profile: VpnProfile) => void;
  onNew: () => void;
}

export function ProfileList({
  profiles,
  selectedProfileId,
  activeProfileId,
  onSelect,
  onEdit,
  onNew,
}: Props) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-xs font-medium text-white/40 uppercase tracking-widest">
          VPN Profiles
        </h2>
      </div>

      {profiles.length === 0 ? (
        <div className="text-center text-white/40 py-6 text-sm">
          No profiles yet. Create one to get started.
        </div>
      ) : (
        <div className="flex flex-col gap-2 max-h-56 overflow-y-auto">
          {profiles.map((profile) => {
            const isSelected = profile.id === selectedProfileId;
            const isActive = profile.id === activeProfileId;
            return (
              <button
                key={profile.id}
                onClick={() => onSelect(profile.id)}
                className={`flex items-center gap-3 px-3 py-3 rounded-xl text-left transition-colors ${
                  isSelected
                    ? "bg-black/50 border border-blue-500/30"
                    : "bg-black/30 border border-white/8 hover:bg-black/40"
                }`}
              >
                {/* Server Icon */}
                <div className="w-10 h-10 rounded-lg bg-black/30 flex items-center justify-center flex-shrink-0 relative">
                  <svg className="w-5 h-5 text-white/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={1.5}
                      d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
                    />
                  </svg>
                  {isActive && (
                    <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-green-400 rounded-full border-2 border-black/30" />
                  )}
                </div>

                {/* Profile Info */}
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-white/90 truncate">
                    {profile.name || "Unnamed"}
                  </div>
                  <div className="text-xs text-white/40 truncate">
                    {profile.host}
                  </div>
                </div>

                {/* Edit Gear */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onEdit(profile);
                  }}
                  className="text-white/25 hover:text-white/60 p-1 flex-shrink-0 transition-colors"
                  title="Edit profile"
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                    />
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                    />
                  </svg>
                </button>

                {/* Radio Indicator */}
                <div className="flex-shrink-0">
                  {isSelected ? (
                    <div className="w-5 h-5 rounded-full border-2 border-blue-500 flex items-center justify-center">
                      <div className="w-2.5 h-2.5 rounded-full bg-blue-500" />
                    </div>
                  ) : (
                    <div className="w-5 h-5 rounded-full border-2 border-white/20" />
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}

      <button
        onClick={onNew}
        className="mt-2 w-full py-2.5 px-4 border border-dashed border-white/15 bg-black/20 text-white/40 hover:text-white/60 hover:border-white/25 text-sm rounded-xl transition-colors"
      >
        + New Profile
      </button>
    </div>
  );
}
