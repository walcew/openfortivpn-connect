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
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
          VPN Profiles
        </h2>
      </div>

      {profiles.length === 0 ? (
        <div className="text-center text-gray-500 py-6 text-sm">
          No profiles yet. Create one to get started.
        </div>
      ) : (
        <div className="flex flex-col gap-1 max-h-48 overflow-y-auto">
          {profiles.map((profile) => {
            const isSelected = profile.id === selectedProfileId;
            const isActive = profile.id === activeProfileId;
            return (
              <button
                key={profile.id}
                onClick={() => onSelect(profile.id)}
                className={`flex items-center justify-between px-3 py-2 rounded-md text-left transition-colors ${
                  isSelected
                    ? "bg-blue-600/30 border border-blue-500/50"
                    : "hover:bg-gray-700/50 border border-transparent"
                }`}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      isActive ? "bg-green-400" : "bg-gray-500"
                    }`}
                  />
                  <span className="text-sm text-gray-200 truncate">
                    {profile.name || "Unnamed"}
                  </span>
                  <span
                    className={`text-xs px-1.5 py-0.5 rounded flex-shrink-0 ${
                      profile.auth_type === "Saml"
                        ? "bg-blue-500/20 text-blue-300"
                        : "bg-gray-600/50 text-gray-400"
                    }`}
                  >
                    {profile.auth_type === "Saml" ? "SAML" : "Pass"}
                  </span>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onEdit(profile);
                  }}
                  className="text-gray-500 hover:text-gray-300 p-1 flex-shrink-0"
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
              </button>
            );
          })}
        </div>
      )}

      <button
        onClick={onNew}
        className="mt-2 w-full py-2 px-4 border border-dashed border-gray-600 text-gray-400 hover:text-gray-200 hover:border-gray-500 text-sm rounded-md transition-colors"
      >
        + New Profile
      </button>
    </div>
  );
}
