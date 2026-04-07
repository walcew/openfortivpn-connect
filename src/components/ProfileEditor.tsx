import { useState } from "react";
import type { VpnProfile } from "../types";
import { newProfile } from "../types";
import { TrustedCertManager } from "./TrustedCertManager";

interface Props {
  profile: VpnProfile | null; // null = creating new
  onSave: (profile: VpnProfile, password?: string) => Promise<void>;
  onCancel: () => void;
  onDelete?: (id: string) => Promise<void>;
}

export function ProfileEditor({ profile, onSave, onCancel, onDelete }: Props) {
  const isNew = profile === null;
  const [form, setForm] = useState<VpnProfile>(profile ?? newProfile());
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    if (!form.name.trim() || !form.host.trim()) {
      setError("Name and Host are required");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave(form, password || undefined);
    } catch (e) {
      setError(String(e));
      setSaving(false);
    }
  };

  const inputClass =
    "w-full bg-gray-700 border border-gray-600 rounded-md px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 mb-1">
        <button
          onClick={onCancel}
          className="text-gray-400 hover:text-gray-200 transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </button>
        <h2 className="text-sm font-semibold text-gray-300">
          {isNew ? "New Profile" : "Edit Profile"}
        </h2>
        {!isNew && onDelete && (
          <button
            onClick={() => onDelete(form.id)}
            className="ml-auto text-red-400 hover:text-red-300 text-xs"
          >
            Delete
          </button>
        )}
      </div>

      {error && (
        <div className="text-sm text-red-400 bg-red-900/20 rounded px-3 py-2">{error}</div>
      )}

      <div className="flex flex-col gap-2.5 max-h-72 overflow-y-auto pr-1">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-gray-400">Name</span>
          <input
            className={inputClass}
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="My VPN"
          />
        </label>

        <div className="grid grid-cols-3 gap-2">
          <label className="flex flex-col gap-1 col-span-2">
            <span className="text-xs text-gray-400">Host</span>
            <input
              className={inputClass}
              value={form.host}
              onChange={(e) => setForm({ ...form, host: e.target.value })}
              placeholder="vpn.example.com"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-gray-400">Port</span>
            <input
              type="number"
              className={inputClass}
              value={form.port}
              onChange={(e) => setForm({ ...form, port: parseInt(e.target.value) || 8443 })}
            />
          </label>
        </div>

        <div className="flex flex-col gap-1">
          <span className="text-xs text-gray-400">Authentication</span>
          <div className="flex gap-4">
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="radio"
                name="auth_type"
                checked={form.auth_type === "Password"}
                onChange={() => setForm({ ...form, auth_type: "Password" })}
                className="accent-blue-500"
              />
              <span className="text-sm text-gray-300">Password</span>
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="radio"
                name="auth_type"
                checked={form.auth_type === "Saml"}
                onChange={() => setForm({ ...form, auth_type: "Saml" })}
                className="accent-blue-500"
              />
              <span className="text-sm text-gray-300">SAML</span>
            </label>
          </div>
        </div>

        {form.auth_type === "Password" && (
          <>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-gray-400">Username</span>
              <input
                className={inputClass}
                value={form.username ?? ""}
                onChange={(e) => setForm({ ...form, username: e.target.value || null })}
                placeholder="john.doe"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-gray-400">Password</span>
              <input
                type="password"
                className={inputClass}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isNew ? "Enter password" : "Leave empty to keep current"}
              />
            </label>
          </>
        )}

        <label className="flex flex-col gap-1">
          <span className="text-xs text-gray-400">Realm (optional)</span>
          <input
            className={inputClass}
            value={form.realm ?? ""}
            onChange={(e) => setForm({ ...form, realm: e.target.value || null })}
            placeholder="optional"
          />
        </label>

        <TrustedCertManager
          certs={form.trusted_certs}
          onChange={(certs) => setForm({ ...form, trusted_certs: certs })}
        />
      </div>

      <div className="flex gap-2 mt-1">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex-1 py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-md transition-colors"
        >
          {saving ? "Saving..." : "Save"}
        </button>
        <button
          onClick={onCancel}
          className="flex-1 py-2 px-4 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm font-medium rounded-md transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
