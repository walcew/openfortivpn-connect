import { useEffect, useRef, useState } from "react";

interface Props {
  profileName: string;
  onSubmit: (otp: string) => void;
  onCancel: () => void;
}

export function OtpDialog({ profileName, onSubmit, onCancel }: Props) {
  const [otp, setOtp] = useState("");
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    const value = otp.trim();
    if (!value) {
      setError("OTP is required");
      return;
    }
    onSubmit(value);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm bg-neutral-950 border border-white/10 rounded-xl p-4 shadow-xl"
      >
        <h2 className="text-sm font-semibold text-white/90 mb-1">One-time password (OTP)</h2>
        <p className="text-xs text-white/40 mb-4">
          Enter the current OTP for {profileName || "this profile"}.
        </p>

        {error && (
          <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 mb-3">
            {error}
          </div>
        )}

        <input
          ref={inputRef}
          value={otp}
          onChange={(event) => {
            setOtp(event.target.value);
            setError(null);
          }}
          className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 placeholder-white/30 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30"
          placeholder="OTP"
          autoComplete="one-time-code"
        />

        <div className="flex gap-2 mt-4">
          <button
            type="submit"
            className="flex-1 py-2 px-4 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Connect
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="flex-1 py-2 px-4 bg-white/10 hover:bg-white/15 text-white/70 text-sm font-medium rounded-lg transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
