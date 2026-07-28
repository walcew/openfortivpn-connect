import { useEffect, useRef, useState } from "react";

interface Props {
  onSubmit: (code: string) => Promise<void>;
  onCancel: () => void;
}

export function OtpDialog({ onSubmit, onCancel }: Props) {
  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = async () => {
    const trimmed = code.trim();
    if (!trimmed) {
      setError("Enter the authentication code");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit(trimmed);
    } catch (e) {
      setError(String(e));
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-white/10 backdrop-blur-xl rounded-xl p-5 max-w-sm w-full border border-white/15">
        <div className="flex items-center gap-2 mb-3">
          <svg
            className="w-5 h-5 text-blue-400 flex-shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
            />
          </svg>
          <h3 className="text-sm font-semibold text-white/90">
            Two-Factor Authentication
          </h3>
        </div>
        <p className="text-xs text-white/50 mb-3">
          Enter the code from your authenticator app to continue connecting.
        </p>
        <input
          ref={inputRef}
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          className="w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 placeholder-white/30 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30 mb-3 tracking-widest"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void handleSubmit();
          }}
          placeholder="123456"
          disabled={submitting}
        />
        {error && (
          <div className="text-xs text-red-400 mb-3">{error}</div>
        )}
        <div className="flex gap-2">
          <button
            onClick={() => void handleSubmit()}
            disabled={submitting}
            className="flex-1 py-2 px-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {submitting ? "Submitting..." : "Submit"}
          </button>
          <button
            onClick={onCancel}
            disabled={submitting}
            className="flex-1 py-2 px-3 bg-white/10 hover:bg-white/15 disabled:opacity-50 text-white/70 text-sm font-medium rounded-lg transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
