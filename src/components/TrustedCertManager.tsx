import { useState } from "react";

interface Props {
  certs: string[];
  onChange: (certs: string[]) => void;
}

function isValidDigest(s: string): boolean {
  const clean = s.replace(/:/g, "").trim();
  return /^[a-fA-F0-9]{64}$/.test(clean);
}

export function TrustedCertManager({ certs, onChange }: Props) {
  const [input, setInput] = useState("");
  const [adding, setAdding] = useState(false);

  const handleAdd = () => {
    const clean = input.replace(/:/g, "").trim().toLowerCase();
    if (!isValidDigest(clean)) return;
    if (!certs.includes(clean)) {
      onChange([...certs, clean]);
    }
    setInput("");
    setAdding(false);
  };

  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-gray-400">Trusted Certificates</span>
      {certs.length > 0 && (
        <div className="flex flex-col gap-1">
          {certs.map((cert, i) => (
            <div
              key={cert}
              className="flex items-center gap-2 bg-gray-700/50 rounded px-2 py-1"
            >
              <span className="text-xs text-gray-400 font-mono truncate flex-1" title={cert}>
                {cert.substring(0, 16)}...{cert.substring(cert.length - 8)}
              </span>
              <button
                onClick={() => onChange(certs.filter((_, j) => j !== i))}
                className="text-gray-500 hover:text-red-400 flex-shrink-0"
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}
        </div>
      )}
      {adding ? (
        <div className="flex gap-1">
          <input
            className="flex-1 bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs text-gray-200 font-mono focus:outline-none focus:border-blue-500"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAdd()}
            placeholder="SHA256 hex digest (64 chars)"
            autoFocus
          />
          <button
            onClick={handleAdd}
            disabled={!isValidDigest(input.replace(/:/g, "").trim())}
            className="text-xs px-2 py-1 bg-blue-600 disabled:opacity-50 text-white rounded"
          >
            Add
          </button>
          <button
            onClick={() => {
              setAdding(false);
              setInput("");
            }}
            className="text-xs px-2 py-1 bg-gray-700 text-gray-400 rounded"
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          onClick={() => setAdding(true)}
          className="text-xs text-blue-400 hover:text-blue-300 text-left"
        >
          + Add Certificate
        </button>
      )}
    </div>
  );
}
