interface Props {
  digest: string;
  onAccept: () => void;
  onReject: () => void;
}

export function CertDialog({ digest, onAccept, onReject }: Props) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg p-5 max-w-sm w-full border border-gray-700">
        <div className="flex items-center gap-2 mb-3">
          <svg
            className="w-5 h-5 text-yellow-400 flex-shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
            />
          </svg>
          <h3 className="text-sm font-semibold text-gray-200">
            Untrusted Certificate
          </h3>
        </div>
        <p className="text-xs text-gray-400 mb-3">
          The server presented a certificate that is not trusted. Do you want to
          trust this certificate and continue?
        </p>
        <div className="bg-gray-900 rounded p-2 mb-4">
          <p className="text-xs text-gray-500 mb-1">SHA256 Digest:</p>
          <p className="text-xs font-mono text-gray-300 break-all">{digest}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={onAccept}
            className="flex-1 py-2 px-3 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md transition-colors"
          >
            Trust & Reconnect
          </button>
          <button
            onClick={onReject}
            className="flex-1 py-2 px-3 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm font-medium rounded-md transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
