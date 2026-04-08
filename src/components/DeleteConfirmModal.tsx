interface Props {
  profileName: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function DeleteConfirmModal({ profileName, onConfirm, onCancel }: Props) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-white/10 backdrop-blur-xl rounded-xl p-5 max-w-sm w-full border border-white/15">
        {/* Warning icon */}
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
              />
            </svg>
          </div>
          <h3 className="text-sm font-semibold text-white">Delete Profile</h3>
        </div>

        <p className="text-sm text-white/60 mb-4">
          Are you sure you want to delete "<span className="text-white/80">{profileName}</span>"?
          This action cannot be undone.
        </p>

        <div className="flex gap-2">
          <button
            onClick={onCancel}
            className="flex-1 py-2 px-4 bg-white/10 hover:bg-white/15 text-white/70 text-sm font-medium rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 py-2 px-4 bg-red-500/80 hover:bg-red-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}
