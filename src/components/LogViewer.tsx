import { useEffect, useRef, useState } from "react";
import type { LogLine } from "../types";

interface Props {
  logs: LogLine[];
  isOpen: boolean;
  onClose: () => void;
  onClear: () => void;
}

const LEVEL_COLORS: Record<string, string> = {
  error: "text-red-400",
  warn: "text-yellow-400",
  info: "text-gray-300",
};

export function LogViewer({ logs, isOpen, onClose, onClear }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  if (!isOpen) return null;

  const handleCopy = async () => {
    const text = logs.map((l) => `[${l.timestamp}] ${l.message}`).join("\n");
    await navigator.clipboard.writeText(text);
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-end justify-center z-50">
      <div className="w-full h-3/4 bg-gray-900 rounded-t-xl flex flex-col border-t border-gray-700">
        <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700">
          <span className="text-sm font-semibold text-gray-300">Logs</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={`text-xs px-2 py-1 rounded ${
                autoScroll
                  ? "bg-blue-600/30 text-blue-300"
                  : "bg-gray-700 text-gray-400"
              }`}
            >
              Auto-scroll {autoScroll ? "ON" : "OFF"}
            </button>
            <button
              onClick={handleCopy}
              className="text-xs px-2 py-1 bg-gray-700 text-gray-400 hover:text-gray-200 rounded"
            >
              Copy
            </button>
            <button
              onClick={onClear}
              className="text-xs px-2 py-1 bg-gray-700 text-gray-400 hover:text-gray-200 rounded"
            >
              Clear
            </button>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-gray-300 ml-1"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
        <div
          ref={scrollRef}
          className="flex-1 overflow-y-auto px-4 py-2 font-mono text-xs leading-5"
        >
          {logs.length === 0 ? (
            <div className="text-gray-600 text-center mt-8">No logs yet</div>
          ) : (
            logs.map((log, i) => (
              <div key={i} className={LEVEL_COLORS[log.level] ?? "text-gray-300"}>
                {log.message}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
