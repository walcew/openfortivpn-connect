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
  info: "text-white/60",
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
      <div className="w-full h-3/4 bg-black/80 backdrop-blur-xl rounded-t-xl flex flex-col border-t border-white/10">
        <div className="flex items-center justify-between px-4 py-2 border-b border-white/10">
          <span className="text-sm font-semibold text-white/70">Logs</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={`text-xs px-2 py-1 rounded-md ${
                autoScroll
                  ? "bg-blue-500/20 text-blue-300"
                  : "bg-white/10 text-white/40"
              }`}
            >
              Auto-scroll {autoScroll ? "ON" : "OFF"}
            </button>
            <button
              onClick={handleCopy}
              className="text-xs px-2 py-1 bg-white/10 text-white/40 hover:text-white/70 rounded-md transition-colors"
            >
              Copy
            </button>
            <button
              onClick={onClear}
              className="text-xs px-2 py-1 bg-white/10 text-white/40 hover:text-white/70 rounded-md transition-colors"
            >
              Clear
            </button>
            <button
              onClick={onClose}
              className="text-white/30 hover:text-white/60 ml-1 transition-colors"
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
            <div className="text-white/20 text-center mt-8">No logs yet</div>
          ) : (
            logs.map((log, i) => (
              <div key={i} className={LEVEL_COLORS[log.level] ?? "text-white/60"}>
                {log.message}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
