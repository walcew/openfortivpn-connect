import { getCurrentWindow } from "@tauri-apps/api/window";

export function TitleBar() {
  const handleMouseDown = (e: React.MouseEvent) => {
    // Only drag on primary (left) button
    if (e.buttons === 1) {
      if (e.detail === 2) {
        getCurrentWindow().toggleMaximize();
      } else {
        getCurrentWindow().startDragging();
      }
    }
  };

  return (
    <div
      data-tauri-drag-region
      onMouseDown={handleMouseDown}
      className="h-[28px] shrink-0 relative"
    >
      {/* Centered title - pointer-events-none so drag works through it */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <span className="text-[11px] font-semibold text-white/60 tracking-wider">
          OPENFORTIVPN CONNECT
        </span>
      </div>
    </div>
  );
}
