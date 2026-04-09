import type { BandwidthData } from "../types";

interface Props {
  data: BandwidthData[];
}

function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
  if (bytesPerSec < 1024 * 1024)
    return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const CHART_HEIGHT = 80;
const MAX_POINTS = 60;

export function BandwidthChart({ data }: Props) {
  if (data.length === 0) return null;

  const latest = data[data.length - 1];

  // Compute max speed for Y-axis scaling (minimum 1 KB/s)
  const maxSpeed = Math.max(
    ...data.map((d) => Math.max(d.rx_speed, d.tx_speed)),
    1024,
  );

  // Build SVG paths using viewBox-relative coordinates
  const viewWidth = MAX_POINTS - 1;
  const offset = MAX_POINTS - data.length;

  const buildPath = (key: "rx_speed" | "tx_speed"): string => {
    const points = data.map((d, i) => {
      const x = offset + i;
      const y = CHART_HEIGHT - (d[key] / maxSpeed) * CHART_HEIGHT;
      return `${x},${y}`;
    });
    const lastX = offset + data.length - 1;
    const firstX = offset;
    return `M${points[0]} ${points.slice(1).map((p) => `L${p}`).join(" ")} L${lastX},${CHART_HEIGHT} L${firstX},${CHART_HEIGHT} Z`;
  };

  const rxPath = buildPath("rx_speed");
  const txPath = buildPath("tx_speed");

  return (
    <div className="mt-3">
      {/* Max speed label */}
      <div className="text-[10px] text-white/30 text-right mb-0.5">
        {formatSpeed(maxSpeed)}
      </div>

      {/* Chart */}
      <svg
        width="100%"
        height={CHART_HEIGHT}
        viewBox={`0 0 ${viewWidth} ${CHART_HEIGHT}`}
        preserveAspectRatio="none"
        className="rounded border border-white/5"
      >
        {/* Grid lines */}
        <line
          x1="0"
          y1={CHART_HEIGHT / 2}
          x2={viewWidth}
          y2={CHART_HEIGHT / 2}
          stroke="rgba(255,255,255,0.05)"
          strokeDasharray="2,2"
        />

        {/* RX area (green) */}
        <path
          d={rxPath}
          fill="rgba(74, 222, 128, 0.2)"
          stroke="rgba(74, 222, 128, 0.7)"
          strokeWidth="0.5"
          vectorEffect="non-scaling-stroke"
        />
        {/* TX area (orange) */}
        <path
          d={txPath}
          fill="rgba(251, 146, 60, 0.15)"
          stroke="rgba(251, 146, 60, 0.7)"
          strokeWidth="0.5"
          vectorEffect="non-scaling-stroke"
        />
      </svg>

      {/* Speed indicators */}
      <div className="flex justify-between text-xs text-white/50 mt-1.5">
        <div className="flex items-center gap-1.5">
          <span className="inline-block w-2 h-2 rounded-full bg-green-400/70" />
          <span>
            <span className="text-green-400/90">
              {formatSpeed(latest.rx_speed)}
            </span>{" "}
            down
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="inline-block w-2 h-2 rounded-full bg-orange-400/70" />
          <span>
            <span className="text-orange-400/90">
              {formatSpeed(latest.tx_speed)}
            </span>{" "}
            up
          </span>
        </div>
      </div>

      {/* Total transferred */}
      <div className="flex justify-between text-[10px] text-white/30 mt-0.5">
        <span>{formatBytes(latest.rx_bytes)} received</span>
        <span>{formatBytes(latest.tx_bytes)} sent</span>
      </div>
    </div>
  );
}
