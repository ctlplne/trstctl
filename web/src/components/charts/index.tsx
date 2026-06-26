import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export type ChartTone = "critical" | "high" | "medium" | "low" | "neutral" | "success" | "warning" | "info" | "brand";

const toneVar: Record<ChartTone, string> = {
  critical: "--risk-critical",
  high: "--risk-high",
  medium: "--risk-medium",
  low: "--risk-low",
  neutral: "--status-neutral",
  success: "--status-success",
  warning: "--status-warning",
  info: "--status-info",
  brand: "--brand-accent",
};

const toneText: Record<ChartTone, string> = {
  critical: "text-risk-critical",
  high: "text-risk-high",
  medium: "text-risk-medium",
  low: "text-risk-low",
  neutral: "text-muted-foreground",
  success: "text-status-success",
  warning: "text-status-warning",
  info: "text-status-info",
  brand: "text-brand-accent",
};

function toneColor(tone: ChartTone): string {
  return `hsl(var(${toneVar[tone]}))`;
}

export type StatTileProps = {
  label: string;
  value: string | number;
  hint?: string;
  tone?: ChartTone;
  icon?: ReactNode;
  className?: string;
};

export function StatTile({ label, value, hint, tone, icon, className }: StatTileProps) {
  return (
    <div className={cn("rounded-panel bg-card p-4 shadow-elevation1", className)}>
      <div className="flex items-center gap-2">
        {icon ? (
          <span aria-hidden="true" className="text-muted-foreground">
            {icon}
          </span>
        ) : null}
        <p className="text-caption text-muted-foreground">{label}</p>
      </div>
      <p className={cn("mt-1 text-display font-semibold tabular-nums", tone ? toneText[tone] : "text-foreground")}>{value}</p>
      {hint ? <p className="mt-1 text-caption text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

export type MeterSegment = { value: number; tone: ChartTone; label: string };

export function Meter({ segments, ariaLabel, className }: { segments: MeterSegment[]; ariaLabel: string; className?: string }) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0) || 1;
  return (
    <div role="img" aria-label={ariaLabel} className={cn("flex h-2.5 w-full overflow-hidden rounded-full bg-muted", className)}>
      {segments.map((segment) => (
        <span
          key={segment.label}
          title={`${segment.label}: ${segment.value}`}
          style={{ width: `${(segment.value / total) * 100}%`, backgroundColor: toneColor(segment.tone) }}
        />
      ))}
    </div>
  );
}

export type BucketDatum = { label: string; value: number; tone?: ChartTone };

export function BucketBar({ data, ariaLabel, height = 160, className }: { data: BucketDatum[]; ariaLabel: string; height?: number; className?: string }) {
  const max = Math.max(1, ...data.map((datum) => datum.value));
  const barWidth = 36;
  const gap = 20;
  const chartHeight = height - 28;
  const width = data.length * (barWidth + gap);
  return (
    <svg role="img" aria-label={ariaLabel} viewBox={`0 0 ${width} ${height}`} width="100%" height={height} className={className}>
      <title>{ariaLabel}</title>
      {data.map((datum, index) => {
        const barHeight = Math.round((datum.value / max) * chartHeight);
        const x = index * (barWidth + gap) + gap / 2;
        return (
          <g key={datum.label}>
            <rect x={x} y={chartHeight - barHeight} width={barWidth} height={barHeight} rx={4} style={{ fill: toneColor(datum.tone ?? "neutral") }} />
            <text x={x + barWidth / 2} y={chartHeight - barHeight - 6} textAnchor="middle" fontSize={11} style={{ fill: "hsl(var(--foreground))" }}>
              {datum.value}
            </text>
            <text x={x + barWidth / 2} y={height - 8} textAnchor="middle" fontSize={11} style={{ fill: "hsl(var(--muted-foreground))" }}>
              {datum.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export type DonutSegment = { value: number; tone: ChartTone; label: string };

export function Donut({ segments, ariaLabel, size = 120, className }: { segments: DonutSegment[]; ariaLabel: string; size?: number; className?: string }) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0) || 1;
  const radius = size / 2 - 10;
  const circumference = 2 * Math.PI * radius;
  return (
    <svg role="img" aria-label={ariaLabel} viewBox={`0 0 ${size} ${size}`} width={size} height={size} className={className}>
      <title>{ariaLabel}</title>
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" strokeWidth={12} style={{ stroke: "hsl(var(--muted))" }} />
      {segments.map((segment, index) => {
        const before = segments.slice(0, index).reduce((sum, item) => sum + item.value, 0);
        const offset = (before / total) * circumference;
        const length = (segment.value / total) * circumference;
        return (
          <circle
            key={segment.label}
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            strokeWidth={12}
            strokeDasharray={`${length} ${circumference - length}`}
            strokeDashoffset={-offset}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            style={{ stroke: toneColor(segment.tone) }}
          >
            <title>{`${segment.label}: ${segment.value}`}</title>
          </circle>
        );
      })}
    </svg>
  );
}

export function Sparkline({
  points,
  ariaLabel,
  tone = "brand",
  width = 120,
  height = 32,
  className,
}: {
  points: number[];
  ariaLabel: string;
  tone?: ChartTone;
  width?: number;
  height?: number;
  className?: string;
}) {
  const max = Math.max(1, ...points);
  const min = Math.min(0, ...points);
  const span = max - min || 1;
  const step = points.length > 1 ? width / (points.length - 1) : width;
  const d = points
    .map((point, index) => `${index === 0 ? "M" : "L"}${(index * step).toFixed(1)} ${(height - ((point - min) / span) * height).toFixed(1)}`)
    .join(" ");
  return (
    <svg role="img" aria-label={ariaLabel} viewBox={`0 0 ${width} ${height}`} width={width} height={height} className={className}>
      <title>{ariaLabel}</title>
      <path d={d} fill="none" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" style={{ stroke: toneColor(tone) }} />
    </svg>
  );
}
