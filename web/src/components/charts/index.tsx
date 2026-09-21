import { useId, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { translateNow } from "@/i18n/I18nProvider";

export type ChartTone =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "neutral"
  | "success"
  | "warning"
  | "info"
  | "brand"
  | "operate"
  | "observe"
  | "disclose"
  | "gold";

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
  operate: "--operate",
  observe: "--observe",
  disclose: "--disclose",
  gold: "--primary",
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
  operate: "text-operate",
  observe: "text-observe",
  disclose: "text-disclose",
  gold: "text-primary",
};

/** chartToneColor resolves a semantic chart tone to its themed CSS color.
 * Use this (not raw hsl(var(--…)) strings) wherever chart-adjacent UI needs
 * a matching swatch, so every chart pulls from one palette. */
export function chartToneColor(tone: ChartTone): string {
  return `hsl(var(${toneVar[tone]}))`;
}

function toneColor(tone: ChartTone): string {
  return chartToneColor(tone);
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
          title={translateNow("source.value1.value2.efae3eb968", { value1: segment.label, value2: segment.value })}
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
            <text
              x={x + barWidth / 2}
              y={chartHeight - barHeight - 6}
              textAnchor="middle"
              fontSize={11}
              className="tabular-nums"
              style={{ fill: "hsl(var(--foreground))" }}
            >
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

export type TimeBarDatum = { label: string; value: number; tone?: ChartTone };

export function TimeBarChart({
  ariaLabel,
  className,
  data,
  height = 180,
  tone = "brand",
}: {
  data: TimeBarDatum[];
  ariaLabel: string;
  height?: number;
  tone?: ChartTone;
  className?: string;
}) {
  const max = Math.max(1, ...data.map((datum) => datum.value));
  const width = Math.max(180, data.length * 56);
  const padX = 18;
  const top = 20;
  // Keep a range and its unit readable in narrow panels. SVG text does not
  // wrap by itself; reserve a line for each word instead of shrinking the font.
  const labelLines = data.map((datum) => datum.label.trim().split(/\s+/u));
  const lineHeight = 14;
  const bottom = 14 + Math.max(1, ...labelLines.map((lines) => lines.length)) * lineHeight;
  const chartHeight = height - top - bottom;
  const step = data.length > 0 ? (width - padX * 2) / data.length : width - padX * 2;
  const barWidth = Math.max(16, Math.min(34, step * 0.62));
  return (
    <svg role="img" aria-label={ariaLabel} viewBox={`0 0 ${width} ${height}`} width="100%" height={height} className={className}>
      <title>{ariaLabel}</title>
      {[0.25, 0.5, 0.75].map((line) => (
        <line key={line} x1={padX} x2={width - padX} y1={top + line * chartHeight} y2={top + line * chartHeight} stroke="hsl(var(--border))" strokeWidth="1" />
      ))}
      {data.map((datum, index) => {
        const barHeight = Math.round((datum.value / max) * chartHeight);
        const x = padX + index * step + (step - barWidth) / 2;
        const y = top + chartHeight - barHeight;
        return (
          <g key={datum.label}>
            <rect x={x} y={y} width={barWidth} height={barHeight} rx={4} style={{ fill: toneColor(datum.tone ?? tone) }}>
              <title>{translateNow("source.value1.value2.efae3eb968", { value1: datum.label, value2: datum.value })}</title>
            </rect>
            <text
              x={x + barWidth / 2}
              y={Math.max(12, y - 6)}
              textAnchor="middle"
              fontSize={11}
              className="tabular-nums"
              style={{ fill: "hsl(var(--foreground))" }}
            >
              {datum.value}
            </text>
            <text textAnchor="middle" fontSize={11} aria-label={datum.label} style={{ fill: "hsl(var(--muted-foreground))" }}>
              {labelLines[index]!.map((line, lineIndex) => (
                <tspan key={lineIndex} x={x + barWidth / 2} y={height - bottom + lineHeight * (lineIndex + 1)}>
                  {line}
                </tspan>
              ))}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export type StackedTimeBarDatum = { label: string; segments: Array<{ label: string; value: number; tone: ChartTone }> };

export function StackedTimeBarChart({
  ariaLabel,
  className,
  data,
  height = 180,
}: {
  data: StackedTimeBarDatum[];
  ariaLabel: string;
  height?: number;
  className?: string;
}) {
  const max = Math.max(1, ...data.map((datum) => datum.segments.reduce((sum, segment) => sum + segment.value, 0)));
  const width = Math.max(220, data.length * 64);
  const padX = 18;
  const top = 20;
  const bottom = 42;
  const chartHeight = height - top - bottom;
  const step = data.length > 0 ? (width - padX * 2) / data.length : width - padX * 2;
  const barWidth = Math.max(18, Math.min(38, step * 0.58));
  const legend = Array.from(new Map(data.flatMap((datum) => datum.segments.map((segment) => [segment.label, segment.tone] as const))));
  return (
    <svg role="img" aria-label={ariaLabel} viewBox={`0 0 ${width} ${height}`} width="100%" height={height} className={className}>
      <title>{ariaLabel}</title>
      {[0.25, 0.5, 0.75].map((line) => (
        <line key={line} x1={padX} x2={width - padX} y1={top + line * chartHeight} y2={top + line * chartHeight} stroke="hsl(var(--border))" strokeWidth="1" />
      ))}
      {data.map((datum, index) => {
        const x = padX + index * step + (step - barWidth) / 2;
        let cursor = top + chartHeight;
        return (
          <g key={datum.label}>
            {datum.segments.map((segment) => {
              const h = Math.round((segment.value / max) * chartHeight);
              cursor -= h;
              return (
                <rect key={segment.label} x={x} y={cursor} width={barWidth} height={h} rx={2} style={{ fill: toneColor(segment.tone) }}>
                  <title>{translateNow("source.value1.value2.value3.19d646a699", { value1: datum.label, value2: segment.label, value3: segment.value })}</title>
                </rect>
              );
            })}
            <text x={x + barWidth / 2} y={height - 24} textAnchor="middle" fontSize={11} style={{ fill: "hsl(var(--muted-foreground))" }}>
              {datum.label}
            </text>
          </g>
        );
      })}
      {legend.map(([label, tone], index) => {
        const x = padX + index * 92;
        return (
          <g key={label} transform={`translate(${x} ${height - 12})`}>
            <rect width="8" height="8" rx="2" y="-7" style={{ fill: toneColor(tone) }} />
            <text x="12" y="0" fontSize={11} style={{ fill: "hsl(var(--muted-foreground))" }}>
              {label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export type DonutSegment = { value: number; tone: ChartTone; label: string };

export function Donut({
  segments,
  ariaLabel,
  size = 128,
  centerLabel,
  centerSub,
  withLegend = false,
  className,
}: {
  segments: DonutSegment[];
  ariaLabel: string;
  size?: number;
  /** Optional headline value rendered inside the ring (e.g. the total). */
  centerLabel?: string;
  centerSub?: string;
  /** Renders a swatch legend beside the ring using the same tone palette. */
  withLegend?: boolean;
  className?: string;
}) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0) || 1;
  const strokeWidth = size / 8;
  const radius = size / 2 - strokeWidth / 2 - 2;
  const circumference = 2 * Math.PI * radius;
  const ring = (
    // aria-label only (no <title>) so the chart heading text is not duplicated
    // for text queries and assistive tech.
    <svg role="img" aria-label={ariaLabel} viewBox={`0 0 ${size} ${size}`} width={size} height={size} className={className}>
      <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" strokeWidth={strokeWidth} style={{ stroke: "hsl(var(--muted))" }} />
        {segments.map((segment, index) => {
          const before = segments.slice(0, index).reduce((sum, item) => sum + item.value, 0);
          const offset = (before / total) * circumference;
          const length = (segment.value / total) * circumference;
          return (
            <circle
              key={`${segment.label}-${index}`}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              strokeWidth={strokeWidth}
              strokeDasharray={`${length} ${circumference - length}`}
              strokeDashoffset={-offset}
              style={{ stroke: toneColor(segment.tone) }}
            >
              <title>{translateNow("source.value1.value2.efae3eb968", { value1: segment.label, value2: segment.value })}</title>
            </circle>
          );
        })}
      </g>
      {centerLabel != null && (
        <text x={size / 2} y={centerSub ? size / 2 - 3 : size / 2 + 5} textAnchor="middle" className="fill-foreground text-[18px] font-semibold tabular-nums">
          {centerLabel}
        </text>
      )}
      {centerSub != null && (
        <text x={size / 2} y={size / 2 + 15} textAnchor="middle" className="fill-muted-foreground text-[9px]">
          {centerSub}
        </text>
      )}
    </svg>
  );
  if (!withLegend) return ring;
  return (
    <div className="flex items-center gap-4">
      {ring}
      <ul className="min-w-0 flex-1 space-y-1.5">
        {segments.map((segment, index) => (
          <li key={`${segment.label}-${index}`} className="flex items-center justify-between gap-2 text-caption">
            <span className="flex min-w-0 items-center gap-2">
              <span aria-hidden="true" className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: toneColor(segment.tone) }} />
              <span className="truncate text-muted-foreground">{segment.label}</span>
            </span>
            <span className="shrink-0 font-medium tabular-nums">{segment.value}</span>
          </li>
        ))}
      </ul>
    </div>
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
  /** Omit for purely decorative sparklines next to an already-labeled value. */
  ariaLabel?: string;
  tone?: ChartTone;
  width?: number;
  height?: number;
  className?: string;
}) {
  const max = Math.max(1, ...points);
  const min = Math.min(0, ...points);
  const span = max - min || 1;
  const step = points.length > 1 ? width / (points.length - 1) : width;
  const pad = 2;
  const y = (point: number) => pad + (1 - (point - min) / span) * (height - pad * 2);
  const d = points.map((point, index) => `${index === 0 ? "M" : "L"}${(index * step).toFixed(1)} ${y(point).toFixed(1)}`).join(" ");
  return (
    <svg
      role={ariaLabel ? "img" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      className={cn("max-w-full", className)}
    >
      {ariaLabel && <title>{ariaLabel}</title>}
      <path d={d} fill="none" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" style={{ stroke: toneColor(tone) }} />
    </svg>
  );
}

/** AreaTrend is the standard filled line chart for time series (issuance
 * trends and similar): quarter grid lines, a soft gradient fill, and point
 * markers — all drawn from the shared tone palette. */
export function AreaTrend({
  points,
  ariaLabel,
  tone = "brand",
  width = 640,
  height = 200,
  className,
}: {
  points: number[];
  ariaLabel: string;
  tone?: ChartTone;
  width?: number;
  height?: number;
  className?: string;
}) {
  const gradientId = useId();
  const pad = 8;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const span = Math.max(1, max - min);
  const x = (index: number) => pad + (points.length > 1 ? (index / (points.length - 1)) * (width - pad * 2) : 0);
  const y = (value: number) => pad + (1 - (value - min) / span) * (height - pad * 2);
  const line = points.map((value, index) => `${x(index).toFixed(1)},${y(value).toFixed(1)}`).join(" ");
  const area = `M ${x(0)},${y(points[0] ?? 0)} L ${line.split(" ").join(" L ")} L ${x(points.length - 1)},${height - pad} L ${x(0)},${height - pad} Z`;
  const color = toneColor(tone);
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className={cn("h-48 w-full", className)} role="img" aria-label={ariaLabel}>
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.22" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((line_) => (
        <line
          key={line_}
          x1={pad}
          x2={width - pad}
          y1={pad + line_ * (height - pad * 2)}
          y2={pad + line_ * (height - pad * 2)}
          stroke="hsl(var(--border))"
          strokeWidth="1"
        />
      ))}
      <path d={area} fill={`url(#${gradientId})`} />
      <polyline points={line} fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      {points.map((value, index) => (
        <circle key={index} cx={x(index)} cy={y(value)} r="2.6" fill="hsl(var(--card))" stroke={color} strokeWidth="1.6" />
      ))}
    </svg>
  );
}
