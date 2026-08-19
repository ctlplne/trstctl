import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";
import { describeStatus, type StatusTone, type StatusVocabulary } from "@/lib/statusVocab";

const toneClasses: Record<StatusTone, string> = {
  operate: "border-status-info/30 bg-transparent text-status-info",
  observe: "border-border bg-transparent text-foreground",
  disclose: "border-border bg-transparent text-muted-foreground",
  success: "border-status-success/30 bg-transparent text-status-success",
  warning: "border-status-warning/30 bg-status-warning/10 text-status-warning",
  critical: "border-risk-critical/30 bg-risk-critical/10 text-risk-critical",
  high: "border-risk-high/30 bg-risk-high/10 text-risk-high",
  medium: "border-risk-medium/30 bg-risk-medium/10 text-risk-medium",
  low: "border-border bg-transparent text-muted-foreground",
  neutral: "border-border bg-muted/40 text-muted-foreground",
  info: "border-status-info/30 bg-transparent text-status-info",
};

export type StatusBadgeProps = HTMLAttributes<HTMLSpanElement> & {
  value: string;
  vocabulary?: StatusVocabulary;
  label?: string;
  tone?: StatusTone;
};

export function StatusBadge({ className, value, vocabulary = "lifecycle", label, tone, ...props }: StatusBadgeProps) {
  // Older server responses and deliberately sparse preview fixtures can omit a
  // newly-added status field. Render that as unknown instead of crashing the
  // whole operator surface; absence is not a successful status.
  const normalizedValue = typeof value === "string" && value.trim() !== "" ? value : "unknown";
  const described = describeStatus(vocabulary, normalizedValue);
  const resolvedTone = tone ?? described.tone;
  return (
    <span
      data-status-badge={vocabulary}
      data-status-value={normalizedValue}
      className={cn("inline-flex min-h-7 items-center rounded-control border px-2 py-1 text-caption font-medium", toneClasses[resolvedTone], className)}
      {...props}
    >
      {label ?? described.label}
    </span>
  );
}
