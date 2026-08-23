import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";
import { describeStatus, type StatusTone, type StatusVocabulary } from "@/lib/statusVocab";

const toneTextClasses: Record<StatusTone, string> = {
  operate: "text-status-info",
  observe: "text-foreground",
  disclose: "text-muted-foreground",
  success: "text-status-success",
  warning: "text-status-warning",
  critical: "text-risk-critical",
  high: "text-risk-high",
  medium: "text-risk-medium",
  low: "text-muted-foreground",
  neutral: "text-muted-foreground",
  info: "text-status-info",
};

const toneDotClasses: Record<StatusTone, string> = {
  operate: "bg-status-info",
  observe: "bg-foreground",
  disclose: "bg-muted-foreground",
  success: "bg-status-success",
  warning: "bg-status-warning",
  critical: "bg-risk-critical",
  high: "bg-risk-high",
  medium: "bg-risk-medium",
  low: "bg-muted-foreground",
  neutral: "bg-muted-foreground",
  info: "bg-status-info",
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
      className={cn("inline-flex min-h-6 items-center gap-1.5 text-caption font-medium leading-none", toneTextClasses[resolvedTone], className)}
      {...props}
    >
      <span aria-hidden="true" data-status-dot={resolvedTone} className={cn("h-1.5 w-1.5 shrink-0 rounded-full", toneDotClasses[resolvedTone])} />
      {label ?? described.label}
    </span>
  );
}
