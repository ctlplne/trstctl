import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { translateNow } from "@/i18n/I18nProvider";

export function BulkActionBar({ count, onClear, children, className }: { count: number; onClear: () => void; children: ReactNode; className?: string }) {
  if (count === 0) return null;
  return (
    <div
      role="region"
      aria-label={translateNow("source.bulk.actions.19f0dd9ac4")}
      className={cn("flex items-center gap-3 rounded-control border border-border bg-muted px-3 py-2 text-body", className)}
    >
      <span className="font-medium tabular-nums">{count} {" "}{translateNow("source.selected.d7cbbb688b")}</span>
      <div className="flex items-center gap-2">{children}</div>
      <button type="button" onClick={onClear} className="ml-auto text-caption text-muted-foreground underline">
        {translateNow("source.clear.selection.cea4d2e010")}</button>
    </div>
  );
}
