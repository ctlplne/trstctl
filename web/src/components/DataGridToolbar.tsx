import { Search } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export type DataGridToolbarProps = {
  searchLabel?: string;
  searchPlaceholder?: string;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  filters?: ReactNode;
  bulkActions?: ReactNode;
  columnChooser?: ReactNode;
  actions?: ReactNode;
  className?: string;
};

export function DataGridToolbar({
  searchLabel = "Search rows",
  searchPlaceholder = "Search...",
  searchValue,
  onSearchChange,
  filters,
  bulkActions,
  columnChooser,
  actions,
  className,
}: DataGridToolbarProps) {
  return (
    <div className={cn("flex w-full flex-wrap items-end gap-2", className)}>
      {onSearchChange && (
        <label className="grid min-w-56 gap-1 text-sm font-medium">
          <span className="sr-only">{searchLabel}</span>
          <span className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <input
              type="search"
              aria-label={searchLabel}
              placeholder={searchPlaceholder}
              value={searchValue ?? ""}
              onChange={(event) => onSearchChange(event.target.value)}
              className="min-h-9 w-full rounded-control border border-input bg-background py-2 pl-8 pr-3 text-sm"
            />
          </span>
        </label>
      )}
      {filters && <div className="flex flex-wrap items-end gap-2">{filters}</div>}
      {bulkActions && <div className="flex flex-wrap items-center gap-2">{bulkActions}</div>}
      {columnChooser}
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
