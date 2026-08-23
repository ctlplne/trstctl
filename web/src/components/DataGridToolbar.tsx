import { ChevronDown, Search, SlidersHorizontal } from "lucide-react";
import { useId, useState, type ReactNode, type Ref } from "react";
import { cn } from "@/lib/utils";

export type DataGridToolbarProps = {
  searchLabel?: string;
  searchPlaceholder?: string;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  searchInputId?: string;
  searchInputRef?: Ref<HTMLInputElement>;
  filters?: ReactNode;
  filterLabel?: string;
  filterSummary?: string;
  bulkActions?: ReactNode;
  savedViews?: ReactNode;
  columnChooser?: ReactNode;
  actions?: ReactNode;
  className?: string;
};

export function DataGridToolbar({
  searchLabel = "Search rows",
  searchPlaceholder = "Search...",
  searchValue,
  onSearchChange,
  searchInputId,
  searchInputRef,
  filters,
  filterLabel = "Filters",
  filterSummary,
  bulkActions,
  savedViews,
  columnChooser,
  actions,
  className,
}: DataGridToolbarProps) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const filtersId = useId();

  return (
    <div className={cn("grid w-full gap-3", className)}>
      <div className="flex w-full flex-wrap items-end gap-2">
        {onSearchChange && (
          <label className="grid min-w-56 flex-1 gap-1 text-sm font-medium sm:max-w-sm">
            <span className="sr-only">{searchLabel}</span>
            <span className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
              <input
                id={searchInputId}
                ref={searchInputRef}
                type="search"
                aria-label={searchLabel}
                placeholder={searchPlaceholder}
                value={searchValue ?? ""}
                onChange={(event) => onSearchChange(event.target.value)}
                className="min-h-9 w-full rounded-control border border-border bg-background py-2 pl-8 pr-3 text-sm"
              />
            </span>
          </label>
        )}
        {filters && (
          <button
            type="button"
            aria-controls={filtersId}
            aria-expanded={filtersOpen}
            onClick={() => setFiltersOpen((open) => !open)}
            className="inline-flex min-h-9 items-center gap-2 rounded-control border border-border bg-background px-3 py-2 text-sm font-medium text-foreground transition-colors hover:bg-muted/60"
          >
            <SlidersHorizontal className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            {filterLabel}
            {filterSummary ? <span className="text-caption font-normal text-muted-foreground">{filterSummary}</span> : null}
            <ChevronDown className={cn("h-3.5 w-3.5 text-muted-foreground transition-transform", filtersOpen && "rotate-180")} aria-hidden="true" />
          </button>
        )}
        {bulkActions && <div className="flex flex-wrap items-center gap-2">{bulkActions}</div>}
        {savedViews}
        {columnChooser}
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {filters && filtersOpen && (
        <div id={filtersId} role="group" aria-label={filterLabel} className="flex flex-wrap items-end gap-3 border-y border-border bg-muted/20 px-3 py-3">
          {filters}
        </div>
      )}
    </div>
  );
}
