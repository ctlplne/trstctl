import { useMemo, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

/**
 * Column describes one column of a DataTable: a stable key, a header node, and a
 * render function from a row to a cell. `align="end"` right-aligns (useful for
 * numbers/actions); `className`/`headClassName` reach the td/th.
 */
export type Column<T> = {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  align?: "start" | "end";
  className?: string;
  headClassName?: string;
};

type Density = "compact" | "comfortable";

export type DataTableProps<T> = {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  /** sr-only <caption> — required so every table is announced (WCAG). */
  caption: string;
  loading?: boolean;
  loadingLabel?: string;
  error?: string | null;
  errorTitle?: string;
  /** Rendered (inside the table) when there are no rows and we're not loading. */
  empty?: ReactNode;
  onRowClick?: (row: T) => void;
  rowClassName?: (row: T) => string | undefined;
  /** Show a Compact/Comfortable density toggle, persisted per table. */
  density?: boolean;
  densityStorageKey?: string;
  /** Enable client-side pagination at this page size. */
  pageSize?: number;
  /** Extra controls rendered at the end of the table's header bar. */
  toolbarEnd?: ReactNode;
  /** If set, the table wrapper becomes role="region" with this accessible name. */
  regionLabel?: string;
  /** Extra classes on the <table> (e.g. a min-width for wide tables). */
  tableClassName?: string;
  className?: string;
};

function readDensity(key?: string): Density {
  if (!key) return "comfortable";
  try {
    return localStorage.getItem(key) === "compact" ? "compact" : "comfortable";
  } catch {
    return "comfortable";
  }
}

/**
 * DataTable is the single, shared inventory table for trstctl's list pages
 * (F4: one consistent page template). It renders a `.ui-table` with a sr-only
 * caption, typed columns, integrated loading/error/empty states, optional
 * row-click, an optional density toggle, and optional client-side pagination —
 * so every list page looks and behaves the same and pages stop hand-rolling
 * `<table>` markup. The rendered cell content is exactly `column.render(row)`,
 * so existing text/role assertions keep working after a page migrates.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  loading = false,
  loadingLabel = "Loading…",
  error = null,
  errorTitle = "Could not load data",
  empty,
  onRowClick,
  rowClassName,
  density = false,
  densityStorageKey,
  pageSize,
  toolbarEnd,
  regionLabel,
  tableClassName,
  className,
}: DataTableProps<T>) {
  const [densityMode, setDensityMode] = useState<Density>(() => readDensity(densityStorageKey));
  const [page, setPage] = useState(0);

  const total = rows.length;
  const pageCount = pageSize ? Math.max(1, Math.ceil(total / pageSize)) : 1;
  const clampedPage = Math.min(page, pageCount - 1);
  const visibleRows = useMemo(() => {
    if (!pageSize) return rows;
    const start = clampedPage * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, pageSize, clampedPage]);

  function setDensity(next: Density) {
    setDensityMode(next);
    if (densityStorageKey) {
      try {
        localStorage.setItem(densityStorageKey, next);
      } catch {
        /* storage unavailable — density just isn't remembered */
      }
    }
  }

  const showHeaderBar = density || toolbarEnd;
  const colCount = columns.length;

  return (
    <div className={cn("grid gap-2", className)}>
      {showHeaderBar && (
        <div className="flex flex-wrap items-center justify-end gap-2">
          {toolbarEnd}
          {density && (
            <div role="group" aria-label="Row density" className="inline-flex overflow-hidden rounded-control border border-border text-caption">
              {(["comfortable", "compact"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  aria-pressed={densityMode === mode}
                  onClick={() => setDensity(mode)}
                  className={cn(
                    "px-2.5 py-1 capitalize transition-colors",
                    densityMode === mode ? "bg-brand-accent/10 font-medium text-brand-accent" : "text-muted-foreground hover:bg-foreground/[0.04]",
                  )}
                >
                  {mode}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="ui-panel overflow-x-auto" {...(regionLabel ? { role: "region", "aria-label": regionLabel } : {})}>
        <table className={cn("ui-table", tableClassName)} data-density={densityMode}>
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.key} scope="col" className={cn(col.align === "end" && "text-end", col.headClassName)}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={colCount}>
                  <LoadingState>{loadingLabel}</LoadingState>
                </td>
              </tr>
            ) : error ? (
              <tr>
                <td colSpan={colCount}>
                  <ErrorState title={errorTitle}>{error}</ErrorState>
                </td>
              </tr>
            ) : total === 0 ? (
              <tr>
                <td colSpan={colCount} className="text-muted-foreground">
                  {empty ?? "No results."}
                </td>
              </tr>
            ) : (
              visibleRows.map((row) => (
                <tr
                  key={rowKey(row)}
                  className={cn(
                    onRowClick && "cursor-pointer hover:bg-foreground/[0.03] focus-within:bg-foreground/[0.03]",
                    rowClassName?.(row),
                  )}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                >
                  {columns.map((col) => (
                    <td key={col.key} className={cn(col.align === "end" && "text-end tabular-nums", col.className)}>
                      {col.render(row)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {pageSize && total > pageSize && (
        <div className="flex flex-wrap items-center justify-between gap-2 text-caption text-muted-foreground">
          <span aria-live="polite">
            Showing {clampedPage * pageSize + 1}–{Math.min(total, (clampedPage + 1) * pageSize)} of {total}
          </span>
          <span className="inline-flex items-center gap-1">
            <button
              type="button"
              className="rounded-control border border-border px-2 py-1 disabled:opacity-40 enabled:hover:bg-foreground/[0.04]"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={clampedPage === 0}
            >
              Prev
            </button>
            <span className="px-1">
              Page {clampedPage + 1} of {pageCount}
            </span>
            <button
              type="button"
              className="rounded-control border border-border px-2 py-1 disabled:opacity-40 enabled:hover:bg-foreground/[0.04]"
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              disabled={clampedPage >= pageCount - 1}
            >
              Next
            </button>
          </span>
        </div>
      )}
    </div>
  );
}
