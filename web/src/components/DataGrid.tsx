import { useMemo, useState, type ReactNode } from "react";
import { ChevronDown, ChevronsUpDown, ChevronUp, Columns3 } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import {
  ErrorState,
  LoadingState,
  PermissionDeniedState,
  UnavailableState,
} from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type SortDirection = "asc" | "desc";

export type DataGridColumn<Row> = {
  id: string;
  header: ReactNode;
  cell: (row: Row) => ReactNode;
  sortable?: boolean;
  hiddenByDefault?: boolean;
  className?: string;
};

export type DataGridState = "ready" | "loading" | "empty" | "error" | "permission-denied" | "unavailable";

export type DataGridSort = {
  columnId: string;
  direction: SortDirection;
};

export type DataGridToolbarControls = {
  columnChooser: ReactNode;
};

export type DataGridProps<Row> = {
  ariaLabel: string;
  rows: Row[];
  columns: Array<DataGridColumn<Row>>;
  getRowId: (row: Row) => string;
  state?: DataGridState;
  stateMessage?: ReactNode;
  stateTitle?: string;
  sort?: DataGridSort;
  onSort?: (sort: DataGridSort) => void;
  onRowOpen?: (row: Row) => void;
  rowActionLabel?: (row: Row) => string;
  toolbar?: ReactNode | ((controls: DataGridToolbarControls) => ReactNode);
  bulkSlot?: ReactNode;
  pagination?: ReactNode;
  className?: string;
};

export function DataGrid<Row>({
  ariaLabel,
  rows,
  columns,
  getRowId,
  state = rows.length === 0 ? "empty" : "ready",
  stateMessage,
  stateTitle,
  sort,
  onSort,
  onRowOpen,
  rowActionLabel = () => "View details",
  toolbar,
  bulkSlot,
  pagination,
  className,
}: DataGridProps<Row>) {
  const [chooserOpen, setChooserOpen] = useState(false);
  const [visibleColumnIds, setVisibleColumnIds] = useState<Set<string>>(
    () => new Set(columns.filter((column) => !column.hiddenByDefault).map((column) => column.id)),
  );
  const visibleColumns = useMemo(
    () => columns.filter((column) => visibleColumnIds.has(column.id)),
    [columns, visibleColumnIds],
  );

  function toggleColumn(columnId: string) {
    setVisibleColumnIds((current) => {
      const next = new Set(current);
      if (next.has(columnId)) {
        if (next.size > 1) next.delete(columnId);
      } else {
        next.add(columnId);
      }
      return next;
    });
  }

  function nextSort(columnId: string): DataGridSort {
    if (sort?.columnId === columnId) {
      return { columnId, direction: sort.direction === "asc" ? "desc" : "asc" };
    }
    return { columnId, direction: "asc" };
  }

  const columnChooser = (
    <div className="relative">
      <Button
        type="button"
        variant="outline"
        size="sm"
        aria-expanded={chooserOpen}
        onClick={() => setChooserOpen((open) => !open)}
      >
        <Columns3 className="h-4 w-4" aria-hidden="true" />
        Columns
      </Button>
      {chooserOpen && (
        <div className="absolute right-0 z-20 mt-2 min-w-52 rounded-panel border border-border bg-card p-2 text-sm shadow-elevation2">
          <fieldset>
            <legend className="px-2 pb-1 text-caption font-medium text-muted-foreground">
              Visible columns
            </legend>
            {columns.map((column) => (
              <label key={column.id} className="flex items-center gap-2 rounded-control px-2 py-1.5">
                <input
                  type="checkbox"
                  checked={visibleColumnIds.has(column.id)}
                  onChange={() => toggleColumn(column.id)}
                />
                <span>{column.header}</span>
              </label>
            ))}
          </fieldset>
        </div>
      )}
    </div>
  );
  const toolbarNode = typeof toolbar === "function" ? toolbar({ columnChooser }) : toolbar;

  return (
    <section className={cn("grid gap-3", className)} aria-label={ariaLabel}>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {toolbarNode}
          {bulkSlot}
        </div>
        {typeof toolbar === "function" ? null : columnChooser}
      </div>

      {state !== "ready" ? (
        <GridState state={state} title={stateTitle}>{stateMessage}</GridState>
      ) : (
        <div className="overflow-x-auto rounded-panel border border-border bg-card shadow-elevation1">
          <table className="w-full min-w-[40rem] text-left text-body">
            <caption className="sr-only">{ariaLabel}</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                {visibleColumns.map((column) => (
                  <th key={column.id} scope="col" className={cn("px-3 py-2 font-medium", column.className)}>
                    {column.sortable && onSort ? (
                      <button
                        type="button"
                        className="inline-flex items-center gap-1 rounded-control text-left hover:text-foreground"
                        onClick={() => onSort(nextSort(column.id))}
                      >
                        <span>{column.header}</span>
                        <SortIcon active={sort?.columnId === column.id} direction={sort?.direction ?? "asc"} />
                      </button>
                    ) : (
                      column.header
                    )}
                  </th>
                ))}
                {onRowOpen && <th scope="col" className="px-3 py-2 font-medium">Action</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={getRowId(row)} className="border-b border-border align-top last:border-0">
                  {visibleColumns.map((column) => (
                    <td key={column.id} className={cn("px-3 py-2", column.className)}>
                      {column.cell(row)}
                    </td>
                  ))}
                  {onRowOpen && (
                    <td className="px-3 py-2">
                      <Button type="button" size="sm" variant="outline" onClick={() => onRowOpen(row)}>
                        {rowActionLabel(row)}
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pagination}
    </section>
  );
}

function GridState({ state, title, children }: { state: DataGridState; title?: string; children?: ReactNode }) {
  switch (state) {
    case "loading":
      return <LoadingState>{children ?? "Loading rows..."}</LoadingState>;
    case "error":
      return <ErrorState title={title ?? "Could not load rows"}>{children}</ErrorState>;
    case "permission-denied":
      return <PermissionDeniedState>{children ?? "Your session cannot read these rows."}</PermissionDeniedState>;
    case "unavailable":
      return <UnavailableState title={title ?? "Rows unavailable"}>{children}</UnavailableState>;
    case "empty":
      return <EmptyState title={title ?? "No rows"}>{children}</EmptyState>;
    default:
      return null;
  }
}

function SortIcon({ active, direction }: { active: boolean; direction: SortDirection }) {
  if (!active) return <ChevronsUpDown className="h-3.5 w-3.5" aria-hidden="true" />;
  if (direction === "asc") return <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />;
  return <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />;
}
