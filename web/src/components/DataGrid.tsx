import { useEffect, useMemo, useState, type ReactNode } from "react";
import { ChevronDown, ChevronsUpDown, ChevronUp, Columns3 } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { readGridPreferences, sanitizeViewMetadata, writeGridPreferences, type GridViewPrimitive, type SavedGridView } from "@/lib/gridViews";
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
  savedViews?: ReactNode;
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
  selection?: {
    selectedIds: Set<string>;
    onSelectedIdsChange: (ids: Set<string>) => void;
    getRowLabel?: (row: Row) => string;
  };
  pagination?: ReactNode;
  viewStorageKey?: string;
  viewMetadata?: Record<string, GridViewPrimitive | undefined>;
  onViewRestore?: (metadata: Record<string, GridViewPrimitive>, sort?: DataGridSort) => void;
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
  selection,
  pagination,
  viewStorageKey,
  viewMetadata,
  onViewRestore,
  className,
}: DataGridProps<Row>) {
  const [chooserOpen, setChooserOpen] = useState(false);
  const [viewName, setViewName] = useState("");
  const [savedViews, setSavedViews] = useState<SavedGridView[]>(() => (viewStorageKey ? readGridPreferences(viewStorageKey).views : []));
  const columnIds = useMemo(() => columns.map((column) => column.id), [columns]);
  const defaultVisibleColumnIds = useMemo(() => columns.filter((column) => !column.hiddenByDefault).map((column) => column.id), [columns]);
  const defaultColumnOrder = useMemo(() => columns.map((column) => column.id), [columns]);
  const [visibleColumnIds, setVisibleColumnIds] = useState<Set<string>>(() => new Set(initialVisibleIds(columns, viewStorageKey)));
  const [columnOrder, setColumnOrder] = useState<string[]>(() => initialColumnOrder(columns, viewStorageKey));
  const columnById = useMemo(() => new Map(columns.map((column) => [column.id, column])), [columns]);
  const visibleColumns = useMemo(
    () =>
      columnOrder
        .map((columnId) => columnById.get(columnId))
        .filter((column): column is DataGridColumn<Row> => Boolean(column && visibleColumnIds.has(column.id))),
    [columnById, columnOrder, visibleColumnIds],
  );
  const allVisibleRowIds = useMemo(() => rows.map(getRowId), [getRowId, rows]);
  const selectedVisibleCount = selection ? allVisibleRowIds.filter((id) => selection.selectedIds.has(id)).length : 0;
  const allVisibleSelected = selection ? allVisibleRowIds.length > 0 && selectedVisibleCount === allVisibleRowIds.length : false;
  const partiallySelected = selection ? selectedVisibleCount > 0 && !allVisibleSelected : false;

  useEffect(() => {
    if (!viewStorageKey) return;
    const preferences = readGridPreferences(viewStorageKey);
    setSavedViews(preferences.views);
    setVisibleColumnIds(new Set(normalizeVisibleIds(preferences.visibleColumnIds, columnIds, defaultVisibleColumnIds)));
    setColumnOrder(normalizeColumnOrder(preferences.columnOrder, columnIds, defaultColumnOrder));
  }, [columnIds, defaultColumnOrder, defaultVisibleColumnIds, viewStorageKey]);

  function persist(next: { columnOrder?: string[]; visibleColumnIds?: Set<string>; views?: SavedGridView[] }) {
    if (!viewStorageKey) return;
    writeGridPreferences(viewStorageKey, {
      columnOrder: next.columnOrder ?? columnOrder,
      visibleColumnIds: Array.from(next.visibleColumnIds ?? visibleColumnIds),
      views: next.views ?? savedViews,
    });
  }

  function toggleColumn(columnId: string) {
    setVisibleColumnIds((current) => {
      const next = new Set(current);
      if (next.has(columnId)) {
        if (next.size > 1) next.delete(columnId);
      } else {
        next.add(columnId);
      }
      persist({ visibleColumnIds: next });
      return next;
    });
  }

  function moveColumn(columnId: string, delta: -1 | 1) {
    setColumnOrder((current) => {
      const index = current.indexOf(columnId);
      const target = index + delta;
      if (index < 0 || target < 0 || target >= current.length) return current;
      const next = [...current];
      [next[index], next[target]] = [next[target], next[index]];
      persist({ columnOrder: next });
      return next;
    });
  }

  function saveCurrentView() {
    if (!viewStorageKey || !viewName.trim()) return;
    const nextView: SavedGridView = {
      id: `${Date.now()}-${viewName
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")}`,
      name: viewName.trim(),
      createdAt: new Date().toISOString(),
      columnOrder,
      visibleColumnIds: Array.from(visibleColumnIds),
      sort,
      metadata: sanitizeViewMetadata(viewMetadata),
    };
    const nextViews = [nextView, ...savedViews.filter((view) => view.name !== nextView.name)].slice(0, 8);
    setSavedViews(nextViews);
    setViewName("");
    persist({ views: nextViews });
  }

  function restoreView(view: SavedGridView) {
    const nextOrder = normalizeColumnOrder(view.columnOrder, columnIds, defaultColumnOrder);
    const nextVisible = new Set(normalizeVisibleIds(view.visibleColumnIds, columnIds, defaultVisibleColumnIds));
    setColumnOrder(nextOrder);
    setVisibleColumnIds(nextVisible);
    persist({ columnOrder: nextOrder, visibleColumnIds: nextVisible });
    if (view.sort && onSort) onSort(view.sort);
    onViewRestore?.(view.metadata, view.sort);
  }

  function setSelected(id: string, checked: boolean) {
    if (!selection) return;
    const next = new Set(selection.selectedIds);
    if (checked) {
      next.add(id);
    } else {
      next.delete(id);
    }
    selection.onSelectedIdsChange(next);
  }

  function setAllVisible(checked: boolean) {
    if (!selection) return;
    const next = new Set(selection.selectedIds);
    for (const id of allVisibleRowIds) {
      if (checked) {
        next.add(id);
      } else {
        next.delete(id);
      }
    }
    selection.onSelectedIdsChange(next);
  }

  function nextSort(columnId: string): DataGridSort {
    if (sort?.columnId === columnId) {
      return { columnId, direction: sort.direction === "asc" ? "desc" : "asc" };
    }
    return { columnId, direction: "asc" };
  }

  const columnChooser = (
    <div className="relative">
      <Button type="button" variant="outline" size="sm" aria-expanded={chooserOpen} onClick={() => setChooserOpen((open) => !open)}>
        <Columns3 className="h-4 w-4" aria-hidden="true" />
        Columns
      </Button>
      {chooserOpen && (
        <div className="absolute end-0 z-20 mt-2 min-w-52 rounded-panel border border-border bg-card p-2 text-sm shadow-elevation2">
          <fieldset>
            <legend className="px-2 pb-1 text-caption font-medium text-muted-foreground">Visible columns</legend>
            {columns.map((column) => (
              <div key={column.id} className="flex items-center gap-2 rounded-control px-2 py-1.5">
                <label className="flex flex-1 items-center gap-2">
                  <input type="checkbox" checked={visibleColumnIds.has(column.id)} onChange={() => toggleColumn(column.id)} />
                  <span>{column.header}</span>
                </label>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={`Move ${columnLabel(column)} up`}
                  disabled={columnOrder.indexOf(column.id) <= 0}
                  className="h-7 w-7"
                  onClick={() => moveColumn(column.id, -1)}
                >
                  <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={`Move ${columnLabel(column)} down`}
                  disabled={columnOrder.indexOf(column.id) === columnOrder.length - 1}
                  className="h-7 w-7"
                  onClick={() => moveColumn(column.id, 1)}
                >
                  <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                </Button>
              </div>
            ))}
          </fieldset>
        </div>
      )}
    </div>
  );
  const savedViewControls = viewStorageKey ? (
    <div className="flex flex-wrap items-end gap-2">
      <label className="grid gap-1 text-sm font-medium">
        <span className="sr-only">Saved view name</span>
        <input
          aria-label="Saved view name"
          value={viewName}
          onChange={(event) => setViewName(event.target.value)}
          placeholder="View name"
          className="min-h-9 w-36 rounded-control border border-input bg-background px-3 py-2 text-sm"
        />
      </label>
      <Button type="button" variant="outline" size="sm" disabled={!viewName.trim()} onClick={saveCurrentView}>
        Save view
      </Button>
      {savedViews.map((view) => (
        <Button key={view.id} type="button" variant="ghost" size="sm" onClick={() => restoreView(view)}>
          {`Restore view ${view.name}`}
        </Button>
      ))}
    </div>
  ) : undefined;
  const toolbarNode = typeof toolbar === "function" ? toolbar({ columnChooser, savedViews: savedViewControls }) : toolbar;

  return (
    <section className={cn("grid gap-3", className)} aria-label={ariaLabel}>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {toolbarNode}
          {bulkSlot}
        </div>
        {typeof toolbar === "function" ? null : (
          <div className="flex flex-wrap items-center gap-2">
            {savedViewControls}
            {columnChooser}
          </div>
        )}
      </div>

      {state !== "ready" ? (
        <GridState state={state} title={stateTitle}>
          {stateMessage}
        </GridState>
      ) : (
        <div className="overflow-x-auto rounded-panel border border-border bg-card shadow-elevation1">
          <table className="w-full min-w-[40rem] text-start text-body">
            <caption className="sr-only">{ariaLabel}</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                {selection && (
                  <th scope="col" className="px-3 py-2 font-medium">
                    <input
                      type="checkbox"
                      aria-label="Select all visible rows"
                      checked={allVisibleSelected}
                      ref={(input) => {
                        if (input) input.indeterminate = partiallySelected;
                      }}
                      onChange={(event) => setAllVisible(event.target.checked)}
                    />
                  </th>
                )}
                {visibleColumns.map((column) => (
                  <th key={column.id} scope="col" className={cn("px-3 py-2 font-medium", column.className)}>
                    {column.sortable && onSort ? (
                      <button
                        type="button"
                        className="inline-flex items-center gap-1 rounded-control text-start hover:text-foreground"
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
                {onRowOpen && (
                  <th scope="col" className="px-3 py-2 font-medium">
                    Action
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={getRowId(row)} className="border-b border-border align-top last:border-0">
                  {selection && (
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        aria-label={`Select ${selection.getRowLabel?.(row) ?? getRowId(row)}`}
                        checked={selection.selectedIds.has(getRowId(row))}
                        onChange={(event) => setSelected(getRowId(row), event.target.checked)}
                      />
                    </td>
                  )}
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

function initialVisibleIds<Row>(columns: Array<DataGridColumn<Row>>, storageKey?: string): string[] {
  const valid = columns.map((column) => column.id);
  const fallback = columns.filter((column) => !column.hiddenByDefault).map((column) => column.id);
  if (!storageKey) return fallback;
  return normalizeVisibleIds(readGridPreferences(storageKey).visibleColumnIds, valid, fallback);
}

function initialColumnOrder<Row>(columns: Array<DataGridColumn<Row>>, storageKey?: string): string[] {
  const valid = columns.map((column) => column.id);
  if (!storageKey) return valid;
  return normalizeColumnOrder(readGridPreferences(storageKey).columnOrder, valid, valid);
}

function normalizeVisibleIds(ids: string[] | undefined, valid: string[], fallback: string[]): string[] {
  const filtered = (ids ?? fallback).filter((id) => valid.includes(id));
  return filtered.length > 0 ? filtered : fallback;
}

function normalizeColumnOrder(ids: string[] | undefined, valid: string[], fallback: string[]): string[] {
  const ordered = (ids ?? fallback).filter((id) => valid.includes(id));
  return [...ordered, ...valid.filter((id) => !ordered.includes(id))];
}

function columnLabel<Row>(column: DataGridColumn<Row>): string {
  return typeof column.header === "string" ? column.header : column.id;
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
