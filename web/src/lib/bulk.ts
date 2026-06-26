import { useCallback, useMemo, useState } from "react";

export interface BulkResult<T = void> {
  id: string;
  ok: boolean;
  value?: T;
  error?: string;
}

export async function runBulk<T>(ids: readonly string[], fn: (id: string) => Promise<T>): Promise<BulkResult<T>[]> {
  const settled = await Promise.allSettled(ids.map((id) => fn(id)));
  return ids.map((id, index) => {
    const entry = settled[index];
    if (entry.status === "fulfilled") return { id, ok: true, value: entry.value };
    return { id, ok: false, error: String(entry.reason) };
  });
}

export interface BulkSelection {
  selected: ReadonlySet<string>;
  count: number;
  isSelected: (id: string) => boolean;
  toggle: (id: string) => void;
  selectAll: (ids: readonly string[]) => void;
  clear: () => void;
}

export function useBulkSelection(): BulkSelection {
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set());
  const toggle = useCallback((id: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);
  const selectAll = useCallback((ids: readonly string[]) => setSelected(new Set(ids)), []);
  const clear = useCallback(() => setSelected(new Set()), []);
  const isSelected = useCallback((id: string) => selected.has(id), [selected]);
  return useMemo(
    () => ({ selected, count: selected.size, isSelected, toggle, selectAll, clear }),
    [selected, isSelected, toggle, selectAll, clear],
  );
}
