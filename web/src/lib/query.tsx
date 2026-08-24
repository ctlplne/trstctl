import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, type ReactNode } from "react";

const AppQueryContext = createContext(false);
const invalidateEventName = "trstctl:invalidate-app-queries";

/** Existing pages that still own local state can publish the exact cached read
 * models their mutation made stale. The provider performs the invalidation;
 * callers do not need a QueryClient hook and remain usable in isolated tests. */
export function invalidateAppQueryKeys(keys: readonly (readonly unknown[])[]): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(invalidateEventName, { detail: keys }));
}

/** S-C5: the TanStack Query layer. Adoption policy (see web/DESIGN.md): new
 * surfaces use useApiQuery/useQueryClient directly; existing pages migrate off
 * lib/useResource when they are next touched. The adapter below deliberately
 * mirrors useResource's { data, loading, error } shape so a pilot migration is
 * a small diff and existing loading/error markup keeps working — the win is
 * caching, request de-duplication, and real refetch/invalidation, which
 * useResource never had ("useResource has no refetch"). */

export function createAppQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // One retry: transient blips recover, real failures surface fast and
        // fail closed into the page's ErrorState.
        retry: 1,
        // Server truth wins on navigation, but within a screen a 30s window
        // absorbs re-render storms without re-fetching.
        staleTime: 30_000,
        // Focus refetch stays off until the visibility-aware polling pass
        // (certctl's PERF-H1 pattern) lands as its own change.
        refetchOnWindowFocus: false,
      },
    },
  });
}

export function AppQueryProvider({ children }: { children: ReactNode }) {
  // One client per provider mount (per test render) — never module-global, so
  // tests cannot leak cache entries into each other.
  const client = useMemo(() => createAppQueryClient(), []);

  // Live tiles (certctl's PERF-H1 pattern): when the tab returns to
  // visibility, refresh exactly the queries marked live — the operator sees
  // fresh numbers immediately instead of waiting for the next poll tick.
  // Hidden tabs poll nothing (the interval gate below), so this is the
  // catch-up half of the pattern.
  useEffect(() => {
    function onVisibilityChange() {
      if (document.visibilityState !== "visible") return;
      void client.invalidateQueries({ predicate: (query) => query.meta?.live === true });
    }
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, [client]);

  useEffect(() => {
    function onInvalidate(event: Event) {
      const keys = (event as CustomEvent<readonly (readonly unknown[])[]>).detail;
      if (!Array.isArray(keys)) return;
      for (const queryKey of keys) {
        if (Array.isArray(queryKey)) void client.invalidateQueries({ queryKey });
      }
    }
    window.addEventListener(invalidateEventName, onInvalidate);
    return () => window.removeEventListener(invalidateEventName, onInvalidate);
  }, [client]);

  return (
    <AppQueryContext.Provider value>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </AppQueryContext.Provider>
  );
}

/** Safe presence probe for shell chrome that can also render in isolated tests
 * and component workbenches. Data hooks still run only under the real provider. */
export function useHasAppQueryProvider(): boolean {
  return useContext(AppQueryContext);
}

export interface ApiQueryOptions {
  /** Keeps dependent queries idle until their parent selection exists. */
  enabled?: boolean;
  /** Marks a live tile: poll every intervalMs while the tab is visible, pause
   * entirely while hidden, and refresh immediately on return to visibility. */
  live?: { intervalMs: number };
}

/** liveRefetchInterval: visible → poll at the tile's cadence; hidden → false
 * (no polling, no wasted backend cycles or battery). Exported for the guard
 * test. */
export function liveRefetchInterval(intervalMs: number): number | false {
  if (typeof document !== "undefined" && document.visibilityState === "hidden") return false;
  return intervalMs;
}

export interface ApiQueryResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  errorValue: unknown | null;
  refetch: () => void;
}

/** useApiQuery: the useResource-compatible adapter over useQuery. */
export function useApiQuery<T>(key: readonly unknown[], loader: () => Promise<T>, options?: ApiQueryOptions): ApiQueryResult<T> {
  const live = options?.live;
  const query = useQuery({
    queryKey: key,
    queryFn: loader,
    enabled: options?.enabled,
    meta: live ? { live: true } : undefined,
    refetchInterval: live ? () => liveRefetchInterval(live.intervalMs) : undefined,
  });
  return {
    data: query.data ?? null,
    loading: query.isPending,
    error: query.error ? (query.error instanceof Error ? query.error.message : String(query.error)) : null,
    errorValue: query.error ?? null,
    refetch: () => void query.refetch(),
  };
}

export { useQueryClient };
