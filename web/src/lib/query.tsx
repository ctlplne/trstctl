import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, type ReactNode } from "react";

/** S-C5: the TanStack Query layer. Adoption policy (see web/AGENTS.md): new
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
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

export interface ApiQueryResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

/** useApiQuery: the useResource-compatible adapter over useQuery. */
export function useApiQuery<T>(key: readonly unknown[], loader: () => Promise<T>): ApiQueryResult<T> {
  const query = useQuery({ queryKey: key, queryFn: loader });
  return {
    data: query.data ?? null,
    loading: query.isPending,
    error: query.error ? (query.error instanceof Error ? query.error.message : String(query.error)) : null,
    refetch: () => void query.refetch(),
  };
}

export { useQueryClient };
