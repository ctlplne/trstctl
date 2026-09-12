import { useEffect, useMemo, useState } from "react";
import { useInfiniteQuery, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { api, type Certificate, type CertificatePage } from "@/lib/api";

/** Search and keyset pages share one tenant/actor/filter cache identity. Aborted
 * or late responses stay on their original key, including post-mutation reads. */
export function useCertificateInventory(scope: readonly unknown[], query: string, limit: number, expiringBefore?: string) {
  const client = useQueryClient();
  const normalized = query.trim();
  const [settledQuery, setSettledQuery] = useState(normalized);
  useEffect(() => {
    const timer = setTimeout(() => setSettledQuery(normalized), 250);
    return () => clearTimeout(timer);
  }, [normalized]);
  const waiting = normalized !== settledQuery;
  const queryPrefix = ["certificate-inventory", ...scope];
  const queryKey = [...queryPrefix, { query: settledQuery, limit, expiringBefore }];
  const result = useInfiniteQuery({
    queryKey,
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) => api.certificatePage({ limit, cursor: pageParam, query: settledQuery || undefined, expiringBefore, signal }),
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
    enabled: !waiting,
    retry: false,
  });
  const certificates = useMemo(() => (waiting ? [] : (result.data?.pages.flatMap((page) => page.items ?? []) ?? [])), [result.data, waiting]);
  return {
    certificates,
    loading: waiting || result.isPending,
    loadingMore: result.isFetchingNextPage,
    fetching: result.isFetching,
    hasNextPage: !waiting && result.hasNextPage,
    error: waiting ? null : result.error,
    loadNextPage: () => {
      if (!waiting && !result.isFetching) void result.fetchNextPage();
    },
    refresh: async (updated?: Certificate) => {
      // Retire pre-mutation requests before updating all cached views for this
      // tenant and actor. An inactive search must not later restore old state.
      await client.cancelQueries({ queryKey: queryPrefix });
      if (updated) {
        client.setQueriesData<InfiniteData<CertificatePage>>(
          { queryKey: queryPrefix },
          (current) =>
            current && {
              ...current,
              pages: current.pages.map((page) => ({ ...page, items: page.items.map((row) => (row.id === updated.id ? updated : row)) })),
            },
        );
      }
      await client.invalidateQueries({ queryKey: queryPrefix });
    },
  };
}
