import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Owner } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

export function Owners() {
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(() => searchParams.get("owner") ?? searchParams.get("q") ?? "");
  const [kind, setKind] = useState(() => searchParams.get("kind") ?? "all");
  const { data, loading, error } = useResource(api.owners);
  const owners = useMemo(() => data ?? [], [data]);
  const kinds = useMemo(() => Array.from(new Set(owners.map((owner) => owner.kind).filter(Boolean))).sort(), [owners]);
  const filteredOwners = useMemo(() => filterOwners(owners, query, kind), [kind, owners, query]);

  return (
    <section aria-labelledby="owners-heading" className="space-y-4">
      <PageHeader titleId="owners-heading" title="Owners" description="Search served owner records by name, ID, kind, or email." />
      {loading && <LoadingState>Loading owners…</LoadingState>}
      {error && <ErrorState title="Could not load owners">{error}</ErrorState>}
      {data && (
        <>
          <form className="flex flex-wrap items-end gap-3" role="search" onSubmit={(event) => event.preventDefault()}>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-search">
              Search owners
              <input
                id="owner-search"
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="min-h-9 w-72 max-w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                placeholder="Owner name, ID, email, or kind"
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-kind">
              Owner kind
              <select
                id="owner-kind"
                value={kind}
                onChange={(event) => setKind(event.target.value)}
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
              >
                <option value="all">All kinds</option>
                {kinds.map((ownerKind) => (
                  <option key={ownerKind} value={ownerKind}>
                    {ownerKind}
                  </option>
                ))}
              </select>
            </label>
            <p className="pb-2 text-caption text-muted-foreground">
              Showing {filteredOwners.length} of {data.length}
            </p>
          </form>

          <table className="ui-table">
            <caption className="sr-only">Credential owners</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Kind</th>
                <th scope="col">Email</th>
              </tr>
            </thead>
            <tbody>
              {data.length === 0 && (
                <tr>
                  <td colSpan={3} className="text-muted-foreground">
                    No owners yet.
                  </td>
                </tr>
              )}
              {data.length > 0 && filteredOwners.length === 0 && (
                <tr>
                  <td colSpan={3} className="text-muted-foreground">
                    No owners match the current filters.
                  </td>
                </tr>
              )}
              {filteredOwners.map((owner) => (
                <tr key={owner.id}>
                  <td>{owner.name}</td>
                  <td>{owner.kind}</td>
                  <td>{owner.email ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}

function filterOwners(owners: Owner[], query: string, kind: string): Owner[] {
  const needle = query.trim().toLowerCase();
  return owners.filter((owner) => {
    const matchesKind = kind === "all" || owner.kind === kind;
    if (!matchesKind) return false;
    if (!needle) return true;
    return [owner.id, owner.name, owner.kind, owner.email ?? ""].join(" ").toLowerCase().includes(needle);
  });
}
