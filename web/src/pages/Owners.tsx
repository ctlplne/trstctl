import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Owner } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { OrphanGovernance } from "@/components/nhi";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

const columns: DataGridColumn<Owner>[] = [
  { id: "name", header: "Name", cell: (owner) => owner.name },
  { id: "kind", header: "Kind", cell: (owner) => owner.kind },
  { id: "email", header: "Email", cell: (owner) => owner.email ?? "—" },
];

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
      <PageHeader
        titleId="owners-heading"
        title="Owners"
        description="Search owner records — the people and teams accountable for credentials — by name, ID, kind, or email."
      />
      <OrphanGovernance owners={owners} />
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

          <DataGrid
            ariaLabel="Credential owners"
            rows={filteredOwners}
            columns={columns}
            getRowId={(owner) => owner.id}
            state={filteredOwners.length === 0 ? "empty" : "ready"}
            stateTitle={data.length === 0 ? "No owners yet" : "No owners match the current filters"}
            stateMessage={data.length === 0 ? "Add an owner to start tracking accountability." : "No owners match the current search or kind filter."}
          />
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
