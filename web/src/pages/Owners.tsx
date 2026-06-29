import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Owner, type OwnershipAttribution, type OwnershipAttributionItem } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { OrphanGovernance } from "@/components/nhi";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";

const columns: DataGridColumn<Owner>[] = [
  { id: "name", header: "Name", cell: (owner) => owner.name },
  { id: "kind", header: "Kind", cell: (owner) => owner.kind },
  { id: "email", header: "Email", cell: (owner) => owner.email ?? "—" },
];

function emptyOwnershipAttribution(): OwnershipAttribution {
  return { generated_at: new Date(0).toISOString(), items: [], summary: {}, coverage: [] };
}

function readOwnershipAttribution(): Promise<OwnershipAttribution> {
  const client = api as typeof api & { ownershipAttribution?: () => Promise<OwnershipAttribution> };
  return client.ownershipAttribution ? client.ownershipAttribution() : Promise.resolve(emptyOwnershipAttribution());
}

export function Owners() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(() => searchParams.get("owner") ?? searchParams.get("q") ?? "");
  const [kind, setKind] = useState(() => searchParams.get("kind") ?? "all");
  const { data, loading, error } = useResource(api.owners);
  const attribution = useResource(readOwnershipAttribution);
  const owners = useMemo(() => data ?? [], [data]);
  const attributionRows = useMemo(() => attribution.data?.items ?? [], [attribution.data]);
  const attributionColumns = useMemo<DataGridColumn<OwnershipAttributionItem>[]>(
    () => [
      { id: "display_name", header: t("owners.attribution.nhi"), cell: (item) => item.display_name },
      { id: "kind", header: t("owners.attribution.kind"), cell: (item) => item.kind },
      { id: "owner", header: t("owners.attribution.owner"), cell: (item) => item.owner?.name ?? t("owners.attribution.unattributed") },
      { id: "owner_kind", header: t("owners.attribution.ownerKind"), cell: (item) => item.owner?.kind ?? t("owners.attribution.orphaned") },
      { id: "source", header: t("owners.attribution.source"), cell: (item) => item.attribution_source },
    ],
    [t],
  );
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
      {attribution.loading && <LoadingState>{t("owners.attribution.loading")}</LoadingState>}
      {attribution.error && <ErrorState title={t("owners.attribution.error")}>{attribution.error}</ErrorState>}
      {attribution.data && (
        <section aria-labelledby="owner-attribution-heading" className="space-y-3">
          <h2 id="owner-attribution-heading" className="text-title font-semibold">
            {t("owners.attribution.heading")}
          </h2>
          <DataGrid
            ariaLabel={t("owners.attribution.ariaLabel")}
            rows={attributionRows}
            columns={attributionColumns}
            getRowId={(item) => item.id}
            state={attributionRows.length === 0 ? "empty" : "ready"}
            stateTitle={t("owners.attribution.emptyTitle")}
            stateMessage={t("owners.attribution.emptyMessage")}
          />
        </section>
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
