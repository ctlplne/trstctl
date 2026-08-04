import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Owner, type OwnershipAttribution, type OwnershipAttributionItem } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ToastProvider";
import { OrphanGovernance } from "@/components/nhi";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

const ownerKinds: Owner["kind"][] = ["user", "team", "workload", "service"];

function emptyOwnershipAttribution(): OwnershipAttribution {
  return { generated_at: new Date(0).toISOString(), items: [], summary: {}, coverage: [] };
}

function readOwnershipAttribution(): Promise<OwnershipAttribution> {
  const client = api as typeof api & { ownershipAttribution?: () => Promise<OwnershipAttribution> };
  return client.ownershipAttribution ? client.ownershipAttribution() : Promise.resolve(emptyOwnershipAttribution());
}

// UnownedQueuePanel surfaces the ownership gaps that block an incident (I1).
//
// Three counts, never one. A single "unowned: 47" would be a number nobody can
// act on: a missing owner record, an owner who names a person but no system, and
// an owner nobody has re-confirmed are three different pieces of work, and the
// middle one is the one people miss — it looks owned until somebody needs a
// blast radius.
function UnownedQueuePanel() {
  const queue = useApiQuery(["unowned-identities"], api.unownedIdentities);
  const data = queue.data;
  // Guard the array, not just the object. A response whose shape is present but
  // whose items are absent is exactly what a fixture or a partial payload looks
  // like, and reading .slice on it takes down the whole Owners page rather than
  // hiding one panel.
  const items = data?.items ?? [];
  if (!data || items.length === 0) return null;
  return (
    <section aria-labelledby="unowned-heading" className="ui-panel space-y-3 p-comfortable">
      <h2 id="unowned-heading" className="text-title font-semibold">
        {translateNow("source.unowned.queue.i1own00001")}
      </h2>
      <p className="text-sm">
        {translateNow("source.unowned.counts.i1own00002", {
          value1: String(data.counts?.no_owner ?? 0),
          value2: String(data.counts?.owner_missing_application_model ?? 0),
          value3: String(data.counts?.ownership_never_attested ?? 0),
        })}
      </p>
      <ul className="space-y-2 text-sm">
        {items.slice(0, 25).map((item) => (
          <li key={item.identity_id} className="border-b border-border pb-2 last:border-0">
            <span className="font-mono text-xs">{item.name}</span>
            <span className="mt-1 block text-caption text-muted-foreground">{item.detail}</span>
          </li>
        ))}
      </ul>
      <p className="text-caption text-muted-foreground">{data.guidance}</p>
    </section>
  );
}

export function Owners() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(() => searchParams.get("owner") ?? searchParams.get("q") ?? "");
  const [kind, setKind] = useState(() => searchParams.get("kind") ?? "all");
  // S-C5a pilot: the query layer replaces useResource — the cache is the one
  // source of row truth, mutations write through setQueryData for instant UI
  // and invalidate for server truth (the refetch useResource never had).
  const queryClient = useQueryClient();
  const { data, loading, error } = useApiQuery(["owners"], api.owners);
  const attribution = useApiQuery(["ownership-attribution"], readOwnershipAttribution);
  const { toast } = useToast();
  const rows = data;
  const [editTarget, setEditTarget] = useState<Owner | null>(null);
  const [editName, setEditName] = useState("");
  const [editKind, setEditKind] = useState<Owner["kind"]>("user");
  const [editEmail, setEditEmail] = useState("");
  const [editBusy, setEditBusy] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Owner | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const owners = useMemo(() => rows ?? [], [rows]);
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

  function openEdit(owner: Owner) {
    setEditTarget(owner);
    setEditName(owner.name);
    setEditKind(owner.kind);
    setEditEmail(owner.email ?? "");
    setEditError(null);
  }

  function openDelete(owner: Owner) {
    setDeleteTarget(owner);
    setDeleteConfirm("");
    setDeleteError(null);
  }

  async function submitEdit() {
    if (!editTarget) return;
    const name = editName.trim();
    if (!name) {
      setEditError("Name is required.");
      return;
    }
    setEditBusy(true);
    setEditError(null);
    try {
      const updated = await api.updateOwner(editTarget.id, { name, kind: editKind, email: editEmail.trim() || undefined });
      queryClient.setQueryData<Owner[]>(["owners"], (current) => (current ? current.map((owner) => (owner.id === updated.id ? updated : owner)) : current));
      void queryClient.invalidateQueries({ queryKey: ["owners"] });
      setEditTarget(null);
      toast({ kind: "success", title: t("parity.ownerUpdated_07b92f"), description: updated.name });
    } catch (err) {
      setEditError(err instanceof Error ? err.message : String(err));
    } finally {
      setEditBusy(false);
    }
  }

  async function submitDelete() {
    if (!deleteTarget || deleteConfirm !== deleteTarget.name) return;
    const target = deleteTarget;
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await api.deleteOwner(target.id);
      queryClient.setQueryData<Owner[]>(["owners"], (current) => (current ? current.filter((owner) => owner.id !== target.id) : current));
      void queryClient.invalidateQueries({ queryKey: ["owners"] });
      setDeleteTarget(null);
      setDeleteConfirm("");
      toast({ kind: "success", title: t("parity.ownerDeleted_079d61"), description: target.name });
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleteBusy(false);
    }
  }

  const columns: DataGridColumn<Owner>[] = [
    { id: "name", header: "Name", cell: (owner) => owner.name },
    { id: "kind", header: "Kind", cell: (owner) => owner.kind },
    { id: "email", header: "Email", cell: (owner) => owner.email ?? "—" },
    {
      id: "actions",
      header: "Actions",
      cell: (owner) => (
        <div className="flex flex-wrap gap-2">
          <Button type="button" size="sm" variant="outline" onClick={() => openEdit(owner)}>
            {t("parity.edit_530164")}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="border-risk-critical/40 text-risk-critical hover:bg-risk-critical/10"
            onClick={() => openDelete(owner)}
          >
            {t("parity.delete_f6fdbe")}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <section aria-labelledby="owners-heading" className="space-y-4">
      <PageHeader
        titleId="owners-heading"
        title={translateNow("source.owners.58f5df9b24")}
        description="Search owner records — the people and teams accountable for credentials — by name, ID, kind, or email."
      />
      <OrphanGovernance owners={owners} />
      <UnownedQueuePanel />
      {loading && <LoadingState>{translateNow("source.loading.owners.8fcc1cacd9")}</LoadingState>}
      {error && <ErrorState title={translateNow("source.could.not.load.owners.f32406fb21")}>{error}</ErrorState>}
      {rows && (
        <>
          <form className="flex flex-wrap items-end gap-3" role="search" onSubmit={(event) => event.preventDefault()}>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-search">
              {translateNow("source.search.owners.55a040f1a5")}
              <input
                id="owner-search"
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="min-h-9 w-72 max-w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                placeholder={translateNow("source.owner.name.id.email.or.kind.d0081dd7f1")}
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-kind">
              {translateNow("source.owner.kind.eb9923cec7")}
              <select
                id="owner-kind"
                value={kind}
                onChange={(event) => setKind(event.target.value)}
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
              >
                <option value="all">{translateNow("source.all.kinds.ddd0c2108e")}</option>
                {kinds.map((ownerKind) => (
                  <option key={ownerKind} value={ownerKind}>
                    {ownerKind}
                  </option>
                ))}
              </select>
            </label>
            <p className="pb-2 text-caption text-muted-foreground">
              {translateNow("source.showing.d604310a78")} {filteredOwners.length} {translateNow("source.of.28391d3bc6")} {rows.length}
            </p>
          </form>

          <DataGrid
            ariaLabel="Credential owners"
            rows={filteredOwners}
            columns={columns}
            getRowId={(owner) => owner.id}
            state={filteredOwners.length === 0 ? "empty" : "ready"}
            stateTitle={rows.length === 0 ? "No owners yet" : "No owners match the current filters"}
            stateMessage={rows.length === 0 ? "Add an owner to start tracking accountability." : "No owners match the current search or kind filter."}
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

      <Dialog
        open={editTarget !== null}
        onClose={() => {
          if (!editBusy) setEditTarget(null);
        }}
        titleId="owner-edit-title"
        panelClassName="fixed left-1/2 top-1/2 grid w-[min(92vw,30rem)] -translate-x-1/2 -translate-y-1/2 gap-4 rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {editTarget && (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void submitEdit();
            }}
          >
            <h2 id="owner-edit-title" className="text-title font-semibold">
              {translateNow("source.edit.464c4ffd01")} {editTarget.name}
            </h2>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-name">
              {translateNow("source.name.dcd1d5223f")}
              <input
                id="owner-edit-name"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={editName}
                onChange={(event) => setEditName(event.target.value)}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-kind">
              {translateNow("source.owner.kind.eb9923cec7")}
              <select
                id="owner-edit-kind"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={editKind}
                onChange={(event) => setEditKind(event.target.value as Owner["kind"])}
              >
                {ownerKinds.map((ownerKind) => (
                  <option key={ownerKind} value={ownerKind}>
                    {ownerKind}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-email">
              {t("parity.emailOptional_5c10b5")}
              <input
                id="owner-edit-email"
                type="email"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={editEmail}
                onChange={(event) => setEditEmail(event.target.value)}
              />
            </label>
            {editError && <p className="text-sm font-medium text-risk-critical">{editError}</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setEditTarget(null)} disabled={editBusy}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={editBusy}>
                {t("parity.saveOwner_b67638")}
              </Button>
            </div>
          </form>
        )}
      </Dialog>

      <Dialog
        open={deleteTarget !== null}
        onClose={() => {
          if (!deleteBusy) setDeleteTarget(null);
        }}
        titleId="owner-delete-title"
        descriptionId="owner-delete-description"
        role="alertdialog"
        closeOnBackdropClick={false}
        panelClassName="fixed left-1/2 top-1/2 grid w-[min(92vw,30rem)] -translate-x-1/2 -translate-y-1/2 gap-4 rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {deleteTarget && (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void submitDelete();
            }}
          >
            <div>
              <h2 id="owner-delete-title" className="text-title font-semibold">
                {translateNow("source.delete.e2d0a54968")} {deleteTarget.name}
              </h2>
              <p id="owner-delete-description" className="mt-1 text-sm text-muted-foreground">
                {t("parity.deletingAnOwnerRemovesTheAccountability_cdfad5")}
              </p>
            </div>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-delete-confirm">
              {t("parity.typeTheExactOwnerName_1205b0")}
              <input
                id="owner-delete-confirm"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={deleteConfirm}
                onChange={(event) => setDeleteConfirm(event.target.value)}
                placeholder={deleteTarget.name}
                autoComplete="off"
                spellCheck={false}
                required
              />
            </label>
            {deleteError && <p className="text-sm font-medium text-risk-critical">{deleteError}</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setDeleteTarget(null)} disabled={deleteBusy}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button
                type="submit"
                variant="outline"
                className="border-risk-critical/40 text-risk-critical hover:bg-risk-critical/10"
                disabled={deleteBusy || deleteConfirm !== deleteTarget.name}
              >
                {t("parity.deleteOwner_b5f9bd")}
              </Button>
            </div>
          </form>
        )}
      </Dialog>
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
