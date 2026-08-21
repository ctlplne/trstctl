import { type ReactNode, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Owner, type OwnershipAttribution, type OwnershipAttributionItem } from "@/lib/api";
import { OwnershipConflictsPanel } from "@/components/OwnershipConflictsPanel";
import { CMDBSyncPanel } from "@/components/CMDBSyncPanel";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ToastProvider";
import { OrphanGovernance } from "@/components/nhi";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

const ownerKinds: Owner["kind"][] = ["user", "team", "workload", "service", "vendor"];
type OwnerDisclosure = "directory" | "gaps" | "evidence";

function emptyOwnershipAttribution(): OwnershipAttribution {
  return { generated_at: new Date(0).toISOString(), items: [], summary: {}, coverage: [] };
}

function readOwnershipAttribution(): Promise<OwnershipAttribution> {
  const client = api as typeof api & { ownershipAttribution?: () => Promise<OwnershipAttribution> };
  return client.ownershipAttribution ? client.ownershipAttribution() : Promise.resolve(emptyOwnershipAttribution());
}

function attributionCount(summary: Record<string, unknown> | undefined, key: string, fallback: number): number {
  const value = summary?.[key];
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : fallback;
}

// UnownedQueuePanel surfaces the ownership gaps that block an incident (I1).
//
// Four counts, never one. A single "unowned: 47" would be a number nobody can
// act on: a missing owner record, an owner who names a person but no system, and
// an owner nobody has re-confirmed are three different pieces of work, and the
// middle one is the one people miss — it looks owned until somebody needs a
// blast radius.
function UnownedQueuePanel() {
  const { t } = useTranslation();
  const queue = useApiQuery(["unowned-identities"], api.unownedIdentities);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [exceptionTarget, setExceptionTarget] = useState<{ identity_id: string; name: string } | null>(null);
  const [exceptionReason, setExceptionReason] = useState("");
  const [exceptionHours, setExceptionHours] = useState("24");
  const [exceptionBusy, setExceptionBusy] = useState(false);
  const [exceptionError, setExceptionError] = useState<string | null>(null);
  const data = queue.data;
  // Guard the array, not just the object. A response whose shape is present but
  // whose items are absent is exactly what a fixture or a partial payload looks
  // like, and reading .slice on it takes down the whole Owners page rather than
  // hiding one panel.
  const items = data?.items ?? [];
  if (!data || items.length === 0) return null;
  async function submitException() {
    if (!exceptionTarget) return;
    const reason = exceptionReason.trim();
    const hours = Number(exceptionHours);
    if (!reason || !Number.isFinite(hours) || hours <= 0 || hours > 720) {
      setExceptionError(t("owners.readiness.exceptionValidation"));
      return;
    }
    setExceptionBusy(true);
    setExceptionError(null);
    try {
      await api.grantOwnershipException(exceptionTarget.identity_id, {
        reason,
        expires_at: new Date(Date.now() + hours * 60 * 60 * 1000).toISOString(),
      });
      void queryClient.invalidateQueries({ queryKey: ["unowned-identities"] });
      toast({ kind: "success", title: t("owners.readiness.exceptionGranted"), description: exceptionTarget.name });
      setExceptionTarget(null);
      setExceptionReason("");
    } catch (err) {
      setExceptionError(err instanceof Error ? err.message : String(err));
    } finally {
      setExceptionBusy(false);
    }
  }

  return (
    <>
      <section aria-labelledby="unowned-heading" className="ui-panel space-y-3 p-comfortable">
        <h2 id="unowned-heading" className="text-title font-semibold">
          {translateNow("source.unowned.queue.i1own00001")}
        </h2>
        <p className="text-sm">
          {translateNow("source.unowned.counts.i1own00002", {
            value1: String(data.counts?.no_owner ?? 0),
            value2: String(data.counts?.owner_missing_application_model ?? 0),
            value3: String(data.counts?.ownership_never_attested ?? 0),
          })}{" "}
          {t("owners.readiness.staleCount", { count: String(data.counts?.ownership_attestation_stale ?? 0) })}
        </p>
        <ul className="space-y-2 text-sm">
          {items.slice(0, 25).map((item) => (
            <li key={item.identity_id} className="border-b border-border pb-2 last:border-0">
              <span className="font-mono text-xs">{item.name}</span>
              <span className="mt-1 block text-caption text-muted-foreground">{item.detail}</span>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="mt-2"
                onClick={() => {
                  setExceptionTarget({ identity_id: item.identity_id, name: item.name });
                  setExceptionError(null);
                }}
              >
                {t("owners.readiness.grantTemporary")}
              </Button>
            </li>
          ))}
        </ul>
        <p className="text-caption text-muted-foreground">{data.guidance}</p>
      </section>
      <Dialog
        open={exceptionTarget !== null}
        onClose={() => {
          if (!exceptionBusy) setExceptionTarget(null);
        }}
        titleId="ownership-exception-title"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(92vw,30rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {exceptionTarget && (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void submitException();
            }}
          >
            <h2 id="ownership-exception-title" className="text-title font-semibold">
              {t("owners.readiness.exceptionTitle", { name: exceptionTarget.name })}
            </h2>
            <p className="text-sm text-muted-foreground">{t("owners.readiness.exceptionDescription")}</p>
            <label className="grid gap-1 text-body font-medium" htmlFor="ownership-exception-reason">
              {t("owners.readiness.reason")}
              <Textarea
                id="ownership-exception-reason"
                className="min-h-24 font-normal"
                value={exceptionReason}
                onChange={(event) => setExceptionReason(event.target.value)}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="ownership-exception-hours">
              {t("owners.readiness.expiryHours")}
              <Input
                id="ownership-exception-hours"
                type="number"
                min="1"
                max="720"
                className="font-normal"
                value={exceptionHours}
                onChange={(event) => setExceptionHours(event.target.value)}
                required
              />
            </label>
            {exceptionError && <p className="text-sm font-medium text-risk-critical">{exceptionError}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" disabled={exceptionBusy} onClick={() => setExceptionTarget(null)}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={exceptionBusy}>
                {t("owners.readiness.grant")}
              </Button>
            </div>
          </form>
        )}
      </Dialog>
    </>
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
  const [editorOpen, setEditorOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<Owner | null>(null);
  const [editName, setEditName] = useState("");
  const [editKind, setEditKind] = useState<Owner["kind"]>("user");
  const [editEmail, setEditEmail] = useState("");
  const [editApplicationID, setEditApplicationID] = useState("");
  const [editService, setEditService] = useState("");
  const [editBusinessUnit, setEditBusinessUnit] = useState("");
  const [editEnvironment, setEditEnvironment] = useState("");
  const [editEscalationChain, setEditEscalationChain] = useState("");
  const [attestingID, setAttestingID] = useState<string | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Owner | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [open, setOpen] = useState<Record<OwnerDisclosure, boolean>>({ directory: false, gaps: false, evidence: false });
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
  const knownCount = attributionCount(attribution.data?.summary, "total", attributionRows.length);
  const ownerGapCount = attributionCount(attribution.data?.summary, "orphaned", attributionRows.filter((item) => !item.owner).length);
  const assignedCount = attributionCount(attribution.data?.summary, "attributed", Math.max(0, knownCount - ownerGapCount));
  const currentOwnerCount = owners.filter((owner) => owner.ownership_current).length;

  function openEdit(owner: Owner) {
    setEditTarget(owner);
    setEditName(owner.name);
    setEditKind(owner.kind);
    setEditEmail(owner.email ?? "");
    setEditApplicationID(owner.application_id ?? "");
    setEditService(owner.service ?? "");
    setEditBusinessUnit(owner.business_unit ?? "");
    setEditEnvironment(owner.environment ?? "");
    setEditEscalationChain((owner.escalation_chain ?? []).join("\n"));
    setEditError(null);
    setEditorOpen(true);
  }

  function openCreate() {
    setEditTarget(null);
    setEditName("");
    setEditKind("team");
    setEditEmail("");
    setEditApplicationID("");
    setEditService("");
    setEditBusinessUnit("");
    setEditEnvironment("");
    setEditEscalationChain("");
    setEditError(null);
    setEditorOpen(true);
  }

  function openDelete(owner: Owner) {
    setDeleteTarget(owner);
    setDeleteConfirm("");
    setDeleteError(null);
  }

  async function submitEdit() {
    const name = editName.trim();
    if (!name) {
      setEditError("Name is required.");
      return;
    }
    setEditBusy(true);
    setEditError(null);
    try {
      const input = {
        name,
        kind: editKind,
        email: editEmail.trim() || undefined,
        application_id: editApplicationID.trim() || undefined,
        service: editService.trim() || undefined,
        business_unit: editBusinessUnit.trim() || undefined,
        environment: editEnvironment.trim() || undefined,
        escalation_chain: editEscalationChain
          .split("\n")
          .map((entry) => entry.trim())
          .filter(Boolean),
      };
      const updated = editTarget ? await api.updateOwner(editTarget.id, input) : await api.createOwner(input);
      queryClient.setQueryData<Owner[]>(["owners"], (current) => {
        if (!current) return current;
        return editTarget ? current.map((owner) => (owner.id === updated.id ? updated : owner)) : [...current, updated];
      });
      void queryClient.invalidateQueries({ queryKey: ["owners"] });
      setEditTarget(null);
      setEditorOpen(false);
      toast({ kind: "success", title: editTarget ? t("parity.ownerUpdated_07b92f") : t("owners.readiness.created"), description: updated.name });
    } catch (err) {
      setEditError(err instanceof Error ? err.message : String(err));
    } finally {
      setEditBusy(false);
    }
  }

  async function attestOwner(owner: Owner) {
    setAttestingID(owner.id);
    try {
      const updated = await api.attestOwner(owner.id);
      queryClient.setQueryData<Owner[]>(["owners"], (current) => current?.map((item) => (item.id === updated.id ? updated : item)));
      void queryClient.invalidateQueries({ queryKey: ["unowned-identities"] });
      toast({ kind: "success", title: t("owners.readiness.attested"), description: updated.name });
    } catch (err) {
      toast({ kind: "error", title: t("owners.readiness.attestFailed"), description: err instanceof Error ? err.message : String(err) });
    } finally {
      setAttestingID(null);
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
    { id: "application", header: t("owners.readiness.applicationID"), cell: (owner) => owner.application_id ?? "Unknown" },
    { id: "environment", header: t("owners.readiness.environment"), cell: (owner) => owner.environment ?? "Unknown" },
    {
      id: "readiness",
      header: t("owners.readiness.column"),
      cell: (owner) => (
        <span className={owner.ownership_current ? "text-status-success" : "text-risk-critical"}>
          {owner.ownership_current
            ? owner.ownership_attestation_due_at
              ? t("owners.readiness.current", { date: owner.ownership_attestation_due_at.slice(0, 10) })
              : t("owners.readiness.currentNoDate")
            : owner.ownership_complete
              ? owner.ownership_attested
                ? t("owners.readiness.due")
                : t("owners.readiness.needsAttestation")
              : t("owners.readiness.incomplete")}
        </span>
      ),
    },
    {
      // I2: where this ownership claim came from, and when that source last
      // said it. An owner with no recorded origin reads as "not recorded" and
      // never as "manual" — absence of provenance is not evidence of a human.
      id: "ownership_source",
      header: translateNow("source.ownership.source.column.i2own00006"),
      cell: (owner) =>
        owner.ownership_source ? (
          <span className="text-caption">
            {owner.ownership_source_observed_at
              ? translateNow("source.ownership.source.observed.i2own00008", {
                  value1: owner.ownership_source,
                  value2: owner.ownership_source_observed_at.slice(0, 10),
                })
              : owner.ownership_source}
          </span>
        ) : (
          <span className="text-caption text-muted-foreground">{translateNow("source.ownership.source.unrecorded.i2own00007")}</span>
        ),
    },
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
            disabled={!owner.ownership_complete || attestingID === owner.id}
            onClick={() => void attestOwner(owner)}
          >
            {owner.ownership_attested ? t("owners.readiness.reattest") : t("owners.readiness.attest")}
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
        title={t("nav.item.ownership")}
        description={t("owners.design.answer")}
        technicalDetails={t("owners.design.technicalDetails")}
        actions={
          <Button type="button" onClick={openCreate}>
            {t("owners.design.assign")}
          </Button>
        }
      />

      {loading || attribution.loading ? (
        <LoadingState>{t("owners.design.checkingCoverage")}</LoadingState>
      ) : error || attribution.error ? (
        <ErrorState title={t("owners.design.coverageError")}>{error || attribution.error}</ErrorState>
      ) : (
        <div className="ui-panel grid gap-2 p-comfortable" role="status" aria-live="polite">
          <h2 className="text-title font-semibold">
            {knownCount === 0
              ? t("owners.design.statusEmpty")
              : ownerGapCount === 0
                ? t("owners.design.statusComplete")
                : ownerGapCount === 1
                  ? t("owners.design.statusNeedsOne")
                  : t("owners.design.statusNeedsMany", { count: String(ownerGapCount) })}
          </h2>
          <p className="max-w-3xl text-sm text-muted-foreground">
            {t("owners.design.statusBody", {
              assigned: String(assignedCount),
              known: String(knownCount),
              current: String(currentOwnerCount),
              owners: String(owners.length),
            })}
          </p>
        </div>
      )}

      <OwnerDetails
        title={t("owners.design.disclosure.directory")}
        open={open.directory}
        onToggle={(value) => setOpen((current) => ({ ...current, directory: value }))}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("owners.design.directoryHelp")}</p>
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
                stateTitle={rows.length === 0 ? t("owners.design.noOwners") : t("owners.design.noOwnerMatches")}
                stateMessage={rows.length === 0 ? t("owners.design.noOwnersHelp") : t("owners.design.noOwnerMatchesHelp")}
              />
            </>
          )}
        </div>
      </OwnerDetails>

      <OwnerDetails title={t("owners.design.disclosure.gaps")} open={open.gaps} onToggle={(value) => setOpen((current) => ({ ...current, gaps: value }))}>
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("owners.design.gapsHelp")}</p>
          <OrphanGovernance owners={owners} />
          <UnownedQueuePanel />
        </div>
      </OwnerDetails>

      <OwnerDetails
        title={t("owners.design.disclosure.evidence")}
        open={open.evidence}
        onToggle={(value) => setOpen((current) => ({ ...current, evidence: value }))}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("owners.design.evidenceRule")}</p>
          <CMDBSyncPanel />
          <OwnershipConflictsPanel />
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
        </div>
      </OwnerDetails>

      <Dialog
        open={editorOpen}
        onClose={() => {
          if (!editBusy) setEditorOpen(false);
        }}
        titleId="owner-edit-title"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(92vw,30rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {editorOpen && (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void submitEdit();
            }}
          >
            <h2 id="owner-edit-title" className="text-title font-semibold">
              {editTarget ? t("owners.readiness.editTitle", { name: editTarget.name }) : t("owners.design.assign")}
            </h2>
            {!editTarget && <p className="text-sm text-muted-foreground">{t("owners.design.assignHelp")}</p>}
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
              <Select id="owner-edit-kind" className="font-normal" value={editKind} onChange={(event) => setEditKind(event.target.value as Owner["kind"])}>
                {ownerKinds.map((ownerKind) => (
                  <option key={ownerKind} value={ownerKind}>
                    {ownerKind}
                  </option>
                ))}
              </Select>
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
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-application">
              {t("owners.readiness.applicationID")}
              <input
                id="owner-edit-application"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={editApplicationID}
                onChange={(event) => setEditApplicationID(event.target.value)}
                placeholder={t("owners.readiness.applicationPlaceholder")}
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-service">
              {t("owners.readiness.service")}
              <input
                id="owner-edit-service"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={editService}
                onChange={(event) => setEditService(event.target.value)}
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-business-unit">
              {t("owners.readiness.businessUnit")}
              <input
                id="owner-edit-business-unit"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={editBusinessUnit}
                onChange={(event) => setEditBusinessUnit(event.target.value)}
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-environment">
              {t("owners.readiness.environment")}
              <input
                id="owner-edit-environment"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={editEnvironment}
                onChange={(event) => setEditEnvironment(event.target.value)}
                placeholder={t("owners.readiness.environmentPlaceholder")}
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="owner-edit-escalation">
              {t("owners.readiness.escalation")}
              <Textarea
                id="owner-edit-escalation"
                className="min-h-24 font-mono font-normal"
                value={editEscalationChain}
                onChange={(event) => setEditEscalationChain(event.target.value)}
              />
            </label>
            {editError && <p className="text-sm font-medium text-risk-critical">{editError}</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setEditorOpen(false)} disabled={editBusy}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={editBusy}>
                {editTarget ? t("parity.saveOwner_b67638") : t("owners.readiness.create")}
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

function OwnerDetails({ title, open, onToggle, children }: { title: string; open: boolean; onToggle: (open: boolean) => void; children: ReactNode }) {
  return (
    <details className="rounded-panel border border-border bg-card shadow-elevation1" open={open} onToggle={(event) => onToggle(event.currentTarget.open)}>
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      <div className="border-t border-border p-4">{open ? children : null}</div>
    </details>
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
