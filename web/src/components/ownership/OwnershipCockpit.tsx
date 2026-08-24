import { useMemo, useState } from "react";
import { api, type Owner, type OwnershipAttribution, type OwnershipAttributionItem, type UnownedQueue } from "@/lib/api";
import { useQueryClient } from "@/lib/query";
import { useToast } from "@/components/ToastProvider";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Eyebrow } from "@/components/typography";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";

interface OwnershipCockpitProps {
  owners: Owner[];
  attribution: OwnershipAttribution;
  readiness?: UnownedQueue;
  onCreateOwner: () => void;
  onEditOwner: (owner: Owner) => void;
  onAttestOwner: (owner: Owner) => void;
  attestingID: string | null;
}

function routeFor(owner: Owner): string[] {
  return [owner.email?.trim() ?? "", ...(owner.escalation_chain ?? []).map((entry) => entry.trim())].filter(Boolean);
}

function hierarchyKey(owner: Owner): string {
  return owner.business_unit?.trim() || "Business unit not recorded";
}

function readinessLabelKey(reason: string | undefined): MessageKey {
  switch (reason) {
    case "no_owner":
      return "owners.cockpit.reason.noOwner";
    case "owner_missing_application_model":
      return "owners.cockpit.reason.missingScope";
    case "ownership_never_attested":
      return "owners.cockpit.reason.neverReviewed";
    case "ownership_attestation_stale":
      return "owners.cockpit.reason.staleReview";
    default:
      return "owners.cockpit.reason.noEffectiveOwner";
  }
}

export function OwnershipCockpit(props: OwnershipCockpitProps) {
  const { t, formatDate } = useTranslation();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [assignmentOpen, setAssignmentOpen] = useState(false);
  const [assignmentOwnerID, setAssignmentOwnerID] = useState("");
  const [assignmentReason, setAssignmentReason] = useState("");
  const [assignmentBusy, setAssignmentBusy] = useState(false);
  const [assignmentError, setAssignmentError] = useState<string | null>(null);
  const [queueScope, setQueueScope] = useState<"gaps" | "all">("gaps");
  const [queueOwner, setQueueOwner] = useState("all");

  const items = useMemo(() => props.attribution.items ?? [], [props.attribution.items]);
  const gaps = useMemo(() => items.filter((item) => item.attribution_status === "orphaned"), [items]);
  const assetsByOwner = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      if (item.owner) counts.set(item.owner.id, (counts.get(item.owner.id) ?? 0) + 1);
    }
    return counts;
  }, [items]);
  const activeOwners = useMemo(() => props.owners.filter((owner) => (assetsByOwner.get(owner.id) ?? 0) > 0), [assetsByOwner, props.owners]);
  const hierarchy = useMemo(() => {
    const groups = new Map<string, Owner[]>();
    for (const owner of activeOwners) {
      const key = hierarchyKey(owner);
      groups.set(key, [...(groups.get(key) ?? []), owner]);
    }
    return Array.from(groups.entries()).sort(([left], [right]) => left.localeCompare(right));
  }, [activeOwners]);
  const reviewGaps = activeOwners.filter((owner) => !owner.ownership_current).length;
  const routeGaps = activeOwners.filter((owner) => routeFor(owner).length === 0).length;
  const readinessByIdentityID = useMemo(() => new Map((props.readiness?.items ?? []).map((item) => [item.identity_id, item])), [props.readiness?.items]);
  const queueItems = useMemo(() => {
    const scoped = queueScope === "gaps" ? gaps : items;
    if (queueOwner === "all") return scoped;
    if (queueOwner === "unowned") return scoped.filter((item) => !item.owner);
    return scoped.filter((item) => item.owner?.id === queueOwner);
  }, [gaps, items, queueOwner, queueScope]);
  const selectedItems = items.filter((item) => selected.has(item.id));
  const selectedIncludesReassignment = selectedItems.some((item) => item.owner);

  function openAssignment(itemsToAssign: OwnershipAttributionItem[]) {
    setSelected(new Set(itemsToAssign.map((item) => item.id)));
    setAssignmentOwnerID(props.owners.find((owner) => owner.kind === "team" || owner.kind === "service")?.id ?? props.owners[0]?.id ?? "");
    setAssignmentReason("");
    setAssignmentError(null);
    setAssignmentOpen(true);
  }

  async function submitAssignment() {
    if (!assignmentOwnerID || selectedItems.length === 0 || !assignmentReason.trim()) {
      setAssignmentError(t("owners.cockpit.assignment.validation"));
      return;
    }
    setAssignmentBusy(true);
    setAssignmentError(null);
    try {
      const result = await api.assignOwnership({
        owner_id: assignmentOwnerID,
        inventory_ids: selectedItems.map((item) => item.id),
        reason: assignmentReason.trim(),
      });
      const owner = props.owners.find((candidate) => candidate.id === result.owner_id);
      void queryClient.invalidateQueries({ queryKey: ["owners"] });
      void queryClient.invalidateQueries({ queryKey: ["ownership-attribution"] });
      void queryClient.invalidateQueries({ queryKey: ["unowned-identities"] });
      void queryClient.invalidateQueries({ queryKey: ["certificates"] });
      toast({
        kind: "success",
        title:
          result.assigned.length === 1
            ? t("owners.cockpit.assignment.success.one", { owner: owner?.name ?? result.owner_id })
            : t("owners.cockpit.assignment.success", { count: String(result.assigned.length), owner: owner?.name ?? result.owner_id }),
      });
      setSelected(new Set());
      setAssignmentOpen(false);
    } catch (err) {
      setAssignmentError(err instanceof Error ? err.message : String(err));
    } finally {
      setAssignmentBusy(false);
    }
  }

  return (
    <section aria-label={t("owners.cockpit.ariaLabel")} className="space-y-4">
      <div className="ui-panel grid gap-4 p-comfortable">
        <div className="grid gap-1">
          <Eyebrow as="p">{t("owners.cockpit.eyebrow")}</Eyebrow>
          <h2 id="ownership-operations-heading" className="text-title font-semibold">
            {items.length === 0
              ? t("owners.design.statusEmpty")
              : gaps.length === 0
                ? t("owners.cockpit.answer.complete")
                : gaps.length === 1
                  ? t("owners.cockpit.answer.one")
                  : t("owners.cockpit.answer.gaps", { count: String(gaps.length) })}
          </h2>
          <p className="max-w-3xl text-sm text-muted-foreground">{t("owners.cockpit.answer.body")}</p>
        </div>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {[
            ["known-assets", t("owners.cockpit.metric.known"), items.length],
            ["owner-gaps", t("owners.cockpit.metric.unowned"), gaps.length],
            ["review-gaps", t("owners.cockpit.metric.review"), reviewGaps],
            ["route-gaps", t("owners.cockpit.metric.route"), routeGaps],
          ].map(([id, label, value]) => (
            <div key={String(id)} className="rounded-control border border-border bg-background/70 p-3">
              <p className="text-caption text-muted-foreground">{label}</p>
              <p className="mt-1 text-metric font-semibold tabular-nums" data-metric={id}>
                {value}
              </p>
            </div>
          ))}
        </div>
      </div>

      <section aria-labelledby="accountability-hierarchy-heading" className="ui-panel space-y-4 p-comfortable">
        <div className="grid gap-1">
          <h3 id="accountability-hierarchy-heading" className="text-title font-semibold">
            {t("owners.cockpit.hierarchy.title")}
          </h3>
          <p className="max-w-3xl text-sm text-muted-foreground">{t("owners.cockpit.hierarchy.body")}</p>
        </div>
        {hierarchy.length === 0 ? (
          <div className="rounded-control border border-dashed border-border p-4 text-sm text-muted-foreground">{t("owners.cockpit.hierarchy.empty")}</div>
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {hierarchy.map(([businessUnit, owners]) => (
              <section key={businessUnit} className="rounded-control border border-border bg-background/60 p-4">
                <p className="text-caption text-muted-foreground">{t("owners.cockpit.hierarchy.businessUnit")}</p>
                <h4 className="mt-1 text-body font-semibold">{businessUnit}</h4>
                <div className="mt-3 grid gap-3">
                  {owners.map((owner) => {
                    const route = routeFor(owner);
                    const count = assetsByOwner.get(owner.id) ?? 0;
                    return (
                      <article key={owner.id} className="rounded-control border border-border bg-card p-3">
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div>
                            <p className="font-semibold">{owner.name}</p>
                            <p className="text-caption text-muted-foreground">
                              {owner.kind} · {owner.service || owner.application_id || t("owners.cockpit.scope.unrecorded")} ·{" "}
                              {owner.environment || t("owners.cockpit.scope.unrecorded")}
                            </p>
                          </div>
                          <p className="text-caption font-medium">{t("owners.cockpit.assets", { count: String(count) })}</p>
                        </div>
                        <dl className="mt-3 grid gap-2 text-sm">
                          <div>
                            <dt className="text-caption text-muted-foreground">{t("owners.cockpit.route")}</dt>
                            <dd className={route.length === 0 ? "font-medium text-risk-critical" : "break-words"}>
                              {route.length === 0 ? t("owners.cockpit.route.missing") : route.join(" → ")}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-caption text-muted-foreground">{t("owners.cockpit.review")}</dt>
                            <dd className={owner.ownership_current ? "text-status-success" : "font-medium text-risk-critical"}>
                              {owner.ownership_current
                                ? owner.ownership_attestation_due_at
                                  ? t("owners.cockpit.review.current", { date: formatDate(owner.ownership_attestation_due_at) })
                                  : t("owners.readiness.currentNoDate")
                                : owner.ownership_attested
                                  ? t("owners.readiness.due")
                                  : t("owners.readiness.needsAttestation")}
                            </dd>
                          </div>
                        </dl>
                        <div className="mt-3 flex flex-wrap gap-2">
                          <Button type="button" size="sm" variant="outline" onClick={() => props.onEditOwner(owner)}>
                            {t("parity.edit_530164")}
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={!owner.ownership_complete || props.attestingID === owner.id}
                            onClick={() => props.onAttestOwner(owner)}
                          >
                            {owner.ownership_attested ? t("owners.readiness.reattest") : t("owners.readiness.attest")}
                          </Button>
                        </div>
                      </article>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        )}
      </section>

      <section aria-labelledby="ownership-action-heading" className="ui-panel space-y-3 overflow-hidden">
        <div className="flex flex-wrap items-start justify-between gap-3 px-4 pt-4">
          <div>
            <h3 id="ownership-action-heading" className="text-title font-semibold">
              {t("owners.cockpit.queue.title")}
            </h3>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("owners.cockpit.queue.body")}</p>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="grid gap-1 text-caption font-medium" htmlFor="ownership-queue-scope">
              {t("owners.cockpit.queue.scope")}
              <Select
                id="ownership-queue-scope"
                className="min-w-40 font-normal"
                value={queueScope}
                onChange={(event) => {
                  setQueueScope(event.target.value as "gaps" | "all");
                  setSelected(new Set());
                }}
              >
                <option value="gaps">{t("owners.cockpit.queue.scope.gaps")}</option>
                <option value="all">{t("owners.cockpit.queue.scope.all")}</option>
              </Select>
            </label>
            <label className="grid gap-1 text-caption font-medium" htmlFor="ownership-queue-owner">
              {t("owners.cockpit.queue.ownerFilter")}
              <Select
                id="ownership-queue-owner"
                className="min-w-40 font-normal"
                value={queueOwner}
                onChange={(event) => {
                  setQueueOwner(event.target.value);
                  setSelected(new Set());
                }}
              >
                <option value="all">{t("owners.cockpit.queue.ownerFilter.all")}</option>
                <option value="unowned">{t("owners.cockpit.queue.ownerFilter.unowned")}</option>
                {props.owners.map((owner) => (
                  <option key={owner.id} value={owner.id}>
                    {owner.name}
                  </option>
                ))}
              </Select>
            </label>
            <Button className="sm:col-span-2" type="button" disabled={selectedItems.length === 0} onClick={() => openAssignment(selectedItems)}>
              {selectedIncludesReassignment
                ? selectedItems.length === 1
                  ? t("owners.cockpit.assignment.reassignSelected.one")
                  : t("owners.cockpit.assignment.reassignSelected", { count: String(selectedItems.length) })
                : selectedItems.length === 1
                  ? t("owners.cockpit.assignment.selected.one")
                  : t("owners.cockpit.assignment.selected", { count: String(selectedItems.length) })}
            </Button>
          </div>
        </div>
        {queueItems.length === 0 ? (
          <p className="px-4 pb-4 text-sm text-muted-foreground">
            {queueScope === "gaps" && queueOwner === "all" ? t("owners.cockpit.queue.empty") : t("owners.cockpit.queue.noMatches")}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[50rem] text-left text-sm" aria-label={t("owners.cockpit.queue.ariaLabel")}>
              <thead className="border-y border-border bg-muted/50 text-caption text-muted-foreground">
                <tr>
                  <th className="px-4 py-2 font-medium">{t("owners.cockpit.queue.select")}</th>
                  <th className="px-3 py-2 font-medium">{t("owners.attribution.nhi")}</th>
                  <th className="px-3 py-2 font-medium">{t("owners.attribution.kind")}</th>
                  <th className="px-3 py-2 font-medium">{t("owners.cockpit.queue.reason")}</th>
                  <th className="px-4 py-2 font-medium">{t("owners.cockpit.queue.action")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {queueItems.slice(0, 25).map((item) => {
                  const identityID = item.id.startsWith("identity/") ? item.id.slice("identity/".length) : "";
                  const readiness = readinessByIdentityID.get(identityID);
                  const reason = item.owner ? t("owners.cockpit.reason.currentOwner", { owner: item.owner.name }) : t(readinessLabelKey(readiness?.reason));
                  return (
                    <tr key={item.id}>
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          className="size-4 accent-brand-accent"
                          aria-label={t("owners.cockpit.queue.selectAsset", { name: item.display_name })}
                          checked={selected.has(item.id)}
                          onChange={(event) => {
                            setSelected((current) => {
                              const next = new Set(current);
                              if (event.target.checked) next.add(item.id);
                              else next.delete(item.id);
                              return next;
                            });
                          }}
                        />
                      </td>
                      <th scope="row" className="px-3 py-3 font-medium">
                        {item.display_name}
                      </th>
                      <td className="px-3 py-3">{item.kind}</td>
                      <td className="px-3 py-3 text-risk-critical">{reason}</td>
                      <td className="px-4 py-3">
                        <Button type="button" size="sm" variant="outline" onClick={() => openAssignment([item])}>
                          {item.owner ? t("owners.cockpit.assignment.reassign") : t("owners.design.assign")}
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Dialog
        open={assignmentOpen}
        onClose={() => {
          if (!assignmentBusy) setAssignmentOpen(false);
        }}
        titleId="ownership-assignment-title"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(92vw,34rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {assignmentOpen && (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void submitAssignment();
            }}
          >
            <div>
              <h2 id="ownership-assignment-title" className="text-title font-semibold">
                {t("owners.cockpit.assignment.title")}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">{t("owners.cockpit.assignment.body", { count: String(selectedItems.length) })}</p>
            </div>
            {props.owners.length === 0 ? (
              <div className="rounded-control border border-dashed border-border p-4 text-sm">
                <p>{t("owners.cockpit.assignment.noOwners")}</p>
                <Button type="button" className="mt-3" variant="outline" onClick={props.onCreateOwner}>
                  {t("owners.readiness.create")}
                </Button>
              </div>
            ) : (
              <label className="grid gap-1 text-body font-medium" htmlFor="ownership-assignment-owner">
                {t("owners.cockpit.assignment.owner")}
                <Select
                  id="ownership-assignment-owner"
                  className="font-normal"
                  value={assignmentOwnerID}
                  onChange={(event) => setAssignmentOwnerID(event.target.value)}
                  required
                >
                  {props.owners.map((owner) => (
                    <option key={owner.id} value={owner.id}>
                      {owner.name} · {owner.kind} · {owner.environment || t("owners.cockpit.scope.unrecorded")}
                    </option>
                  ))}
                </Select>
              </label>
            )}
            <label className="grid gap-1 text-body font-medium" htmlFor="ownership-assignment-reason">
              {t("owners.cockpit.assignment.reason")}
              <Textarea
                id="ownership-assignment-reason"
                className="min-h-24 font-normal"
                value={assignmentReason}
                onChange={(event) => setAssignmentReason(event.target.value)}
                maxLength={2000}
                required
              />
            </label>
            {assignmentError && <p className="text-sm font-medium text-risk-critical">{assignmentError}</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" variant="ghost" disabled={assignmentBusy} onClick={() => setAssignmentOpen(false)}>
                {t("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={assignmentBusy || props.owners.length === 0}>
                {t("owners.design.assign")}
              </Button>
            </div>
          </form>
        )}
      </Dialog>
    </section>
  );
}
