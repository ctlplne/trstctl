import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  api,
  ApiError,
  identityState,
  type BulkRevokeRequest,
  type BulkRevokeResult,
  type ConnectorDelivery,
  type GraphImpact,
  type Identity,
  type NHIDecommissionRequest,
  type NHIDecommissionResponse,
  type RotationRun,
  type TransitionTo,
} from "@/lib/api";
import { Dialog } from "@/components/Dialog";
import { IssuancePipeline } from "@/components/issuance";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DetailDrawer } from "@/components/DetailDrawer";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { PageHeader } from "@/components/PageHeader";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";

/** action is a lifecycle transition offered for a given state. `to` is bound to the
 * OpenAPI-generated transition enum (TransitionTo), so the UI can never offer (or send)
 * a target the backend contract does not accept — drift here fails the build. */
interface Action {
  label: string;
  to: TransitionTo;
}

const lifecycleTargets: TransitionTo[] = ["issued", "deployed", "renewing", "revoked", "retired"];
const identityKinds = ["x509_certificate", "ssh_certificate", "ssh_key", "secret", "api_key", "workload_identity"] as const satisfies Identity["kind"][];
const bulkRevokeReasons: BulkRevokeRequest["reason"][] = [
  "unspecified",
  "keyCompromise",
  "caCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "certificateHold",
  "removeFromCRL",
  "privilegeWithdrawn",
  "aaCompromise",
];
type KindFilter = "all" | Identity["kind"];
type DecommissionSignalType = NHIDecommissionRequest["signals"][number]["type"];
type BlastRadiusState = {
  error: string | null;
  impact: GraphImpact | null;
  loading: boolean;
  nodeId: string | null;
};

const emptyBlastRadiusState: BlastRadiusState = {
  error: null,
  impact: null,
  loading: false,
  nodeId: null,
};

const kindCopy: Record<Identity["kind"], { title: string; description: string }> = {
  x509_certificate: {
    title: "X.509 certificate identity",
    description: "A TLS or mTLS identity whose lifecycle is backed by certificate issuance, revocation, and expiry evidence.",
  },
  ssh_certificate: {
    title: "SSH certificate identity",
    description: "A short-lived SSH host or user certificate identity controlled by the SSH CA and lifecycle state machine.",
  },
  ssh_key: {
    title: "SSH key identity",
    description: "A standing SSH key identity that should be owned, rotated, and retired like any other non-human credential.",
  },
  secret: {
    title: "Secret identity",
    description: "A password, shared secret, or opaque credential identity tracked separately from certificate inventory.",
  },
  api_key: {
    title: "API key identity",
    description: "An API token or service key identity where ownership, age, and retirement matter more than a certificate chain.",
  },
  workload_identity: {
    title: "Workload identity",
    description: "A service, job, agent, or workload identity that can be issued short-lived credentials instead of storing static secrets.",
  },
};

/** isDestructive reports whether a target state is a destructive transition that must
 * be confirmed before it runs — revoke permanently invalidates the credential, and
 * retire discards it (SURFACE-007). */
function isDestructive(to: TransitionTo): boolean {
  return to === "revoked" || to === "retired";
}

/** errorMessage renders an action error, special-casing a 429 so the user sees a
 * concrete retry hint (Retry-After) instead of a bare failure (SURFACE-007). */
function apiProblemMessage(err: unknown): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : String(err);
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError && err.isRateLimited) {
    return err.retryAfterSeconds != null ? `Rate limited — please retry in ${err.retryAfterSeconds}s.` : "Rate limited — please retry shortly.";
  }
  return `Action failed: ${apiProblemMessage(err)}`;
}

/** actionsFor returns the lifecycle actions valid from a state — the UI mirror
 * of the orchestrator's transition table (issue → deploy → renew, revoke, and
 * retire). */
function actionsFor(state: string): Action[] {
  switch (state) {
    case "requested":
      return [{ label: "Issue", to: "issued" }];
    case "issued":
      return [
        { label: "Deploy", to: "deployed" },
        { label: "Revoke", to: "revoked" },
      ];
    case "deployed":
      return [
        { label: "Renew", to: "renewing" },
        { label: "Revoke", to: "revoked" },
      ];
    case "renewing":
      return [{ label: "Revoke", to: "revoked" }];
    case "revoked":
      return [{ label: "Retire", to: "retired" }];
    default:
      return [];
  }
}

function actionForTarget(state: string, target: TransitionTo): Action | undefined {
  return actionsFor(state).find((a) => a.to === target);
}

function terminalMessage(state: string): string | null {
  if (state === "retired") {
    return "Terminal state: retired identities have no valid next transition.";
  }
  if (state === "revoked") {
    return "Terminal trust state: relying parties should no longer accept this identity; only record-retirement cleanup remains.";
  }
  return null;
}

function evidenceTime(value: { created_at?: string; updated_at?: string }): number {
  const parsed = Date.parse(value.updated_at || value.created_at || "");
  return Number.isNaN(parsed) ? 0 : parsed;
}

function latestDeliveryByIdentity(deliveries: ConnectorDelivery[] | null): Map<string, ConnectorDelivery> {
  const out = new Map<string, ConnectorDelivery>();
  for (const receipt of deliveries ?? []) {
    if (!receipt.identity_id) continue;
    const current = out.get(receipt.identity_id);
    if (!current || evidenceTime(receipt) >= evidenceTime(current)) out.set(receipt.identity_id, receipt);
  }
  return out;
}

function latestRotationByIdentity(runs: RotationRun[] | null): Map<string, RotationRun> {
  const out = new Map<string, RotationRun>();
  for (const run of runs ?? []) {
    const current = out.get(run.identity_id);
    if (!current || evidenceTime(run) >= evidenceTime(current)) out.set(run.identity_id, run);
  }
  return out;
}

function shortFingerprint(value?: string): string {
  if (!value) return "-";
  return value.length <= 16 ? value : `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function deliveryEvidence(identity: Identity, delivery?: ConnectorDelivery, rotation?: RotationRun): string {
  const state = identityState(identity);
  if (rotation?.status === "running") {
    return `Rotation running (${rotation.trigger}); predecessor ${shortFingerprint(rotation.predecessor_fingerprint)}.`;
  }
  if (rotation?.status === "failed") {
    return `Rotation failed (${rotation.trigger}): ${rotation.error || rotation.reason || "worker error"}.`;
  }
  if (rotation?.status === "succeeded" && !delivery) {
    return `Rotation succeeded (${rotation.trigger}); successor ${shortFingerprint(rotation.successor_fingerprint)}.`;
  }
  if (delivery) {
    const target = `${delivery.connector}/${delivery.target}`;
    const fp = shortFingerprint(delivery.fingerprint);
    if (delivery.status === "delivered") return `Delivered to ${target}; fingerprint ${fp}.`;
    if (delivery.status === "failed") return `Delivery failed for ${target}: ${delivery.reason || delivery.detail || "worker error"}.`;
    return `Delivery receipt ${delivery.status} for ${target}; ${delivery.reason || delivery.detail || "awaiting plugin"}.`;
  }
  switch (state) {
    case "requested":
      return "Awaiting issue approval or issue request; no downstream delivery yet.";
    case "issued":
      return "Issued. Deploy can be requested; no connector delivery receipt yet.";
    case "deployed":
      return "Backend state says deployed; no connector delivery receipt has been projected yet.";
    case "renewing":
      return "Renewal in progress; waiting for a rotation-run receipt.";
    case "revoked":
      return "Revoked. Delivery and rotation receipts remain available as evidence.";
    case "retired":
      return "Terminal retired state; no next lifecycle action.";
    default:
      return "Lifecycle state is known; no downstream delivery receipt yet.";
  }
}

function transitionNotice(to: TransitionTo): string {
  return `${to} request accepted. Idempotency-Key protects retried submissions from duplicate execution; downstream outbox delivery receipts update asynchronously.`;
}

function deniedKey(id: string, to: TransitionTo): string {
  return `${id}:${to}`;
}

function decommissionInputLabelKey(
  type: DecommissionSignalType,
): "identities.decommission.vendor" | "identities.decommission.inactiveBefore" | "identities.decommission.subject" {
  if (type === "vendor_term") return "identities.decommission.vendor";
  if (type === "inactivity") return "identities.decommission.inactiveBefore";
  return "identities.decommission.subject";
}

function localDateTimeToISO(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
}

function formatDate(value?: string): string {
  return formatDateTimePolicy(value);
}

function displayValue(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function stringAttribute(identity: Identity, keys: string[]): string | null {
  for (const key of keys) {
    const value = identity.attributes?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

export function graphNodeIdForIdentity(identity: Identity): string | null {
  const explicit = stringAttribute(identity, ["graph_node_id", "graph_node", "graph_id"]);
  if (explicit) return explicit;

  const credentialID = stringAttribute(identity, ["credential_id", "certificate_id"]);
  if (credentialID) return credentialID.startsWith("cert:") ? credentialID : `cert:${credentialID}`;

  return identity.kind === "x509_certificate" && identity.id ? `cert:${identity.id}` : null;
}

function attributeRows(identity: Identity): Array<[string, string]> {
  return Object.entries(identity.attributes ?? {})
    .slice(0, 8)
    .map(([key, value]) => [key, displayValue(value)]);
}

export function Identities() {
  const { t } = useTranslation();
  const [items, setItems] = useState<Identity[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deliveryReceipts, setDeliveryReceipts] = useState<ConnectorDelivery[] | null>(null);
  const [rotationRuns, setRotationRuns] = useState<RotationRun[] | null>(null);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [deniedTransitions, setDeniedTransitions] = useState<Record<string, string>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Identity | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [transitionReasons, setTransitionReasons] = useState<Record<string, string>>({});
  const [showForm, setShowForm] = useState(false);
  // A destructive transition awaiting explicit confirmation (SURFACE-007). null
  // means no confirmation is pending.
  const [pending, setPending] = useState<{ id: string; name: string; to: TransitionTo; label: string; reason?: string } | null>(null);
  const [pendingConfirmName, setPendingConfirmName] = useState("");
  const [pendingReason, setPendingReason] = useState("");
  const [kindFilter, setKindFilter] = useState<KindFilter>("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [bulkConfirmOpen, setBulkConfirmOpen] = useState(false);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkReason, setBulkReason] = useState<BulkRevokeRequest["reason"]>("keyCompromise");
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [bulkResult, setBulkResult] = useState<BulkRevokeResult | null>(null);
  const [decommissionType, setDecommissionType] = useState<DecommissionSignalType>("departure");
  const [decommissionTarget, setDecommissionTarget] = useState("");
  const [decommissionReason, setDecommissionReason] = useState("");
  const [decommissionBusy, setDecommissionBusy] = useState(false);
  const [decommissionResult, setDecommissionResult] = useState<NHIDecommissionResponse | null>(null);
  const [pendingImpact, setPendingImpact] = useState<BlastRadiusState>(emptyBlastRadiusState);
  const pendingConfirmRef = useRef<HTMLInputElement>(null);
  const bulkConfirmRef = useRef<HTMLButtonElement>(null);
  const impactRequestRef = useRef(0);
  const filteredItems = useMemo(() => (items ?? []).filter((identity) => kindFilter === "all" || identity.kind === kindFilter), [items, kindFilter]);
  const selectedRows = useMemo(() => filteredItems.filter((identity) => selectedIds.has(identity.id)), [filteredItems, selectedIds]);
  const latestDelivery = useMemo(() => latestDeliveryByIdentity(deliveryReceipts), [deliveryReceipts]);
  const latestRotation = useMemo(() => latestRotationByIdentity(rotationRuns), [rotationRuns]);

  const load = useCallback(async () => {
    try {
      setItems(await api.identities());
      setError(null);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  const loadEvidence = useCallback(async () => {
    try {
      const [deliveries, rotations] = await Promise.all([api.connectorDeliveries({ limit: 50 }), api.rotationRuns({ limit: 50 })]);
      setDeliveryReceipts(deliveries.items ?? []);
      setRotationRuns(rotations.items ?? []);
      setEvidenceError(null);
    } catch (err) {
      setEvidenceError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
    void loadEvidence();
  }, [load, loadEvidence]);

  const loadDetail = useCallback(async (id: string) => {
    setDetailLoading(true);
    setDetailError(null);
    try {
      setDetail(await api.getIdentity(id));
    } catch (err) {
      setDetailError(`Could not load identity detail: ${apiProblemMessage(err)}`);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const openDetail = useCallback(
    (identity: Identity) => {
      setSelectedId(identity.id);
      setDetail(identity);
      void loadDetail(identity.id);
    },
    [loadDetail],
  );

  const act = useCallback(
    async (id: string, to: TransitionTo, reason?: string) => {
      setBusyId(id);
      setError(null);
      setNotice(null);
      try {
        await api.transitionIdentity(id, to, reason?.trim() || `${to} via UI`);
        await load();
        await loadEvidence();
        if (selectedId === id) {
          await loadDetail(id);
        }
        setNotice(transitionNotice(to));
        setDeniedTransitions((current) => {
          const next = { ...current };
          delete next[deniedKey(id, to)];
          return next;
        });
      } catch (err) {
        if (err instanceof ApiError && err.status === 403) {
          setDeniedTransitions((current) => ({ ...current, [deniedKey(id, to)]: apiProblemMessage(err) }));
        }
        setError(errorMessage(err));
      } finally {
        setBusyId(null);
      }
    },
    [load, loadDetail, loadEvidence, selectedId],
  );

  /** request runs a transition immediately, EXCEPT a destructive one (revoke/retire)
   * which is first parked in `pending` so the user must confirm it in a dialog that
   * names the credential (SURFACE-007). */
  function clearPending() {
    impactRequestRef.current += 1;
    setPending(null);
    setPendingConfirmName("");
    setPendingImpact(emptyBlastRadiusState);
  }

  const loadBlastRadius = useCallback((identity: Identity) => {
    const nodeId = graphNodeIdForIdentity(identity);
    const requestID = impactRequestRef.current + 1;
    impactRequestRef.current = requestID;

    if (!nodeId) {
      setPendingImpact({
        nodeId: null,
        impact: null,
        loading: false,
        error: "Blast-radius impact unavailable: no graph node mapping for this identity.",
      });
      return;
    }

    setPendingImpact({ nodeId, impact: null, loading: true, error: null });
    api
      .graphBlastRadius(nodeId)
      .then((impact) => {
        if (impactRequestRef.current === requestID) {
          setPendingImpact({ nodeId, impact, loading: false, error: null });
        }
      })
      .catch((err) => {
        if (impactRequestRef.current === requestID) {
          setPendingImpact({
            nodeId,
            impact: null,
            loading: false,
            error: `Blast-radius impact unavailable: ${apiProblemMessage(err)}`,
          });
        }
      });
  }, []);

  const request = useCallback(
    (identity: Identity, to: TransitionTo, label: string, reason?: string) => {
      if (isDestructive(to)) {
        setPendingConfirmName("");
        setPendingReason(reason?.trim() || (to === "revoked" ? "operator requested revocation" : "operator requested retirement"));
        setPending({ id: identity.id, name: identity.name, to, label, reason });
        loadBlastRadius(identity);
        return;
      }
      void act(identity.id, to, reason);
    },
    [act, loadBlastRadius],
  );

  /** runBulkRevoke sends ONE bulk revocation request for the selected
   * identities (no client-side fan-out); the server reports revoked, skipped,
   * and failed per item. */
  async function runBulkRevoke() {
    const ids = selectedRows.map((identity) => identity.id);
    if (ids.length === 0) return;
    setBulkBusy(true);
    setBulkError(null);
    setBulkResult(null);
    try {
      const result = await api.bulkRevokeIdentities({ identity_ids: ids, reason: bulkReason });
      setBulkResult(result);
      setSelectedIds(new Set());
      setBulkConfirmOpen(false);
      await load();
      await loadEvidence();
    } catch (err) {
      setBulkError(apiProblemMessage(err));
    } finally {
      setBulkBusy(false);
    }
  }

  async function runDecommission(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = decommissionTarget.trim();
    if (!value) {
      setError(`${t(decommissionInputLabelKey(decommissionType))} is required`);
      return;
    }
    const signal: NHIDecommissionRequest["signals"][number] =
      decommissionType === "vendor_term"
        ? { type: "vendor_term", vendor_name: value, evidence_refs: ["ui:identities/decommission"] }
        : decommissionType === "inactivity"
          ? { type: "inactivity", inactive_before: localDateTimeToISO(value), evidence_refs: ["ui:identities/decommission"] }
          : { type: "departure", subject: value, evidence_refs: ["ui:identities/decommission"] };
    setDecommissionBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await api.decommissionNHI({
        reason: decommissionReason.trim() || `${decommissionType} decommission via UI`,
        signals: [signal],
      });
      setDecommissionResult(result);
      await load();
      await loadEvidence();
      setNotice(`NHI decommission accepted: ${result.summary.revoked} revoked, ${result.summary.retired} retired, ${result.summary.skipped} skipped.`);
    } catch (err) {
      setError(`NHI decommission failed: ${apiProblemMessage(err)}`);
    } finally {
      setDecommissionBusy(false);
    }
  }

  const identityColumns = useMemo<Array<DataGridColumn<Identity>>>(
    () => [
      {
        id: "name",
        header: "Name",
        sortable: true,
        cell: (identity) => <span className="font-medium">{identity.name}</span>,
      },
      {
        id: "kind",
        header: "Kind",
        cell: (identity) => identity.kind ?? "unknown",
      },
      {
        id: "owner",
        header: "Owner",
        cell: (identity) => identity.owner_id || "—",
      },
      {
        id: "state",
        header: "State",
        cell: (identity) => <StatusBadge vocabulary="lifecycle" value={identityState(identity)} />,
      },
      {
        id: "delivery",
        header: "Delivery evidence",
        cell: (identity) => (
          <span className="text-muted-foreground">{deliveryEvidence(identity, latestDelivery.get(identity.id), latestRotation.get(identity.id))}</span>
        ),
      },
      {
        id: "actions",
        header: "Actions",
        cell: (identity) => {
          const state = identityState(identity);
          const actions = actionsFor(state);
          return (
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" variant="outline" onClick={() => openDetail(identity)}>
                View details
              </Button>
              {actions.map((a) => (
                <div key={a.to} className="space-y-1">
                  <Button
                    type="button"
                    size="sm"
                    variant={isDestructive(a.to) ? "outline" : "default"}
                    disabled={busyId === identity.id || Boolean(deniedTransitions[deniedKey(identity.id, a.to)])}
                    aria-describedby={deniedTransitions[deniedKey(identity.id, a.to)] ? `denied-${identity.id}-${a.to}` : undefined}
                    onClick={() => request(identity, a.to, a.label)}
                  >
                    {a.label}
                  </Button>
                  {deniedTransitions[deniedKey(identity.id, a.to)] && (
                    <p id={`denied-${identity.id}-${a.to}`} className="max-w-xs text-xs text-status-warning">
                      {deniedTransitions[deniedKey(identity.id, a.to)]}
                    </p>
                  )}
                </div>
              ))}
            </div>
          );
        },
      },
    ],
    [busyId, deniedTransitions, latestDelivery, latestRotation, openDetail, request],
  );

  return (
    <section aria-labelledby="identities-heading">
      <PageHeader
        titleId="identities-heading"
        title="Identities"
        description="The non-human identities trstctl manages — services, agents, and workloads — and their lifecycle: issue, deploy, renew, revoke, retire. Each can hold certificates (see Certificates) and secrets (see Secrets)."
        actions={
          <Button type="button" onClick={() => setShowForm((s) => !s)}>
            New identity
          </Button>
        }
      />

      <IssuancePipeline identities={items ?? []} />

      {showForm && (
        <NewIdentityForm
          onDone={() => {
            setShowForm(false);
            void load();
          }}
        />
      )}

      {notice && (
        <p role="status" className="mb-3 text-sm text-status-success">
          {notice}
        </p>
      )}

      {pending && (
        <Dialog
          open
          role="alertdialog"
          onClose={clearPending}
          titleId="confirm-title"
          descriptionId="confirm-desc"
          initialFocusRef={pendingConfirmRef}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-destructive/40 bg-card p-4 shadow-elevation2"
        >
          <h2 id="confirm-title" className="text-title font-semibold text-destructive">
            {pending.label} “{pending.name}”?
          </h2>
          <p id="confirm-desc" className="mt-1 text-sm text-destructive">
            {pending.to === "revoked"
              ? `Revoking “${pending.name}” permanently invalidates the credential; relying parties will stop trusting it. This cannot be undone.`
              : `Retiring “${pending.name}” discards the credential record. This cannot be undone.`}
          </p>
          <BlastRadiusImpactPanel state={pendingImpact} />
          <div className="mt-3 grid gap-3">
            <label className="block text-sm font-medium text-destructive" htmlFor="destructive-confirm-name">
              Type credential name to confirm
            </label>
            <input
              ref={pendingConfirmRef}
              id="destructive-confirm-name"
              value={pendingConfirmName}
              onChange={(e) => setPendingConfirmName(e.target.value)}
              className="rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
              placeholder={pending.name}
            />
            <label className="block text-sm font-medium text-destructive" htmlFor="destructive-reason">
              {pending.to === "revoked" ? "Revocation reason" : "Transition reason"}
            </label>
            <textarea
              id="destructive-reason"
              value={pendingReason}
              onChange={(e) => setPendingReason(e.target.value)}
              className="min-h-20 rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
              placeholder={pending.to === "revoked" ? "e.g. key compromise CAB-1234" : "e.g. record cleanup approved in CAB-1234"}
            />
          </div>
          <div className="mt-3 flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="destructive"
              disabled={busyId === pending.id || pendingConfirmName.trim() !== pending.name}
              onClick={() => {
                const p = pending;
                clearPending();
                void act(p.id, p.to, pendingReason);
              }}
            >
              {`Yes, ${pending.label.toLowerCase()}`}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={clearPending}>
              Cancel
            </Button>
          </div>
        </Dialog>
      )}

      {selectedRows.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-border bg-muted px-3 py-2 text-sm">
          <span className="font-medium">{selectedRows.length} selected</span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => {
              setBulkError(null);
              setBulkConfirmOpen(true);
            }}
          >
            Bulk revoke selected
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>
            Clear selection
          </Button>
        </div>
      )}

      {bulkConfirmOpen && (
        <Dialog
          open
          role="alertdialog"
          onClose={() => setBulkConfirmOpen(false)}
          titleId="bulk-revoke-title"
          descriptionId="bulk-revoke-desc"
          initialFocusRef={bulkConfirmRef}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-xl rounded-panel border border-destructive/40 bg-card p-4 text-sm shadow-elevation2"
        >
          <h2 id="bulk-revoke-title" className="text-title font-semibold text-destructive">
            Revoke {selectedRows.length} selected identities?
          </h2>
          <p id="bulk-revoke-desc" className="mt-1 text-destructive">
            This submits a single bulk revocation request for the {selectedRows.length} selected identities; the server reports revoked, skipped, and failed per
            item. Connector and downstream delivery still complete asynchronously through the outbox.
          </p>
          <label className="mt-3 grid gap-1 text-sm font-medium text-destructive" htmlFor="identity-bulk-revoke-reason">
            Revocation reason
            <select
              id="identity-bulk-revoke-reason"
              value={bulkReason}
              onChange={(event) => setBulkReason(event.target.value as BulkRevokeRequest["reason"])}
              className="min-h-9 rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm font-normal text-foreground"
            >
              {bulkRevokeReasons.map((reason) => (
                <option key={reason} value={reason}>
                  {reason}
                </option>
              ))}
            </select>
          </label>
          {bulkError && <p className="mt-3 text-sm font-medium text-risk-critical">{bulkError}</p>}
          <div className="mt-3 flex gap-2">
            <Button ref={bulkConfirmRef} type="button" size="sm" variant="destructive" loading={bulkBusy} onClick={() => void runBulkRevoke()}>
              Confirm bulk revoke
            </Button>
            <Button type="button" size="sm" variant="ghost" disabled={bulkBusy} onClick={() => setBulkConfirmOpen(false)}>
              Cancel
            </Button>
          </div>
        </Dialog>
      )}

      {bulkResult && (
        <div role="status" className="mb-3 rounded-md border border-border p-3 text-sm">
          <p className="font-medium">
            Revoked {bulkResult.total_revoked} of {bulkResult.total_matched} (skipped {bulkResult.total_skipped}, failed {bulkResult.total_failed})
          </p>
          {bulkResult.items.some((item) => item.status !== "revoked") && (
            <ul className="mt-2 space-y-1">
              {bulkResult.items
                .filter((item) => item.status !== "revoked")
                .map((item) => (
                  <li key={item.id}>
                    {(items ?? []).find((identity) => identity.id === item.id)?.name ?? item.id} {item.status}
                    {item.error ? `: ${item.error}` : ""}
                  </li>
                ))}
            </ul>
          )}
        </div>
      )}

      {!items && !error && <LoadingState>Loading identities...</LoadingState>}
      {error && <ErrorState title="Identity action failed">{error}</ErrorState>}

      {items && items.length === 0 && !showForm && (
        <EmptyState title="No identities yet" ctaTo="/wizard" ctaLabel="Set up your first certificate">
          Issue your first certificate to start tracking and rotating credentials.
        </EmptyState>
      )}

      {items && items.length > 0 && (
        <div id="manual-lifecycle-transitions" className="space-y-3">
          <label className="grid max-w-xs gap-1 text-sm font-medium" htmlFor="identity-kind-filter">
            Kind
            <select
              id="identity-kind-filter"
              value={kindFilter}
              onChange={(event) => setKindFilter(event.target.value as KindFilter)}
              className="rounded-md border border-border bg-background px-3 py-2"
            >
              <option value="all">All kinds</option>
              {identityKinds.map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </select>
          </label>
          <DataGrid
            ariaLabel="Credential identities and their lifecycle state"
            rows={filteredItems}
            columns={identityColumns}
            getRowId={(identity) => identity.id}
            selection={{
              selectedIds,
              onSelectedIdsChange: setSelectedIds,
              getRowLabel: (identity) => identity.name,
            }}
            state={filteredItems.length === 0 ? "empty" : "ready"}
            stateTitle="No identities match this kind"
            stateMessage="Choose another identity kind or clear the filter."
          />
        </div>
      )}

      <DeliveryEvidencePanel deliveries={deliveryReceipts} rotations={rotationRuns} error={evidenceError} />

      <section aria-labelledby="decommission-heading" className="mb-3 grid gap-3 rounded-md border border-border p-3">
        <div>
          <h2 id="decommission-heading" className="text-title font-semibold">
            {t("identities.decommission.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("identities.decommission.description")}</p>
        </div>
        <form
          aria-label={t("identities.decommission.ariaLabel")}
          className="grid gap-3 md:grid-cols-[minmax(10rem,12rem)_1fr_1fr_auto]"
          onSubmit={(event) => void runDecommission(event)}
        >
          <label className="grid gap-1 text-sm font-medium" htmlFor="nhi-decommission-type">
            {t("identities.decommission.signal")}
            <select
              id="nhi-decommission-type"
              className="ui-input"
              value={decommissionType}
              onChange={(event) => {
                setDecommissionType(event.target.value as DecommissionSignalType);
                setDecommissionTarget("");
                setDecommissionResult(null);
              }}
            >
              <option value="departure">{t("identities.decommission.departure")}</option>
              <option value="vendor_term">{t("identities.decommission.vendorTerm")}</option>
              <option value="inactivity">{t("identities.decommission.inactivity")}</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="nhi-decommission-target">
            {t(decommissionInputLabelKey(decommissionType))}
            <input
              id="nhi-decommission-target"
              className="ui-input"
              type={decommissionType === "inactivity" ? "datetime-local" : "text"}
              value={decommissionTarget}
              onChange={(event) => setDecommissionTarget(event.target.value)}
              placeholder={decommissionType === "vendor_term" ? "Acme SaaS" : decommissionType === "departure" ? "alice@example.com" : undefined}
              required
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="nhi-decommission-reason">
            Reason
            <input
              id="nhi-decommission-reason"
              className="ui-input"
              value={decommissionReason}
              onChange={(event) => setDecommissionReason(event.target.value)}
              placeholder={t("identities.decommission.reasonPlaceholder")}
            />
          </label>
          <div className="flex items-end">
            <Button type="submit" variant="destructive" className="w-full" loading={decommissionBusy}>
              {t("identities.decommission.submit")}
            </Button>
          </div>
        </form>

        {decommissionResult && (
          <div role="status" className="rounded-md border border-border p-3 text-sm">
            <p className="font-medium">
              CAP-GOV-04: matched {decommissionResult.summary.total_matched}; revoked {decommissionResult.summary.revoked}; retired{" "}
              {decommissionResult.summary.retired}; failed {decommissionResult.summary.failed}
            </p>
            <ul className="mt-2 space-y-1">
              {decommissionResult.items.slice(0, 5).map((item) => (
                <li key={item.identity_id}>
                  {item.name} {item.action} via {item.signal_type}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <DetailDrawer
        open={!!selectedId}
        title="Identity detail"
        description={detail ? `${detail.name} detail fields.` : "Identity detail."}
        onClose={() => setSelectedId(null)}
      >
        <IdentityDetailPanel
          identity={detail}
          loading={detailLoading}
          error={detailError}
          busy={busyId === selectedId}
          deniedTransitions={deniedTransitions}
          deliveryReceipt={selectedId ? latestDelivery.get(selectedId) : undefined}
          rotationRun={selectedId ? latestRotation.get(selectedId) : undefined}
          reason={selectedId ? (transitionReasons[selectedId] ?? "") : ""}
          onReasonChange={(value) => {
            if (!selectedId) return;
            setTransitionReasons((current) => ({ ...current, [selectedId]: value }));
          }}
          onTransition={(to, label) => {
            if (!detail) return;
            request(detail, to, label, transitionReasons[detail.id]);
          }}
        />
      </DetailDrawer>
    </section>
  );
}

function DeliveryEvidencePanel({
  deliveries,
  rotations,
  error,
}: {
  deliveries: ConnectorDelivery[] | null;
  rotations: RotationRun[] | null;
  error: string | null;
}) {
  const loading = !deliveries && !rotations && !error;
  const recentDeliveries = (deliveries ?? []).slice(0, 5);
  const recentRotations = (rotations ?? []).slice(0, 5);

  return (
    <section aria-labelledby="delivery-evidence-heading" className="mb-4 border-y border-border py-4">
      <div className="mb-3">
        <h2 id="delivery-evidence-heading" className="text-title font-semibold">
          Delivery and rotation evidence
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          The console reads projected connector delivery receipts and lifecycle rotation runs. These are audit-safe routing records: no certificate private key
          or secret value is returned.
        </p>
      </div>
      {loading && <LoadingState>Loading delivery evidence...</LoadingState>}
      {error && <ErrorState title="Delivery evidence failed to load">{error}</ErrorState>}
      {!loading && !error && recentDeliveries.length === 0 && recentRotations.length === 0 && (
        <EmptyState title="No delivery or rotation receipts yet">Issue, deploy, or renew an identity to produce outbox-backed evidence.</EmptyState>
      )}
      {(recentDeliveries.length > 0 || recentRotations.length > 0) && (
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="ui-panel overflow-x-auto">
            <table className="ui-table min-w-[42rem]">
              <caption className="sr-only">Recent connector delivery receipts</caption>
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Connector</th>
                  <th scope="col">Target</th>
                  <th scope="col">Fingerprint</th>
                  <th scope="col">Reason</th>
                </tr>
              </thead>
              <tbody>
                {recentDeliveries.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-muted-foreground">
                      No connector receipts.
                    </td>
                  </tr>
                ) : (
                  recentDeliveries.map((receipt) => (
                    <tr key={receipt.id} className="align-top">
                      <td className="font-mono text-xs">{receipt.status}</td>
                      <td>{receipt.connector}</td>
                      <td>{receipt.target}</td>
                      <td className="break-all font-mono text-xs">{shortFingerprint(receipt.fingerprint)}</td>
                      <td>{receipt.reason || receipt.detail || "-"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div className="ui-panel overflow-x-auto">
            <table className="ui-table min-w-[42rem]">
              <caption className="sr-only">Recent lifecycle rotation runs</caption>
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Trigger</th>
                  <th scope="col">Successor</th>
                  <th scope="col">Rollback</th>
                  <th scope="col">Completed</th>
                </tr>
              </thead>
              <tbody>
                {recentRotations.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-muted-foreground">
                      No rotation runs.
                    </td>
                  </tr>
                ) : (
                  recentRotations.map((run) => (
                    <tr key={run.id} className="align-top">
                      <td className="font-mono text-xs">{run.status}</td>
                      <td>{run.trigger}</td>
                      <td className="break-all font-mono text-xs">{shortFingerprint(run.successor_fingerprint)}</td>
                      <td>{run.rollback_ref || run.error || "-"}</td>
                      <td>{formatDate(run.completed_at || run.updated_at)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

function BlastRadiusImpactPanel({ state }: { state: BlastRadiusState }) {
  if (state.loading) {
    return (
      <div className="mt-3 rounded-control border border-destructive/30 bg-background/80 p-3 text-sm text-destructive">
        Loading blast-radius impact from graph...
      </div>
    );
  }

  if (state.error) {
    return <div className="mt-3 rounded-control border border-destructive/30 bg-background/80 p-3 text-sm text-destructive">{state.error}</div>;
  }

  if (!state.impact) return null;

  const affected = state.impact.affected.length;
  const byKind = Object.entries(state.impact.by_kind ?? {});
  return (
    <section
      aria-labelledby="destructive-blast-radius-heading"
      className="mt-3 rounded-control border border-destructive/30 bg-background/80 p-3 text-sm text-destructive"
    >
      <h3 id="destructive-blast-radius-heading" className="font-semibold">
        Blast-radius impact
      </h3>
      <p className="mt-1">
        Graph node <span className="font-mono text-xs">{state.nodeId}</span> reports {affected} downstream affected node{affected === 1 ? "" : "s"} before this
        destructive action.
      </p>
      {byKind.length > 0 && (
        <dl className="mt-2 grid gap-2 sm:grid-cols-2">
          {byKind.map(([kind, value]) => (
            <div key={kind} className="rounded-control border border-destructive/20 px-2 py-1">
              <dt className="font-medium">{kind}</dt>
              <dd>{displayValue(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}

function IdentityDetailPanel({
  identity,
  loading,
  error,
  busy,
  deniedTransitions,
  deliveryReceipt,
  rotationRun,
  reason,
  onReasonChange,
  onTransition,
}: {
  identity: Identity | null;
  loading: boolean;
  error: string | null;
  busy: boolean;
  deniedTransitions: Record<string, string>;
  deliveryReceipt?: ConnectorDelivery;
  rotationRun?: RotationRun;
  reason: string;
  onReasonChange: (value: string) => void;
  onTransition: (to: TransitionTo, label: string) => void;
}) {
  const state = identity ? identityState(identity) : "";
  const kind = identity?.kind ? kindCopy[identity.kind] : null;
  const terminal = terminalMessage(state);
  const rows = identity ? attributeRows(identity) : [];

  return (
    <section aria-labelledby="identity-detail-content-heading" className="text-sm">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase text-muted-foreground">Identity detail</p>
          <h2 id="identity-detail-content-heading" className="text-title font-semibold">
            Detail fields
          </h2>
        </div>
        {loading && <p role="status">Loading identity detail...</p>}
      </div>

      {error && (
        <p role="alert" className="mb-3 text-sm text-destructive">
          {error}
        </p>
      )}

      {identity && (
        <>
          <section aria-labelledby="identity-kind-heading" className="mb-4 rounded-md border border-border p-3">
            <h3 id="identity-kind-heading" className="font-semibold">
              {kind?.title ?? "Identity"}
            </h3>
            <p className="mt-1 text-muted-foreground">{kind?.description ?? "A non-human identity bound to this tenant."}</p>
            {terminal && <p className="mt-2 rounded-md bg-muted px-3 py-2 text-xs font-medium text-foreground">{terminal}</p>}
          </section>

          <dl className="grid gap-3 md:grid-cols-2">
            <div>
              <dt className="font-medium text-muted-foreground">Name</dt>
              <dd>{identity.name}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Status</dt>
              <dd>{state || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Kind</dt>
              <dd>{identity.kind}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Not after</dt>
              <dd>{formatDate(identity.not_after)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Not before</dt>
              <dd>{formatDate(identity.not_before)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Owner</dt>
              <dd>
                <a className="text-primary underline" href={`/owners?owner=${encodeURIComponent(identity.owner_id)}`}>
                  Owner {identity.owner_id}
                </a>
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Issuer</dt>
              <dd>
                {identity.issuer_id ? (
                  <a className="text-primary underline" href={`/protocols?issuer=${encodeURIComponent(identity.issuer_id)}`}>
                    Issuer {identity.issuer_id}
                  </a>
                ) : (
                  "No issuer bound"
                )}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Identity ID</dt>
              <dd className="break-all font-mono text-xs">{identity.id}</dd>
            </div>
          </dl>

          <section aria-labelledby="identity-attributes-heading" className="mt-4">
            <h3 id="identity-attributes-heading" className="font-semibold">
              Kind attributes
            </h3>
            {rows.length > 0 ? (
              <dl className="mt-2 grid gap-2 md:grid-cols-2">
                {rows.map(([key, value]) => (
                  <div key={key}>
                    <dt className="font-medium text-muted-foreground">{key}</dt>
                    <dd className="break-all font-mono text-xs">{value}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="mt-1 text-muted-foreground">No extra kind attributes were returned.</p>
            )}
          </section>

          <CredentialActivityTimeline credentialLabel={identity.name} deliveryReceipt={deliveryReceipt} rotationRun={rotationRun} />

          <section aria-labelledby="identity-lifecycle-heading" className="mt-5 border-t border-border pt-4">
            <h3 id="identity-lifecycle-heading" className="font-semibold">
              Lifecycle state machine
            </h3>
            <p className="mt-1 text-muted-foreground">Only valid next states are enabled. Disabled targets are not sent to the backend.</p>
            <label htmlFor="transition-reason" className="mt-3 block text-sm font-medium">
              Transition reason
            </label>
            <textarea
              id="transition-reason"
              value={reason}
              onChange={(e) => onReasonChange(e.target.value)}
              className="mt-1 min-h-20 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              placeholder="e.g. change approved in CAB-1234"
            />
            <div className="mt-3 flex flex-wrap gap-2">
              {lifecycleTargets.map((target) => {
                const action = actionForTarget(state, target);
                const denied = deniedTransitions[deniedKey(identity.id, target)];
                const disabled = busy || !action || Boolean(denied);
                const reasonId = `state-machine-${identity.id}-${target}-reason`;
                return (
                  <div key={target} className="max-w-xs space-y-1">
                    <Button
                      type="button"
                      size="sm"
                      variant={isDestructive(target) ? "outline" : "default"}
                      disabled={disabled}
                      aria-describedby={reasonId}
                      onClick={() => action && onTransition(target, action.label)}
                    >
                      Move to {target}
                    </Button>
                    <p id={reasonId} className="text-xs text-muted-foreground">
                      {denied || (action ? `Valid from ${state}.` : target === state ? "Already in this state." : `Invalid from ${state || "unknown"}.`)}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>
        </>
      )}
    </section>
  );
}

function NewIdentityForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [wildcardAck, setWildcardAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const serviceName = name.trim() || "new-service";
  const isWildcard = serviceName.startsWith("*.");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.issueCertificate({
        name: serviceName,
        ...(isWildcard ? { wildcardBlastRadiusAcknowledged: wildcardAck } : {}),
      });
      onDone();
    } catch (err) {
      setError(`Could not issue: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="mb-4 flex items-end gap-3 rounded-md border border-border p-4">
      <div className="flex-1 space-y-1">
        <label htmlFor="new-identity-name" className="block text-sm font-medium">
          Service name
        </label>
        <input
          id="new-identity-name"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            if (!e.target.value.trim().startsWith("*.")) setWildcardAck(false);
          }}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          placeholder="e.g. payments-api"
        />
        {isWildcard && (
          <label className="mt-2 flex items-start gap-2 text-sm font-medium" htmlFor="wildcard-ack">
            <input
              id="wildcard-ack"
              type="checkbox"
              checked={wildcardAck}
              onChange={(e) => setWildcardAck(e.target.checked)}
              className="mt-1 h-4 w-4 rounded border-border"
            />
            <span>
              Acknowledge wildcard blast radius
              <span className="block text-xs font-normal text-muted-foreground">DNS-01 validation is required; renewal uses the lifecycle scheduler.</span>
            </span>
          </label>
        )}
      </div>
      <Button type="submit" disabled={busy || (isWildcard && !wildcardAck)}>
        Issue
      </Button>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}
