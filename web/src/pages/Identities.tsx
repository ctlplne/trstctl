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
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

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
    title: translateNow("source.x.509.certificate.identity.ac455e032b"),
    description: translateNow("source.a.tls.or.mtls.identity.whose.lifecycle.is.d720dfba65"),
  },
  ssh_certificate: {
    title: translateNow("source.ssh.certificate.identity.d5833485f8"),
    description: translateNow("source.a.short.lived.ssh.host.or.user.certificate.17848c47a5"),
  },
  ssh_key: {
    title: translateNow("source.ssh.key.identity.b8252e7aa8"),
    description: translateNow("source.a.standing.ssh.key.identity.that.should.be.6e4dc64176"),
  },
  secret: {
    title: translateNow("source.secret.identity.62453fba82"),
    description: translateNow("source.a.password.shared.secret.or.opaque.credent.b98b0c5e45"),
  },
  api_key: {
    title: translateNow("source.api.key.identity.bc78809131"),
    description: translateNow("source.an.api.token.or.service.key.identity.where.8f7b48a2e6"),
  },
  workload_identity: {
    title: translateNow("source.workload.identity.ebfedeba5e"),
    description: translateNow("source.a.service.job.agent.or.workload.identity.t.dcc4188b56"),
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
      return [{ label: translateNow("source.issue.48dc76dfa2"), to: "issued" }];
    case "issued":
      return [
        { label: translateNow("source.deploy.4c236daafb"), to: "deployed" },
        { label: translateNow("source.revoke.87e6d00bbf"), to: "revoked" },
      ];
    case "deployed":
      return [
        { label: translateNow("source.renew.90c1689b0b"), to: "renewing" },
        { label: translateNow("source.revoke.87e6d00bbf"), to: "revoked" },
      ];
    case "renewing":
      return [{ label: translateNow("source.revoke.87e6d00bbf"), to: "revoked" }];
    case "revoked":
      return [{ label: translateNow("source.retire.da8597f3f2"), to: "retired" }];
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
                {translateNow("source.view.details.d1bf045bb5")}
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
        title={translateNow("source.identities.8d4d8fef65")}
        description="The non-human identities trstctl manages — services, agents, and workloads — and their lifecycle: issue, deploy, renew, revoke, retire. Each can hold certificates (see Certificates) and secrets (see Secrets)."
        actions={
          <Button type="button" onClick={() => setShowForm((s) => !s)}>
            {translateNow("source.new.identity.51c2e7c139")}
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
              : translateNow("source.retiring.value1.discards.the.credential.re.7f368527a3", { value1: pending.name })}
          </p>
          <BlastRadiusImpactPanel state={pendingImpact} />
          <div className="mt-3 grid gap-3">
            <label className="block text-sm font-medium text-destructive" htmlFor="destructive-confirm-name">
              {translateNow("source.type.credential.name.to.confirm.cc8d26a179")}
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
              {pending.to === "revoked" ? translateNow("source.revocation.reason.b11670420f") : translateNow("source.transition.reason.2b9e603491")}
            </label>
            <textarea
              id="destructive-reason"
              value={pendingReason}
              onChange={(e) => setPendingReason(e.target.value)}
              className="min-h-20 rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
              placeholder={
                pending.to === "revoked"
                  ? translateNow("source.e.g.key.compromise.cab.1234.ff97b4f9ff")
                  : translateNow("source.e.g.record.cleanup.approved.in.cab.1234.8cc38f337d")
              }
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
              {translateNow("source.yes.value1.0cb667502c", { value1: pending.label.toLowerCase() })}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={clearPending}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
          </div>
        </Dialog>
      )}

      {selectedRows.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-border bg-muted px-3 py-2 text-sm">
          <span className="font-medium">
            {selectedRows.length} {translateNow("source.selected.d7cbbb688b")}
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => {
              setBulkError(null);
              setBulkConfirmOpen(true);
            }}
          >
            {translateNow("source.bulk.revoke.selected.53f4891ce3")}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>
            {translateNow("source.clear.selection.cea4d2e010")}
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
            {translateNow("source.revoke.87e6d00bbf")} {selectedRows.length} {translateNow("source.selected.identities.a829228e71")}
          </h2>
          <p id="bulk-revoke-desc" className="mt-1 text-destructive">
            {translateNow("source.this.submits.a.single.bulk.revocation.requ.ab3df219e2")} {selectedRows.length} selected identities; the server reports
            revoked, skipped, and failed per item. Connector and downstream delivery still complete asynchronously through the outbox.
          </p>
          <label className="mt-3 grid gap-1 text-sm font-medium text-destructive" htmlFor="identity-bulk-revoke-reason">
            {translateNow("source.revocation.reason.b11670420f")}
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
              {translateNow("source.confirm.bulk.revoke.d613327838")}
            </Button>
            <Button type="button" size="sm" variant="ghost" disabled={bulkBusy} onClick={() => setBulkConfirmOpen(false)}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
          </div>
        </Dialog>
      )}

      {bulkResult && (
        <div role="status" className="mb-3 rounded-md border border-border p-3 text-sm">
          <p className="font-medium">
            {translateNow("source.revoked.f6f738d043")} {bulkResult.total_revoked} {translateNow("source.of.28391d3bc6")} {bulkResult.total_matched}{" "}
            {translateNow("source.skipped.22a5b0caf3")} {bulkResult.total_skipped}
            {translateNow("source.failed.ff18811f27")} {bulkResult.total_failed})
          </p>
          {bulkResult.items.some((item) => item.status !== "revoked") && (
            <ul className="mt-2 space-y-1">
              {bulkResult.items
                .filter((item) => item.status !== "revoked")
                .map((item) => (
                  <li key={item.id}>
                    {(items ?? []).find((identity) => identity.id === item.id)?.name ?? item.id} {item.status}
                    {item.error ? translateNow("source.value1.92dd63d2f3", { value1: item.error }) : ""}
                  </li>
                ))}
            </ul>
          )}
        </div>
      )}

      {!items && !error && <LoadingState>{translateNow("source.loading.identities.45d7e0b5b9")}</LoadingState>}
      {error && <ErrorState title={translateNow("source.identity.action.failed.5e3283fa66")}>{error}</ErrorState>}

      {items && items.length === 0 && !showForm && (
        <EmptyState title={translateNow("source.no.identities.yet.c8697bd1bc")} ctaTo="/wizard" ctaLabel="Set up your first certificate">
          {translateNow("source.issue.your.first.certificate.to.start.trac.355cebb739")}
        </EmptyState>
      )}

      {items && items.length > 0 && (
        <div id="manual-lifecycle-transitions" className="space-y-3">
          <label className="grid max-w-xs gap-1 text-sm font-medium" htmlFor="identity-kind-filter">
            {translateNow("source.kind.f5387f9bb6")}
            <select
              id="identity-kind-filter"
              value={kindFilter}
              onChange={(event) => setKindFilter(event.target.value as KindFilter)}
              className="rounded-md border border-border bg-background px-3 py-2"
            >
              <option value="all">{translateNow("source.all.kinds.ddd0c2108e")}</option>
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
              placeholder={
                decommissionType === "vendor_term"
                  ? translateNow("source.acme.saas.5d97e28912")
                  : decommissionType === "departure"
                    ? translateNow("source.alice.example.com.ff8d9819fc")
                    : undefined
              }
              required
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="nhi-decommission-reason">
            {translateNow("source.reason.f81ab834de")}
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
              {translateNow("source.cap.gov.04.matched.d376577cb5")} {decommissionResult.summary.total_matched}; revoked {decommissionResult.summary.revoked};
              retired {decommissionResult.summary.retired}; failed {decommissionResult.summary.failed}
            </p>
            <ul className="mt-2 space-y-1">
              {decommissionResult.items.slice(0, 5).map((item) => (
                <li key={item.identity_id}>
                  {item.name} {item.action} {translateNow("source.via.4d327af41f")} {item.signal_type}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <DetailDrawer
        open={!!selectedId}
        title={translateNow("source.identity.detail.f34a3c7053")}
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
          {translateNow("source.delivery.and.rotation.evidence.1fc4ef65bb")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.the.console.reads.projected.connector.deli.091ecd8115")}</p>
      </div>
      {loading && <LoadingState>{translateNow("source.loading.delivery.evidence.7f2cdadedd")}</LoadingState>}
      {error && <ErrorState title={translateNow("source.delivery.evidence.failed.to.load.2625e33346")}>{error}</ErrorState>}
      {!loading && !error && recentDeliveries.length === 0 && recentRotations.length === 0 && (
        <EmptyState title={translateNow("source.no.delivery.or.rotation.receipts.yet.21fb574bf8")}>
          {translateNow("source.issue.deploy.or.renew.an.identity.to.produ.722d26ac6c")}
        </EmptyState>
      )}
      {(recentDeliveries.length > 0 || recentRotations.length > 0) && (
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="ui-panel overflow-x-auto">
            <table className="ui-table min-w-[42rem]">
              <caption className="sr-only">{translateNow("source.recent.connector.delivery.receipts.3a2bf7db18")}</caption>
              <thead>
                <tr>
                  <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                  <th scope="col">{translateNow("source.connector.8f0d706fff")}</th>
                  <th scope="col">{translateNow("source.target.978354db0c")}</th>
                  <th scope="col">{translateNow("source.fingerprint.ba7af0b704")}</th>
                  <th scope="col">{translateNow("source.reason.f81ab834de")}</th>
                </tr>
              </thead>
              <tbody>
                {recentDeliveries.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-muted-foreground">
                      {translateNow("source.no.connector.receipts.86d1a1527d")}
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
              <caption className="sr-only">{translateNow("source.recent.lifecycle.rotation.runs.4de11752b6")}</caption>
              <thead>
                <tr>
                  <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                  <th scope="col">{translateNow("source.trigger.8b9c643731")}</th>
                  <th scope="col">{translateNow("source.successor.d29e68e27e")}</th>
                  <th scope="col">{translateNow("source.rollback.c591f55749")}</th>
                  <th scope="col">{translateNow("source.completed.22a970d2e5")}</th>
                </tr>
              </thead>
              <tbody>
                {recentRotations.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-muted-foreground">
                      {translateNow("source.no.rotation.runs.cf68af2637")}
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
        {translateNow("source.loading.blast.radius.impact.from.graph.771409e0df")}
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
        {translateNow("source.blast.radius.impact.42dfddadef")}
      </h3>
      <p className="mt-1">
        {translateNow("source.graph.node.8779202b33")} <span className="font-mono text-xs">{state.nodeId}</span> {translateNow("source.reports.7f26104f77")}{" "}
        {affected} {translateNow("source.downstream.affected.node.0dfbe99d70")}
        {affected === 1 ? "" : "s"} {translateNow("source.before.this.destructive.action.b4c45f22e1")}
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
          <p className="text-xs font-medium uppercase text-muted-foreground">{translateNow("source.identity.detail.f34a3c7053")}</p>
          <h2 id="identity-detail-content-heading" className="text-title font-semibold">
            {translateNow("source.detail.fields.6c69673d46")}
          </h2>
        </div>
        {loading && <p role="status">{translateNow("source.loading.identity.detail.0d1feafcee")}</p>}
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
              {kind?.title ?? translateNow("source.identity.999f23fcd7")}
            </h3>
            <p className="mt-1 text-muted-foreground">{kind?.description ?? translateNow("source.a.non.human.identity.bound.to.this.tenant.f58740df6d")}</p>
            {terminal && <p className="mt-2 rounded-md bg-muted px-3 py-2 text-xs font-medium text-foreground">{terminal}</p>}
          </section>

          <dl className="grid gap-3 md:grid-cols-2">
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.name.dcd1d5223f")}</dt>
              <dd>{identity.name}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.status.920e413c7d")}</dt>
              <dd>{state || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.kind.f5387f9bb6")}</dt>
              <dd>{identity.kind}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.not.after.577c1c7930")}</dt>
              <dd>{formatDate(identity.not_after)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.not.before.69bf0cd3a1")}</dt>
              <dd>{formatDate(identity.not_before)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.owner.4b1b8aa360")}</dt>
              <dd>
                <a className="text-primary underline" href={`/owners?owner=${encodeURIComponent(identity.owner_id)}`}>
                  {translateNow("source.owner.4b1b8aa360")} {identity.owner_id}
                </a>
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.issuer.39e02c46a0")}</dt>
              <dd>
                {identity.issuer_id ? (
                  <a className="text-primary underline" href={`/protocols?issuer=${encodeURIComponent(identity.issuer_id)}`}>
                    {translateNow("source.issuer.39e02c46a0")} {identity.issuer_id}
                  </a>
                ) : (
                  translateNow("source.no.issuer.bound.d1e424a34f")
                )}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.identity.id.2f8124d39c")}</dt>
              <dd className="break-all font-mono text-xs">{identity.id}</dd>
            </div>
          </dl>

          <section aria-labelledby="identity-attributes-heading" className="mt-4">
            <h3 id="identity-attributes-heading" className="font-semibold">
              {translateNow("source.kind.attributes.9505322c06")}
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
              <p className="mt-1 text-muted-foreground">{translateNow("source.no.extra.kind.attributes.were.returned.9f899e73ae")}</p>
            )}
          </section>

          <CredentialActivityTimeline credentialLabel={identity.name} deliveryReceipt={deliveryReceipt} rotationRun={rotationRun} />

          <section aria-labelledby="identity-lifecycle-heading" className="mt-5 border-t border-border pt-4">
            <h3 id="identity-lifecycle-heading" className="font-semibold">
              {translateNow("source.lifecycle.state.machine.4fd45925e4")}
            </h3>
            <p className="mt-1 text-muted-foreground">{translateNow("source.only.valid.next.states.are.enabled.disable.643c38f3f4")}</p>
            <label htmlFor="transition-reason" className="mt-3 block text-sm font-medium">
              {translateNow("source.transition.reason.2b9e603491")}
            </label>
            <textarea
              id="transition-reason"
              value={reason}
              onChange={(e) => onReasonChange(e.target.value)}
              className="mt-1 min-h-20 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              placeholder={translateNow("source.e.g.change.approved.in.cab.1234.6a0cc1f9e3")}
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
                      {translateNow("source.move.to.beb8194bc4")} {target}
                    </Button>
                    <p id={reasonId} className="text-xs text-muted-foreground">
                      {denied ||
                        (action
                          ? translateNow("source.valid.from.value1.ae82fe20dd", { value1: state })
                          : target === state
                            ? translateNow("source.already.in.this.state.f32a2089a5")
                            : translateNow("source.invalid.from.value1.26f942026d", { value1: state || "unknown" }))}
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
          {translateNow("source.service.name.1bb8870cc0")}
        </label>
        <input
          id="new-identity-name"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            if (!e.target.value.trim().startsWith("*.")) setWildcardAck(false);
          }}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          placeholder={translateNow("source.e.g.payments.api.b39781a2b3")}
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
              {translateNow("source.acknowledge.wildcard.blast.radius.868520eb71")}
              <span className="block text-xs font-normal text-muted-foreground">DNS-01 validation is required; renewal uses the lifecycle scheduler.</span>
            </span>
          </label>
        )}
      </div>
      <Button type="submit" disabled={busy || (isWildcard && !wildcardAck)}>
        {translateNow("source.issue.48dc76dfa2")}
      </Button>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}
