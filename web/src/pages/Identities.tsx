import { useCallback, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  api,
  ApiError,
  identityState,
  type BulkRevokeRequest,
  type BulkRevokeResult,
  type ConnectorDelivery,
  type GraphImpact,
  type Identity,
  type IdentityTransitionPreview,
  type NHIDecommissionRequest,
  type NHIDecommissionResponse,
  type Owner,
  type RotationRun,
  type TransitionTo,
} from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { apiProblemContext, apiProblemMessage } from "@/lib/apiProblem";
import { Dialog } from "@/components/Dialog";
import { IssuancePipeline } from "@/components/issuance";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DetailDrawer } from "@/components/DetailDrawer";
import { IdentityActivityEvidence } from "@/pages/identities/IdentityActivityEvidence";
import { IdentityIssuerEvidence } from "@/pages/identities/IdentityIssuerEvidence";
import { Button, buttonVariants } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { PageHeader } from "@/components/PageHeader";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { graphNodeIdForIdentity, revocationReasons } from "@/lib/revocation";
import { LifecycleAutomationPanel } from "@/pages/identities/LifecycleAutomationPanel";

export { graphNodeIdForIdentity } from "@/lib/revocation";

/** action is a lifecycle transition offered for a given state. `to` is bound to the
 * OpenAPI-generated transition enum (TransitionTo), so the UI can never offer (or send)
 * a target the backend contract does not accept — drift here fails the build. */
interface Action {
  label: string;
  to: TransitionTo;
}

const lifecycleTargets: TransitionTo[] = ["issued", "deployed", "renewing", "revoked", "retired"];
const identityKinds = ["x509_certificate", "ssh_certificate", "ssh_key", "secret", "api_key", "workload_identity"] as const satisfies Identity["kind"][];
type KindFilter = "all" | Identity["kind"];
type DecommissionSignalType = NHIDecommissionRequest["signals"][number]["type"];
type BlastRadiusState = {
  error: string | null;
  impact: GraphImpact | null;
  loading: boolean;
  nodeId: string | null;
};

type PendingTransition = {
  id: string;
  name: string;
  to: TransitionTo;
  label: string;
  reason: string;
  destructive: boolean;
};

type TransitionPreviewState = {
  key: string;
  plan: IdentityTransitionPreview | null;
  loading: boolean;
  error: string | null;
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

function identityKindLabel(kind?: Identity["kind"]): string {
  switch (kind) {
    case "x509_certificate":
      return translateNow("identities.kind.x509");
    case "ssh_certificate":
      return translateNow("identities.kind.sshCertificate");
    case "ssh_key":
      return translateNow("identities.kind.sshKey");
    case "secret":
      return translateNow("identities.kind.secret");
    case "api_key":
      return translateNow("identities.kind.apiKey");
    case "workload_identity":
      return translateNow("identities.kind.workload");
    default:
      return translateNow("identities.kind.unknown");
  }
}

function titleCaseMachineValue(value?: string): string | null {
  const normalized = value?.trim().replace(/[_-]+/g, " ");
  if (!normalized) return null;
  return normalized.replace(/\b\w/g, (character) => character.toUpperCase());
}

function ownerLabel(owner?: Owner): string {
  return owner?.name?.trim() || translateNow("identities.owner.unavailable");
}

function ownerEnvironment(owner?: Owner): string | null {
  return titleCaseMachineValue(owner?.environment);
}

/** Revocation and retirement both require review and exact-name confirmation.
 * Publication, client enforcement, and retained history remain separate evidence. */
function isDestructive(to: TransitionTo): boolean {
  return to === "revoked" || to === "retired";
}

/** errorMessage renders an action error, special-casing a 429 so the user sees a
 * concrete retry hint (Retry-After) instead of a bare failure (SURFACE-007). */
function errorMessage(err: unknown): string {
  if (err instanceof ApiError && err.isRateLimited) {
    return err.retryAfterSeconds != null ? `Rate limited — please retry in ${err.retryAfterSeconds}s.` : "Rate limited — please retry shortly.";
  }
  return apiProblemContext(err, "Action failed");
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
    case "renewal_failed":
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
    return translateNow("identities.lifecycle.revokedState");
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

function deliverySummary(identity: Identity, delivery?: ConnectorDelivery, rotation?: RotationRun): string {
  const state = identityState(identity);
  if (rotation?.status === "running") return translateNow("identities.delivery.rotating");
  if (rotation?.status === "failed") return translateNow("identities.delivery.rotationFailed");
  if (rotation?.status === "succeeded" && !delivery) return translateNow("identities.delivery.rotationSucceeded");
  if (delivery?.status === "delivered") return translateNow("identities.delivery.delivered");
  if (delivery?.status === "failed" && delivery.reason === "plugin_surface_unconfigured") {
    return translateNow("identities.delivery.connectorSetup");
  }
  if (delivery?.status === "failed") return translateNow("identities.delivery.failed");
  if (delivery) return translateNow("identities.delivery.waiting");
  switch (state) {
    case "requested":
      return translateNow("identities.delivery.awaitingIssue");
    case "issued":
      return translateNow("identities.delivery.readyToDeploy");
    case "deployed":
      return translateNow("identities.delivery.noReceipt");
    case "renewing":
      return translateNow("identities.delivery.rotating");
    case "revoked":
      return translateNow("identities.delivery.revoked");
    case "retired":
      return translateNow("identities.delivery.retired");
    default:
      return translateNow("identities.delivery.noReceipt");
  }
}

function connectorReasonSummary(reason?: string, detail?: string): string {
  if (reason === "plugin_surface_unconfigured") return translateNow("identities.delivery.connectorSetupShort");
  return titleCaseMachineValue(reason || detail) || translateNow("identities.delivery.noReason");
}

function transitionNotice(to: TransitionTo): string {
  return `${to} request accepted. Idempotency-Key protects retried submissions from duplicate execution; downstream outbox delivery receipts update asynchronously.`;
}

function deniedKey(id: string, to: TransitionTo): string {
  return `${id}:${to}`;
}

function transitionPreviewKey(id: string, to: TransitionTo, reason: string): string {
  return JSON.stringify([id, to, reason.trim()]);
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

function attributeRows(identity: Identity): Array<[string, string]> {
  return Object.entries(identity.attributes ?? {})
    .slice(0, 8)
    .map(([key, value]) => [key, displayValue(value)]);
}

export function Identities() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [actionError, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [deniedTransitions, setDeniedTransitions] = useState<Record<string, string>>({});
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get("identity");
  const setSelectedId = useCallback(
    (id: string | null) => {
      setSearchParams((current) => {
        const next = new URLSearchParams(current);
        if (id) next.set("identity", id);
        else next.delete("identity");
        return next;
      });
    },
    [setSearchParams],
  );
  // Acceptance and outbox completion are different moments. Keep the inventory,
  // open drawer and projected receipts live, using the shared visible-tab gate.
  const inventory = useApiQuery(["identities"], api.identities, { live: { intervalMs: 10_000 } });
  const ownerQuery = useApiQuery(["owners"], api.owners);
  const deliveries = useApiQuery(["connector-deliveries", { limit: 50 }], () => api.connectorDeliveries({ limit: 50 }), {
    live: { intervalMs: 10_000 },
  });
  const rotations = useApiQuery(["rotation-runs", { limit: 50 }], () => api.rotationRuns({ limit: 50 }), { live: { intervalMs: 10_000 } });
  const identityDetail = useApiQuery(["identity", selectedId], () => api.getIdentity(selectedId!), {
    enabled: selectedId !== null,
    live: { intervalMs: 10_000 },
  });
  const items = inventory.data;
  const owners = ownerQuery.data;
  const error = actionError ?? inventory.error;
  const deliveryReceipts = deliveries.data?.items ?? null;
  const rotationRuns = rotations.data?.items ?? null;
  const evidenceError = deliveries.error ?? rotations.error;
  const evidencePartial = Boolean(deliveries.data?.next_cursor || rotations.data?.next_cursor);
  const evidenceNotice = evidenceError
    ? translateNow("source.delivery.evidence.failed.to.load.2625e33346")
    : !deliveries.data || !rotations.data
      ? translateNow("source.loading.delivery.evidence.7f2cdadedd")
      : evidencePartial
        ? translateNow("identities.evidence.partialSummary")
        : null;
  const detail = identityDetail.data ?? items?.find((identity) => identity.id === selectedId) ?? null;
  const detailLoading = identityDetail.loading && selectedId !== null;
  const detailError = identityDetail.errorValue ? apiProblemContext(identityDetail.errorValue, "Could not load identity detail") : null;
  const [transitionReasons, setTransitionReasons] = useState<Record<string, string>>({});
  const [showForm, setShowForm] = useState(false);
  // A destructive transition awaiting explicit confirmation (SURFACE-007). null
  // means no confirmation is pending.
  const [pending, setPending] = useState<PendingTransition | null>(null);
  const [pendingConfirmName, setPendingConfirmName] = useState("");
  const [pendingReason, setPendingReason] = useState("");
  const [transitionPreview, setTransitionPreview] = useState<TransitionPreviewState>({ key: "", plan: null, loading: false, error: null });
  const [query, setQuery] = useState("");
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
  const pendingReturnFocusRef = useRef<HTMLButtonElement | null>(null);
  const bulkConfirmRef = useRef<HTMLButtonElement>(null);
  const impactRequestRef = useRef(0);
  const ownerByID = useMemo(() => new Map((owners ?? []).map((owner) => [owner.id, owner])), [owners]);
  const filteredItems = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase();
    return (items ?? []).filter((identity) => {
      if (kindFilter !== "all" && identity.kind !== kindFilter) return false;
      if (!normalizedQuery) return true;
      const owner = ownerByID.get(identity.owner_id);
      return [identity.name, identity.id, identity.kind, identityKindLabel(identity.kind), identityState(identity), owner?.name, owner?.environment].some(
        (value) => value?.toLocaleLowerCase().includes(normalizedQuery),
      );
    });
  }, [items, kindFilter, ownerByID, query]);
  const selectedRows = useMemo(() => filteredItems.filter((identity) => selectedIds.has(identity.id)), [filteredItems, selectedIds]);
  const latestDelivery = useMemo(() => latestDeliveryByIdentity(deliveryReceipts), [deliveryReceipts]);
  const latestRotation = useMemo(() => latestRotationByIdentity(rotationRuns), [rotationRuns]);

  const load = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["identities"] }),
      queryClient.invalidateQueries({ queryKey: ["owners"] }),
      queryClient.invalidateQueries({ queryKey: ["identity"] }),
    ]);
  }, [queryClient]);

  const loadEvidence = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["connector-deliveries"] }),
      queryClient.invalidateQueries({ queryKey: ["rotation-runs"] }),
      queryClient.invalidateQueries({ queryKey: ["lifecycle-automation-plan"] }),
    ]);
  }, [queryClient]);

  const acceptIdentity = useCallback(
    async (identity: Identity) => {
      // Discard reads started before this actual mutation response, then publish
      // the returned state. The subsequent invalidation and live reads obtain the
      // asynchronous outcome; the browser never invents a completed transition.
      await Promise.all([queryClient.cancelQueries({ queryKey: ["identities"] }), queryClient.cancelQueries({ queryKey: ["identity", identity.id] })]);
      queryClient.setQueryData<Identity[]>(["identities"], (current) =>
        current?.some((item) => item.id === identity.id) ? current.map((item) => (item.id === identity.id ? identity : item)) : [...(current ?? []), identity],
      );
      queryClient.setQueryData(["identity", identity.id], identity);
    },
    [queryClient],
  );

  const openDetail = useCallback(
    (identity: Identity) => {
      setSelectedId(identity.id);
      // Opening a recently cached identity also asks the server for its current
      // state. A late response for a previously selected ID stays in its own key.
      void queryClient.invalidateQueries({ queryKey: ["identity", identity.id] });
    },
    [queryClient, setSelectedId],
  );

  const act = useCallback(
    async (id: string, to: TransitionTo, reason?: string, expectedVersion?: number, identityName?: string): Promise<boolean> => {
      setBusyId(id);
      setError(null);
      setNotice(null);
      try {
        const updated = await api.transitionIdentity(id, to, reason?.trim() || `${to} via UI`, undefined, undefined, expectedVersion);
        if (identityState(updated) !== to) {
          throw new Error(
            translateNow("identities.lifecycle.verificationFailed", {
              actual: identityState(updated) || "unknown",
              expected: to,
            }),
          );
        }
        await acceptIdentity(updated);
        await load();
        await loadEvidence();
        setNotice(
          translateNow("identities.lifecycle.verified", {
            identity: identityName || updated.name || id,
            state: to,
            detail: transitionNotice(to),
          }),
        );
        setDeniedTransitions((current) => {
          const next = { ...current };
          delete next[deniedKey(id, to)];
          return next;
        });
        return true;
      } catch (err) {
        if (err instanceof ApiError && err.status === 403) {
          setDeniedTransitions((current) => ({ ...current, [deniedKey(id, to)]: apiProblemMessage(err, "Transition denied") }));
        }
        setError(errorMessage(err));
        return false;
      } finally {
        setBusyId(null);
      }
    },
    [acceptIdentity, load, loadEvidence],
  );

  /** request runs a transition immediately, EXCEPT a destructive one (revoke/retire)
   * which is first parked in `pending` so the user must confirm it in a dialog that
   * names the credential (SURFACE-007). */
  function clearPending() {
    const returnTarget = pendingReturnFocusRef.current;
    impactRequestRef.current += 1;
    setPending(null);
    setPendingConfirmName("");
    setPendingReason("");
    setTransitionPreview({ key: "", plan: null, loading: false, error: null });
    setPendingImpact(emptyBlastRadiusState);
    if (returnTarget) {
      requestAnimationFrame(() => {
        if (document.contains(returnTarget)) returnTarget.focus();
      });
    }
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
            error: apiProblemContext(err, "Blast-radius impact unavailable"),
          });
        }
      });
  }, []);

  const reviewTransition = useCallback(async (transition: PendingTransition, reason: string) => {
    const key = transitionPreviewKey(transition.id, transition.to, reason);
    setTransitionPreview({ key, plan: null, loading: true, error: null });
    try {
      const plan = await api.previewIdentityTransition(transition.id, transition.to, reason.trim() || `${transition.to} via UI`);
      setTransitionPreview({ key, plan, loading: false, error: null });
    } catch (err) {
      setTransitionPreview({
        key,
        plan: null,
        loading: false,
        error: apiProblemContext(err, translateNow("identities.lifecycle.previewFailed")),
      });
    }
  }, []);

  const request = useCallback(
    (identity: Identity, to: TransitionTo, label: string, reason?: string) => {
      const destructive = isDestructive(to);
      const requestedReason = reason?.trim() || "";
      const reviewedReason =
        to === "revoked"
          ? revocationReasons.includes(requestedReason as BulkRevokeRequest["reason"])
            ? requestedReason
            : "unspecified"
          : requestedReason || (to === "retired" ? "operator requested retirement" : `${to} via UI`);
      const transition: PendingTransition = { id: identity.id, name: identity.name, to, label, reason: reviewedReason, destructive };
      // LifecycleAutomationPanel can start this review without the identity
      // drawer already being open. The reviewed-action dialog is intentionally
      // owned by that drawer, so bind the exact row before setting `pending`;
      // otherwise the button looks enabled but renders no review surface.
      setSelectedId(identity.id);
      setPendingConfirmName("");
      setPendingReason(reviewedReason);
      setPending(transition);
      setPendingImpact(emptyBlastRadiusState);
      void reviewTransition(transition, reviewedReason);
      if (destructive) {
        loadBlastRadius(identity);
      }
    },
    [loadBlastRadius, reviewTransition, setSelectedId],
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
      setBulkError(apiProblemMessage(err, "Bulk revoke failed"));
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
      setError(apiProblemContext(err, "NHI decommission failed"));
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
        cell: (identity) => (
          <span className="grid gap-0.5">
            <span className="font-medium">{identity.name}</span>
            <span className="text-xs text-muted-foreground">{identityKindLabel(identity.kind)}</span>
          </span>
        ),
      },
      {
        id: "owner",
        header: "Owner",
        cell: (identity) => {
          const owner = ownerByID.get(identity.owner_id);
          const environment = ownerEnvironment(owner);
          return (
            <span className="grid gap-0.5">
              <span className="font-medium">{identity.owner_id ? ownerLabel(owner) : translateNow("identities.owner.unassigned")}</span>
              {environment && <span className="text-xs text-muted-foreground">{environment}</span>}
            </span>
          );
        },
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
          <span className="text-muted-foreground">
            {evidenceNotice ?? deliverySummary(identity, latestDelivery.get(identity.id), latestRotation.get(identity.id))}
          </span>
        ),
      },
      {
        id: "actions",
        header: "Actions",
        cell: (identity) => (
          <Button type="button" size="sm" variant="outline" onClick={() => openDetail(identity)}>
            {translateNow("source.view.details.d1bf045bb5")}
          </Button>
        ),
      },
    ],
    [evidenceNotice, latestDelivery, latestRotation, openDetail, ownerByID],
  );

  return (
    <section aria-labelledby="identities-heading">
      <PageHeader
        titleId="identities-heading"
        title={t("identities.page.title")}
        description={t("identities.page.answer")}
        technicalDetails={t("identities.page.details")}
        actions={
          <>
            <a className={buttonVariants()} href="#identity-search">
              {t("identities.find.action")}
            </a>
            <Button type="button" variant="outline" onClick={() => setShowForm((visible) => !visible)}>
              {t("identities.add.action")}
            </Button>
          </>
        }
      />

      <IssuancePipeline identities={items ?? []} />

      <LifecycleAutomationPanel identities={items ?? []} onReviewRenewal={(identity, label, reason) => request(identity, "renewing", label, reason)} />

      {showForm && (
        <NewIdentityForm
          owners={owners ?? []}
          onDone={async (issued) => {
            await acceptIdentity(issued);
            setShowForm(false);
            setSelectedId(issued.id);
            setNotice(issued.name.startsWith("*.") ? `${t("identities.wildcard.issued", { name: issued.name })} ${t("identities.wildcard.issuedNext")}` : null);
            void load();
            void loadEvidence();
          }}
        />
      )}

      {notice && (
        <p role="status" className="mb-3 text-sm text-status-success">
          {notice}
        </p>
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
              {revocationReasons.map((reason) => (
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
          <DataGrid
            ariaLabel="Credential identities and their lifecycle state"
            rows={filteredItems}
            columns={identityColumns}
            getRowId={(identity) => identity.id}
            toolbar={
              <div id="identity-search" className="grid w-full gap-3 sm:grid-cols-[minmax(14rem,1fr)_minmax(11rem,14rem)] sm:items-end">
                <label className="grid gap-1 text-sm font-medium" htmlFor="identity-search-input">
                  {t("identities.search.label")}
                  <input
                    id="identity-search-input"
                    type="search"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    className="ui-input"
                    placeholder={t("identities.search.placeholder")}
                  />
                </label>
                <label className="grid gap-1 text-sm font-medium" htmlFor="identity-kind-filter">
                  {t("identities.filter.type")}
                  <select
                    id="identity-kind-filter"
                    value={kindFilter}
                    onChange={(event) => setKindFilter(event.target.value as KindFilter)}
                    className="ui-input"
                  >
                    <option value="all">{t("identities.filter.allTypes")}</option>
                    {identityKinds.map((kind) => (
                      <option key={kind} value={kind}>
                        {identityKindLabel(kind)}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            }
            selection={{
              selectedIds,
              onSelectedIdsChange: setSelectedIds,
              getRowLabel: (identity) => identity.name,
            }}
            state={filteredItems.length === 0 ? "empty" : "ready"}
            stateTitle={t("identities.search.emptyTitle")}
            stateMessage={t("identities.search.emptyBody")}
          />
        </div>
      )}

      <details className="group mb-4 border-y border-border py-4">
        <summary className="cursor-pointer list-none font-medium text-foreground marker:hidden">
          {t("identities.evidence.open")}
          <span className="ms-2 text-xs font-normal text-muted-foreground group-open:hidden">{t("identities.evidence.openHint")}</span>
          <span className="ms-2 hidden text-xs font-normal text-muted-foreground group-open:inline">{t("identities.evidence.closeHint")}</span>
        </summary>
        <DeliveryEvidencePanel
          identities={items ?? []}
          deliveries={deliveryReceipts}
          rotations={rotationRuns}
          error={evidenceError}
          partial={evidencePartial}
          notice={evidenceNotice}
        />
      </details>

      <section aria-labelledby="decommission-heading" className="mb-3 border-y border-border py-4">
        <div>
          <h2 id="decommission-heading" className="text-title font-semibold">
            {t("identities.decommission.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("identities.decommission.description")}</p>
        </div>
        <details className="group mt-3">
          <summary className="cursor-pointer list-none font-medium text-brand-accent marker:hidden">
            {t("identities.decommission.open")}
            <span aria-hidden="true" className="ms-2 text-muted-foreground group-open:hidden">
              +
            </span>
            <span aria-hidden="true" className="ms-2 hidden text-muted-foreground group-open:inline">
              −
            </span>
          </summary>
          <form
            aria-label={t("identities.decommission.ariaLabel")}
            className="mt-3 grid gap-3 md:grid-cols-[minmax(10rem,12rem)_1fr_1fr_auto]"
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
            <div role="status" className="mt-3 border-s-2 border-status-success ps-3 text-sm">
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
        </details>
      </section>

      <DetailDrawer
        open={!!selectedId}
        title={translateNow("source.identity.detail.f34a3c7053")}
        description={detail ? `${detail.name} detail fields.` : "Identity detail."}
        onClose={() => setSelectedId(null)}
      >
        <IdentityDetailPanel
          identity={detail}
          owner={detail ? ownerByID.get(detail.owner_id) : undefined}
          loading={detailLoading}
          error={detailError}
          busy={busyId === selectedId}
          deniedTransitions={deniedTransitions}
          reason={selectedId ? (transitionReasons[selectedId] ?? "") : ""}
          onReasonChange={(value) => {
            if (!selectedId) return;
            setTransitionReasons((current) => ({ ...current, [selectedId]: value }));
          }}
          onTransition={(to, label, returnFocus) => {
            if (!detail) return;
            pendingReturnFocusRef.current = returnFocus ?? null;
            request(detail, to, label, transitionReasons[detail.id]);
          }}
        />
        {pending && (
          <Dialog
            open
            role={pending.destructive ? "alertdialog" : "dialog"}
            onClose={clearPending}
            titleId="confirm-title"
            descriptionId="confirm-desc"
            initialFocusRef={pending.destructive ? pendingConfirmRef : undefined}
            returnFocusRef={pendingReturnFocusRef}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            overlayClassName="absolute inset-0 bg-black/55"
            panelClassName={`relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border bg-card p-4 shadow-elevation2 ${pending.destructive ? "border-destructive/40" : "border-border"}`}
          >
            <h2 id="confirm-title" className={`text-title font-semibold ${pending.destructive ? "text-destructive" : "text-foreground"}`}>
              {translateNow("identities.lifecycle.reviewTitle", { action: pending.label, identity: pending.name })}
            </h2>
            <p id="confirm-desc" className={`mt-1 text-sm ${pending.destructive ? "text-destructive" : "text-muted-foreground"}`}>
              {pending.to === "revoked"
                ? translateNow("identities.lifecycle.revokeReview", { identity: pending.name })
                : pending.to === "retired"
                  ? translateNow("source.retiring.value1.discards.the.credential.re.7f368527a3", { value1: pending.name })
                  : translateNow("identities.lifecycle.reviewIntro")}
            </p>

            {transitionPreview.loading && (
              <p role="status" className="mt-4 text-sm text-muted-foreground">
                {translateNow("identities.lifecycle.reviewLoading")}
              </p>
            )}
            {transitionPreview.error && (
              <div role="alert" className="mt-4 rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                <p>{transitionPreview.error}</p>
                <Button type="button" size="sm" variant="outline" className="mt-2" onClick={() => void reviewTransition(pending, pendingReason)}>
                  {translateNow("identities.lifecycle.reviewRetry")}
                </Button>
              </div>
            )}
            {transitionPreview.plan && (
              <section aria-labelledby="lifecycle-preview-heading" className="mt-4 grid gap-4 rounded-panel border border-border bg-muted/20 p-4 text-sm">
                <div>
                  <p className="text-caption font-semibold text-status-success">{translateNow("identities.lifecycle.reviewNoChanges")}</p>
                  <h3 id="lifecycle-preview-heading" className="mt-1 font-semibold">
                    {transitionPreview.plan.from} → {transitionPreview.plan.to}
                  </h3>
                  <p className="mt-1 text-muted-foreground">{transitionPreview.plan.guidance}</p>
                </div>
                <dl className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <dt className="text-caption text-muted-foreground">{translateNow("identities.lifecycle.reviewOwner")}</dt>
                    <dd className="font-medium">{transitionPreview.plan.owner_name || transitionPreview.plan.owner_id}</dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">{translateNow("identities.lifecycle.reviewEffect")}</dt>
                    <dd className="font-medium">{transitionPreview.plan.side_effect_destination || translateNow("identities.lifecycle.reviewNoEffect")}</dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">{translateNow("identities.lifecycle.reviewVersion")}</dt>
                    <dd className="font-medium">{transitionPreview.plan.expected_version}</dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">{translateNow("identities.lifecycle.reviewPermission")}</dt>
                    <dd className="font-medium">{transitionPreview.plan.required_permission}</dd>
                  </div>
                </dl>
                <div className="grid gap-4 md:grid-cols-3">
                  <div>
                    <h4 className="font-semibold">{translateNow("identities.lifecycle.reviewBefore")}</h4>
                    <ul className="mt-1 list-disc space-y-1 ps-5 text-muted-foreground">
                      {transitionPreview.plan.prerequisites.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4 className="font-semibold">{translateNow("identities.lifecycle.reviewWrites")}</h4>
                    <ul className="mt-1 list-disc space-y-1 ps-5 text-muted-foreground">
                      {transitionPreview.plan.execution_writes.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                      {transitionPreview.plan.execution_external_effects.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4 className="font-semibold">{translateNow("identities.lifecycle.reviewProof")}</h4>
                    <ul className="mt-1 list-disc space-y-1 ps-5 text-muted-foreground">
                      {transitionPreview.plan.verification_steps.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                {(transitionPreview.plan.warnings ?? []).length > 0 && (
                  <ul className="list-disc space-y-1 rounded-control border border-status-warning/30 bg-status-warning/5 p-3 ps-8 text-status-warning">
                    {(transitionPreview.plan.warnings ?? []).map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                )}
              </section>
            )}

            {pending.destructive && (
              <>
                <BlastRadiusImpactPanel state={pendingImpact} />
                <div className="mt-3 grid gap-3">
                  <label className="block text-sm font-medium text-destructive" htmlFor="destructive-confirm-name">
                    {translateNow("source.type.credential.name.to.confirm.cc8d26a179")}
                  </label>
                  <input
                    ref={pendingConfirmRef}
                    id="destructive-confirm-name"
                    value={pendingConfirmName}
                    onChange={(event) => setPendingConfirmName(event.target.value)}
                    className="rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
                    placeholder={pending.name}
                  />
                  <label className="block text-sm font-medium text-destructive" htmlFor="destructive-reason">
                    {pending.to === "revoked" ? translateNow("source.revocation.reason.b11670420f") : translateNow("source.transition.reason.2b9e603491")}
                  </label>
                  {pending.to === "revoked" ? (
                    <select
                      id="destructive-reason"
                      value={pendingReason}
                      onChange={(event) => setPendingReason(event.target.value)}
                      className="rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
                    >
                      {revocationReasons.map((reason) => (
                        <option key={reason} value={reason}>
                          {reason}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <textarea
                      id="destructive-reason"
                      value={pendingReason}
                      onChange={(event) => setPendingReason(event.target.value)}
                      className="min-h-20 rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
                      placeholder={translateNow("source.e.g.record.cleanup.approved.in.cab.1234.8cc38f337d")}
                    />
                  )}
                </div>
              </>
            )}

            {transitionPreview.plan && transitionPreview.key !== transitionPreviewKey(pending.id, pending.to, pendingReason) && (
              <p role="status" className="mt-3 text-sm text-status-warning">
                {translateNow("identities.lifecycle.reviewChanged")}
              </p>
            )}
            <div className="mt-3 flex gap-2">
              <Button
                type="button"
                size="sm"
                variant={pending.destructive ? "destructive" : "default"}
                disabled={
                  busyId === pending.id ||
                  !transitionPreview.plan?.ready ||
                  transitionPreview.key !== transitionPreviewKey(pending.id, pending.to, pendingReason) ||
                  (pending.destructive && pendingConfirmName.trim() !== pending.name)
                }
                onClick={() => {
                  const transition = pending;
                  const expectedVersion = transitionPreview.plan?.expected_version;
                  void act(transition.id, transition.to, pendingReason, expectedVersion, transition.name).then((succeeded) => {
                    if (succeeded) clearPending();
                  });
                }}
              >
                {pending.destructive
                  ? translateNow("source.yes.value1.0cb667502c", { value1: pending.label.toLowerCase() })
                  : translateNow("identities.lifecycle.reviewRun")}
              </Button>
              {transitionPreview.key !== transitionPreviewKey(pending.id, pending.to, pendingReason) && (
                <Button type="button" size="sm" variant="outline" onClick={() => void reviewTransition(pending, pendingReason)}>
                  {translateNow("identities.lifecycle.reviewUpdated")}
                </Button>
              )}
              <Button type="button" size="sm" variant="ghost" onClick={clearPending}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
            </div>
          </Dialog>
        )}
      </DetailDrawer>
    </section>
  );
}

function DeliveryEvidencePanel({
  identities,
  deliveries,
  rotations,
  error,
  partial,
  notice,
}: {
  identities: Identity[];
  deliveries: ConnectorDelivery[] | null;
  rotations: RotationRun[] | null;
  error: string | null;
  partial: boolean;
  notice: string | null;
}) {
  const loading = (!deliveries || !rotations) && !error;
  const loadedDeliveries = (deliveries ?? []).slice(0, 5);
  const loadedRotations = (rotations ?? []).slice(0, 5);
  const identityByID = new Map(identities.map((identity) => [identity.id, identity]));

  return (
    <section aria-labelledby="delivery-evidence-heading" className="pt-4">
      <div className="mb-3 max-w-3xl">
        <h2 id="delivery-evidence-heading" className="text-title font-semibold">
          {translateNow("source.delivery.and.rotation.evidence.1fc4ef65bb")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.the.console.reads.projected.connector.deli.091ecd8115")}</p>
      </div>
      {partial && (
        <p role="status" className="mb-3 text-sm text-muted-foreground">
          {translateNow("identities.evidence.globalPartial")}
        </p>
      )}
      {loading && <LoadingState>{translateNow("source.loading.delivery.evidence.7f2cdadedd")}</LoadingState>}
      {error && <ErrorState title={translateNow("source.delivery.evidence.failed.to.load.2625e33346")}>{error}</ErrorState>}
      {!loading && !error && !notice && loadedDeliveries.length === 0 && loadedRotations.length === 0 && (
        <EmptyState title={translateNow("source.no.delivery.or.rotation.receipts.yet.21fb574bf8")}>
          {translateNow("source.issue.deploy.or.renew.an.identity.to.produ.722d26ac6c")}
        </EmptyState>
      )}
      {(loadedDeliveries.length > 0 || loadedRotations.length > 0) && (
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
                {loadedDeliveries.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-muted-foreground">
                      {notice ?? translateNow("source.no.connector.receipts.86d1a1527d")}
                    </td>
                  </tr>
                ) : (
                  loadedDeliveries.map((receipt) => (
                    <tr key={receipt.id} className="align-top">
                      <td className="font-mono text-xs">{receipt.status}</td>
                      <td>{receipt.connector}</td>
                      <td>{receipt.target}</td>
                      <td className="break-all font-mono text-xs">{shortFingerprint(receipt.fingerprint)}</td>
                      <td>
                        <span>{connectorReasonSummary(receipt.reason, receipt.detail)}</span>
                        {(receipt.reason || receipt.detail) && (
                          <details className="mt-1 text-xs text-muted-foreground">
                            <summary className="cursor-pointer">{translateNow("identities.evidence.showExactReason")}</summary>
                            <code className="break-all">{receipt.reason || receipt.detail}</code>
                          </details>
                        )}
                      </td>
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
                  <th scope="col">{translateNow("identities.evidence.identity")}</th>
                  <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                  <th scope="col">{translateNow("source.trigger.8b9c643731")}</th>
                  <th scope="col">{translateNow("source.successor.d29e68e27e")}</th>
                  <th scope="col">{translateNow("source.rollback.c591f55749")}</th>
                  <th scope="col">{translateNow("source.completed.22a970d2e5")}</th>
                </tr>
              </thead>
              <tbody>
                {loadedRotations.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-muted-foreground">
                      {notice ?? translateNow("source.no.rotation.runs.cf68af2637")}
                    </td>
                  </tr>
                ) : (
                  loadedRotations.map((run) => (
                    <tr key={run.id} className="align-top">
                      <td className="break-all font-medium">{identityByID.get(run.identity_id)?.name || run.identity_id}</td>
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
  owner,
  loading,
  error,
  busy,
  deniedTransitions,
  reason,
  onReasonChange,
  onTransition,
}: {
  identity: Identity | null;
  owner?: Owner;
  loading: boolean;
  error: string | null;
  busy: boolean;
  deniedTransitions: Record<string, string>;
  reason: string;
  onReasonChange: (value: string) => void;
  onTransition: (to: TransitionTo, label: string, returnFocus?: HTMLButtonElement) => void;
}) {
  const state = identity ? identityState(identity) : "";
  const kind = identity?.kind ? kindCopy[identity.kind] : null;
  const terminal = terminalMessage(state);
  const rows = identity ? attributeRows(identity) : [];
  const availableActions = actionsFor(state);

  return (
    <section aria-labelledby="identity-detail-content-heading" className="text-sm">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium text-muted-foreground">{translateNow("source.identity.detail.f34a3c7053")}</p>
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
              <dd>
                <span>{identityKindLabel(identity.kind)}</span>
                <details className="mt-1 text-xs text-muted-foreground">
                  <summary className="cursor-pointer">{translateNow("identities.kind.showExact")}</summary>
                  <code>{identity.kind}</code>
                </details>
              </dd>
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
                  {ownerLabel(owner)}
                </a>
                {ownerEnvironment(owner) && <span className="ms-2 text-xs text-muted-foreground">{ownerEnvironment(owner)}</span>}
                <details className="mt-1 text-xs text-muted-foreground">
                  <summary className="cursor-pointer">{translateNow("identities.owner.showId")}</summary>
                  <code className="break-all">{identity.owner_id}</code>
                </details>
              </dd>
            </div>
            <IdentityIssuerEvidence identity={identity} />
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

          <IdentityActivityEvidence key={identity.id} identity={identity} />

          <section aria-labelledby="identity-lifecycle-heading" className="mt-5 border-t border-border pt-4">
            <h3 id="identity-lifecycle-heading" className="font-semibold">
              {translateNow("identities.lifecycle.nextHeading")}
            </h3>
            <p className="mt-1 text-muted-foreground">{translateNow("identities.lifecycle.nextDescription")}</p>
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
            {availableActions.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {availableActions.map((action) => {
                  const denied = deniedTransitions[deniedKey(identity.id, action.to)];
                  return (
                    <div key={action.to} className="max-w-xs space-y-1">
                      <Button
                        type="button"
                        size="sm"
                        variant={isDestructive(action.to) ? "outline" : "default"}
                        disabled={busy || Boolean(denied)}
                        aria-describedby={denied ? `next-${identity.id}-${action.to}-reason` : undefined}
                        onClick={(event) => onTransition(action.to, action.label, event.currentTarget)}
                      >
                        {action.label}
                      </Button>
                      {denied ? (
                        <p id={`next-${identity.id}-${action.to}-reason`} className="text-xs text-status-warning">
                          {denied}
                        </p>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}

            <details className="group mt-4 border-t border-border pt-3">
              <summary className="cursor-pointer text-sm font-medium text-muted-foreground marker:text-muted-foreground">
                {translateNow("identities.lifecycle.rulesSummary")}
              </summary>
              <p className="mt-2 text-xs text-muted-foreground">{translateNow("source.only.valid.next.states.are.enabled.disable.643c38f3f4")}</p>
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
                        onClick={(event) => action && onTransition(target, action.label, event.currentTarget)}
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
            </details>
          </section>
        </>
      )}
    </section>
  );
}

function NewIdentityForm({ owners, onDone }: { owners: Owner[]; onDone: (issued: Identity) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [ownerId, setOwnerId] = useState("");
  const [wildcardAck, setWildcardAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const serviceName = name.trim() || "new-service";
  const isWildcard = serviceName.startsWith("*.");
  const readyOwners = owners
    .filter((owner) => owner.ownership_complete === true && owner.ownership_current === true)
    .sort((left, right) => ownerLabel(left).localeCompare(ownerLabel(right)));

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const issued = await api.issueCertificate({
        name: serviceName,
        ownerId,
        ...(isWildcard ? { wildcardBlastRadiusAcknowledged: wildcardAck } : {}),
      });
      onDone(issued);
    } catch (err) {
      setError(isWildcard ? apiProblemContext(err, t("identities.wildcard.issueFailed")) : apiProblemContext(err, t("identities.issue.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="mb-4 grid gap-3 rounded-md border border-border p-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
      <div className="min-w-0 space-y-1">
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
        <label htmlFor="new-identity-owner" className="mt-3 block text-sm font-medium">
          {t("identities.issue.ownerLabel")}
        </label>
        <select
          id="new-identity-owner"
          value={ownerId}
          onChange={(event) => setOwnerId(event.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
        >
          <option value="">{t("identities.issue.ownerPlaceholder")}</option>
          {readyOwners.map((owner) => {
            const label = ownerLabel(owner);
            return (
              <option key={owner.id} value={owner.id}>
                {owner.environment
                  ? t("identities.issue.ownerOption", {
                      owner: label,
                      environment: titleCaseMachineValue(owner.environment) ?? owner.environment,
                    })
                  : label}
              </option>
            );
          })}
        </select>
        <p className="text-xs text-muted-foreground">{t("identities.issue.ownerHelp")}</p>
        {readyOwners.length === 0 && (
          <p className="text-sm text-risk-warning">
            {t("identities.issue.noReadyOwners")}{" "}
            <Link className="font-medium underline underline-offset-2" to="/owners">
              {t("identities.issue.manageOwners")}
            </Link>
          </p>
        )}
        {isWildcard && (
          <section aria-labelledby="wildcard-safety-heading" className="mt-3 rounded-control border border-status-warning/30 bg-status-warning/5 p-3">
            <h3 id="wildcard-safety-heading" className="text-sm font-semibold">
              {t("identities.wildcard.safetyHeading")}
            </h3>
            <ol className="mt-2 grid gap-2 text-xs text-muted-foreground sm:grid-cols-3">
              <li className="border-s-2 border-border ps-2">{t("identities.wildcard.dnsOnly")}</li>
              <li className="border-s-2 border-border ps-2">{t("identities.wildcard.policy")}</li>
              <li className="border-s-2 border-border ps-2">{t("identities.wildcard.renewal")}</li>
            </ol>
            <label className="mt-3 flex items-start gap-2 text-sm font-medium" htmlFor="wildcard-ack">
              <input
                id="wildcard-ack"
                type="checkbox"
                checked={wildcardAck}
                onChange={(e) => setWildcardAck(e.target.checked)}
                className="mt-1 h-4 w-4 rounded border-border"
              />
              <span>
                {translateNow("source.acknowledge.wildcard.blast.radius.868520eb71")}
                <span className="block text-xs font-normal text-muted-foreground">{t("identities.wildcard.ackHelp")}</span>
              </span>
            </label>
          </section>
        )}
      </div>
      <Button type="submit" className="w-full md:w-auto" disabled={busy || !ownerId || (isWildcard && !wildcardAck)}>
        {translateNow("source.issue.48dc76dfa2")}
      </Button>
      {error && (
        <div role="alert" className="text-sm text-destructive md:col-span-2">
          <p className="font-medium">{error}</p>
          {isWildcard && (
            <p className="mt-1">
              <a className="font-medium underline underline-offset-2" href="/protocols#dns-config-heading">
                {t("identities.wildcard.recoveryAction")}
              </a>{" "}
              {t("identities.wildcard.recoveryBoundary")}
            </p>
          )}
        </div>
      )}
    </form>
  );
}
