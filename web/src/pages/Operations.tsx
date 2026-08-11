import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { CheckCircle2, RefreshCw, XCircle } from "lucide-react";
import { approvalRequestsQueryKey, approvalRows, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { api, ApiError, type ConnectorDelivery, type PendingApprovalRequest, type RotationRun } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { formatDateTime } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { AgentJobLedgerPanel } from "@/pages/operations/AgentJobLedgerPanel";
import { Dialog } from "@/components/Dialog";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";

type OperationType = "approval" | "deployment" | "rotation";
type Notice = { kind: "error" | "success" | "warning"; message: string };
type RejectTarget = Extract<OperationRow, { type: "approval" }> | null;

type OperationRow =
  | {
      id: string;
      type: "rotation";
      status: string;
      statusKey: string;
      subject: string;
      attempts: string;
      verification: "not_applicable";
      updatedAt: string;
      rotation: RotationRun;
    }
  | {
      id: string;
      type: "deployment";
      status: string;
      statusKey: string;
      subject: string;
      attempts: string;
      verification: "failed" | "pending" | "verified";
      updatedAt: string;
      delivery: ConnectorDelivery;
    }
  | {
      id: string;
      type: "approval";
      status: "Awaiting approval";
      statusKey: "awaiting_approval";
      subject: string;
      attempts: string;
      verification: "not_applicable";
      updatedAt: string;
      approval: ApprovalQueueRow;
    };

function statusOptions(queuedLabel: string) {
  return [
    { value: "", label: translateNow("source.all.statuses.8ee57323a6") },
    { value: "running", label: translateNow("source.running.f4ccae29e1") },
    { value: "succeeded", label: translateNow("source.succeeded.6d9a6f97a5") },
    { value: "failed", label: translateNow("source.failed.031a8f0f65") },
    { value: "delivered", label: translateNow("source.delivered.9061156573") },
    { value: "queued", label: queuedLabel },
    { value: "awaiting_approval", label: translateNow("source.awaiting.approval.ae25c9b1d3") },
  ];
}

const typeOptions: Array<{ value: "" | OperationType; label: string }> = [
  { value: "", label: translateNow("source.all.types.f10988e79e") },
  { value: "rotation", label: translateNow("source.rotation.57b5e2fc1b") },
  { value: "deployment", label: translateNow("source.deployment.870a8ffd98") },
  { value: "approval", label: translateNow("source.approval.147fb813a2") },
];

export function Operations() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const rotations = useApiQuery(["rotation-runs", { limit: 50 }], () => api.rotationRuns({ limit: 50 }), { live: { intervalMs: 10_000 } });
  const deliveries = useApiQuery(["connector-deliveries", { limit: 50 }], () => api.connectorDeliveries({ limit: 50 }), {
    live: { intervalMs: 10_000 },
  });
  const approvals = useApiQuery(approvalRequestsQueryKey, api.approvalRequests, { live: { intervalMs: 10_000 } });
  const [error, setError] = useState<Notice | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState<"" | OperationType>("");
  const [rejectTarget, setRejectTarget] = useState<RejectTarget>(null);
  const rows = useMemo<OperationRow[]>(
    () => [
      ...(rotations.data?.items ?? []).map(rotationOperationRow),
      ...(deliveries.data?.items ?? []).map(deliveryOperationRow),
      ...approvalRows(approvals.data ?? []).map(approvalOperationRow),
    ],
    [approvals.data, deliveries.data, rotations.data],
  );
  const loading = rotations.loading || deliveries.loading || approvals.loading;
  const loadError = rotations.error ?? deliveries.error ?? approvals.error;

  const filteredRows = useMemo(
    () => rows.filter((row) => (!statusFilter || row.statusKey === statusFilter) && (!typeFilter || row.type === typeFilter)),
    [rows, statusFilter, typeFilter],
  );

  async function approve(row: Extract<OperationRow, { type: "approval" }>) {
    setBusyKey(row.id);
    setNotice(null);
    setError(null);
    try {
      const result = await api.approveApprovalRequest(row.approval.id, row.approval.intent_digest);
      queryClient.setQueryData<PendingApprovalRequest[]>(approvalRequestsQueryKey, (current) =>
        current
          ?.map((request) =>
            request.id === row.approval.id
              ? {
                  ...request,
                  approval_count: result.approval_count,
                  required_approvals: result.required_approvals,
                  status: result.status,
                }
              : request,
          )
          .filter((request) => request.status === "pending"),
      );
      setNotice({
        kind: "success",
        message: `${row.approval.action} approval recorded for ${row.approval.resource_name || row.approval.resource_id}`,
      });
      void queryClient.invalidateQueries({ queryKey: approvalRequestsQueryKey });
    } catch (err) {
      setError({ kind: "error", message: errorText(err, "Could not approve request") });
    } finally {
      setBusyKey(null);
    }
  }

  async function reject(row: Extract<OperationRow, { type: "approval" }>, reason: string) {
    setBusyKey(row.id);
    setNotice(null);
    setError(null);
    try {
      await api.denyApprovalRequest(row.approval.id, row.approval.intent_digest, reason);
      queryClient.setQueryData<PendingApprovalRequest[]>(approvalRequestsQueryKey, (current) => current?.filter((request) => request.id !== row.approval.id));
      setRejectTarget(null);
      setNotice({ kind: "success", message: `request rejected for ${row.approval.resource_name || row.approval.resource_id}` });
      void queryClient.invalidateQueries({ queryKey: approvalRequestsQueryKey });
    } catch (err) {
      setError({ kind: "error", message: errorText(err, "Could not reject request") });
    } finally {
      setBusyKey(null);
    }
  }

  function cancel(row: OperationRow) {
    setNotice({ kind: "warning", message: translateNow("source.cancel.is.not.available.for.this.operation.0210a0d77e") });
    setBusyKey(row.id);
    window.setTimeout(() => setBusyKey((current) => (current === row.id ? null : current)), 250);
  }

  return (
    <div className="grid gap-6">
      <PageHeader
        title={translateNow("source.operations.queue.42686cb416")}
        titleId="operations-heading"
        description="The execution queue — jobs in flight like credential rotations and connector deployments, with attempts and outcomes. To approve or deny pending requests, see Approvals."
        actions={
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              rotations.refetch();
              deliveries.refetch();
              approvals.refetch();
            }}
            disabled={loading}
          >
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            {translateNow("source.refresh.0e91610117")}
          </Button>
        }
      />

      {notice && <OperationNotice notice={notice} onDismiss={() => setNotice(null)} />}
      {error && <ErrorState title={translateNow("source.operations.unavailable.b176555a53")}>{error.message}</ErrorState>}
      {!error && loadError && <ErrorState title={translateNow("source.operations.unavailable.b176555a53")}>{loadError}</ErrorState>}

      {/* A1: estate-touching work is executed by agents, so the queue an operator
          needs to watch is the one agents claim from — not only the control
          plane's own execution queue below. */}
      <AgentJobLedgerPanel />

      <div className="ui-panel grid gap-3 p-comfortable sm:grid-cols-2 lg:grid-cols-[minmax(12rem,16rem)_minmax(12rem,16rem)_1fr]">
        <label className="grid gap-2 text-sm font-medium">
          {translateNow("source.status.filter.9bfe8b184f")}
          <select
            aria-label={translateNow("source.status.filter.9bfe8b184f")}
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-focus focus:ring-2 focus:ring-focus/20"
          >
            {statusOptions(t("operations.status.queued")).map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-2 text-sm font-medium">
          {translateNow("source.type.filter.5607113309")}
          <select
            aria-label={translateNow("source.type.filter.5607113309")}
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value as "" | OperationType)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-focus focus:ring-2 focus:ring-focus/20"
          >
            {typeOptions.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <div className="flex items-end text-sm text-muted-foreground">
          {filteredRows.length} {translateNow("source.rows.bc51e9e65d")}
        </div>
      </div>

      {loading ? (
        <LoadingState>{translateNow("source.loading.operations.f0b144434b")}</LoadingState>
      ) : filteredRows.length === 0 ? (
        <EmptyState
          icon={<RefreshCw className="h-5 w-5" aria-hidden="true" />}
          title={translateNow("source.no.operations.found.7472e6ceb1")}
          primaryAction={{ label: translateNow("source.review.approvals.51320f88b0"), to: "/approvals", icon: <CheckCircle2 className="h-4 w-4" /> }}
          secondaryAction={{
            label: translateNow("source.open.expiring.certificates.45cc9bb64d"),
            to: "/certificates?expiry=30d",
            icon: <RefreshCw className="h-4 w-4" />,
          }}
        >
          {translateNow("source.adjust.filters.refresh.the.queue.or.move.t.4a4fa7f45b")}
        </EmptyState>
      ) : (
        <OperationsTable
          rows={filteredRows}
          busyKey={busyKey}
          onApprove={(row) => void approve(row)}
          onCancel={cancel}
          onReject={(row) => setRejectTarget(row)}
        />
      )}

      <RotationRunsSection />

      {rejectTarget && (
        <RejectDialog
          row={rejectTarget}
          busy={busyKey === rejectTarget.id}
          onClose={() => setRejectTarget(null)}
          onSubmit={(reason) => void reject(rejectTarget, reason)}
        />
      )}
    </div>
  );
}

function OperationsTable({
  busyKey,
  onApprove,
  onCancel,
  onReject,
  rows,
}: {
  rows: OperationRow[];
  busyKey: string | null;
  onApprove: (row: Extract<OperationRow, { type: "approval" }>) => void;
  onReject: (row: Extract<OperationRow, { type: "approval" }>) => void;
  onCancel: (row: OperationRow) => void;
}) {
  const columns: DataGridColumn<OperationRow>[] = [
    { id: "operation", header: "Operation", className: "font-mono text-xs", cell: (row) => row.id },
    { id: "type", header: "Type", cell: (row) => operationTypeLabel(row.type) },
    { id: "status", header: "Status", cell: (row) => <StatusBadge value={row.statusKey} label={row.status} tone={statusTone(row.statusKey)} /> },
    { id: "subject", header: "Subject", className: "max-w-xs break-all", cell: (row) => row.subject },
    { id: "attempts", header: "Attempts", cell: (row) => row.attempts },
    { id: "verification", header: "Verification", cell: (row) => <VerificationBadge status={row.verification} /> },
    { id: "updated", header: "Updated", cell: (row) => formatDateTime(row.updatedAt) },
    {
      id: "actions",
      header: "Actions",
      cell: (row) => <OperationActions row={row} busy={busyKey === row.id} onApprove={onApprove} onReject={onReject} onCancel={onCancel} />,
    },
  ];
  return <DataGrid ariaLabel="Operations queue" rows={rows} columns={columns} getRowId={(row) => row.id} state="ready" />;
}

function OperationActions({
  busy,
  onApprove,
  onCancel,
  onReject,
  row,
}: {
  row: OperationRow;
  busy: boolean;
  onApprove: (row: Extract<OperationRow, { type: "approval" }>) => void;
  onReject: (row: Extract<OperationRow, { type: "approval" }>) => void;
  onCancel: (row: OperationRow) => void;
}) {
  if (row.type === "approval") {
    return (
      <div className="flex flex-wrap gap-2">
        <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onApprove(row)}>
          {translateNow("source.approve.value1.for.value2.f59c2fc633", {
            value1: row.approval.action,
            value2: row.approval.resource_name || row.approval.resource_id,
          })}
        </Button>
        <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onReject(row)}>
          {translateNow("source.reject.value1.for.value2.30ca8dca77", {
            value1: row.approval.action,
            value2: row.approval.resource_name || row.approval.resource_id,
          })}
        </Button>
      </div>
    );
  }
  if (row.statusKey === "running" || row.statusKey === "queued") {
    return (
      <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onCancel(row)}>
        {translateNow("source.cancel.value1.64342fbae8", { value1: row.id })}
      </Button>
    );
  }
  return <span className="text-sm text-muted-foreground">-</span>;
}

function RejectDialog({
  busy,
  onClose,
  onSubmit,
  row,
}: {
  row: Extract<OperationRow, { type: "approval" }>;
  busy: boolean;
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const title = `Reject ${row.approval.action} for ${row.approval.resource_name || row.approval.resource_id}`;
  const titleId = "operation-reject-heading";
  const descriptionId = "operation-reject-description";

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(reason.trim());
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      initialFocusRef={reasonRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative w-full max-w-md rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="border-b border-border px-5 py-4">
        <h2 id={titleId} className="text-title font-semibold">
          {title}
        </h2>
        <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
          Record why this approval request is being rejected.
        </p>
      </header>
      <form className="grid gap-4 p-5" onSubmit={submit}>
        <label className="grid gap-2 text-sm font-medium">
          {translateNow("source.reason.f81ab834de")}
          <textarea
            ref={reasonRef}
            required
            rows={4}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            className="rounded-control border border-border bg-background px-3 py-2 text-sm outline-none focus:border-focus focus:ring-2 focus:ring-focus/20"
          />
        </label>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
          <Button type="submit" disabled={busy || reason.trim() === ""}>
            {translateNow("source.reject.request.33b1a3b501")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function OperationNotice({ notice, onDismiss }: { notice: Notice; onDismiss: () => void }) {
  const Icon = notice.kind === "success" ? CheckCircle2 : notice.kind === "warning" ? RefreshCw : XCircle;
  return (
    <div className="ui-panel flex items-start justify-between gap-3 p-comfortable text-sm" role="status">
      <div className="flex min-w-0 items-start gap-2">
        <Icon
          className={
            notice.kind === "success"
              ? "mt-0.5 h-4 w-4 shrink-0 text-emerald-600"
              : notice.kind === "warning"
                ? "mt-0.5 h-4 w-4 shrink-0 text-status-warning"
                : "mt-0.5 h-4 w-4 shrink-0 text-destructive"
          }
          aria-hidden="true"
        />
        <p className="min-w-0 break-words font-medium">{notice.message}</p>
      </div>
      <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
        {translateNow("source.dismiss.48845bff33")}
      </Button>
    </div>
  );
}

function VerificationBadge({ status }: { status: OperationRow["verification"] }) {
  if (status === "verified") return <StatusBadge value="delivered" vocabulary="delivery" label="Verified" />;
  if (status === "failed") return <StatusBadge value="failed" vocabulary="delivery" label="Failed" />;
  if (status === "pending") return <StatusBadge value="pending" vocabulary="delivery" label="Pending" />;
  return <span className="text-sm text-muted-foreground">-</span>;
}

function rotationOperationRow(rotation: RotationRun): OperationRow {
  return {
    id: rotation.id,
    type: "rotation",
    status: rotation.status,
    statusKey: rotation.status,
    subject: rotation.identity_id,
    attempts: "1 / n/a",
    verification: "not_applicable",
    updatedAt: rotation.updated_at || rotation.completed_at || rotation.created_at,
    rotation,
  };
}

function deliveryOperationRow(delivery: ConnectorDelivery): OperationRow {
  return {
    id: delivery.id,
    type: "deployment",
    status: delivery.status,
    statusKey: delivery.status,
    subject: `${delivery.connector} -> ${delivery.destination}/${delivery.target}`,
    attempts: `${delivery.attempts} / n/a`,
    verification: delivery.status === "delivered" && delivery.fingerprint ? "verified" : delivery.status === "failed" ? "failed" : "pending",
    updatedAt: delivery.updated_at || delivery.created_at,
    delivery,
  };
}

function approvalOperationRow(approval: ApprovalQueueRow): OperationRow {
  return {
    id: `approval-${approval.id}`,
    type: "approval",
    status: "Awaiting approval",
    statusKey: "awaiting_approval",
    subject: approval.resource_name || approval.resource_id,
    attempts: `${approval.approval_count} / ${approval.required_approvals}`,
    verification: "not_applicable",
    updatedAt: approval.created_at,
    approval,
  };
}

function operationTypeLabel(type: OperationType): string {
  switch (type) {
    case "approval":
      return "Approval";
    case "deployment":
      return "Deployment";
    case "rotation":
      return "Rotation";
  }
}

function statusTone(status: string) {
  if (status === "succeeded" || status === "delivered") return "success";
  if (status === "failed") return "critical";
  if (status === "awaiting_approval" || status === "queued") return "warning";
  if (status === "running") return "operate";
  return "neutral";
}

function RotationRunsSection() {
  const { t } = useTranslation();
  const [runs, setRuns] = useState<RotationRun[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [gridState, setGridState] = useState<"loading" | "ready" | "empty" | "error">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [identityDraft, setIdentityDraft] = useState("");
  const [identityFilter, setIdentityFilter] = useState("");
  const [loadingMore, setLoadingMore] = useState(false);
  const [detail, setDetail] = useState<RotationRun | null>(null);

  const loadRuns = useCallback(async (identityId: string) => {
    setGridState("loading");
    setLoadError(null);
    try {
      const page = await api.rotationRuns(identityId ? { limit: 20, identityId } : { limit: 20 });
      const items = page.items ?? [];
      setRuns(items);
      setNextCursor(page.next_cursor);
      setGridState(items.length === 0 ? "empty" : "ready");
    } catch (err) {
      setLoadError(errorText(err, "Could not load rotation runs"));
      setRuns([]);
      setNextCursor(undefined);
      setGridState("error");
    }
  }, []);

  useEffect(() => {
    void loadRuns("");
  }, [loadRuns]);

  async function loadMore() {
    if (!nextCursor) return;
    setLoadingMore(true);
    try {
      const page = await api.rotationRuns(identityFilter ? { limit: 20, cursor: nextCursor, identityId: identityFilter } : { limit: 20, cursor: nextCursor });
      setRuns((current) => [...current, ...(page.items ?? [])]);
      setNextCursor(page.next_cursor);
    } catch (err) {
      setLoadError(errorText(err, "Could not load more rotation runs"));
    } finally {
      setLoadingMore(false);
    }
  }

  function applyIdentityFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const identityId = identityDraft.trim();
    setIdentityFilter(identityId);
    void loadRuns(identityId);
  }

  function clearIdentityFilter() {
    setIdentityDraft("");
    setIdentityFilter("");
    void loadRuns("");
  }

  const columns: DataGridColumn<RotationRun>[] = [
    { id: "created", header: "Created", cell: (row) => formatDateTime(row.created_at) },
    {
      id: "identity",
      header: "Identity",
      cell: (row) => (
        <span className="block max-w-xs truncate font-mono text-xs" title={row.identity_id}>
          {row.identity_id}
        </span>
      ),
    },
    { id: "trigger", header: "Trigger", cell: (row) => row.trigger },
    { id: "status", header: "Status", cell: (row) => <StatusBadge value={row.status} label={row.status} tone={rotationRunTone(row.status)} /> },
    { id: "completed", header: "Completed", cell: (row) => (row.completed_at ? formatDateTime(row.completed_at) : "-") },
  ];

  return (
    <div className="grid gap-3">
      <div>
        <h2 className="text-title font-semibold">{t("parity.rotationRuns_5ec15c")}</h2>
        <p className="text-sm text-muted-foreground">{t("parity.lifecycleRotationEvidenceWhoRotatedWhat_10ed9a")}</p>
      </div>
      <form aria-label={t("parity.filterRotationRuns_e652a6")} className="flex flex-wrap items-end gap-2" onSubmit={applyIdentityFilter}>
        <label className="grid gap-1 text-body font-medium">
          {t("parity.identityIdFilter_48db11")}
          <input
            value={identityDraft}
            onChange={(event) => setIdentityDraft(event.target.value)}
            placeholder={t("parity.identityUuid_209e1d")}
            className="min-h-9 w-72 rounded-control border border-border bg-background px-3 py-2 text-body"
          />
        </label>
        <Button type="submit" variant="outline" size="sm">
          {t("parity.applyIdentityFilter_72d5ba")}
        </Button>
        {identityFilter && (
          <Button type="button" variant="ghost" size="sm" onClick={clearIdentityFilter}>
            {t("parity.clearIdentityFilter_3c0b9a")}
          </Button>
        )}
      </form>
      <DataGrid
        ariaLabel="Rotation runs"
        rows={runs}
        columns={columns}
        getRowId={(row) => row.id}
        state={gridState}
        stateTitle={gridState === "error" ? "Rotation runs unavailable" : gridState === "empty" ? "No rotation runs" : undefined}
        stateMessage={gridState === "error" ? loadError : gridState === "empty" ? "No lifecycle rotation run has been recorded for this scope yet." : undefined}
        onRowOpen={(row) => setDetail(row)}
        pagination={
          nextCursor ? (
            <div>
              <Button type="button" size="sm" variant="outline" disabled={loadingMore} onClick={() => void loadMore()}>
                {loadingMore ? translateNow("source.loading.more.rotation.runs.15b9534a52") : translateNow("source.load.more.rotation.runs.4e5894a950")}
              </Button>
            </div>
          ) : undefined
        }
      />
      {detail && <RotationRunDetailDialog run={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

function RotationRunDetailDialog({ onClose, run }: { run: RotationRun; onClose: () => void }) {
  const { t } = useTranslation();
  const titleId = "rotation-run-detail-heading";
  const descriptionId = "rotation-run-detail-description";
  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="border-b border-border px-5 py-4">
        <h2 id={titleId} className="text-title font-semibold">
          {translateNow("source.rotation.run.value1.e6b35404aa", { value1: run.id })}
        </h2>
        <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
          {t("parity.fullLifecycleRotationRunRecordIncluding_02687f")}
        </p>
      </header>
      <dl className="grid gap-2 p-5 text-sm">
        <RotationRunDetailRow term="Run ID" mono>
          {run.id}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Identity" mono>
          {run.identity_id}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Status">
          <StatusBadge value={run.status} label={run.status} tone={rotationRunTone(run.status)} />
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Trigger">{run.trigger}</RotationRunDetailRow>
        <RotationRunDetailRow term="Reason">{run.reason || "-"}</RotationRunDetailRow>
        <RotationRunDetailRow term="Predecessor fingerprint" mono>
          {run.predecessor_fingerprint || "-"}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Successor fingerprint" mono>
          {run.successor_fingerprint || "-"}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Rollback ref" mono>
          {run.rollback_ref || "-"}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Error">
          {run.error ? <span className={run.status === "failed" ? "text-risk-critical" : undefined}>{run.error}</span> : "-"}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Idempotency key" mono>
          {run.idempotency_key || "-"}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Outbox ID">{run.outbox_id != null ? String(run.outbox_id) : "-"}</RotationRunDetailRow>
        <RotationRunDetailRow term="Tenant" mono>
          {run.tenant_id}
        </RotationRunDetailRow>
        <RotationRunDetailRow term="Created">{formatDateTime(run.created_at)}</RotationRunDetailRow>
        <RotationRunDetailRow term="Completed">{run.completed_at ? formatDateTime(run.completed_at) : "-"}</RotationRunDetailRow>
        <RotationRunDetailRow term="Updated">{formatDateTime(run.updated_at)}</RotationRunDetailRow>
      </dl>
      <div className="flex justify-end border-t border-border px-5 py-4">
        <Button type="button" variant="outline" onClick={onClose}>
          {translateNow("source.close.7d9eb7acb1")}
        </Button>
      </div>
    </Dialog>
  );
}

function RotationRunDetailRow({ children, mono = false, term }: { term: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[11rem_1fr] sm:gap-2">
      <dt className="font-medium text-muted-foreground">{term}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words"}>{children}</dd>
    </div>
  );
}

function rotationRunTone(status: RotationRun["status"]) {
  if (status === "succeeded") return "success";
  if (status === "failed") return "critical";
  return "info";
}

function errorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return err.body || fallback;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
