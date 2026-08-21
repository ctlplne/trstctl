import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode, type RefObject } from "react";
import { AlertTriangle, CheckCircle2, ExternalLink, RefreshCw, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { approvalRequestsQueryKey, approvalRows, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { api, ApiError, type BulkheadStats, type ConnectorDelivery, type PendingApprovalRequest, type RotationRun } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { formatDateTime } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { AgentJobLedgerPanel } from "@/pages/operations/AgentJobLedgerPanel";
import { Dialog } from "@/components/Dialog";
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
  const jobPosture = useApiQuery(["agent-job-posture"], () => api.agentJobPosture(), { live: { intervalMs: 10_000 } });
  const bulkheads = useApiQuery(["bulkhead-stats"], () => api.bulkheadStats(), { live: { intervalMs: 10_000 } });
  const [error, setError] = useState<Notice | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState<"" | OperationType>("");
  const [rejectTarget, setRejectTarget] = useState<RejectTarget>(null);
  const [detailTarget, setDetailTarget] = useState<OperationRow | null>(null);
  const firstFailedReviewRef = useRef<HTMLButtonElement>(null);
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
  const failedRows = useMemo(() => rows.filter((row) => isFailureStatus(row.statusKey)), [rows]);
  const attentionRows = useMemo(
    () => rows.filter((row) => isFailureStatus(row.statusKey) || isActiveStatus(row.statusKey) || row.statusKey === "awaiting_approval"),
    [rows],
  );
  const waitingJobs = useMemo(
    () => (jobPosture.data?.queues ?? []).reduce((total, queue) => total + (queue.enabled ? queue.pending : 0), 0),
    [jobPosture.data],
  );
  const oldestWaitingSeconds = useMemo(
    () => Math.max(0, ...(jobPosture.data?.queues ?? []).map((queue) => (queue.enabled ? (queue.oldest_unclaimed_seconds ?? 0) : 0))),
    [jobPosture.data],
  );
  const checkingAttention = loading || jobPosture.loading;
  const agentQueueUnavailable = !jobPosture.loading && (jobPosture.error !== null || jobPosture.data?.served !== true);

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

  return (
    <div className="grid gap-6">
      <PageHeader
        title={t("operations.page.title")}
        titleId="operations-heading"
        description={t("operations.page.answer")}
        technicalDetails={t("operations.page.details")}
        actions={
          <Button type="button" onClick={() => firstFailedReviewRef.current?.focus()} disabled={failedRows.length === 0}>
            {t("operations.page.reviewFailed")}
          </Button>
        }
      />

      {notice && <OperationNotice notice={notice} onDismiss={() => setNotice(null)} />}
      {error && <ErrorState title={translateNow("source.operations.unavailable.b176555a53")}>{error.message}</ErrorState>}
      {!error && loadError && <ErrorState title={translateNow("source.operations.unavailable.b176555a53")}>{loadError}</ErrorState>}

      <section aria-labelledby="operations-attention-heading" className="ui-panel grid gap-4 p-comfortable">
        <div className="flex items-start gap-3">
          {checkingAttention ? (
            <RefreshCw className="mt-0.5 h-5 w-5 shrink-0 animate-spin text-muted-foreground" aria-hidden="true" />
          ) : failedRows.length > 0 || waitingJobs > 0 || agentQueueUnavailable ? (
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />
          ) : (
            <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
          )}
          <div>
            <h2 id="operations-attention-heading" className="text-title font-semibold">
              {t("operations.attention.heading")}
            </h2>
            {checkingAttention ? (
              <p className="mt-1 text-sm text-muted-foreground">{t("operations.attention.checking")}</p>
            ) : failedRows.length === 0 && waitingJobs === 0 && !agentQueueUnavailable ? (
              <>
                <p className="mt-1 font-medium">{t("operations.attention.empty")}</p>
                <p className="mt-1 text-sm text-muted-foreground">{t("operations.attention.emptyDetail")}</p>
              </>
            ) : (
              <div className="mt-1 grid gap-1 text-sm">
                {failedRows.length > 0 ? (
                  <p className="font-medium">
                    {failedRows.length === 1 ? t("operations.attention.failedOne") : t("operations.attention.failedMany", { count: failedRows.length })}
                  </p>
                ) : null}
                {waitingJobs > 0 ? (
                  <p className="text-muted-foreground">
                    {waitingJobs === 1
                      ? t("operations.attention.waitingOne", { age: waitLabel(oldestWaitingSeconds) })
                      : t("operations.attention.waitingMany", { count: waitingJobs, age: waitLabel(oldestWaitingSeconds) })}
                  </p>
                ) : null}
                {agentQueueUnavailable ? <p className="text-muted-foreground">{t("operations.attention.agentUnavailable")}</p> : null}
              </div>
            )}
          </div>
        </div>

        {loading ? (
          <LoadingState>{translateNow("source.loading.operations.f0b144434b")}</LoadingState>
        ) : attentionRows.length > 0 ? (
          <OperationWorkList
            ariaLabel={t("operations.list.attention")}
            rows={attentionRows}
            busyKey={busyKey}
            firstFailedReviewRef={firstFailedReviewRef}
            onApprove={(row) => void approve(row)}
            onOpen={setDetailTarget}
            onReject={setRejectTarget}
          />
        ) : null}
      </section>

      <TechnicalDisclosure title={t("operations.disclosure.pools")}>
        <BulkheadEvidence stats={bulkheads.data} loading={bulkheads.loading} error={bulkheads.error} />
        <AgentJobLedgerPanel posture={jobPosture.data ?? null} />
      </TechnicalDisclosure>

      <TechnicalDisclosure title={t("operations.disclosure.all")}>
        <div className="grid gap-4">
          <div className="ui-panel grid gap-3 p-comfortable sm:grid-cols-2 lg:grid-cols-[minmax(12rem,16rem)_minmax(12rem,16rem)_1fr_auto]">
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
            <Button
              type="button"
              variant="outline"
              className="sm:col-span-2 lg:col-span-1"
              onClick={() => {
                rotations.refetch();
                deliveries.refetch();
                approvals.refetch();
                jobPosture.refetch();
                bulkheads.refetch();
              }}
              disabled={loading}
            >
              <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {translateNow("source.refresh.0e91610117")}
            </Button>
          </div>
          {loading ? (
            <LoadingState>{translateNow("source.loading.operations.f0b144434b")}</LoadingState>
          ) : filteredRows.length === 0 ? (
            <p className="rounded-control border border-dashed border-border p-4 text-sm text-muted-foreground">{t("operations.filters.noMatches")}</p>
          ) : (
            <OperationWorkList
              ariaLabel={t("operations.list.all")}
              rows={filteredRows}
              busyKey={busyKey}
              onApprove={(row) => void approve(row)}
              onOpen={setDetailTarget}
              onReject={setRejectTarget}
            />
          )}
        </div>
      </TechnicalDisclosure>

      <TechnicalDisclosure title={t("operations.disclosure.rotations")}>
        <RotationRunsSection />
      </TechnicalDisclosure>

      {rejectTarget && (
        <RejectDialog
          row={rejectTarget}
          busy={busyKey === rejectTarget.id}
          onClose={() => setRejectTarget(null)}
          onSubmit={(reason) => void reject(rejectTarget, reason)}
        />
      )}
      {detailTarget && <OperationDetailDialog row={detailTarget} onClose={() => setDetailTarget(null)} />}
    </div>
  );
}

function OperationWorkList({
  ariaLabel,
  busyKey,
  firstFailedReviewRef,
  onApprove,
  onOpen,
  onReject,
  rows,
}: {
  ariaLabel: string;
  rows: OperationRow[];
  busyKey: string | null;
  firstFailedReviewRef?: RefObject<HTMLButtonElement>;
  onApprove: (row: Extract<OperationRow, { type: "approval" }>) => void;
  onReject: (row: Extract<OperationRow, { type: "approval" }>) => void;
  onOpen: (row: OperationRow) => void;
}) {
  const firstFailedIndex = rows.findIndex((row) => isFailureStatus(row.statusKey));
  return (
    <ul aria-label={ariaLabel} className="grid gap-3">
      {rows.map((row, index) => {
        const label = operationLabel(row);
        const isFirstFailed = index === firstFailedIndex;
        return (
          <li key={row.id} className="rounded-control border border-border bg-background p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="font-semibold text-foreground">{label}</h3>
                  <StatusBadge value={row.statusKey} label={humanStatus(row)} tone={statusTone(row.statusKey)} />
                </div>
                <p className="mt-1 text-sm text-muted-foreground">{operationSummary(row)}</p>
                <p className="mt-1 text-caption text-muted-foreground">{translateNow("operations.list.updated", { date: formatDateTime(row.updatedAt) })}</p>
              </div>
              {row.type === "approval" ? (
                <div className="flex flex-wrap gap-2">
                  <Button type="button" size="sm" variant="outline" disabled={busyKey === row.id} onClick={() => onApprove(row)}>
                    {translateNow("source.approve.value1.for.value2.f59c2fc633", {
                      value1: row.approval.action,
                      value2: row.approval.resource_name || row.approval.resource_id,
                    })}
                  </Button>
                  <Button type="button" size="sm" variant="outline" disabled={busyKey === row.id} onClick={() => onReject(row)}>
                    {translateNow("source.reject.value1.for.value2.30ca8dca77", {
                      value1: row.approval.action,
                      value2: row.approval.resource_name || row.approval.resource_id,
                    })}
                  </Button>
                </div>
              ) : (
                <Button ref={isFirstFailed ? firstFailedReviewRef : undefined} type="button" size="sm" variant="outline" onClick={() => onOpen(row)}>
                  {translateNow("operations.list.review", { label })}
                </Button>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function TechnicalDisclosure({ children, title }: { children: ReactNode; title: string }) {
  const [open, setOpen] = useState(false);
  return (
    <details className="group rounded-panel border border-border bg-card px-4 py-3 shadow-elevation1">
      <summary onClick={() => setOpen((current) => !current)} className="cursor-pointer list-none font-semibold text-foreground marker:hidden">
        <span aria-hidden="true" className="me-2 inline-block text-muted-foreground transition-transform group-open:rotate-90">
          ›
        </span>
        {title}
      </summary>
      {open ? <div className="mt-4 grid gap-4 border-t border-border pt-4">{children}</div> : null}
    </details>
  );
}

function BulkheadEvidence({ error, loading, stats }: { error: string | null; loading: boolean; stats: BulkheadStats | null }) {
  if (loading) return <LoadingState>{translateNow("operations.bulkheads.loading")}</LoadingState>;
  if (error) return <ErrorState title={translateNow("operations.bulkheads.unavailable")}>{error}</ErrorState>;
  if (!stats?.served) return <p className="text-sm text-muted-foreground">{translateNow("operations.bulkheads.notServed")}</p>;
  if (stats.pools.length === 0) return <p className="text-sm text-muted-foreground">{translateNow("operations.bulkheads.empty")}</p>;

  return (
    <section aria-labelledby="worker-pools-heading" className="grid gap-3">
      <div>
        <h3 id="worker-pools-heading" className="font-semibold">
          {translateNow("operations.bulkheads.heading")}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{translateNow("operations.bulkheads.description")}</p>
      </div>
      <ul className="grid gap-3 sm:grid-cols-2">
        {stats.pools.map((pool) => (
          <li key={pool.name} className="rounded-control border border-border bg-background p-4">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <h4 className="break-all font-mono text-sm font-semibold">{pool.name}</h4>
              <StatusBadge
                value={pool.rejected > 0 || pool.panicked > 0 ? "failed" : pool.saturation_percent >= 80 ? "queued" : "succeeded"}
                label={translateNow("operations.bulkheads.full", { percent: pool.saturation_percent })}
                tone={pool.rejected > 0 || pool.panicked > 0 ? "critical" : pool.saturation_percent >= 80 ? "warning" : "success"}
              />
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-3 text-sm">
              <div>
                <dt className="text-caption text-muted-foreground">{translateNow("operations.bulkheads.workers")}</dt>
                <dd className="font-medium">{pool.workers}</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">{translateNow("operations.bulkheads.waiting")}</dt>
                <dd className="font-medium">{pool.queued}</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">{translateNow("operations.bulkheads.boundary")}</dt>
                <dd className="font-medium">{translateNow("operations.bulkheads.boundaryValue", { count: pool.capacity })}</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">{translateNow("operations.bulkheads.rejectedPanicked")}</dt>
                <dd className="font-medium">
                  {pool.rejected} / {pool.panicked}
                </dd>
              </div>
            </dl>
          </li>
        ))}
      </ul>
    </section>
  );
}

function OperationDetailDialog({ onClose, row }: { onClose: () => void; row: OperationRow }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const label = operationLabel(row);
  const title = translateNow(isFailureStatus(row.statusKey) ? "operations.detail.failedTitle" : "operations.detail.title", { label });
  const titleId = "operation-detail-heading";
  const descriptionId = "operation-detail-description";
  const fields = operationDetailFields(row);

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      initialFocusRef={closeRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="border-b border-border px-5 py-4">
        <h2 id={titleId} className="text-title font-semibold">
          {title}
        </h2>
        <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
          {translateNow("operations.detail.description")}
        </p>
      </header>
      <div className="grid gap-4 p-5">
        <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
          {fields.map((field) => (
            <div key={field.label} className={field.wide ? "sm:col-span-2" : undefined}>
              <dt className="text-caption font-medium text-muted-foreground">{field.label}</dt>
              <dd className={field.technical ? "mt-1 break-all font-mono text-xs" : "mt-1 break-words"}>{field.value}</dd>
            </div>
          ))}
        </dl>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
          <Link to={`/audit?q=${encodeURIComponent(row.id)}`} className="inline-flex items-center gap-2 text-sm font-medium text-link hover:underline">
            {translateNow("operations.detail.eventLog")}
            <ExternalLink className="h-4 w-4" aria-hidden="true" />
          </Link>
          <Button ref={closeRef} type="button" variant="outline" onClick={onClose}>
            {translateNow("operations.detail.close")}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function operationDetailFields(row: OperationRow): Array<{ label: string; value: ReactNode; technical?: boolean; wide?: boolean }> {
  const common = [
    { label: translateNow("operations.detail.jobId"), value: row.id, technical: true },
    { label: translateNow("operations.detail.status"), value: humanStatus(row) },
    { label: translateNow("operations.detail.updated"), value: formatDateTime(row.updatedAt) },
  ];
  if (row.type === "deployment") {
    return [
      ...common,
      { label: translateNow("operations.detail.attempts"), value: String(row.delivery.attempts) },
      { label: translateNow("operations.detail.connector"), value: row.delivery.connector, technical: true },
      { label: translateNow("operations.detail.destination"), value: row.delivery.destination, technical: true },
      { label: translateNow("operations.detail.target"), value: row.delivery.target, technical: true },
      ...(row.delivery.reason ? [{ label: translateNow("operations.detail.failureReason"), value: row.delivery.reason, wide: true }] : []),
      ...(row.delivery.detail ? [{ label: translateNow("operations.detail.outcome"), value: row.delivery.detail, wide: true }] : []),
      ...(row.delivery.idempotency_key ? [{ label: translateNow("operations.detail.idempotency"), value: row.delivery.idempotency_key, technical: true }] : []),
      ...(row.delivery.outbox_id !== undefined
        ? [{ label: translateNow("operations.detail.outbox"), value: String(row.delivery.outbox_id), technical: true }]
        : []),
      ...(row.delivery.rollback_ref ? [{ label: translateNow("operations.detail.rollback"), value: row.delivery.rollback_ref, technical: true }] : []),
    ];
  }
  if (row.type === "rotation") {
    return [
      ...common,
      { label: translateNow("operations.detail.identityId"), value: row.rotation.identity_id, technical: true },
      { label: translateNow("operations.detail.trigger"), value: row.rotation.trigger },
      ...(row.rotation.reason ? [{ label: translateNow("operations.detail.reason"), value: row.rotation.reason, wide: true }] : []),
      ...(row.rotation.error ? [{ label: translateNow("operations.detail.failure"), value: row.rotation.error, wide: true }] : []),
      ...(row.rotation.idempotency_key ? [{ label: translateNow("operations.detail.idempotency"), value: row.rotation.idempotency_key, technical: true }] : []),
      ...(row.rotation.outbox_id !== undefined
        ? [{ label: translateNow("operations.detail.outbox"), value: String(row.rotation.outbox_id), technical: true }]
        : []),
      ...(row.rotation.rollback_ref ? [{ label: translateNow("operations.detail.rollback"), value: row.rotation.rollback_ref, technical: true }] : []),
    ];
  }
  return [
    ...common,
    { label: translateNow("operations.detail.requestId"), value: row.approval.id, technical: true },
    { label: translateNow("operations.detail.intentDigest"), value: row.approval.intent_digest, technical: true, wide: true },
    { label: translateNow("operations.detail.action"), value: row.approval.action },
    { label: translateNow("operations.detail.resource"), value: row.approval.resource_name || row.approval.resource_id },
  ];
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

function operationLabel(row: OperationRow): string {
  if (row.type === "rotation") return translateNow("operations.label.rotation");
  if (row.type === "approval") {
    return translateNow("operations.label.approval", {
      action: humanizeIdentifier(row.approval.action),
      resource: row.approval.resource_name || row.approval.resource_id,
    });
  }
  const destination = row.delivery.destination.split("/").filter(Boolean).at(-1) || row.delivery.target || row.delivery.connector;
  return translateNow("operations.label.deployment", { destination: humanizeIdentifier(destination) });
}

function operationSummary(row: OperationRow): string {
  if (row.type === "deployment") {
    if (isFailureStatus(row.statusKey)) {
      return row.delivery.attempts === 1
        ? translateNow("operations.summary.deploymentFailedOne")
        : translateNow("operations.summary.deploymentFailedMany", { count: row.delivery.attempts });
    }
    if (row.statusKey === "queued") return translateNow("operations.summary.deploymentQueued");
    if (row.statusKey === "delivered" || row.statusKey === "verified") return translateNow("operations.summary.deploymentCompleted");
    return translateNow("operations.summary.deploymentRunning");
  }
  if (row.type === "rotation") {
    if (row.statusKey === "failed") return translateNow("operations.summary.rotationFailed");
    if (row.statusKey === "running") return translateNow("operations.summary.rotationRunning");
    return translateNow("operations.summary.rotationCompleted");
  }
  return translateNow("operations.summary.approval", {
    count: row.approval.approval_count,
    required: row.approval.required_approvals,
  });
}

function humanStatus(row: OperationRow): string {
  if (row.statusKey === "awaiting_approval") return translateNow("operations.status.awaitingApproval");
  if (row.statusKey === "verify_failed") return translateNow("operations.status.verificationFailed");
  if (row.statusKey === "delivered") return translateNow("operations.status.delivered");
  if (row.statusKey === "succeeded") return translateNow("operations.status.completed");
  return humanizeIdentifier(row.statusKey);
}

function humanizeIdentifier(value: string): string {
  return value
    .replace(/[._/-]+/g, " ")
    .trim()
    .split(/\s+/)
    .map((part) => {
      const lower = part.toLowerCase();
      if (lower === "api") return "API";
      if (lower === "github") return "GitHub";
      if (lower === "ssh") return "SSH";
      if (lower === "spiffe") return "SPIFFE";
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

function waitLabel(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}

function statusTone(status: string) {
  if (status === "succeeded" || status === "delivered") return "success";
  if (isFailureStatus(status)) return "critical";
  if (status === "running") return "operate";
  if (status === "awaiting_approval" || isActiveStatus(status)) return "warning";
  return "neutral";
}

function isFailureStatus(status: string): boolean {
  return ["failed", "verify_failed", "rollback_refused", "rollback_failed", "dry_run_blocked"].includes(status);
}

function isActiveStatus(status: string): boolean {
  return ["queued", "running", "rollback_queued", "dry_run_queued"].includes(status);
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
