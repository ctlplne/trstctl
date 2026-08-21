import { useCallback, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Info } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { IssuanceRequestsPanel, issuanceRequestsQueryKey, readIssuanceRequests } from "@/components/IssuanceRequestsPanel";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Eyebrow, Num } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { ApiError, UnauthorizedError, api, type EphemeralApproval, type IssuanceRequest, type PendingApprovalRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { approvalAuditHref, approvalRequestsQueryKey, approvalRows, requesterMatchesPrincipal, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { useApiQuery, useQueryClient } from "@/lib/query";

type Notice = { kind: "permission" | "error"; message: string };
type OpenSections = { queue: boolean; history: boolean; specialized: boolean };

export function Approvals() {
  const { formatDate, t } = useTranslation();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const requests = useApiQuery(approvalRequestsQueryKey, api.approvalRequests);
  const issuanceRequests = useApiQuery(issuanceRequestsQueryKey, readIssuanceRequests);
  const [error, setError] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selectedRequest, setSelectedRequest] = useState<ApprovalQueueRow | null>(null);
  const [reviewDialogOpen, setReviewDialogOpen] = useState(false);
  const [rejectionOpen, setRejectionOpen] = useState(false);
  const [rejectionReason, setRejectionReason] = useState("");
  const [open, setOpen] = useState<OpenSections>({ queue: false, history: false, specialized: false });
  const reviewHeadingRef = useRef<HTMLHeadingElement>(null);
  const [ephemeralRequestID, setEphemeralRequestID] = useState("");
  const [ephemeralBusy, setEphemeralBusy] = useState(false);
  const [ephemeralError, setEphemeralError] = useState<string | null>(null);
  const [ephemeralApproval, setEphemeralApproval] = useState<EphemeralApproval | null>(null);

  const rows = useMemo(() => approvalRows(requests.data ?? []), [requests.data]);
  const issuanceItems = issuanceRequests.data?.items ?? [];
  const waitingIssuance = issuanceItems.filter((request) => request.status === "requested");
  const waitingCount = rows.length + waitingIssuance.length;
  const reviewableRequest = rows.find((row) => !requesterMatchesPrincipal(row, user)) ?? null;
  const reviewableIssuance = waitingIssuance.find((request) => !issuanceRequesterMatchesPrincipal(request, user)) ?? null;
  const ownOnly = waitingCount > 0 && !reviewableRequest && !reviewableIssuance;
  const queryError = requests.errorValue ? noticeForError(requests.errorValue) : null;
  const issuanceQueryError = issuanceRequests.errorValue ? noticeForError(issuanceRequests.errorValue) : null;
  const visibleError = error ?? queryError ?? issuanceQueryError;
  const summaryLoading = requests.loading || issuanceRequests.loading;

  const closeReview = useCallback(() => {
    setReviewDialogOpen(false);
    setSelectedRequest(null);
    setRejectionOpen(false);
    setRejectionReason("");
  }, []);

  const openReview = useCallback((row: ApprovalQueueRow) => {
    setSelectedRequest(row);
    setRejectionOpen(false);
    setRejectionReason("");
    setError(null);
    setNotice(null);
    setReviewDialogOpen(true);
  }, []);

  const retainDecision = useCallback(
    (row: ApprovalQueueRow, result: { approval_count: number; required_approvals: number; status: PendingApprovalRequest["status"] }) => {
      queryClient.setQueryData<PendingApprovalRequest[]>(approvalRequestsQueryKey, (current) =>
        current
          ?.map((request) =>
            request.id === row.id
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
    },
    [queryClient],
  );

  const approve = useCallback(
    async (row: ApprovalQueueRow) => {
      const key = rowKey(row);
      setBusyKey(key);
      setError(null);
      setNotice(null);
      try {
        const result = await api.approveApprovalRequest(row.id, row.intent_digest);
        retainDecision(row, result);
        setNotice(t("approvals.design.approvalRecorded", { action: row.action, resource: row.resource_name || row.resource_id }));
        closeReview();
        void queryClient.invalidateQueries({ queryKey: approvalRequestsQueryKey });
      } catch (err) {
        setError({ kind: "error", message: approvalErrorMessage(err) });
      } finally {
        setBusyKey(null);
      }
    },
    [closeReview, queryClient, retainDecision, t],
  );

  async function deny(event: FormEvent<HTMLFormElement>, row: ApprovalQueueRow) {
    event.preventDefault();
    const reason = rejectionReason.trim();
    if (!reason) return;
    setBusyKey(rowKey(row));
    setError(null);
    setNotice(null);
    try {
      const result = await api.denyApprovalRequest(row.id, row.intent_digest, reason);
      retainDecision(row, result);
      setNotice(t("approvals.design.denialRecorded", { action: row.action, resource: row.resource_name || row.resource_id }));
      closeReview();
      void queryClient.invalidateQueries({ queryKey: approvalRequestsQueryKey });
    } catch (err) {
      setError({ kind: "error", message: approvalErrorMessage(err) });
    } finally {
      setBusyKey(null);
    }
  }

  function reviewNextRequest() {
    if (reviewableRequest) {
      openReview(reviewableRequest);
      return;
    }
    if (reviewableIssuance) {
      setOpen((current) => ({ ...current, history: true }));
    }
  }

  async function approveEphemeralCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEphemeralError(null);
    setEphemeralApproval(null);
    setEphemeralBusy(true);
    try {
      const resourceID = ephemeralRequestID.trim();
      const exactRequest = rows.find((request) => request.resource_kind === "ephemeral" && request.resource_id === resourceID && request.action === "issue");
      if (!exactRequest) throw new Error(t("source.no.pending.approvals.261de9be5f"));
      const result = await api.approveEphemeralCredential(exactRequest.id, {
        action: "issue",
        request_id: exactRequest.id,
        intent_digest: exactRequest.intent_digest,
      });
      setEphemeralApproval(result);
      setEphemeralRequestID("");
    } catch (err) {
      setEphemeralError(approvalErrorMessage(err));
    } finally {
      setEphemeralBusy(false);
    }
  }

  const columns = useMemo<Array<DataGridColumn<ApprovalQueueRow>>>(
    () => [
      {
        id: "resource",
        header: t("approvals.design.change"),
        sortable: true,
        cell: (row) => (
          <div className="grid gap-0.5">
            <span className="font-medium">{row.resource_name || row.resource_id}</span>
            <span className="text-caption text-muted-foreground">{actionSummary(row)}</span>
            <span className="font-mono text-xs text-muted-foreground">
              {row.resource_kind} · {row.resource_id}
            </span>
          </div>
        ),
      },
      {
        id: "requester",
        header: t("approvals.design.requester"),
        cell: (row) => row.requester,
      },
      {
        id: "reason",
        header: t("approvals.design.why"),
        cell: (row) => row.reason || t("approvals.design.noReason"),
      },
      {
        id: "quorum",
        header: (
          <span className="inline-flex items-center gap-1" title={t("source.recorded.approvals.and.required.approvals.4d359a312b")}>
            {t("source.approvals.2bfc347157")}
            <Info className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        ),
        cell: (row) => <ApprovalQuorum have={row.approval_count} need={row.required_approvals} />,
      },
      {
        id: "grant",
        header: t("approvals.design.expires"),
        cell: (row) => <span className="whitespace-nowrap">{formatDate(row.expires_at)}</span>,
      },
      {
        id: "evidence",
        header: t("approvals.design.evidence"),
        cell: (row) => (
          <div className="grid gap-1">
            <span>
              {row.evidence_refs.length > 0
                ? t("approvals.design.evidenceCount", { count: String(row.evidence_refs.length) })
                : t("approvals.design.noEvidence")}
            </span>
            <Link className="text-brand-accent underline" to={approvalAuditHref(row)}>
              {t("source.audit.trail.c1ada08ce1")}
            </Link>
          </div>
        ),
      },
      {
        id: "decision",
        header: t("approvals.design.review"),
        cell: (row) => (
          <Button type="button" size="sm" variant="outline" onClick={() => openReview(row)}>
            {t("approvals.design.review")}
          </Button>
        ),
      },
    ],
    [formatDate, openReview, t],
  );

  const summaryTitle = summaryLoading
    ? t("approvals.design.checking")
    : visibleError
      ? t("approvals.design.unknown")
      : waitingCount === 0
        ? t("approvals.design.emptyTitle")
        : waitingCount === 1
          ? t("approvals.design.oneWaitingTitle")
          : t("approvals.design.manyWaitingTitle", { count: String(waitingCount) });
  const countText = waitingCount === 1 ? t("approvals.design.oneWaiting") : t("approvals.design.manyWaiting", { count: String(waitingCount) });
  const reviewActionHelp = summaryLoading
    ? t("approvals.design.reviewChecking")
    : visibleError
      ? t("approvals.design.reviewUnknown")
      : waitingCount === 0
        ? t("approvals.design.reviewEmpty")
        : ownOnly
          ? t("approvals.design.reviewOwn")
          : t("approvals.design.reviewHelp");

  return (
    <section aria-labelledby="approvals-heading" className="space-y-4">
      <PageHeader
        title={t("approvals.design.title")}
        titleId="approvals-heading"
        description={t("approvals.design.answer")}
        technicalDetails={t("approvals.design.technicalDetails")}
        actions={
          <Button
            type="button"
            aria-describedby="review-request-action-help"
            disabled={summaryLoading || Boolean(visibleError) || waitingCount === 0 || ownOnly}
            onClick={reviewNextRequest}
          >
            {t("approvals.design.review")}
          </Button>
        }
      />

      <section aria-labelledby="approval-summary-heading" className="ui-panel grid gap-4 p-comfortable">
        <div className="grid gap-1">
          <h2 id="approval-summary-heading" className="text-title font-semibold">
            {summaryTitle}
          </h2>
          {!summaryLoading && !visibleError ? <p className="text-body">{countText}</p> : null}
          <p id="review-request-action-help" className="max-w-3xl text-caption text-muted-foreground">
            {reviewActionHelp}
          </p>
        </div>

        {!summaryLoading && !visibleError && reviewableRequest ? <GenericRequestSummary row={reviewableRequest} /> : null}
        {!summaryLoading && !visibleError && !reviewableRequest && reviewableIssuance ? <IssuanceRequestSummary request={reviewableIssuance} /> : null}
      </section>

      {notice && (
        <p role="status" className="rounded-control border border-border bg-card p-3 text-body text-status-success">
          {notice}
        </p>
      )}
      {visibleError?.kind === "permission" && <PermissionDeniedState>{visibleError.message}</PermissionDeniedState>}
      {visibleError?.kind === "error" && <ErrorState title={t("source.approvals.unavailable.8071a7e2c8")}>{visibleError.message}</ErrorState>}

      <ApprovalDetails
        title={t("approvals.design.disclosure.queue")}
        open={open.queue}
        onToggle={(value) => setOpen((current) => ({ ...current, queue: value }))}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("approvals.design.queueHelp")}</p>
          {requests.loading && !visibleError && <LoadingState>{t("source.loading.approvals.192880172b")}</LoadingState>}
          {requests.data && !visibleError && rows.length === 0 && <EmptyState title={t("approvals.design.emptyQueue")} />}
          {requests.data && !visibleError && rows.length > 0 && (
            <DataGrid ariaLabel={t("approvals.design.queueLabel")} rows={rows} columns={columns} getRowId={rowKey} />
          )}
        </div>
      </ApprovalDetails>

      <ApprovalDetails
        title={t("approvals.design.disclosure.history")}
        open={open.history}
        onToggle={(value) => setOpen((current) => ({ ...current, history: value }))}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("approvals.design.historyHelp")}</p>
          {open.history ? <IssuanceRequestsPanel currentPrincipal={user} /> : null}
          {open.history && !issuanceRequests.loading && !issuanceRequests.errorValue && issuanceItems.length === 0 ? (
            <EmptyState title={t("approvals.design.emptyHistory")} />
          ) : null}
        </div>
      </ApprovalDetails>

      <ApprovalDetails
        title={t("approvals.design.disclosure.specialized")}
        open={open.specialized}
        onToggle={(value) => setOpen((current) => ({ ...current, specialized: value }))}
      >
        <section aria-labelledby="ephemeral-approvals-heading" className="grid max-w-xl gap-3">
          <div>
            <h2 id="ephemeral-approvals-heading" className="text-title font-semibold">
              {t("parity.ephemeralCredentialApprovals_9a4b68")}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">{t("approvals.design.specializedHelp")}</p>
          </div>
          <form aria-label={t("parity.approveEphemeralCredential_760861")} className="grid gap-3" onSubmit={(event) => void approveEphemeralCredential(event)}>
            <label className="grid gap-1 text-body font-medium">
              {t("parity.requestId_63aa59")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                value={ephemeralRequestID}
                onChange={(event) => setEphemeralRequestID(event.target.value)}
                placeholder={t("parity.req7c2f9a_03dd4e")}
                required
              />
            </label>
            <div>
              <Button type="submit" disabled={ephemeralBusy || !ephemeralRequestID.trim()}>
                {t("source.approve.issue.a4353290b7")}
              </Button>
            </div>
          </form>
          {ephemeralError && (
            <p role="alert" className="text-sm text-destructive">
              {ephemeralError}
            </p>
          )}
          {ephemeralApproval && (
            <p role="status" className="text-body text-status-success">
              {t("source.value1.approval.recorded.for.value2.by.val.87cb845f84", {
                value1: ephemeralApproval.action,
                value2: ephemeralApproval.resource,
                value3: ephemeralApproval.approver,
                value4: ephemeralApproval.approvals,
              })}
            </p>
          )}
        </section>
      </ApprovalDetails>

      <Dialog
        open={reviewDialogOpen && Boolean(selectedRequest)}
        onClose={closeReview}
        titleId="review-request-heading"
        descriptionId="review-request-description"
        initialFocusRef={reviewHeadingRef}
        panelAnimation="none"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(94vw,48rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {selectedRequest ? (
          <div className="grid min-w-0 gap-4 text-sm">
            <div>
              <h2 ref={reviewHeadingRef} id="review-request-heading" className="text-title font-semibold" tabIndex={-1}>
                {t("approvals.design.review")}
              </h2>
              <p id="review-request-description" className="mt-1 max-w-3xl text-sm text-muted-foreground">
                {t("approvals.design.dialogHelp")}
              </p>
            </div>

            <GenericRequestSummary row={selectedRequest} detailed />

            <dl className="grid gap-3 rounded-control border border-border bg-muted/20 p-4 sm:grid-cols-2">
              <ReviewFact label={t("approvals.design.policyResult")} value={t("approvals.design.policyRequired")} />
              <ReviewFact label={t("approvals.design.requester")} value={selectedRequest.requester} />
              <ReviewFact label={t("approvals.design.approvalProgress")} value={`${selectedRequest.approval_count}/${selectedRequest.required_approvals}`} />
              <ReviewFact label={t("approvals.design.expires")} value={formatDate(selectedRequest.expires_at)} />
              <ReviewFact label={t("approvals.design.requestId")} value={selectedRequest.id} mono />
              <ReviewFact label={t("approvals.design.targetVersion")} value={selectedRequest.target_version} mono />
              <ReviewFact label={t("approvals.design.intentDigest")} value={selectedRequest.intent_digest} mono className="sm:col-span-2" />
            </dl>

            <section aria-labelledby="approval-evidence-heading" className="grid gap-2">
              <h3 id="approval-evidence-heading" className="font-semibold">
                {t("approvals.design.evidence")}
              </h3>
              {selectedRequest.evidence_refs.length > 0 ? (
                <ul className="grid gap-1 rounded-control border border-border p-3 font-mono text-xs">
                  {selectedRequest.evidence_refs.map((reference) => (
                    <li key={reference} className="break-all">
                      {reference}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted-foreground">{t("approvals.design.noEvidence")}</p>
              )}
              <p className="text-caption text-muted-foreground">{t("approvals.design.evidenceBoundary")}</p>
              <Link className="w-fit text-brand-accent underline" to={approvalAuditHref(selectedRequest)}>
                {t("source.audit.trail.c1ada08ce1")}
              </Link>
            </section>

            {requesterMatchesPrincipal(selectedRequest, user) ? (
              <p id="self-approval-help" className="rounded-control border border-warning-border bg-warning-subtle p-3 text-sm text-warning-foreground">
                {t("approvals.design.selfApproval")}
              </p>
            ) : null}

            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {error.message}
              </p>
            ) : null}

            {rejectionOpen ? (
              <form className="grid gap-3 rounded-control border border-border p-4" onSubmit={(event) => void deny(event, selectedRequest)}>
                <label className="grid gap-1 font-medium">
                  {t("approvals.design.rejectionReason")}
                  <input className="ui-input font-normal" value={rejectionReason} onChange={(event) => setRejectionReason(event.target.value)} required />
                </label>
                <div className="flex flex-wrap justify-end gap-2">
                  <Button type="button" variant="ghost" onClick={() => setRejectionOpen(false)}>
                    {t("approvals.design.keepOpen")}
                  </Button>
                  <Button type="submit" variant="destructive" disabled={busyKey === rowKey(selectedRequest) || !rejectionReason.trim()}>
                    {t("approvals.design.confirmRejection")}
                  </Button>
                </div>
              </form>
            ) : (
              <div className="flex flex-wrap justify-end gap-2">
                <Button type="button" variant="ghost" onClick={closeReview}>
                  {t("source.cancel.19766ed6cc")}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  disabled={busyKey === rowKey(selectedRequest) || requesterMatchesPrincipal(selectedRequest, user)}
                  aria-describedby={requesterMatchesPrincipal(selectedRequest, user) ? "self-approval-help" : undefined}
                  onClick={() => setRejectionOpen(true)}
                >
                  {t("approvals.design.reject")}
                </Button>
                <Button
                  type="button"
                  disabled={busyKey === rowKey(selectedRequest) || requesterMatchesPrincipal(selectedRequest, user)}
                  aria-describedby={requesterMatchesPrincipal(selectedRequest, user) ? "self-approval-help" : undefined}
                  onClick={() => void approve(selectedRequest)}
                >
                  {t("approvals.design.approve")}
                </Button>
              </div>
            )}
          </div>
        ) : null}
      </Dialog>
    </section>
  );
}

function ApprovalDetails({ title, open, onToggle, children }: { title: string; open: boolean; onToggle: (open: boolean) => void; children: ReactNode }) {
  return (
    <details className="rounded-panel border border-border bg-card shadow-elevation1" open={open} onToggle={(event) => onToggle(event.currentTarget.open)}>
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      <div className="border-t border-border p-4">{open ? children : null}</div>
    </details>
  );
}

function GenericRequestSummary({ row, detailed = false }: { row: ApprovalQueueRow; detailed?: boolean }) {
  const { formatDate, t } = useTranslation();
  return (
    <section aria-label={t("approvals.design.nextRequest")} className="grid gap-3 rounded-control border border-border bg-muted/20 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Eyebrow as="p">{t("approvals.design.change")}</Eyebrow>
          <h3 className="mt-1 text-lg font-semibold">{actionSummary(row)}</h3>
        </div>
        <StatusBadge vocabulary="lifecycle" value="pending" label={t("approvals.design.policyRequiredShort")} tone="warning" />
      </div>
      <dl className="grid gap-3 sm:grid-cols-3">
        <ReviewFact label={t("approvals.design.why")} value={row.reason || t("approvals.design.noReason")} />
        <ReviewFact label={t("approvals.design.consequence")} value={t(consequenceKey(row.action))} />
        <ReviewFact label={t("approvals.design.requester")} value={row.requester} />
      </dl>
      {!detailed ? <p className="text-caption text-muted-foreground">{t("approvals.design.expiresOn", { date: formatDate(row.expires_at) })}</p> : null}
    </section>
  );
}

function IssuanceRequestSummary({ request }: { request: IssuanceRequest }) {
  const { formatDate, t } = useTranslation();
  return (
    <section aria-label={t("approvals.design.nextRequest")} className="grid gap-3 rounded-control border border-border bg-muted/20 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Eyebrow as="p">{t("approvals.design.change")}</Eyebrow>
          <h3 className="mt-1 text-lg font-semibold">{t("approvals.design.issueSubject", { subject: request.subject })}</h3>
        </div>
        <StatusBadge vocabulary="lifecycle" value="pending" label={t("approvals.design.policyRequiredShort")} tone="warning" />
      </div>
      <dl className="grid gap-3 sm:grid-cols-3">
        <ReviewFact label={t("approvals.design.why")} value={request.justification || t("approvals.design.noReason")} />
        <ReviewFact label={t("approvals.design.consequence")} value={t("approvals.design.consequence.issue")} />
        <ReviewFact label={t("approvals.design.requester")} value={request.requester} />
      </dl>
      <p className="text-caption text-muted-foreground">{t("approvals.design.expiresOn", { date: formatDate(request.expires_at) })}</p>
    </section>
  );
}

function ReviewFact({ label, value, mono = false, className = "" }: { label: string; value: string; mono?: boolean; className?: string }) {
  return (
    <div className={className}>
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className={`mt-1 break-words text-sm ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

function actionSummary(row: ApprovalQueueRow): string {
  const resource = row.resource_name || row.resource_id;
  return translateNow(actionSummaryKey(row.action), { resource });
}

function actionSummaryKey(action: ApprovalQueueRow["action"]): MessageKey {
  switch (action) {
    case "issue":
      return "approvals.design.action.issue";
    case "create":
      return "approvals.design.action.create";
    case "rotate":
    case "managedkey:rotate":
      return "approvals.design.action.rotate";
    case "revoke":
    case "managedkey:revoke":
      return "approvals.design.action.revoke";
    case "sign":
      return "approvals.design.action.sign";
    case "recover":
      return "approvals.design.action.recover";
    case "delete":
    case "managedkey:zeroize":
      return "approvals.design.action.delete";
  }
}

function consequenceKey(action: ApprovalQueueRow["action"]): MessageKey {
  switch (action) {
    case "issue":
      return "approvals.design.consequence.issue";
    case "create":
      return "approvals.design.consequence.create";
    case "rotate":
    case "managedkey:rotate":
      return "approvals.design.consequence.rotate";
    case "revoke":
    case "managedkey:revoke":
      return "approvals.design.consequence.revoke";
    case "sign":
      return "approvals.design.consequence.sign";
    case "recover":
      return "approvals.design.consequence.recover";
    case "delete":
    case "managedkey:zeroize":
      return "approvals.design.consequence.delete";
  }
}

function rowKey(row: ApprovalQueueRow): string {
  return row.id;
}

function issuanceRequesterMatchesPrincipal(request: IssuanceRequest, principal: { subject: string; email?: string } | null): boolean {
  if (!principal) return false;
  const requester = request.requester.trim().toLowerCase();
  return Boolean(requester && [principal.subject, principal.email].some((candidate) => candidate?.trim().toLowerCase() === requester));
}

function ApprovalQuorum({ have, need }: { have: number; need: number }) {
  const remaining = Math.max(0, need - have);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="inline-flex items-baseline gap-1" aria-label={translateNow("source.value1.value2.7d8908f134", { value1: have, value2: need })}>
        <Num className="font-medium">{String(have)}</Num>
        <span className="text-caption text-muted-foreground">/</span>
        <Num>{String(need)}</Num>
      </span>
      {remaining > 0 ? (
        <StatusBadge vocabulary="lifecycle" value="pending" label={translateNow("approvals.quorum.remaining", { count: String(remaining) })} tone="warning" />
      ) : (
        <StatusBadge vocabulary="lifecycle" value="approved" label={translateNow("approvals.quorum.met")} tone="success" />
      )}
    </div>
  );
}

function noticeForError(err: unknown): Notice {
  if (err instanceof UnauthorizedError) {
    return { kind: "permission", message: translateNow("source.your.session.cannot.read.tenant.approval.r.220db554b4") };
  }
  return { kind: "error", message: apiProblemMessage(err, "Could not load approvals") };
}

function approvalErrorMessage(err: unknown): string {
  if (err instanceof ApiError && err.isRateLimited) {
    return err.retryAfterSeconds != null
      ? `Approval rate limited — please retry in ${err.retryAfterSeconds}s.`
      : "Approval rate limited — please retry shortly.";
  }
  return apiProblemMessage(err, "Approval failed");
}
