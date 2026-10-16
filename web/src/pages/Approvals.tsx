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
import {
  ApiError,
  UnauthorizedError,
  api,
  type EphemeralApproval,
  type IssuanceRequest,
  type PendingApprovalRequest,
  type ProfileEditApprovalRecord,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { hasPermission } from "@/lib/access";
import { approvalAuditHref, approvalRequestsQueryKey, approvalRows, requesterMatchesPrincipal, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { useApiQuery, useQueryClient } from "@/lib/query";

type Notice = { kind: "permission" | "error"; message: string };
type OpenSections = { queue: boolean; history: boolean; specialized: boolean };
const profileApprovalsQueryKey = ["profile-edit-approvals"] as const;

export function Approvals() {
  const { formatDate, t } = useTranslation();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canReadGeneral = ["certs:issue", "secrets:write", "keys:approve", "access:approve"].some((permission) => hasPermission(user, permission));
  const canReadIssuance = hasPermission(user, "certs:read");
  const canReadProfiles = hasPermission(user, "profiles:read");
  const canApproveProfiles = hasPermission(user, "profiles:write");
  const requests = useApiQuery(approvalRequestsQueryKey, api.approvalRequests, { enabled: canReadGeneral });
  const issuanceRequests = useApiQuery(issuanceRequestsQueryKey, readIssuanceRequests, { enabled: canReadIssuance });
  const profileApprovals = useApiQuery(profileApprovalsQueryKey, api.profileEditApprovals, { enabled: canReadProfiles });
  const [error, setError] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selectedRequest, setSelectedRequest] = useState<ApprovalQueueRow | null>(null);
  const [reviewDialogOpen, setReviewDialogOpen] = useState(false);
  const [rejectionOpen, setRejectionOpen] = useState(false);
  const [rejectionReason, setRejectionReason] = useState("");
  const [selectedIssuance, setSelectedIssuance] = useState<IssuanceRequest | null>(null);
  const [issuanceReviewOpen, setIssuanceReviewOpen] = useState(false);
  const [issuanceRejectionOpen, setIssuanceRejectionOpen] = useState(false);
  const [issuanceRejectionReason, setIssuanceRejectionReason] = useState("");
  const [selectedProfile, setSelectedProfile] = useState<ProfileEditApprovalRecord | null>(null);
  const profileReviewHeadingRef = useRef<HTMLHeadingElement>(null);
  const [open, setOpen] = useState<OpenSections>({ queue: false, history: false, specialized: false });
  const reviewHeadingRef = useRef<HTMLHeadingElement>(null);
  const issuanceReviewHeadingRef = useRef<HTMLHeadingElement>(null);
  const [ephemeralRequestID, setEphemeralRequestID] = useState("");
  const [ephemeralBusy, setEphemeralBusy] = useState(false);
  const [ephemeralError, setEphemeralError] = useState<string | null>(null);
  const [ephemeralApproval, setEphemeralApproval] = useState<EphemeralApproval | null>(null);

  const rows = useMemo(() => approvalRows(requests.data ?? []), [requests.data]);
  const issuanceItems = issuanceRequests.data?.items ?? [];
  const waitingIssuance = issuanceItems.filter((request) => request.status === "requested");
  const profileItems = profileApprovals.data?.items ?? [];
  const waitingProfiles = profileItems.filter((request) => request.state === "awaiting_approval");
  const waitingCount = rows.length + waitingIssuance.length + waitingProfiles.length;
  const reviewableRequest = rows.find((row) => !requesterMatchesPrincipal(row, user)) ?? null;
  const reviewableIssuance = waitingIssuance.find((request) => !issuanceRequesterMatchesPrincipal(request, user)) ?? null;
  const reviewableProfile = canApproveProfiles ? (waitingProfiles.find((request) => !profileRequesterMatchesPrincipal(request, user)) ?? null) : null;
  const ownOnly = waitingCount > 0 && !reviewableRequest && !reviewableIssuance && !reviewableProfile;
  const profileWriteNeeded = ownOnly && !canApproveProfiles && waitingProfiles.some((request) => !profileRequesterMatchesPrincipal(request, user));
  const queryError = canReadGeneral && requests.errorValue ? noticeForError(requests.errorValue) : null;
  const issuanceQueryError = canReadIssuance && issuanceRequests.errorValue ? noticeForError(issuanceRequests.errorValue) : null;
  const profileQueryError = canReadProfiles && profileApprovals.errorValue ? noticeForError(profileApprovals.errorValue) : null;
  const visibleError = error ?? queryError ?? issuanceQueryError ?? profileQueryError;
  const summaryLoading = (canReadGeneral && requests.loading) || (canReadIssuance && issuanceRequests.loading) || (canReadProfiles && profileApprovals.loading);

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

  const closeIssuanceReview = useCallback(() => {
    setIssuanceReviewOpen(false);
    setSelectedIssuance(null);
    setIssuanceRejectionOpen(false);
    setIssuanceRejectionReason("");
  }, []);

  const openIssuanceReview = useCallback((request: IssuanceRequest) => {
    setSelectedIssuance(request);
    setIssuanceRejectionOpen(false);
    setIssuanceRejectionReason("");
    setError(null);
    setNotice(null);
    setIssuanceReviewOpen(true);
  }, []);

  const approveProfile = useCallback(
    async (request: ProfileEditApprovalRecord) => {
      setBusyKey(`profile:${request.id}`);
      setError(null);
      setNotice(null);
      try {
        const updated = await api.approveProfileEditApproval(request.id);
        queryClient.setQueryData<{ items: ProfileEditApprovalRecord[] }>(profileApprovalsQueryKey, (current) =>
          current ? { ...current, items: current.items.map((item) => (item.id === updated.id ? updated : item)) } : current,
        );
        setNotice(t("approvals.profile.applied", { name: request.profile_name }));
        setSelectedProfile(null);
        setOpen((current) => ({ ...current, history: true }));
        void queryClient.invalidateQueries({ queryKey: profileApprovalsQueryKey });
      } catch (err) {
        setError({ kind: "error", message: approvalErrorMessage(err) });
        void queryClient.invalidateQueries({ queryKey: profileApprovalsQueryKey });
      } finally {
        setBusyKey(null);
      }
    },
    [queryClient, t],
  );

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

  const retainIssuanceDecision = useCallback(
    (updated: IssuanceRequest) => {
      queryClient.setQueryData<{ items: IssuanceRequest[]; open: number; guidance: string }>(issuanceRequestsQueryKey, (current) => {
        if (!current) return current;
        const items = current.items.map((request) => (request.id === updated.id ? updated : request));
        return { ...current, items, open: items.filter((request) => request.status === "requested").length };
      });
    },
    [queryClient],
  );

  const approveIssuance = useCallback(
    async (request: IssuanceRequest) => {
      setBusyKey(`issuance:${request.id}`);
      setError(null);
      setNotice(null);
      try {
        retainIssuanceDecision(await api.approveIssuanceRequest(request.id));
        setNotice(t("approvals.design.approvalRecorded", { action: "issue", resource: request.subject }));
        setOpen((current) => ({ ...current, history: true }));
        closeIssuanceReview();
        void queryClient.invalidateQueries({ queryKey: issuanceRequestsQueryKey });
      } catch (err) {
        setError({ kind: "error", message: approvalErrorMessage(err) });
      } finally {
        setBusyKey(null);
      }
    },
    [closeIssuanceReview, queryClient, retainIssuanceDecision, t],
  );

  async function denyIssuance(event: FormEvent<HTMLFormElement>, request: IssuanceRequest) {
    event.preventDefault();
    const reason = issuanceRejectionReason.trim();
    if (!reason) return;
    setBusyKey(`issuance:${request.id}`);
    setError(null);
    setNotice(null);
    try {
      retainIssuanceDecision(await api.denyIssuanceRequest(request.id, reason));
      setNotice(t("approvals.design.denialRecorded", { action: "issue", resource: request.subject }));
      setOpen((current) => ({ ...current, history: true }));
      closeIssuanceReview();
      void queryClient.invalidateQueries({ queryKey: issuanceRequestsQueryKey });
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
      openIssuanceReview(reviewableIssuance);
      return;
    }
    if (reviewableProfile) setSelectedProfile(reviewableProfile);
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
          ? t(profileWriteNeeded ? "approvals.profile.permissionNeeded" : "approvals.design.reviewOwn")
          : reviewableProfile && !reviewableRequest && !reviewableIssuance
            ? t("approvals.profile.reviewActionHelp")
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
        {!summaryLoading && !visibleError && !reviewableRequest && !reviewableIssuance && reviewableProfile ? (
          <ProfileRequestSummary request={reviewableProfile} />
        ) : null}
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
          {canReadProfiles && waitingProfiles.length > 0 ? (
            <section className="grid gap-2" aria-label={t("approvals.profile.queueTitle")}>
              <h3 className="font-semibold">{t("approvals.profile.queueTitle")}</h3>
              {waitingProfiles.map((request) => (
                <div key={request.id} className="flex flex-wrap items-center justify-between gap-3 rounded-control border border-border p-3">
                  <div>
                    <span className="font-medium">{request.profile_name}</span>
                    <p className="text-caption text-muted-foreground">
                      {request.requester} · {formatDate(request.expires_at)}
                    </p>
                  </div>
                  <Button type="button" variant="outline" onClick={() => setSelectedProfile(request)}>
                    {t("approvals.design.review")}
                  </Button>
                </div>
              ))}
            </section>
          ) : null}
        </div>
      </ApprovalDetails>

      <ApprovalDetails
        title={t("approvals.design.disclosure.history")}
        open={open.history}
        onToggle={(value) => setOpen((current) => ({ ...current, history: value }))}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("approvals.design.historyHelp")}</p>
          {open.history && canReadIssuance ? <IssuanceRequestsPanel currentPrincipal={user} /> : null}
          {open.history &&
          canReadIssuance &&
          !issuanceRequests.loading &&
          !issuanceRequests.errorValue &&
          issuanceItems.length === 0 &&
          profileItems.every((request) => request.state === "awaiting_approval") ? (
            <EmptyState title={t("approvals.design.emptyHistory")} />
          ) : null}
          {canReadProfiles && profileItems.some((request) => request.state !== "awaiting_approval") ? (
            <section className="grid gap-2" aria-label={t("approvals.profile.historyTitle")}>
              <h3 className="font-semibold">{t("approvals.profile.historyTitle")}</h3>
              {profileItems
                .filter((request) => request.state !== "awaiting_approval")
                .map((request) => (
                  <p key={request.id} className="rounded-control border border-border p-3 text-sm">
                    {request.profile_name} · {request.state} · {request.id}
                  </p>
                ))}
            </section>
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

      <Dialog
        open={Boolean(selectedProfile)}
        onClose={() => setSelectedProfile(null)}
        titleId="profile-review-request-heading"
        descriptionId="profile-review-request-description"
        initialFocusRef={profileReviewHeadingRef}
        panelAnimation="none"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(94vw,48rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {selectedProfile ? (
          <div className="grid gap-4 text-sm">
            <div>
              <h2 ref={profileReviewHeadingRef} id="profile-review-request-heading" className="text-title font-semibold" tabIndex={-1}>
                {t("approvals.design.review")}
              </h2>
              <p id="profile-review-request-description" className="mt-1 text-muted-foreground">
                {t("approvals.profile.reviewHelp")}
              </p>
            </div>
            <ProfileRequestSummary request={selectedProfile} />
            <dl className="grid gap-3 rounded-control border border-border bg-muted/20 p-4 sm:grid-cols-2">
              <ReviewFact label={t("approvals.design.requester")} value={selectedProfile.requester} />
              <ReviewFact label={t("approvals.design.approvalProgress")} value={`${selectedProfile.approvals.length}/${selectedProfile.required_approvals}`} />
              <ReviewFact label={t("approvals.design.expires")} value={formatDate(selectedProfile.expires_at)} />
              <ReviewFact label={t("approvals.design.requestId")} value={selectedProfile.id} mono />
              <ReviewFact label={t("approvals.profile.specDigest")} value={selectedProfile.spec_sha256} mono className="sm:col-span-2" />
              {selectedProfile.restored_from_version ? (
                <ReviewFact label={t("approvals.profile.restoreVersion")} value={String(selectedProfile.restored_from_version)} />
              ) : null}
              {selectedProfile.restore_reason ? <ReviewFact label={t("approvals.profile.restoreReason")} value={selectedProfile.restore_reason} /> : null}
            </dl>
            <section className="grid gap-2">
              <h3 className="font-semibold">{t("approvals.profile.proposedSpec")}</h3>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-control border border-border bg-muted/20 p-3 font-mono text-xs">
                {JSON.stringify(selectedProfile.spec, null, 2)}
              </pre>
              <Link className="w-fit text-brand-accent underline" to={`/audit?q=${encodeURIComponent(selectedProfile.id)}`}>
                {t("source.audit.trail.c1ada08ce1")}
              </Link>
            </section>
            {profileRequesterMatchesPrincipal(selectedProfile, user) ? (
              <p className="rounded-control border border-warning-border bg-warning-subtle p-3 text-warning-foreground">{t("approvals.design.selfApproval")}</p>
            ) : null}
            {error ? (
              <p role="alert" className="text-destructive">
                {error.message}
              </p>
            ) : null}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setSelectedProfile(null)}>
                {t("source.cancel.19766ed6cc")}
              </Button>
              <Button
                type="button"
                disabled={
                  busyKey === `profile:${selectedProfile.id}` ||
                  !canApproveProfiles ||
                  profileRequesterMatchesPrincipal(selectedProfile, user) ||
                  selectedProfile.state !== "awaiting_approval"
                }
                onClick={() => void approveProfile(selectedProfile)}
              >
                {t("approvals.design.approve")}
              </Button>
            </div>
          </div>
        ) : null}
      </Dialog>

      <Dialog
        open={issuanceReviewOpen && Boolean(selectedIssuance)}
        onClose={closeIssuanceReview}
        titleId="issuance-review-request-heading"
        descriptionId="issuance-review-request-description"
        initialFocusRef={issuanceReviewHeadingRef}
        panelAnimation="none"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(94vw,48rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {selectedIssuance ? (
          <div className="grid min-w-0 gap-4 text-sm">
            <div>
              <h2 ref={issuanceReviewHeadingRef} id="issuance-review-request-heading" className="text-title font-semibold" tabIndex={-1}>
                {t("approvals.design.review")}
              </h2>
              <p id="issuance-review-request-description" className="mt-1 max-w-3xl text-sm text-muted-foreground">
                {t("approvals.design.dialogHelp")}
              </p>
            </div>

            <IssuanceRequestSummary request={selectedIssuance} />

            <dl className="grid gap-3 rounded-control border border-border bg-muted/20 p-4 sm:grid-cols-2">
              <ReviewFact label={t("approvals.design.policyResult")} value={t("approvals.design.policyRequired")} />
              <ReviewFact label={t("approvals.design.requester")} value={selectedIssuance.requester} />
              <ReviewFact label={translateNow("source.profile.d696a35bdd")} value={selectedIssuance.profile || "—"} mono />
              <ReviewFact label={translateNow("source.owner.4b1b8aa360")} value={selectedIssuance.owner_id || "—"} mono />
              <ReviewFact label={t("approvals.design.expires")} value={formatDate(selectedIssuance.expires_at)} />
              <ReviewFact label={t("approvals.design.requestId")} value={selectedIssuance.id} mono />
            </dl>

            <section aria-labelledby="issuance-approval-evidence-heading" className="grid gap-2">
              <h3 id="issuance-approval-evidence-heading" className="font-semibold">
                {t("approvals.design.evidence")}
              </h3>
              <p className="text-caption text-muted-foreground">{t("approvals.design.evidenceBoundary")}</p>
              <Link className="w-fit text-brand-accent underline" to={`/audit?q=${encodeURIComponent(selectedIssuance.id)}`}>
                {t("source.audit.trail.c1ada08ce1")}
              </Link>
            </section>

            <p className="rounded-control border border-border bg-muted/20 p-3 text-sm text-muted-foreground">{t("approvals.design.consequence.issue")}</p>

            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {error.message}
              </p>
            ) : null}

            {issuanceRejectionOpen ? (
              <form className="grid gap-3 rounded-control border border-border p-4" onSubmit={(event) => void denyIssuance(event, selectedIssuance)}>
                <label className="grid gap-1 font-medium">
                  {t("approvals.design.rejectionReason")}
                  <input
                    className="ui-input font-normal"
                    value={issuanceRejectionReason}
                    onChange={(event) => setIssuanceRejectionReason(event.target.value)}
                    required
                  />
                </label>
                <div className="flex flex-wrap justify-end gap-2">
                  <Button type="button" variant="ghost" onClick={() => setIssuanceRejectionOpen(false)}>
                    {t("approvals.design.keepOpen")}
                  </Button>
                  <Button type="submit" variant="destructive" disabled={busyKey === `issuance:${selectedIssuance.id}` || !issuanceRejectionReason.trim()}>
                    {t("approvals.design.confirmRejection")}
                  </Button>
                </div>
              </form>
            ) : (
              <div className="flex flex-wrap justify-end gap-2">
                <Button type="button" variant="ghost" onClick={closeIssuanceReview}>
                  {t("source.cancel.19766ed6cc")}
                </Button>
                <Button type="button" variant="outline" disabled={busyKey === `issuance:${selectedIssuance.id}`} onClick={() => setIssuanceRejectionOpen(true)}>
                  {t("approvals.design.reject")}
                </Button>
                <Button type="button" disabled={busyKey === `issuance:${selectedIssuance.id}`} onClick={() => void approveIssuance(selectedIssuance)}>
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
        <ReviewFact
          label={t("request.wizard.issuerLabel")}
          value={
            request.issuer
              ? t("request.wizard.issuerSummary", { name: request.issuer.name, source: request.issuer.source, id: request.issuer.id })
              : t("request.wizard.issuerLegacy")
          }
        />
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
  const key = actionSummaryKey(row.action);
  return key === "caHierarchy.custody.actions.zeroize.label" ? translateNow(key, { keyId: resource }) : translateNow(key, { resource });
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
      return "approvals.design.action.delete";
    case "managedkey:zeroize":
      return "caHierarchy.custody.actions.zeroize.label";
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
      return "approvals.design.consequence.delete";
    case "managedkey:zeroize":
      return "approvals.design.consequence.managedKeyDelete";
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

function profileRequesterMatchesPrincipal(request: ProfileEditApprovalRecord, principal: { subject: string; email?: string } | null): boolean {
  if (!principal) return false;
  const requester = request.requester.trim().toLowerCase();
  return Boolean(requester && [principal.subject, principal.email].some((candidate) => candidate?.trim().toLowerCase() === requester));
}

function ProfileRequestSummary({ request }: { request: ProfileEditApprovalRecord }) {
  const { t } = useTranslation();
  return (
    <section aria-label={t("approvals.design.nextRequest")} className="grid gap-2 rounded-control border border-border bg-muted/20 p-4">
      <Eyebrow as="p">{t("approvals.design.change")}</Eyebrow>
      <h3 className="text-lg font-semibold">{request.profile_name}</h3>
      <p>{t("approvals.profile.consequence")}</p>
    </section>
  );
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
