import { useCallback, useMemo, useState, type FormEvent } from "react";
import { IssuanceRequestsPanel } from "@/components/IssuanceRequestsPanel";
import { Info } from "lucide-react";
import { Link } from "react-router-dom";
import { ApiError, UnauthorizedError, api, type EphemeralApproval, type PendingApprovalRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { approvalAuditHref, approvalRequestsQueryKey, approvalRows, requesterMatchesPrincipal, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { Num } from "@/components/typography";
import { useAuth } from "@/auth/AuthProvider";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

type Notice = { kind: "permission" | "error"; message: string };

export function Approvals() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const requests = useApiQuery(approvalRequestsQueryKey, api.approvalRequests);
  const [error, setError] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [ephemeralRequestID, setEphemeralRequestID] = useState("");
  const [ephemeralBusy, setEphemeralBusy] = useState(false);
  const [ephemeralError, setEphemeralError] = useState<string | null>(null);
  const [ephemeralApproval, setEphemeralApproval] = useState<EphemeralApproval | null>(null);
  const rows = useMemo(() => approvalRows(requests.data ?? []), [requests.data]);
  const queryError = requests.errorValue ? noticeForError(requests.errorValue) : null;
  const visibleError = error ?? queryError;

  const approve = useCallback(
    async (row: ApprovalQueueRow) => {
      const key = rowKey(row);
      setBusyKey(key);
      setError(null);
      setNotice(null);
      try {
        const result = await api.approveApprovalRequest(row.id, row.intent_digest);
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
        setNotice(`${row.action} approval recorded for ${row.resource_name || row.resource_id} (${result.approval_count})`);
        void queryClient.invalidateQueries({ queryKey: approvalRequestsQueryKey });
      } catch (err) {
        setError({ kind: "error", message: approvalErrorMessage(err) });
      } finally {
        setBusyKey(null);
      }
    },
    [queryClient],
  );

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
        header: "Resource",
        sortable: true,
        cell: (row) => (
          <div className="grid gap-0.5">
            <span className="font-medium">{row.resource_name || row.resource_id}</span>
            <span className="font-mono text-xs text-muted-foreground">
              {row.resource_kind} · {row.resource_id}
            </span>
            <span className="text-caption text-muted-foreground">
              {translateNow("parity.requestId_63aa59")}: <span className="font-mono">{row.id}</span>
            </span>
            <span className="text-caption text-muted-foreground">
              {translateNow("source.version.dd167905de")}: <span className="font-mono">{row.target_version}</span>
            </span>
          </div>
        ),
      },
      {
        id: "action",
        header: "Action",
        cell: (row) => <StatusBadge vocabulary="lifecycle" value={statusForApprovalAction(row.action)} label={row.action} />,
      },
      {
        id: "requester",
        header: "Requester",
        cell: (row) => row.requester,
      },
      {
        id: "reason",
        header: translateNow("policy.accessChange.reason"),
        cell: (row) => row.reason || "—",
      },
      {
        id: "quorum",
        header: (
          <span className="inline-flex items-center gap-1" title={translateNow("source.recorded.approvals.and.required.approvals.4d359a312b")}>
            {translateNow("source.approvals.2bfc347157")}
            <Info className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        ),
        cell: (row) => <ApprovalQuorum have={row.approval_count} need={row.required_approvals} />,
      },
      {
        id: "grant",
        header: "Time-bound grant",
        cell: (row) => (
          <div className="grid gap-0.5 text-caption">
            <span>
              {translateNow("source.created.d70b9e24bc")}: <span className="font-mono">{row.created_at}</span>
            </span>
            <span>
              {translateNow("source.expires.f6725f3af0")}: <span className="font-mono">{row.expires_at}</span>
            </span>
          </div>
        ),
      },
      {
        id: "audit",
        header: "Evidence",
        cell: (row) => (
          <div className="grid gap-1">
            <span className="font-mono text-xs" title={row.intent_digest}>
              {row.intent_digest}
            </span>
            {row.evidence_refs.length > 0 ? (
              <ul className="grid gap-0.5 text-caption text-muted-foreground">
                {row.evidence_refs.map((reference) => (
                  <li key={reference} className="font-mono">
                    {reference}
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-caption text-muted-foreground">{translateNow("policy.accessChange.noEvidenceRef")}</span>
            )}
            <Link className="text-brand-accent underline" to={approvalAuditHref(row)}>
              {translateNow("source.audit.trail.c1ada08ce1")}
            </Link>
          </div>
        ),
      },
      {
        id: "decision",
        header: "Decision",
        cell: (row) => {
          const selfApproval = requesterMatchesPrincipal(row, user);
          const describedBy = selfApproval ? `approval-disabled-${rowKey(row)}` : undefined;
          return (
            <div className="grid gap-1">
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={busyKey === rowKey(row) || selfApproval}
                aria-describedby={describedBy}
                onClick={() => void approve(row)}
              >
                {translateNow("source.approve.value1.for.value2.f59c2fc633", {
                  value1: row.action,
                  value2: row.resource_name || row.resource_id,
                })}
              </Button>
              {selfApproval && (
                <p id={describedBy} className="max-w-xs text-xs text-muted-foreground">
                  Requesters cannot approve their own request; use a distinct approver.
                </p>
              )}
            </div>
          );
        },
      },
    ],
    [approve, busyKey, user],
  );

  return (
    <section aria-labelledby="approvals-heading" className="space-y-6">
      <PageHeader title={translateNow("source.approvals.2bfc347157")} titleId="approvals-heading" />
      <IssuanceRequestsPanel />

      {notice && (
        <p role="status" className="text-body text-status-success">
          {notice}
        </p>
      )}
      {visibleError?.kind === "permission" && <PermissionDeniedState>{visibleError.message}</PermissionDeniedState>}
      {visibleError?.kind === "error" && <ErrorState title={translateNow("source.approvals.unavailable.8071a7e2c8")}>{visibleError.message}</ErrorState>}
      {requests.loading && !visibleError && <LoadingState>{translateNow("source.loading.approvals.192880172b")}</LoadingState>}
      {requests.data && !visibleError && rows.length === 0 && <EmptyState title={translateNow("source.no.pending.approvals.261de9be5f")} />}
      {requests.data && !visibleError && rows.length > 0 && <DataGrid ariaLabel="Pending approvals" rows={rows} columns={columns} getRowId={rowKey} />}

      <section aria-labelledby="ephemeral-approvals-heading" className="ui-panel grid max-w-xl gap-3 p-comfortable">
        <div>
          <h2 id="ephemeral-approvals-heading" className="text-title font-semibold">
            {t("parity.ephemeralCredentialApprovals_9a4b68")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Paste the requester&apos;s client request ID. trstctl finds its exact immutable pending queue record before recording approval.
          </p>
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
              {translateNow("source.approve.issue.a4353290b7")}
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
            {translateNow("source.value1.approval.recorded.for.value2.by.val.87cb845f84", {
              value1: ephemeralApproval.action,
              value2: ephemeralApproval.resource,
              value3: ephemeralApproval.approver,
              value4: ephemeralApproval.approvals,
            })}
          </p>
        )}
      </section>
    </section>
  );
}

function rowKey(row: ApprovalQueueRow): string {
  return row.id;
}

/** S-C18: show the quorum as have/need with what is still outstanding, so an
 * approver reads one number instead of parsing a sentence. Text the server
 * emits in a shape we do not recognize is passed through untouched rather
 * than guessed at. */
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

function statusForApprovalAction(action: ApprovalQueueRow["action"]): string {
  switch (action) {
    case "issue":
      return "requested";
    case "rotate":
      return "renewing";
    case "revoke":
      return "revoked";
    default:
      return "pending";
  }
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
