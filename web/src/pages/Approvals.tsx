import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Info } from "lucide-react";
import { Link } from "react-router-dom";
import { ApiError, UnauthorizedError, api, type EphemeralApproval, type Identity } from "@/lib/api";
import { approvalAuditHref, approvalRows, requesterMatchesPrincipal, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { useAuth } from "@/auth/AuthProvider";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";

type Notice = { kind: "permission" | "error"; message: string };

export function Approvals() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [identities, setIdentities] = useState<Identity[] | null>(null);
  const [error, setError] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [ephemeralRequestID, setEphemeralRequestID] = useState("");
  const [ephemeralBusy, setEphemeralBusy] = useState(false);
  const [ephemeralError, setEphemeralError] = useState<string | null>(null);
  const [ephemeralApproval, setEphemeralApproval] = useState<EphemeralApproval | null>(null);
  const rows = useMemo(() => approvalRows(identities ?? []), [identities]);

  const load = useCallback(async () => {
    setError(null);
    try {
      setIdentities(await api.identities());
    } catch (err) {
      setIdentities(null);
      setError(noticeForError(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const approve = useCallback(
    async (row: ApprovalQueueRow) => {
      const key = rowKey(row);
      setBusyKey(key);
      setError(null);
      setNotice(null);
      try {
        const result = await api.approveIdentityAction(row.identity.id, row.action);
        setNotice(`${result.action} approval recorded for ${result.resource} (${result.approvals})`);
        await load();
      } catch (err) {
        setError({ kind: "error", message: approvalErrorMessage(err) });
      } finally {
        setBusyKey(null);
      }
    },
    [load],
  );

  async function approveEphemeralCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEphemeralError(null);
    setEphemeralApproval(null);
    setEphemeralBusy(true);
    try {
      const result = await api.approveEphemeralCredential(ephemeralRequestID.trim(), { action: "issue" });
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
        cell: (row) => <span className="font-medium">{row.identity.name}</span>,
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
        id: "quorum",
        header: (
          <span className="inline-flex items-center gap-1" title="Recorded approvals and required approvals for this request.">
            Approvals
            <Info className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        ),
        cell: (row) => row.approvals,
      },
      {
        id: "grant",
        header: "Time-bound grant",
        cell: (row) => row.grantExpiresAt,
      },
      {
        id: "audit",
        header: "Evidence",
        cell: (row) => (
          <Link className="text-brand-accent underline" to={approvalAuditHref(row)}>
            Audit trail
          </Link>
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
                {`Approve ${row.action} for ${row.identity.name}`}
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
      <PageHeader
        title="Approvals"
        titleId="approvals-heading"
        description="Dual-control issue, rotate, and revoke decisions for a distinct approver. The queue is built from pending identities; quorum and requester details appear when identity attributes carry them."
      />

      {notice && (
        <p role="status" className="text-body text-status-success">
          {notice}
        </p>
      )}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title="Approvals unavailable">{error.message}</ErrorState>}
      {!identities && !error && <LoadingState>Loading approvals...</LoadingState>}
      {identities && rows.length === 0 && (
        <EmptyState title="No pending approvals">No identities currently require an issue, rotate, or revoke approval.</EmptyState>
      )}
      {identities && rows.length > 0 && <DataGrid ariaLabel="Pending approvals" rows={rows} columns={columns} getRowId={rowKey} />}

      <section aria-labelledby="ephemeral-approvals-heading" className="ui-panel grid max-w-xl gap-3 p-comfortable">
        <div>
          <h2 id="ephemeral-approvals-heading" className="text-title font-semibold">
            {t("parity.ephemeralCredentialApprovals_9a4b68")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Attestation-gated JIT credentials awaiting quorum. There is no server-side pending list; paste the request id from the requester.
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
              Approve issue
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
            {`${ephemeralApproval.action} approval recorded for ${ephemeralApproval.resource} by ${ephemeralApproval.approver} (${ephemeralApproval.approvals} approvals)`}
          </p>
        )}
      </section>
    </section>
  );
}

function rowKey(row: ApprovalQueueRow): string {
  return `${row.identity.id}:${row.action}`;
}

function statusForApprovalAction(action: ApprovalQueueRow["action"]): string {
  switch (action) {
    case "issue":
      return "requested";
    case "rotate":
      return "renewing";
    case "revoke":
      return "revoked";
  }
}

function noticeForError(err: unknown): Notice {
  if (err instanceof UnauthorizedError) {
    return { kind: "permission", message: "Your session cannot read tenant approval requests." };
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

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
