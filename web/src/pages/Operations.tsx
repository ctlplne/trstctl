import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { CheckCircle2, RefreshCw, XCircle } from "lucide-react";
import { approvalRows, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { api, ApiError, type ConnectorDelivery, type RotationRun } from "@/lib/api";
import { formatDateTime } from "@/i18n/format";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
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

const statusOptions = [
  { value: "", label: "All statuses" },
  { value: "running", label: "Running" },
  { value: "succeeded", label: "Succeeded" },
  { value: "failed", label: "Failed" },
  { value: "delivered", label: "Delivered" },
  { value: "unrouted", label: "Unrouted" },
  { value: "awaiting_approval", label: "Awaiting approval" },
];

const typeOptions: Array<{ value: "" | OperationType; label: string }> = [
  { value: "", label: "All types" },
  { value: "rotation", label: "Rotation" },
  { value: "deployment", label: "Deployment" },
  { value: "approval", label: "Approval" },
];

export function Operations() {
  const [rows, setRows] = useState<OperationRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Notice | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState<"" | OperationType>("");
  const [rejectTarget, setRejectTarget] = useState<RejectTarget>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [rotations, deliveries, identities] = await Promise.all([api.rotationRuns({ limit: 50 }), api.connectorDeliveries({ limit: 50 }), api.identities()]);
      setRows([
        ...rotations.items.map(rotationOperationRow),
        ...deliveries.items.map(deliveryOperationRow),
        ...approvalRows(identities).map(approvalOperationRow),
      ]);
    } catch (err) {
      setError({ kind: "error", message: errorText(err, "Could not load operations") });
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const id = window.setInterval(() => void load(), 10_000);
    return () => window.clearInterval(id);
  }, [load]);

  const filteredRows = useMemo(
    () => rows.filter((row) => (!statusFilter || row.statusKey === statusFilter) && (!typeFilter || row.type === typeFilter)),
    [rows, statusFilter, typeFilter],
  );

  async function approve(row: Extract<OperationRow, { type: "approval" }>) {
    setBusyKey(row.id);
    setNotice(null);
    setError(null);
    try {
      const result = await api.approveIdentityAction(row.approval.identity.id, row.approval.action);
      setNotice({ kind: "success", message: `${result.action} approval recorded for ${result.resource}` });
      await load();
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
      await api.transitionIdentity(row.approval.identity.id, "retired", reason);
      setRejectTarget(null);
      setNotice({ kind: "success", message: `request rejected for ${row.approval.identity.id}` });
      await load();
    } catch (err) {
      setError({ kind: "error", message: errorText(err, "Could not reject request") });
    } finally {
      setBusyKey(null);
    }
  }

  function cancel(row: OperationRow) {
    setNotice({ kind: "warning", message: "Cancel is not available for this operation yet. Use the owning workflow to stop or roll it back." });
    setBusyKey(row.id);
    window.setTimeout(() => setBusyKey((current) => (current === row.id ? null : current)), 250);
  }

  return (
    <section aria-labelledby="operations-heading" className="grid gap-6">
      <PageHeader
        title="Operations queue"
        titleId="operations-heading"
        description="The execution queue — jobs in flight like credential rotations and connector deployments, with attempts and outcomes. To approve or deny pending requests, see Approvals."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {notice && <OperationNotice notice={notice} onDismiss={() => setNotice(null)} />}
      {error && <ErrorState title="Operations unavailable">{error.message}</ErrorState>}

      <div className="ui-panel grid gap-3 p-comfortable sm:grid-cols-2 lg:grid-cols-[minmax(12rem,16rem)_minmax(12rem,16rem)_1fr]">
        <label className="grid gap-2 text-sm font-medium">
          Status filter
          <select
            aria-label="Status filter"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
          >
            {statusOptions.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-2 text-sm font-medium">
          Type filter
          <select
            aria-label="Type filter"
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value as "" | OperationType)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
          >
            {typeOptions.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <div className="flex items-end text-sm text-muted-foreground">{filteredRows.length} rows</div>
      </div>

      {loading ? (
        <LoadingState>Loading operations...</LoadingState>
      ) : filteredRows.length === 0 ? (
        <EmptyState
          icon={<RefreshCw className="h-5 w-5" aria-hidden="true" />}
          title="No operations found"
          primaryAction={{ label: "Review approvals", to: "/approvals", icon: <CheckCircle2 className="h-4 w-4" /> }}
          secondaryAction={{ label: "Open expiring certificates", to: "/certificates?expiry=30d", icon: <RefreshCw className="h-4 w-4" /> }}
        >
          Adjust filters, refresh the queue, or move to the approval and certificate worklists that create operations.
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

      {rejectTarget && (
        <RejectDialog
          row={rejectTarget}
          busy={busyKey === rejectTarget.id}
          onClose={() => setRejectTarget(null)}
          onSubmit={(reason) => void reject(rejectTarget, reason)}
        />
      )}
    </section>
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
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[72rem]">
        <caption className="sr-only">Operations queue</caption>
        <thead>
          <tr>
            <th scope="col">Operation</th>
            <th scope="col">Type</th>
            <th scope="col">Status</th>
            <th scope="col">Subject</th>
            <th scope="col">Attempts</th>
            <th scope="col">Verification</th>
            <th scope="col">Updated</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="align-top">
              <td className="font-mono text-xs">{row.id}</td>
              <td>{operationTypeLabel(row.type)}</td>
              <td>
                <StatusBadge value={row.statusKey} label={row.status} tone={statusTone(row.statusKey)} />
              </td>
              <td className="max-w-xs break-all">{row.subject}</td>
              <td>{row.attempts}</td>
              <td>
                <VerificationBadge status={row.verification} />
              </td>
              <td>{formatDateTime(row.updatedAt)}</td>
              <td>
                <OperationActions row={row} busy={busyKey === row.id} onApprove={onApprove} onReject={onReject} onCancel={onCancel} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
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
          {`Approve ${row.approval.action} for ${row.approval.identity.name}`}
        </Button>
        <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onReject(row)}>
          {`Reject ${row.approval.action} for ${row.approval.identity.name}`}
        </Button>
      </div>
    );
  }
  if (row.statusKey === "running" || row.statusKey === "unrouted") {
    return (
      <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onCancel(row)}>
        {`Cancel ${row.id}`}
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
  const title = `Reject ${row.approval.action} for ${row.approval.identity.name}`;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(reason.trim());
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4">
      <section aria-labelledby="operation-reject-heading" role="dialog" aria-modal="true" className="w-full max-w-md rounded-panel border border-border bg-card shadow-elevation2">
        <header className="border-b border-border px-5 py-4">
          <h2 id="operation-reject-heading" className="text-title font-semibold">
            {title}
          </h2>
        </header>
        <form className="grid gap-4 p-5" onSubmit={submit}>
          <label className="grid gap-2 text-sm font-medium">
            Reason
            <textarea
              required
              rows={4}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              className="rounded-control border border-border bg-background px-3 py-2 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
            />
          </label>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || reason.trim() === ""}>
              Reject request
            </Button>
          </div>
        </form>
      </section>
    </div>
  );
}

function OperationNotice({ notice, onDismiss }: { notice: Notice; onDismiss: () => void }) {
  const Icon = notice.kind === "success" ? CheckCircle2 : notice.kind === "warning" ? RefreshCw : XCircle;
  return (
    <div className="ui-panel flex items-start justify-between gap-3 p-comfortable text-sm" role="status">
      <div className="flex min-w-0 items-start gap-2">
        <Icon className={notice.kind === "success" ? "mt-0.5 h-4 w-4 shrink-0 text-emerald-600" : notice.kind === "warning" ? "mt-0.5 h-4 w-4 shrink-0 text-status-warning" : "mt-0.5 h-4 w-4 shrink-0 text-destructive"} aria-hidden="true" />
        <p className="min-w-0 break-words font-medium">{notice.message}</p>
      </div>
      <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
        Dismiss
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
    id: `approval-${approval.identity.id}-${approval.action}`,
    type: "approval",
    status: "Awaiting approval",
    statusKey: "awaiting_approval",
    subject: approval.identity.name,
    attempts: approval.approvals,
    verification: "not_applicable",
    updatedAt: approval.identity.created_at || "",
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
  if (status === "awaiting_approval" || status === "unrouted") return "warning";
  if (status === "running") return "operate";
  return "neutral";
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
