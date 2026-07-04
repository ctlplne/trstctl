import { identityState, type Identity, type Me } from "@/lib/api";

export type ApprovalActionKind = "issue" | "rotate" | "revoke";

export type ApprovalQueueRow = {
  identity: Identity;
  action: ApprovalActionKind;
  label: string;
  requester: string;
  approvals: string;
  grantExpiresAt: string;
};

export function approvalActionsForState(state: string): Array<{ label: string; action: ApprovalActionKind }> {
  switch (state) {
    case "requested":
      return [{ label: "Approve issue", action: "issue" }];
    case "renewing":
      return [{ label: "Approve rotate", action: "rotate" }];
    case "issued":
    case "deployed":
      return [{ label: "Approve revoke", action: "revoke" }];
    default:
      return [];
  }
}

export function approvalRows(identities: Identity[]): ApprovalQueueRow[] {
  return identities.flatMap((identity) =>
    approvalActionsForState(identityState(identity)).map((action) => ({
      identity,
      action: action.action,
      label: action.label,
      requester: stringAttr(identity, "requester") || stringAttr(identity, "requested_by") || "not served",
      approvals: stringAttr(identity, "approvals") || "returned after approval",
      grantExpiresAt: stringAttr(identity, "grant_expires_at") || "expiry not served on queue",
    })),
  );
}

export function requesterMatchesPrincipal(row: ApprovalQueueRow, user: Me | null): boolean {
  if (!user) return false;
  const requester = row.requester.toLowerCase();
  if (!requester || requester === "not served") return false;
  return requester === user.email?.toLowerCase() || requester === user.subject.toLowerCase();
}

export function approvalAuditHref(row: ApprovalQueueRow): string {
  const q = new URLSearchParams({
    type: "identity.approval",
    q: `${row.identity.id} ${row.action}`,
  });
  return `/audit?${q.toString()}`;
}

function stringAttr(identity: Identity, key: string): string {
  const value = identity.attributes?.[key];
  return typeof value === "string" ? value : "";
}
