import { identityState, type Identity, type Me } from "@/lib/api";
import { translateNow } from "@/i18n/I18nProvider";

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
      return [{ get label() {
      return translateNow("source.approve.issue.a4353290b7");
    }, action: "issue" }];
    case "renewing":
      return [{ get label() {
      return translateNow("source.approve.rotate.cdbd42f3c6");
    }, action: "rotate" }];
    case "issued":
    case "deployed":
      return [{ get label() {
      return translateNow("source.approve.revoke.80c949285d");
    }, action: "revoke" }];
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
