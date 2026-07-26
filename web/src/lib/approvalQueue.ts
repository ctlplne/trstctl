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

/** S-C18: the queue rendered whatever the served `approvals` attribute held —
 * "1 of 2", "1/2", a bare count, or a placeholder — so "how many more do I
 * need" was a reading-comprehension exercise per row. This parses the shapes
 * the server actually emits into have/need; anything else keeps its raw text
 * rather than being guessed at. */
export type ApprovalProgress = { have: number; need: number; remaining: number };

export function parseApprovalProgress(raw: string): ApprovalProgress | null {
  const value = raw.trim();
  if (!value) return null;
  // "1 of 2", "1/2", "1 de 2" — a count, a separator, a threshold.
  const pair = value.match(/^(\d+)\s*(?:\/|of|de|von)\s*(\d+)$/i);
  if (pair) {
    const have = Number(pair[1]);
    const need = Number(pair[2]);
    if (need <= 0) return null;
    return { have, need, remaining: Math.max(0, need - have) };
  }
  return null;
}

export function approvalActionsForState(state: string): Array<{ label: string; action: ApprovalActionKind }> {
  switch (state) {
    case "requested":
      return [
        {
          get label() {
            return translateNow("source.approve.issue.a4353290b7");
          },
          action: "issue",
        },
      ];
    case "renewing":
      return [
        {
          get label() {
            return translateNow("source.approve.rotate.cdbd42f3c6");
          },
          action: "rotate",
        },
      ];
    case "issued":
    case "deployed":
      return [
        {
          get label() {
            return translateNow("source.approve.revoke.80c949285d");
          },
          action: "revoke",
        },
      ];
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
