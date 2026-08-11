import type { Me, PendingApprovalRequest } from "@/lib/api";

export type ApprovalActionKind = PendingApprovalRequest["action"];
export type ApprovalQueueRow = PendingApprovalRequest;
export const approvalRequestsQueryKey = ["approval-requests", { status: "pending" }] as const;

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

/** AUD-77: the queue is a projection of real approval requests. An identity's
 * lifecycle state is inventory, not proof that anybody requested an action. */
export function approvalRows(requests: PendingApprovalRequest[]): ApprovalQueueRow[] {
  return requests.filter((request) => request.status === "pending");
}

export function requesterMatchesPrincipal(row: ApprovalQueueRow, user: Me | null): boolean {
  if (!user) return false;
  const requester = row.requester.toLowerCase();
  if (!requester) return false;
  return requester === user.email?.toLowerCase() || requester === user.subject.toLowerCase();
}

export function approvalAuditHref(row: ApprovalQueueRow): string {
  const q = new URLSearchParams({
    q: `${row.id} ${row.intent_digest}`,
  });
  return `/audit?${q.toString()}`;
}
