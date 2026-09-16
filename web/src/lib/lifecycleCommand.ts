import { ApiError } from "@/lib/apiTransport";
import type { IdentityTransitionPreview } from "@/lib/api";

export type LifecycleApproval = { requestId: string; status: string };

// The server fingerprint binds tenant, authenticated requester, identity,
// lifecycle version, target state, reason, and public CSR. Reopening a review
// therefore recovers the same command without storing authority in the browser.
// A deliberate successor to a terminal request uses that request's immutable ID.
export function lifecycleCommandKey(plan: IdentityTransitionPreview, closedRequestId?: string): string {
  return `identity-transition:${plan.request_fingerprint}${closedRequestId ? `:${closedRequestId}` : ""}`;
}

export function lifecycleApproval(error: unknown): LifecycleApproval | null {
  if (!(error instanceof ApiError) || error.status !== 403) return null;
  try {
    const body = JSON.parse(error.body) as Record<string, unknown>;
    if (
      body.code !== "identity_approval_required" ||
      typeof body.approval_request_id !== "string" ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(body.approval_request_id) ||
      typeof body.approval_status !== "string" ||
      !["pending", "approved", "denied", "expired", "superseded"].includes(body.approval_status)
    )
      return null;
    return { requestId: body.approval_request_id, status: body.approval_status };
  } catch {
    return null;
  }
}

export function canRestartLifecycleApproval(approval: LifecycleApproval): boolean {
  return ["denied", "expired", "superseded"].includes(approval.status);
}
