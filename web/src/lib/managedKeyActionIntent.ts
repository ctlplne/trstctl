import { newIdempotencyKey } from "./apiTransport";

type Requester = { tenant_id: string; subject: string };
type Action = "rotate" | "revoke" | "zeroize";

function slot(requester: Requester, action: Action, keyId: string): string {
  return `trstctl:mka:1:${JSON.stringify([requester.tenant_id, requester.subject, action, keyId])}`;
}

/** The approval binds the raw HTTP request key by digest. Keep the same key
 * through the independent decisions, page navigation, and browser restart.
 * A different key creates and supersedes a different approval request. */
export function getOrCreateManagedKeyActionIntent(requester: Requester, action: Action, keyId: string): string | null {
  if (!requester.tenant_id || !requester.subject || !keyId) return null;
  try {
    const name = slot(requester, action, keyId);
    const saved = localStorage.getItem(name);
    if (saved !== null) return /^\w[\w-]{0,127}$/.test(saved) ? saved : null;
    const fresh = newIdempotencyKey();
    localStorage.setItem(name, fresh);
    return fresh;
  } catch {
    return null;
  }
}

/** Clear only after the exact provider effect has completed. A queued receipt,
 * approval wait, or uncertain network response must retain its request key. */
export function clearManagedKeyActionIntent(requester: Requester, action: Action, keyId: string): void {
  try {
    localStorage.removeItem(slot(requester, action, keyId));
  } catch {
    // The provider effect already happened. Keeping the key permits only a
    // safe idempotent replay; clearing it cannot be a prerequisite for success.
  }
}
