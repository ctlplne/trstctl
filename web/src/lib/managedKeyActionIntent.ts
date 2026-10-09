type Requester = { tenant_id: string; subject: string };
type Action = "rotate" | "revoke" | "zeroize";

/** The exact managed-key action is stable across navigation and browser restarts.
 * Derive its retry key from tenant, actor, provider, key, and observed key
 * version. A completed rotation moves to a new version and gets a new key.
 * No approval handle or action state is written to browser storage. */
export async function managedKeyActionIntent(requester: Requester, action: Action, provider: string, keyId: string, version: number): Promise<string | null> {
  if (!requester.tenant_id || !requester.subject || !provider || !keyId || !Number.isSafeInteger(version) || version < 1) return null;
  try {
    const command = JSON.stringify(["trstctl-managed-key-action-v2", requester.tenant_id, requester.subject, action, provider, keyId, version]);
    const input = new TextEncoder().encode(command);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input.buffer as ArrayBuffer));
    return `mka2-${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  } catch {
    return null;
  }
}
