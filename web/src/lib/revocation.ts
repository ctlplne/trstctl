import type { BulkRevokeRequest, Identity } from "@/lib/api";

/** The UI reason list is checked against the OpenAPI-generated request enum.
 * A backend contract change therefore fails TypeScript instead of letting a
 * browser submit a reason the server no longer accepts. */
export const revocationReasons = [
  "unspecified",
  "keyCompromise",
  "caCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "certificateHold",
  "removeFromCRL",
  "privilegeWithdrawn",
  "aaCompromise",
] as const satisfies readonly BulkRevokeRequest["reason"][];

function stringAttribute(identity: Identity, keys: string[]): string | null {
  for (const key of keys) {
    const value = identity.attributes?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

/** Resolve the same certificate graph node used by the Identities and
 * Certificates destructive-action journeys. An explicit server-projected
 * binding wins; the identity id is only the compatibility fallback. */
export function graphNodeIdForIdentity(identity: Identity): string | null {
  const explicit = stringAttribute(identity, ["graph_node_id", "graph_node", "graph_id"]);
  if (explicit) return explicit;

  const credentialID = stringAttribute(identity, ["credential_id", "certificate_id"]);
  if (credentialID) return credentialID.startsWith("cert:") ? credentialID : `cert:${credentialID}`;

  return identity.kind === "x509_certificate" && identity.id ? `id:${identity.id}` : null;
}
