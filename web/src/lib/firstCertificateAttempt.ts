import { api, firstCertificateIdentityRequest, type Api, type IssueCertificateInput } from "@/lib/api";

export type FirstCertificateAttemptErrorCode =
  | "csr_required"
  | "principal_owner_name_required"
  | "secure_ids_unavailable"
  | "authority_selection_unavailable"
  | "session_changed"
  | "creation_not_identified"
  | "saved_identity_missing"
  | "transition_not_accepted";
export class FirstCertificateAttemptError extends Error {
  constructor(readonly code: FirstCertificateAttemptErrorCode) {
    super(code);
  }
}

export type FirstCertificatePrincipal = Readonly<{ tenantId: string; subject: string }>;
export type FirstCertificateAttempt = Readonly<{
  version: 1;
  principal: FirstCertificatePrincipal;
  input: Readonly<IssueCertificateInput & { subjectCSRPEM: string }>;
  createKey: string;
  issueKey: string;
  identityId: string | null;
  phase: "create" | "transition" | "accepted";
}>;
export type FirstCertificateAcceptance = Readonly<{ state: "accepted"; identityId: string; requestKey: string }>;

// The wizard retains this attempt before mutation, displays approval refusals,
// and polls the exact result. Identity metadata is not a delivered certificate.
export function newFirstCertificateAttempt(input: IssueCertificateInput, principal: FirstCertificatePrincipal): FirstCertificateAttempt {
  const csr = input.subjectCSRPEM?.trim() ?? "";
  if (!csr || csr.length > 64 * 1024 || !/^-----BEGIN CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE REQUEST-----$/.test(csr)) {
    throw new FirstCertificateAttemptError("csr_required");
  }
  // The old issuer_id field is not the endpoint authority selector. Do not
  // advertise custom selection until the follow-up binds that actual contract.
  if (input.issuerId) throw new FirstCertificateAttemptError("authority_selection_unavailable");
  if (!principal.tenantId.trim() || !principal.subject.trim() || !input.ownerId.trim() || !input.name.trim()) {
    throw new FirstCertificateAttemptError("principal_owner_name_required");
  }
  if (typeof crypto.randomUUID !== "function") throw new FirstCertificateAttemptError("secure_ids_unavailable");
  return Object.freeze({
    version: 1 as const,
    principal: Object.freeze({ ...principal }),
    input: Object.freeze({ ...input, name: input.name.trim(), ownerId: input.ownerId.trim(), subjectCSRPEM: csr }),
    createKey: crypto.randomUUID(),
    issueKey: crypto.randomUUID(),
    identityId: null,
    phase: "create" as const,
  });
}

export async function submitFirstCertificateAttempt(
  attempt: FirstCertificateAttempt,
  principal: FirstCertificatePrincipal,
  persist: (attempt: FirstCertificateAttempt) => void,
  client: Pick<Api, "createIdentity" | "transitionIdentity"> = api,
): Promise<FirstCertificateAcceptance> {
  if (
    !["create", "transition", "accepted"].includes(attempt.phase) ||
    attempt.version !== 1 ||
    attempt.principal.tenantId !== principal.tenantId ||
    attempt.principal.subject !== principal.subject
  ) {
    throw new FirstCertificateAttemptError("session_changed");
  }
  let current = attempt;
  if (current.phase === "create") {
    // Persistence must succeed before sending the first mutation too. A lost
    // creation response retries the original body/key instead of minting a new attempt.
    persist(current);
    const identity = await client.createIdentity(firstCertificateIdentityRequest(current.input, current.input.ownerId), current.createKey);
    if (!identity.id || identity.status !== "requested") throw new FirstCertificateAttemptError("creation_not_identified");
    current = Object.freeze({ ...current, identityId: identity.id, phase: "transition" as const });
    persist(current);
  }
  if (!current.identityId) throw new FirstCertificateAttemptError("saved_identity_missing");
  const identityId = current.identityId;
  if (current.phase === "transition") {
    const identity = await client.transitionIdentity(
      identityId,
      "issued",
      "first issuance via UI from an operator-supplied CSR",
      current.input.subjectCSRPEM,
      current.issueKey,
    );
    if (identity.id !== identityId || identity.status !== "issued") {
      throw new FirstCertificateAttemptError("transition_not_accepted");
    }
    current = Object.freeze({ ...current, phase: "accepted" as const });
    persist(current);
  }
  return Object.freeze({ state: "accepted", identityId, requestKey: current.issueKey });
}
