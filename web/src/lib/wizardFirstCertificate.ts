import { z } from "zod";
import { ApiError, req, previewTransportIsIsolated, type Identity, type Me, type Owner } from "@/lib/api";
import type { IdentityIssuanceResult, OwnerRequest } from "@/lib/api-types.gen";
import {
  newFirstCertificateAttempt,
  submitFirstCertificateAttempt,
  type FirstCertificateAttempt,
  type FirstCertificatePrincipal,
} from "@/lib/firstCertificateAttempt";
import { firstCertificatePrincipalMatches, registerFirstCertificateOperation } from "@/lib/firstCertificateMemory";

export const PUBLIC_CSR_LIMIT = 64 * 1024;
export const WIZARD_SUBMISSION_MS = 90_000;
export const WIZARD_READ_MS = 10_000;
export const WIZARD_POLL_MS = 240_000;
export const publicCSR = z
  .string()
  .trim()
  .max(PUBLIC_CSR_LIMIT)
  .regex(/^-----BEGIN CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE REQUEST-----$/);
export const wizardCertificateForm = z
  .object({
    name: z.string().trim().min(1).max(255),
    applicationID: z.string().trim().min(1).max(255),
    environment: z.string().trim().min(1).max(255),
    alertContact: z.string().trim().email().max(254),
    ownershipConfirmed: z.boolean().refine(Boolean),
    wildcardAck: z.boolean(),
    subjectCSRPEM: publicCSR,
  })
  .strict()
  .refine((input) => !input.name.startsWith("*.") || input.wildcardAck, { path: ["wildcardAck"] });
export type WizardCertificateForm = z.infer<typeof wizardCertificateForm>;
export type WizardCertificateAttempt = Readonly<{
  principal: FirstCertificatePrincipal;
  input: Readonly<WizardCertificateForm>;
  ownerKey: string;
  attestKey: string;
  owner: Owner | null;
  issuance: FirstCertificateAttempt | null;
  transitionDispatched: boolean;
  csrRejection?: Readonly<{ requestKey: string; subjectCSRPEM: string }> | null;
  replacesRejectedIssueKey?: string;
}>;
export type WizardPublicResult = IdentityIssuanceResult;
export type WizardRecordedCertificate = {
  result: WizardPublicResult & { certificate: NonNullable<WizardPublicResult["certificate"]>; certificate_pem: string };
  identity: Identity;
};
export type WizardFailureKind = "approval" | "refused" | "uncertain";
export function wizardFailureKind(error: unknown): WizardFailureKind {
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
    // This is an approval gate refusal, not proof of a pending queue row or vote.
    try {
      const body = JSON.parse(error.body) as { detail?: unknown };
      if (error.status === 403 && typeof body.detail === "string" && body.detail.startsWith("dual control:")) return "approval";
    } catch {
      /* An unstructured refusal stays a refusal. */
    }
    return "refused";
  }
  return "uncertain";
}
export function newWizardCertificateAttempt(input: WizardCertificateForm, principal: FirstCertificatePrincipal): WizardCertificateAttempt {
  const clean = wizardCertificateForm.parse(input);
  if (!firstCertificatePrincipalMatches(principal) || previewTransportIsIsolated()) throw new Error("session_changed");
  if (typeof crypto.randomUUID !== "function") throw new Error("secure_ids_unavailable");
  if (!crypto.subtle) throw new Error("browser_crypto_unavailable");
  return Object.freeze({
    principal: Object.freeze({ ...principal }),
    input: Object.freeze(clean),
    ownerKey: crypto.randomUUID(),
    attestKey: crypto.randomUUID(),
    owner: null,
    issuance: null,
    transitionDispatched: false,
  });
}

// Only this exact server-side, durably recorded pre-transition CSR refusal
// permits correction. Missing, generic4xx, stale/cross-principal or contradictory
// bodies leave the original attempt frozen. The server returns only a SHA-256 digest of the rejected input; its original
// bytes are never reflected or persisted in the refusal body.
function exactCSRRejection(error: unknown, attempt: WizardCertificateAttempt, csrDigest: string): boolean {
  if (!(error instanceof ApiError) || error.status !== 400 || !attempt.issuance?.identityId || attempt.issuance.phase !== "transition") return false;
  try {
    const body = JSON.parse(error.body) as { code?: unknown; disposition?: Record<string, unknown> };
    const d = body.disposition;
    return (
      body.code === "identity_csr_rejected_before_transition" &&
      Boolean(d) &&
      d!.tenant_id === attempt.principal.tenantId &&
      d!.subject === attempt.principal.subject &&
      d!.identity_id === attempt.issuance.identityId &&
      d!.request_key === attempt.issuance.issueKey &&
      d!.subject_csr_sha256 === csrDigest &&
      d!.to === "issued" &&
      d!.reason === "first issuance via UI from an operator-supplied CSR"
    );
  } catch {
    return false;
  }
}

// An intentional corrected CSR gets one new ISSUE key only. Owner attribution,
// attestation, identity and creation key remain fixed. Retrying an uncertain
// attempt cannot call this path; recover its original response/result first.
export function correctWizardCertificateCSR(attempt: WizardCertificateAttempt, subjectCSRPEM: string): WizardCertificateAttempt {
  const csr = publicCSR.parse(subjectCSRPEM);
  if (!firstCertificatePrincipalMatches(attempt.principal) || previewTransportIsIsolated()) throw new Error("session_changed");
  if (
    !attempt.owner ||
    !attempt.issuance?.identityId ||
    attempt.issuance.phase !== "transition" ||
    !attempt.csrRejection ||
    attempt.csrRejection.requestKey !== attempt.issuance.issueKey ||
    attempt.csrRejection.subjectCSRPEM !== attempt.input.subjectCSRPEM ||
    csr === attempt.input.subjectCSRPEM
  )
    throw new Error("correction_not_authorized");
  if (typeof crypto.randomUUID !== "function") throw new Error("secure_ids_unavailable");
  const issueKey = crypto.randomUUID();
  if (
    !issueKey ||
    issueKey === attempt.issuance.issueKey ||
    issueKey === attempt.issuance.createKey ||
    issueKey === attempt.ownerKey ||
    issueKey === attempt.attestKey
  )
    throw new Error("secure_ids_unavailable");
  return Object.freeze({
    ...attempt,
    input: Object.freeze({ ...attempt.input, subjectCSRPEM: csr }),
    issuance: Object.freeze({ ...attempt.issuance, input: Object.freeze({ ...attempt.issuance.input, subjectCSRPEM: csr }), issueKey }),
    transitionDispatched: false,
    csrRejection: null,
    replacesRejectedIssueKey: attempt.issuance.issueKey,
  });
}

// Fixed HTTP operations only. Both cancellation and the absolute operation limit
// are checked after every await; an aborted reply cannot update the next principal.
// Fresh /auth/me checks reduce stale-session dispatch, but are not an atomic
// server session precondition. The server remains the authentication/RLS authority.
function operation(principal: FirstCertificatePrincipal, outer: AbortSignal, milliseconds: number) {
  if (!Number.isFinite(milliseconds) || milliseconds <= 0 || milliseconds > WIZARD_SUBMISSION_MS) throw new Error("operation_interrupted");
  const controller = new AbortController();
  const stop = () => controller.abort();
  outer.addEventListener("abort", stop, { once: true });
  if (outer.aborted) stop();
  const unregister = registerFirstCertificateOperation(controller);
  const deadline = performance.now() + milliseconds;
  const timer = window.setTimeout(stop, milliseconds);
  function check() {
    if (controller.signal.aborted || performance.now() >= deadline || !firstCertificatePrincipalMatches(principal) || previewTransportIsIsolated())
      throw new Error("operation_interrupted");
  }
  async function read<T>(path: string, init?: RequestInit): Promise<T> {
    check();
    const value = await req<T>(path, { ...init, signal: controller.signal, cache: "no-store" });
    check();
    return value;
  }
  async function authenticate() {
    const me = await read<Me>("/auth/me");
    if (me.tenant_id !== principal.tenantId || me.subject !== principal.subject) {
      stop();
      throw new Error("session_changed");
    }
  }
  async function digestCSR(csr: string) {
    check();
    const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(csr));
    check();
    return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  async function mutation<T>(path: string, body: unknown, key: string): Promise<T> {
    await authenticate();
    check();
    const value = await read<T>(path, { method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": key }, body: JSON.stringify(body) });
    await authenticate();
    return value;
  }
  return {
    check,
    read,
    mutation,
    authenticate,
    digestCSR,
    close: () => {
      window.clearTimeout(timer);
      outer.removeEventListener("abort", stop);
      unregister();
    },
  };
}

export async function submitWizardCertificateAttempt(
  saved: WizardCertificateAttempt,
  signal: AbortSignal,
  retain: (next: WizardCertificateAttempt) => void,
  written: (kind: "owners" | "identities", value: Owner | Identity) => void = () => {},
): Promise<WizardCertificateAttempt> {
  const op = operation(saved.principal, signal, WIZARD_SUBMISSION_MS);
  let current = saved;
  function keep(next: WizardCertificateAttempt) {
    op.check();
    retain(next);
    current = next;
  }
  try {
    keep(current); // Retain the exact keys/body before the first dispatch.
    if (!current.owner) {
      const input: OwnerRequest = {
        kind: "workload",
        name: current.input.name,
        service: current.input.name,
        application_id: current.input.applicationID,
        environment: current.input.environment,
        email: current.input.alertContact,
      };
      const owner = await op.mutation<Owner>("/api/v1/owners", input, current.ownerKey);
      if (!owner.id || owner.tenant_id !== current.principal.tenantId || !owner.ownership_complete) throw new Error("owner_not_ready");
      keep(Object.freeze({ ...current, owner }));
      written("owners", owner);
    }
    if (!current.owner) throw new Error("owner_not_ready");
    if (!current.owner.ownership_current) {
      const owner = await op.mutation<Owner>(`/api/v1/owners/${encodeURIComponent(current.owner.id)}/attest`, {}, current.attestKey);
      if (owner.id !== current.owner.id || owner.tenant_id !== current.principal.tenantId || !owner.ownership_complete || !owner.ownership_current)
        throw new Error("owner_not_ready");
      keep(Object.freeze({ ...current, owner }));
      written("owners", owner);
    }
    if (!current.issuance) {
      keep(
        Object.freeze({
          ...current,
          issuance: newFirstCertificateAttempt(
            {
              name: current.input.name,
              ownerId: current.owner.id,
              subjectCSRPEM: current.input.subjectCSRPEM,
              ...(current.input.name.startsWith("*.") ? { wildcardBlastRadiusAcknowledged: current.input.wildcardAck } : {}),
            },
            current.principal,
          ),
        }),
      );
    }
    if (!current.issuance) throw new Error("attempt_missing");
    await submitFirstCertificateAttempt(current.issuance, current.principal, (issuance) => keep(Object.freeze({ ...current, issuance })), {
      createIdentity: async (input, key) => {
        if (!key) throw new Error("attempt_missing");
        const identity = await op.mutation<Identity>("/api/v1/identities", input, key);
        if (identity.tenant_id !== current.principal.tenantId || identity.owner_id !== current.owner?.id || identity.kind !== "x509_certificate")
          throw new Error("identity_mismatch");
        written("identities", identity);
        return identity;
      },
      transitionIdentity: async (id, to, reason, csr, key) => {
        if (!key || csr !== current.input.subjectCSRPEM || to !== "issued") throw new Error("attempt_mismatch");
        const csrDigest = await op.digestCSR(csr);
        keep(Object.freeze({ ...current, transitionDispatched: true }));
        try {
          const identity = await op.mutation<Identity>(`/api/v1/identities/${encodeURIComponent(id)}/transitions`, { to, reason, subject_csr_pem: csr }, key);
          if (identity.tenant_id !== current.principal.tenantId) throw new Error("identity_mismatch");
          written("identities", identity);
          return identity;
        } catch (error) {
          // Re-authenticate after an error too: a reply received under another
          // cookie principal cannot unlock correction of this principal's work.
          await op.authenticate();
          if (exactCSRRejection(error, current, csrDigest))
            keep(Object.freeze({ ...current, csrRejection: Object.freeze({ requestKey: key, subjectCSRPEM: csr }) }));
          throw error;
        }
      },
    });
    op.check();
    return current;
  } finally {
    op.close();
  }
}

export function publicCertificateBlocks(pem: string): string[] {
  if (!pem || pem.length > 1024 * 1024) throw new Error("public_result_invalid");
  const block = /-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/g;
  const blocks = pem.match(block) ?? [];
  if (blocks.length < 1 || blocks.length > 16 || pem.replace(block, "").trim() !== "") throw new Error("public_result_invalid");
  // Envelope check only: real DER/CSR matching and chain validation stay in the
  // crypto boundary/server and the later stock-client served proof.
  return blocks;
}
export function checkWizardPublicResult(raw: WizardPublicResult, attempt: WizardCertificateAttempt): WizardPublicResult {
  if (!raw || raw.identity_id !== attempt.issuance?.identityId || raw.request_key !== attempt.issuance?.issueKey) throw new Error("result_mismatch");
  if (raw.state === "pending") {
    if (raw.certificate !== undefined || raw.certificate_pem !== undefined) throw new Error("public_result_invalid");
    return raw;
  }
  if (raw.state !== "issued" || !raw.certificate || typeof raw.certificate_pem !== "string") throw new Error("public_result_invalid");
  const cert = raw.certificate;
  if (
    cert.tenant_id !== attempt.principal.tenantId ||
    typeof cert.id !== "string" ||
    !cert.id ||
    typeof cert.fingerprint !== "string" ||
    !cert.fingerprint ||
    typeof cert.subject !== "string" ||
    !["active", "superseded", "revoked"].includes(cert.status)
  )
    throw new Error("public_result_invalid");
  if (cert.key_origin !== "requester") throw new Error("public_result_custody_unconfirmed");
  publicCertificateBlocks(raw.certificate_pem);
  return raw;
}
export async function readWizardCertificateResult(
  attempt: WizardCertificateAttempt,
  signal: AbortSignal,
  pollingDeadline = Infinity,
): Promise<WizardRecordedCertificate | null> {
  if (!attempt.transitionDispatched || !attempt.issuance?.identityId) throw new Error("attempt_missing");
  const op = operation(attempt.principal, signal, Math.min(WIZARD_READ_MS, pollingDeadline - performance.now()));
  try {
    await op.authenticate();
    const path = `/api/v1/identities/${encodeURIComponent(attempt.issuance.identityId)}`;
    const result = checkWizardPublicResult(
      await op.read<WizardPublicResult>(`${path}/issuance-result?request_key=${encodeURIComponent(attempt.issuance.issueKey)}`),
      attempt,
    );
    await op.authenticate();
    if (result.state === "pending") return null;
    const identity = await op.read<Identity>(path);
    await op.authenticate();
    if (identity.id !== result.identity_id || identity.tenant_id !== attempt.principal.tenantId || identity.kind !== "x509_certificate")
      throw new Error("identity_mismatch");
    // checkWizardPublicResult established these fields from the actual envelope.
    return { result: result as WizardRecordedCertificate["result"], identity };
  } finally {
    op.close();
  }
}
export function downloadWizardPublicCertificate(record: WizardRecordedCertificate, kind: "leaf" | "chain", principal: FirstCertificatePrincipal): void {
  if (
    !firstCertificatePrincipalMatches(principal) ||
    record.result.certificate.tenant_id !== principal.tenantId ||
    record.identity.tenant_id !== principal.tenantId
  )
    throw new Error("session_changed");
  const blocks = publicCertificateBlocks(record.result.certificate_pem);
  const text = kind === "leaf" ? blocks[0] + "\n" : record.result.certificate_pem;
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = kind === "leaf" ? "certificate.pem" : "certificate-chain.pem";
  try {
    document.body.appendChild(link);
    link.click();
  } finally {
    link.remove();
    URL.revokeObjectURL(url);
  }
}
