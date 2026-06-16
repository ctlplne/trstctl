// Typed client over the trstctl REST surface (S3.3 / S7.1 / S7.3). All requests
// carry the session cookie; a 401 surfaces as UnauthorizedError so the auth layer
// can redirect to login. Mutations send an Idempotency-Key (AN-5).
//
// FE↔BE contract (SURFACE-005 / EXC-WIRE-04): the resource shapes below are NOT
// hand-written — they are re-exported from ./api-types.gen.ts, which is generated
// from the SERVED OpenAPI contract (internal/api/testdata/openapi.golden.json, pinned
// == the live spec by the Go test TestOpenAPIGolden). So if the backend adds, renames,
// or removes a field, the generated types change and any code in the SPA that reads a
// now-missing field fails `tsc` — the drift cannot ship silently. Regenerate with
// `npm run gen:api`; `npm run build` runs `gen:api --check` first and fails on drift.
import type {
  Certificate as GenCertificate,
  Owner as GenOwner,
  OwnerRequest,
  Issuer as GenIssuer,
  IssuerRequest,
  Identity as GenIdentity,
  IdentityRequest,
  TransitionRequest,
  Agent as GenAgent,
  EnrollmentToken as GenEnrollmentToken,
} from "./api-types.gen";

// Re-export the generated, contract-bound resource types under the names the SPA uses.
export type Certificate = GenCertificate;
export type Owner = GenOwner;
export type Issuer = GenIssuer;
export type Identity = GenIdentity;
export type Agent = GenAgent;
export type EnrollmentToken = GenEnrollmentToken;
// TransitionTo is the set of lifecycle targets the served contract accepts; the UI's
// transition actions are typed against it so an invalid target fails the build.
export type TransitionTo = TransitionRequest["to"];

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class ApiError extends Error {
  status: number;
  body: string;
  /** retryAfterSeconds is set for a 429 when the server sends Retry-After, so the UI
   * can surface a concrete "try again in N seconds" hint instead of a bare failure
   * (SURFACE-007; the server emits Retry-After on rate-limit at api.go). */
  retryAfterSeconds?: number;
  constructor(status: number, body: string, retryAfterSeconds?: number) {
    super(
      status === 429
        ? `rate limited (429)${retryAfterSeconds != null ? ` — retry in ${retryAfterSeconds}s` : ""}`
        : `request failed (${status})`,
    );
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.retryAfterSeconds = retryAfterSeconds;
  }
  /** isRateLimited is a convenience for the UI's special-case path. */
  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

/** parseRetryAfter reads a Retry-After header (RFC 7231: either delta-seconds or an
 * HTTP-date) into seconds, or undefined when absent/unparseable. */
function parseRetryAfter(h: string | null): number | undefined {
  if (!h) return undefined;
  const secs = Number(h);
  if (Number.isFinite(secs)) return Math.max(0, Math.round(secs));
  const when = Date.parse(h);
  if (!Number.isNaN(when)) return Math.max(0, Math.round((when - Date.now()) / 1000));
  return undefined;
}

// Me is the browser-session principal returned by GET /auth/me. It is NOT a REST
// component schema (it comes from the auth/session layer, not the resource API), so it
// is hand-written here rather than generated — and stays minimal by design (subject +
// tenant; no token/secret ever crosses to the client; SURFACE-I01).
export interface Me {
  subject: string;
  tenant_id: string;
  email?: string;
}

export interface CredentialRisk {
  credential_id: string;
  subject: string;
  kind: string;
  score: number;
  exposure: number;
  owner_active: boolean;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "include",
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (res.status === 401) throw new UnauthorizedError();
  if (res.status === 429) {
    // Rate limited: surface Retry-After so the UI can show a concrete retry hint
    // (SURFACE-007). The server emits Retry-After on its per-tenant bulkhead/limit.
    throw new ApiError(429, await res.text(), parseRetryAfter(res.headers.get("Retry-After")));
  }
  if (!res.ok) throw new ApiError(res.status, await res.text());
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** newIdempotencyKey returns a fresh key so a retried mutation cannot execute
 * twice (AN-5). */
function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `idem-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/** mutate issues a state-changing request with an optional JSON body and an
 * Idempotency-Key. */
function mutate<T>(method: string, path: string, body?: unknown): Promise<T> {
  return req<T>(path, {
    method,
    headers: { "Content-Type": "application/json", "Idempotency-Key": newIdempotencyKey() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Api is the client surface the UI depends on; it is mockable in tests. The
 * request inputs are the OpenAPI-generated request bodies (OwnerRequest,
 * IssuerRequest, IdentityRequest, TransitionRequest) so a mutation cannot send a
 * field the server does not accept — the same contract guarantee as the responses. */
export interface Api {
  me(): Promise<Me>;
  certificates(): Promise<Certificate[]>;
  owners(): Promise<Owner[]>;
  createOwner(input: OwnerRequest): Promise<Owner>;
  issuers(): Promise<Issuer[]>;
  createIssuer(input: IssuerRequest): Promise<Issuer>;
  identities(): Promise<Identity[]>;
  createIdentity(input: IdentityRequest): Promise<Identity>;
  transitionIdentity(id: string, to: TransitionRequest["to"], reason?: string): Promise<Identity>;
  /** issueCertificate is the one-call convenience the wizard and the "issue"
   * action use: it ensures an owner, creates the identity, and issues it. */
  issueCertificate(input: { name: string; ownerId?: string; issuerId?: string }): Promise<Identity>;
  agents(): Promise<Agent[]>;
  createEnrollmentToken(): Promise<EnrollmentToken>;
  risk(): Promise<CredentialRisk[]>;
}

export const api: Api = {
  me: () => req<Me>("/auth/me"),
  certificates: () =>
    req<{ items: Certificate[] }>("/api/v1/certificates").then((r) => r.items ?? []),
  owners: () => req<{ items: Owner[] }>("/api/v1/owners").then((r) => r.items ?? []),
  createOwner: (input) => mutate<Owner>("POST", "/api/v1/owners", input),
  issuers: () => req<{ items: Issuer[] }>("/api/v1/issuers").then((r) => r.items ?? []),
  createIssuer: (input) => mutate<Issuer>("POST", "/api/v1/issuers", input),
  identities: () => req<{ items: Identity[] }>("/api/v1/identities").then((r) => r.items ?? []),
  createIdentity: (input) => mutate<Identity>("POST", "/api/v1/identities", input),
  transitionIdentity: (id, to, reason) =>
    mutate<Identity>("POST", `/api/v1/identities/${id}/transitions`, { to, reason }),
  issueCertificate: async (input) => {
    let ownerId = input.ownerId;
    if (!ownerId) {
      const owner = await api.createOwner({ kind: "workload", name: input.name });
      ownerId = owner.id;
    }
    const identity = await api.createIdentity({
      kind: "x509_certificate",
      name: input.name,
      owner_id: ownerId,
      issuer_id: input.issuerId,
    });
    return api.transitionIdentity(identity.id, "issued", "first issuance via UI");
  },
  agents: () => req<{ agents: Agent[] }>("/api/v1/agents").then((r) => r.agents ?? []),
  createEnrollmentToken: () => mutate<EnrollmentToken>("POST", "/api/v1/agents/enrollment-tokens"),
  risk: () =>
    req<{ credentials: CredentialRisk[] }>("/api/v1/risk/credentials?sort=score").then(
      (r) => r.credentials ?? [],
    ),
};

/** loginURL is where the browser is sent to begin the OIDC flow. */
export const loginURL = "/auth/login";

/** identityState returns the credential's lifecycle state. The served contract
 * (OpenAPI Identity) names this field `status`; this helper keeps the call sites
 * decoupled from the field name so a future contract change is a one-line edit here. */
export function identityState(i: Identity): string {
  return i.status ?? "";
}
