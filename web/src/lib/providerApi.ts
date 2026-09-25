// SPDX-License-Identifier: BUSL-1.1

import type { UsageEvidence } from "./api";

// The provider-plane client (epic L3).
//
// /provider/v1 is a SEPARATE plane from /api/v1: its caller is the provider's
// own staff, authenticated by the provider IdP (L1) rather than a tenant
// session. So it does not go through the tenant `req<T>` client. OIDC callers
// may carry a memory-only bearer; SAML callers use the separate HttpOnly
// Provider session cookie and a readable, non-credential CSRF cookie.
//
// The token is held IN MEMORY only — never web storage. The SPA's XSS posture
// (SURFACE-I01) is that auth state must not sit in browser storage where a
// script could read it and where it would persist a privileged credential
// (this bearer can suspend a customer) on the machine. A module-scoped variable
// lives only in the tab's JS heap: it is lost on reload, which means the
// operator re-authenticates rather than leaving a standing credential behind. A
// future hardening moves this to an HttpOnly provider session cookie so the
// token never enters JS at all; until then, memory-only is the posture the
// security guard requires.
let operatorToken: string | null = null;

export function providerToken(): string | null {
  return operatorToken;
}

export function setProviderToken(token: string): void {
  operatorToken = token.trim() || null;
}

export function clearProviderToken(): void {
  operatorToken = null;
}

export type ProviderTenantStatus = "active" | "suspended" | "offboarded";

export interface ProviderTenant {
  id: string;
  slug: string;
  name: string;
  status: ProviderTenantStatus;
  created_at: string;
  updated_at: string;
}

export interface ProviderQuota {
  tenant_id: string;
  max_agents?: number;
  max_tenants?: number;
  max_certificates_stored?: number;
  max_secrets_stored?: number;
  updated_by?: string;
}

export interface ProviderBrand {
  product_name?: string;
  logo_data_uri?: string;
  login_message?: string;
  email_from_name?: string;
  email_footer?: string;
  custom_domain?: string;
}

export interface ProviderDrillCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface ProviderDrillReport {
  passed: boolean;
  checks: ProviderDrillCheck[] | null;
  ran_at: string;
}

export interface ProviderActivity {
  sequence: number;
  event_id: string;
  type: string;
  tenant_id?: string;
  operator_id?: string;
  operator_email?: string;
  grant_id?: string;
  subject?: string;
  reason?: string;
  at: string;
}

export interface ProviderBreakGlassGrant {
  id: string;
  tenant_id: string;
  operator_id: string;
  operator_email?: string;
  reason: string;
  requested_at: string;
  expires_at: string;
  use_count: number;
}

export interface ProviderTenantSnapshot {
  tenant_id: string;
  health: string;
  active_certificates: number;
}

export type ProviderOperatorRole = "admin" | "operator";
export type ProviderOperation = "read" | "provision" | "suspend" | "resume" | "offboard" | "break-glass";

export interface ProviderConsoleCustomerAuthority {
  read_quota: boolean;
  write_quota: boolean;
  write_brand: boolean;
  suspend: boolean;
  resume: boolean;
  offboard: boolean;
}

export interface ProviderConsoleAuthority {
  available: boolean;
  access_read: boolean;
  access_write: boolean;
  provision: boolean;
  isolation_drill: boolean;
  customers: Record<string, ProviderConsoleCustomerAuthority>;
}

export interface ProviderOperator {
  id: string;
  email: string;
  role: ProviderOperatorRole;
  mfa: boolean;
  session?: string;
  authority?: ProviderConsoleAuthority;
}

export interface ProviderOperatorIdentity {
  id: string;
  external_id: string;
  user_name: string;
  email?: string;
  display_name?: string;
  role: ProviderOperatorRole;
  active: boolean;
  source: string;
  created_at: string;
  updated_at: string;
  deprovisioned_at?: string;
}

export interface ProviderDelegation {
  operator_id: string;
  customer_id: string;
  operation: ProviderOperation;
  source: string;
  granted_by?: string;
  granted_at: string;
  expires_at?: string;
  last_used_at?: string;
  revoked_at?: string;
  revoked_by?: string;
}

export interface ProviderOperatorAccess {
  identity: ProviderOperatorIdentity;
  delegations: ProviderDelegation[];
}

export type ProviderUsageEvidence = UsageEvidence;

export interface ProviderEvidenceJWKSet {
  keys: Array<JsonWebKey & { kid?: string; alg?: string; use?: string }>;
}

export interface ProviderEvidenceVerification {
  verified: boolean;
  keyId?: string;
}

/** ProviderAuthError is thrown when no operator token is present or the plane
 * refuses the credential. An anonymous probe quietly keeps the login gate;
 * a rejected sign-in or active session returns there with generic recovery
 * guidance while discarding credentials and the former session cache. */
export class ProviderAuthError extends Error {}

export class ProviderApiError extends Error {
  constructor(
    public status: number,
    public body: string,
  ) {
    super(`provider api ${status}: ${body}`);
  }
}

function newProviderIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `provider-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function providerFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = providerToken();
  const method = String(init?.method ?? "GET").toUpperCase();
  const mutationHeaders: Record<string, string> = method === "GET" || method === "HEAD" ? {} : { "Idempotency-Key": newProviderIdempotencyKey() };
  const csrf = providerCSRFCookie();
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...mutationHeaders,
      ...(csrf && method !== "GET" && method !== "HEAD" ? { "X-Provider-CSRF-Token": csrf } : {}),
      ...(init?.headers ?? {}),
    },
  });
  // Missing customer delegation, role, MFA, or write entitlement is a refusal
  // of this operation, not evidence that the operator's credential expired.
  if (res.status === 401) {
    throw new ProviderAuthError(await res.text());
  }
  if (!res.ok) {
    throw new ProviderApiError(res.status, await res.text());
  }
  return res;
}

async function providerReq<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await providerFetch(path, init);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function providerCSRFCookie(): string | null {
  if (typeof document === "undefined") return null;
  for (const part of document.cookie.split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name === "trstctl_provider_csrf") return decodeURIComponent(value.join("="));
  }
  return null;
}

function providerEvidencePath(customerId: string, periodStart: string, periodEnd: string, format?: "csv"): string {
  const query = new URLSearchParams({ period_start: periodStart, period_end: periodEnd });
  if (format) query.set("format", format);
  return `/provider/v1/tenants/${encodeURIComponent(customerId)}/usage-evidence?${query.toString()}`;
}

// canonicalProviderUsageEvidence is byte-for-byte the Go billing document's
// canonical form. The console verifies THESE displayed values, not merely the
// signature over some hidden payload returned beside them.
export function canonicalProviderUsageEvidence(document: ProviderUsageEvidence): Uint8Array {
  let canonical = `${document.customer_id}\n${document.period_start}\n${document.period_end}\n${String(document.signable)}\n${document.reason}\n`;
  canonical += `${document.observed_from ?? ""}\n${document.observed_to ?? ""}\n`;
  for (const line of document.lines ?? []) {
    canonical += `${line.meter}|${line.kind}|${line.value}\n`;
  }
  for (const line of document.reconciliation ?? []) {
    canonical += `reconcile:${line.meter ?? ""}|${line.metered ?? 0}|${line.event_history ?? 0}|${String(line.checked ?? false)}|${String(line.matches ?? false)}\n`;
  }
  return new TextEncoder().encode(canonical);
}

function decodeBase64URL(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) throw new Error("invalid base64url");
  const base64 = segment.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (segment.length % 4)) % 4);
  const raw = atob(base64);
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

export async function verifyProviderUsageEvidence(document: ProviderUsageEvidence, jwks: ProviderEvidenceJWKSet): Promise<ProviderEvidenceVerification> {
  const envelope = document.signature;
  const keyId = envelope?.key_id;
  if (!envelope?.jws || envelope.alg !== "RS256" || !keyId) return { verified: false, keyId };
  try {
    const parts = envelope.jws.split(".");
    if (parts.length !== 3) return { verified: false, keyId };
    const header = JSON.parse(new TextDecoder().decode(decodeBase64URL(parts[0]))) as {
      alg?: string;
      kid?: string;
      trstctl_artifact?: string;
    };
    if (header.alg !== "RS256" || header.kid !== keyId || header.trstctl_artifact !== "trstctl.audit-evidence/billing-invoice/v1") {
      return { verified: false, keyId };
    }
    const jwk = jwks.keys.find((candidate) => candidate.kid === keyId && candidate.kty === "RSA");
    if (!jwk || (jwk.alg && jwk.alg !== "RS256") || (jwk.use && jwk.use !== "sig")) return { verified: false, keyId };

    const payload = decodeBase64URL(parts[1]);
    if (!equalBytes(payload, canonicalProviderUsageEvidence(document))) return { verified: false, keyId };
    if (hex(await crypto.subtle.digest("SHA-256", asArrayBuffer(payload))) !== document.digest.toLowerCase()) return { verified: false, keyId };

    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const verified = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      asArrayBuffer(decodeBase64URL(parts[2])),
      asArrayBuffer(new TextEncoder().encode(`${parts[0]}.${parts[1]}`)),
    );
    return { verified, keyId };
  } catch {
    return { verified: false, keyId };
  }
}

async function downloadProviderEvidence(customerId: string, periodStart: string, periodEnd: string, format: "json" | "csv"): Promise<void> {
  const response = await providerFetch(providerEvidencePath(customerId, periodStart, periodEnd, format === "csv" ? "csv" : undefined), {
    headers: { Accept: format === "csv" ? "text/csv" : "application/json" },
  });
  const blob = await response.blob();
  const objectURL = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectURL;
  anchor.download = `usage-evidence-${customerId}-${periodStart.slice(0, 10)}-${periodEnd.slice(0, 10)}.${format}`;
  anchor.click();
  URL.revokeObjectURL(objectURL);
}

async function providerCustomerHealth(customerId: string): Promise<ProviderTenantSnapshot> {
  const snapshot = await providerReq<ProviderTenantSnapshot>(`/provider/v1/tenants/${encodeURIComponent(customerId)}/health`);
  if (
    snapshot.tenant_id !== customerId ||
    typeof snapshot.health !== "string" ||
    snapshot.health.trim() === "" ||
    !Number.isSafeInteger(snapshot.active_certificates) ||
    snapshot.active_certificates < 0
  ) {
    // A mismatched or malformed count is UNKNOWN, never another customer's
    // health displayed under the selected customer's label.
    throw new Error("provider: customer health response does not match the requested customer");
  }
  return snapshot;
}

export const providerApi = {
  availability: async (): Promise<boolean | null> => {
    try {
      const res = await fetch("/auth/methods", { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (!res.ok) return null;
      const out = (await res.json()) as { provider_plane?: unknown };
      return typeof out.provider_plane === "boolean" ? out.provider_plane : null;
    } catch {
      return null;
    }
  },
  authMethods: async (): Promise<string[]> => {
    const out = await providerReq<{ methods: string[] | null }>("/provider/v1/auth/methods");
    return out.methods ?? [];
  },
  session: (): Promise<ProviderOperator> => providerReq<ProviderOperator>("/provider/v1/auth/session"),
  signOut: (): Promise<void> => providerReq<void>("/provider/v1/auth/logout", { method: "POST" }),
  listTenants: async (): Promise<ProviderTenant[]> => {
    const out = await providerReq<{ tenants: ProviderTenant[] | null }>("/provider/v1/tenants");
    return out.tenants ?? [];
  },
  listActivity: async (): Promise<ProviderActivity[]> => {
    const out = await providerReq<{ items: ProviderActivity[] | null }>("/provider/v1/activity?limit=100");
    return out.items ?? [];
  },
  listOperatorAccess: async (): Promise<ProviderOperatorAccess[]> => {
    const out = await providerReq<{ operators: ProviderOperatorAccess[] | null }>("/provider/v1/operators");
    return out.operators ?? [];
  },
  listAccessCustomers: async (): Promise<ProviderTenant[]> => {
    const out = await providerReq<{ tenants: ProviderTenant[] | null }>("/provider/v1/access/customers");
    return out.tenants ?? [];
  },
  customerHealth: providerCustomerHealth,
  usageEvidence: (customerId: string, periodStart: string, periodEnd: string): Promise<ProviderUsageEvidence> =>
    providerReq<ProviderUsageEvidence>(providerEvidencePath(customerId, periodStart, periodEnd)),
  evidenceVerificationKeys: (): Promise<ProviderEvidenceJWKSet> => providerReq<ProviderEvidenceJWKSet>("/provider/v1/evidence/verification-keys"),
  verifyUsageEvidence: async (document: ProviderUsageEvidence): Promise<ProviderEvidenceVerification> =>
    verifyProviderUsageEvidence(document, await providerApi.evidenceVerificationKeys()),
  downloadUsageEvidence: (customerId: string, periodStart: string, periodEnd: string, format: "json" | "csv"): Promise<void> =>
    downloadProviderEvidence(customerId, periodStart, periodEnd, format),
  grantOperatorAccess: (
    operatorId: string,
    input: { customer_id: string; operations: ProviderOperation[]; expires_at?: string },
  ): Promise<ProviderOperatorAccess> =>
    providerReq<ProviderOperatorAccess>(`/provider/v1/operators/${encodeURIComponent(operatorId)}/delegations`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  revokeOperatorAccess: (
    operatorId: string,
    input: { customer_id: string; operations: ProviderOperation[]; reason: string },
  ): Promise<ProviderOperatorAccess> =>
    providerReq<ProviderOperatorAccess>(`/provider/v1/operators/${encodeURIComponent(operatorId)}/revocations`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  setOperatorRole: (operatorId: string, role: ProviderOperatorRole): Promise<ProviderOperatorAccess> =>
    providerReq<ProviderOperatorAccess>(`/provider/v1/operators/${encodeURIComponent(operatorId)}/role`, {
      method: "POST",
      body: JSON.stringify({ role }),
    }),
  provisionTenant: (input: { slug: string; name: string }): Promise<ProviderTenant> =>
    providerReq<ProviderTenant>("/provider/v1/tenants", { method: "POST", body: JSON.stringify(input) }),
  suspendTenant: (id: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/suspend`, { method: "POST", body: JSON.stringify({}) }),
  resumeTenant: (id: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/resume`, { method: "POST", body: JSON.stringify({}) }),
  offboardTenant: (id: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/offboard`, { method: "POST", body: JSON.stringify({}) }),
  getQuota: (id: string): Promise<ProviderQuota> => providerReq<ProviderQuota>(`/provider/v1/tenants/${encodeURIComponent(id)}/quota`),
  setQuota: (id: string, quota: ProviderQuota): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/quota`, { method: "PUT", body: JSON.stringify(quota) }),
  setBrand: (id: string, brand: ProviderBrand): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/brand`, { method: "PUT", body: JSON.stringify(brand) }),
  runIsolationDrill: (): Promise<ProviderDrillReport> =>
    providerReq<ProviderDrillReport>("/provider/v1/isolation-drill", { method: "POST", body: JSON.stringify({}) }),
  requestBreakGlass: (input: { tenant_id: string; reason: string; ttl: string }): Promise<ProviderBreakGlassGrant> =>
    providerReq<ProviderBreakGlassGrant>("/provider/v1/breakglass", { method: "POST", body: JSON.stringify(input) }),
  consentBreakGlass: (grantId: string, tenantId: string, approve = true): Promise<ProviderBreakGlassGrant> =>
    providerReq<ProviderBreakGlassGrant>(`/provider/v1/breakglass/${encodeURIComponent(grantId)}/consent`, {
      method: "POST",
      body: JSON.stringify({ tenant_id: tenantId, approve }),
    }),
  breakGlassResults: (grantId: string): Promise<ProviderTenantSnapshot> =>
    providerReq<ProviderTenantSnapshot>(`/provider/v1/breakglass/${encodeURIComponent(grantId)}/results`, {
      method: "POST",
      body: JSON.stringify({}),
    }),
};
