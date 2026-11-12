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

export type ProviderTenantStatus = "active" | "suspension_pending" | "suspended" | "offboarding" | "offboard_failed" | "offboarded";

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
  max_certificates_stored?: number;
  max_secrets_stored?: number;
  updated_by?: string;
}

/** MSP-2: a configured billing system the Provider pushes usage to. */
export interface ProviderBillingTarget {
  id: string;
  name?: string;
  type: string;
  cadence: string;
}

/** MSP-2: one customer's company in one billing system. */
export interface ProviderBillingCompany {
  tenant_id: string;
  target_id: string;
  external_company_id: string;
  mapped_by?: string;
  mapped_at?: string;
}

export interface ProviderBillingCompanies {
  targets: ProviderBillingTarget[];
  companies: ProviderBillingCompany[];
}

/** MSP-2: one customer usage period pushed (or held) for one billing system. */
export interface ProviderBillingSyncPush {
  target_id: string;
  period_start: string;
  period_end: string;
  status: "queued" | "held" | "delivered" | "failed";
  external_company_id?: string;
  evidence_digest?: string;
  reason?: string;
  response_status?: number;
  updated_at: string;
}

export interface ProviderBrand {
  product_name?: string;
  logo_data_uri?: string;
  login_message?: string;
  email_from_name?: string;
  email_footer?: string;
  custom_domain?: string;
  token_overrides?: Record<string, string>;
}

export interface ProviderBrandSnapshot extends ProviderBrand {
  tenant_id: string;
  revision: string;
}

export interface ProviderDrillCheck {
  name: string;
  passed: boolean;
  detail: string;
}

/** A96: one customer's isolation as the deployment serves it. */
export interface ProviderCustomerIsolation {
  tenant_id: string;
  model: string;
  postgres_schema?: string;
  jetstream_subject_lane?: string;
  object_key_prefix?: string;
  audit_stream: { name?: string; exists: boolean; messages: number };
  note?: string;
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
  request_event_id?: string;
  offboard_state?: "pending" | "failed" | "completed";
  can_continue_offboard?: boolean;
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
  consented_at?: string;
  consented_by?: string;
  second_consented_at?: string;
  second_consented_by?: string;
  denied_at?: string;
  denied_by?: string;
  revoked_at?: string;
}

export type ProviderBreakGlassState = "pending" | "awaiting_co_consent" | "active" | "denied" | "withdrawn" | "revoked" | "expired";

export interface ProviderBreakGlassGrantView extends ProviderBreakGlassGrant {
  /** A95: the customer's own consent standing for this grant. */
  tenant_consent_required?: boolean;
  tenant_approvals?: number;
  tenant_denied?: boolean;
  state: ProviderBreakGlassState;
}

export interface ProviderBreakGlassGrantPage {
  items: ProviderBreakGlassGrantView[];
  next_cursor?: string;
}

export interface ProviderTenantSnapshot {
  tenant_id: string;
  health: string;
  active_certificates: number;
  workspace_initialized?: boolean;
}

/** A90: admin, operator, or the name of a custom role defined at /provider/v1/roles. */
export type ProviderOperatorRole = string;

export interface ProviderPermission {
  name: string;
  description: string;
}

export interface ProviderRole {
  name: string;
  description?: string;
  permissions: string[];
  built_in: boolean;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ProviderRoleCatalog {
  roles: ProviderRole[];
  permissions: ProviderPermission[];
}
export type ProviderOperation = "read" | "provision" | "suspend" | "resume" | "offboard" | "break-glass";

export interface ProviderConsoleCustomerAuthority {
  read_quota: boolean;
  write_quota: boolean;
  write_brand: boolean;
  suspend: boolean;
  resume: boolean;
  offboard: boolean;
  break_glass: boolean;
  break_glass_write: boolean;
  write_billing?: boolean;
}

export interface ProviderConsoleAuthority {
  available: boolean;
  access_read: boolean;
  access_write: boolean;
  provision: boolean;
  isolation_drill: boolean;
  /** A90: may define or delete custom Provider roles. */
  roles_write?: boolean;
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
  grant_event_id?: string;
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
/** A186: one recorded version of a tenant template (its baseline as recorded). */
export interface ProviderTemplate {
  id: string;
  version: number;
  name: string;
  baseline: Record<string, unknown>;
  digest: string;
  recorded_by?: string;
  recorded_at?: string;
}

/** A186: a delegated customer's binding to a template version. */
export interface ProviderTemplateApplication {
  tenant_id: string;
  template_id: string;
  version: number;
  digest?: string;
  complete: boolean;
  results: { kind: string; key: string; status: string; outcome: string }[];
  applied_by?: string;
  applied_at?: string;
}

/** A186: a template's versions and the customers bound to it. */
export interface ProviderTemplateDetail {
  latest: ProviderTemplate;
  versions: ProviderTemplate[];
  tenants: ProviderTemplateApplication[];
}

/** A187: a delegated customer's signed assurance report runs, newest first,
 * with the key that signs them. */
export interface ProviderAssuranceReports {
  tenant_id: string;
  signing_key: { public_key_pem: string; public_key_der: string; sha256: string };
  runs: { run_id: string; schedule_id: string; due_at: string; completed_at?: string; artifact_sha256: string }[];
}

export class ProviderAuthError extends Error {}

export class ProviderApiError extends Error {
  readonly code: string | null;

  constructor(
    public status: number,
    public body: string,
  ) {
    let code: string | null = null;
    let detail: string | null = null;
    try {
      const problem: unknown = JSON.parse(body);
      if (problem && typeof problem === "object") {
        if ("code" in problem && typeof problem.code === "string") code = problem.code;
        if ("detail" in problem && typeof problem.detail === "string") detail = problem.detail;
      }
    } catch {
      // Do not render raw upstream HTML or proxy diagnostics in the console.
    }
    super(detail || `Provider request failed (HTTP ${status}).`);
    this.code = code;
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

/** A187-L1: saves one signed assurance report run exactly as the plane serves
 * it (read back from the archive and verified there); the customer verifies
 * the file offline. */
async function downloadProviderAssuranceReport(customerId: string, runId: string): Promise<void> {
  const response = await providerFetch(`/provider/v1/tenants/${encodeURIComponent(customerId)}/assurance-reports/${encodeURIComponent(runId)}`, {
    headers: { Accept: "application/json" },
  });
  const blob = await response.blob();
  const objectURL = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectURL;
  anchor.download = `assurance-report-${customerId}-${runId}.json`;
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
    snapshot.active_certificates < 0 ||
    (snapshot.workspace_initialized !== undefined && typeof snapshot.workspace_initialized !== "boolean")
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
  listTemplates: async (): Promise<ProviderTemplate[]> => (await providerReq<ProviderTemplate[] | null>("/provider/v1/templates")) ?? [],
  getTemplate: (id: string): Promise<ProviderTemplateDetail> => providerReq<ProviderTemplateDetail>(`/provider/v1/templates/${encodeURIComponent(id)}`),
  listActivity: async (): Promise<ProviderActivity[]> => {
    const out = await providerReq<{ items: ProviderActivity[] | null }>("/provider/v1/activity?limit=100");
    return out.items ?? [];
  },
  listOperatorAccess: async (): Promise<ProviderOperatorAccess[]> => {
    const out = await providerReq<{ operators: ProviderOperatorAccess[] | null }>("/provider/v1/operators");
    return out.operators ?? [];
  },
  listRoles: async (): Promise<ProviderRoleCatalog> => {
    const out = await providerReq<{ roles: ProviderRole[] | null; permissions: ProviderPermission[] | null }>("/provider/v1/roles");
    return { roles: out.roles ?? [], permissions: out.permissions ?? [] };
  },
  putRole: (name: string, input: { description: string; permissions: string[] }): Promise<ProviderRole> =>
    providerReq<ProviderRole>(`/provider/v1/roles/${encodeURIComponent(name)}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteRole: (name: string): Promise<void> => providerReq<void>(`/provider/v1/roles/${encodeURIComponent(name)}`, { method: "DELETE" }),
  listAccessCustomers: async (): Promise<ProviderTenant[]> => {
    const out = await providerReq<{ tenants: ProviderTenant[] | null }>("/provider/v1/access/customers");
    return out.tenants ?? [];
  },
  customerHealth: providerCustomerHealth,
  customerIsolation: (customerId: string): Promise<ProviderCustomerIsolation> =>
    providerReq<ProviderCustomerIsolation>(`/provider/v1/tenants/${encodeURIComponent(customerId)}/isolation`),
  assuranceReports: (customerId: string): Promise<ProviderAssuranceReports> =>
    providerReq<ProviderAssuranceReports>(`/provider/v1/tenants/${encodeURIComponent(customerId)}/assurance-reports`),
  downloadAssuranceReport: downloadProviderAssuranceReport,
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
  offboardTenant: (id: string, requestEventId?: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/offboard`, {
      method: "POST",
      body: JSON.stringify(requestEventId ? { request_event_id: requestEventId } : {}),
    }),
  getQuota: (id: string): Promise<ProviderQuota> => providerReq<ProviderQuota>(`/provider/v1/tenants/${encodeURIComponent(id)}/quota`),
  setQuota: (id: string, quota: ProviderQuota): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/quota`, { method: "PUT", body: JSON.stringify(quota) }),
  billingCompanies: (id: string): Promise<ProviderBillingCompanies> =>
    providerReq<ProviderBillingCompanies>(`/provider/v1/tenants/${encodeURIComponent(id)}/billing-companies`),
  setBillingCompany: (id: string, target: string, externalCompanyId: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/billing-companies/${encodeURIComponent(target)}`, {
      method: "PUT",
      body: JSON.stringify({ external_company_id: externalCompanyId }),
    }),
  billingSyncPushes: (id: string): Promise<{ pushes: ProviderBillingSyncPush[] }> =>
    providerReq<{ pushes: ProviderBillingSyncPush[] }>(`/provider/v1/tenants/${encodeURIComponent(id)}/billing-sync`),
  clearBillingCompany: (id: string, target: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/billing-companies/${encodeURIComponent(target)}`, { method: "DELETE" }),
  getBrand: async (id: string): Promise<ProviderBrandSnapshot> => {
    const brand = await providerReq<ProviderBrandSnapshot>(`/provider/v1/tenants/${encodeURIComponent(id)}/brand`);
    if (!brand || brand.tenant_id !== id || typeof brand.revision !== "string" || brand.revision.length === 0) {
      throw new Error("provider: brand readback does not match the requested customer or revision");
    }
    return brand;
  },
  setBrand: (id: string, brand: ProviderBrand, revision: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/brand`, {
      method: "PUT",
      body: JSON.stringify(brand),
      headers: { "If-Match": JSON.stringify(revision) },
    }),
  runIsolationDrill: (): Promise<ProviderDrillReport> =>
    providerReq<ProviderDrillReport>("/provider/v1/isolation-drill", { method: "POST", body: JSON.stringify({}) }),
  requestBreakGlass: (input: { tenant_id: string; reason: string; ttl: string }): Promise<ProviderBreakGlassGrant> =>
    providerReq<ProviderBreakGlassGrant>("/provider/v1/breakglass", { method: "POST", body: JSON.stringify(input) }),
  listBreakGlass: async (customerId: string, before = ""): Promise<ProviderBreakGlassGrantPage> => {
    const query = new URLSearchParams({ limit: "25" });
    if (before) query.set("before", before);
    const page = await providerReq<ProviderBreakGlassGrantPage>(`/provider/v1/tenants/${encodeURIComponent(customerId)}/breakglass?${query.toString()}`);
    if (!Array.isArray(page.items) || page.items.some((grant) => grant.tenant_id !== customerId)) {
      throw new Error("provider: emergency queue does not match the selected customer");
    }
    return page;
  },
  consentBreakGlass: (grantId: string, tenantId: string, approve = true): Promise<ProviderBreakGlassGrant> =>
    providerReq<ProviderBreakGlassGrant>(`/provider/v1/breakglass/${encodeURIComponent(grantId)}/consent`, {
      method: "POST",
      body: JSON.stringify({ tenant_id: tenantId, approve }),
    }),
  breakGlassResults: async (grantId: string, customerId: string): Promise<ProviderTenantSnapshot> => {
    const snapshot = await providerReq<ProviderTenantSnapshot>(`/provider/v1/breakglass/${encodeURIComponent(grantId)}/results`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    if (snapshot.tenant_id !== customerId || !Number.isSafeInteger(snapshot.active_certificates) || snapshot.active_certificates < 0) {
      throw new Error("provider: emergency result does not match the selected customer");
    }
    return snapshot;
  },
};
