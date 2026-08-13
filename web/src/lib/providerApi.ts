// SPDX-License-Identifier: MPL-2.0

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
export type ProviderOperation = "read" | "provision" | "suspend" | "offboard" | "break_glass";

export interface ProviderOperator {
  id: string;
  email: string;
  role: ProviderOperatorRole;
  mfa: boolean;
  session?: string;
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

/** ProviderAuthError is thrown when no operator token is present or the plane
 * refuses the credential — the console renders the login gate rather than an
 * error banner, because "not signed in" is not a failure. */
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

async function providerReq<T>(path: string, init?: RequestInit): Promise<T> {
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
  if (res.status === 401 || res.status === 403) {
    throw new ProviderAuthError(await res.text());
  }
  if (!res.ok) {
    throw new ProviderApiError(res.status, await res.text());
  }
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

export const providerApi = {
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
