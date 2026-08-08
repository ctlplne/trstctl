// SPDX-License-Identifier: MPL-2.0

// The provider-plane client (epic L3).
//
// /provider/v1 is a SEPARATE plane from /api/v1: its caller is the provider's
// own staff, authenticated by the provider IdP (L1) rather than a tenant
// session. So it does not go through the tenant `req<T>` client — it carries an
// operator BEARER token, and a request without one is refused by the plane
// rather than falling back to a tenant cookie that would mean nothing here.
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

async function providerReq<T>(path: string, init?: RequestInit): Promise<T> {
  const token = providerToken();
  if (!token) {
    throw new ProviderAuthError("no provider operator token");
  }
  const res = await fetch(path, {
    ...init,
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
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

export const providerApi = {
  listTenants: async (): Promise<ProviderTenant[]> => {
    const out = await providerReq<{ tenants: ProviderTenant[] | null }>("/provider/v1/tenants");
    return out.tenants ?? [];
  },
  provisionTenant: (input: { slug: string; name: string }): Promise<ProviderTenant> =>
    providerReq<ProviderTenant>("/provider/v1/tenants", { method: "POST", body: JSON.stringify(input) }),
  suspendTenant: (id: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/suspend`, { method: "POST", body: JSON.stringify({}) }),
  offboardTenant: (id: string): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/offboard`, { method: "POST", body: JSON.stringify({}) }),
  getQuota: (id: string): Promise<ProviderQuota> =>
    providerReq<ProviderQuota>(`/provider/v1/tenants/${encodeURIComponent(id)}/quota`),
  setQuota: (id: string, quota: ProviderQuota): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/quota`, { method: "PUT", body: JSON.stringify(quota) }),
  setBrand: (id: string, brand: ProviderBrand): Promise<void> =>
    providerReq<void>(`/provider/v1/tenants/${encodeURIComponent(id)}/brand`, { method: "PUT", body: JSON.stringify(brand) }),
  runIsolationDrill: (): Promise<ProviderDrillReport> =>
    providerReq<ProviderDrillReport>("/provider/v1/isolation-drill", { method: "POST", body: JSON.stringify({}) }),
};
