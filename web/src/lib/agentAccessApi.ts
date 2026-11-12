import { mutate, req } from "./apiTransport";
import type {
  AccessActivityExport,
  AccessActivityList,
  AccessAuthority,
  AccessBundle,
  AccessBundleDeleted,
  AccessBundleGrantChange,
  AccessBundleGrantRequest,
  AccessBundleList,
  AccessBundleRequest,
  AccessBundleStandingApproval,
  AccessBundleStandingApprovalList,
  AccessBundleStandingApprovalRequest,
  AccessBundleStandingApprovalRevoked,
  AccessRun,
  AccessRunIssued,
  AccessRunList,
  AccessRunRequest,
} from "./api-types.gen";

// A251: agent access bundles, their grants, effective authority, runs and
// activity. Every mutation carries its own Idempotency-Key.

export type AccessActivityFilter = { bundle?: string; principal?: string; q?: string };

const query = (params: Record<string, string | number | undefined>) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
};

export const accessBundles = () => req<AccessBundleList>("/api/v1/access/bundles");
export const accessBundle = (id: string) => req<AccessBundle>(`/api/v1/access/bundles/${encodeURIComponent(id)}`);
export const createAccessBundle = (request: AccessBundleRequest, idempotencyKey?: string) =>
  mutate<AccessBundle>("POST", "/api/v1/access/bundles", request, idempotencyKey);
export const updateAccessBundle = (id: string, request: AccessBundleRequest, idempotencyKey?: string) =>
  mutate<AccessBundle>("PUT", `/api/v1/access/bundles/${encodeURIComponent(id)}`, request, idempotencyKey);
export const deleteAccessBundle = (id: string, idempotencyKey?: string) =>
  mutate<AccessBundleDeleted>("DELETE", `/api/v1/access/bundles/${encodeURIComponent(id)}`, undefined, idempotencyKey);
export const grantAccessBundle = (id: string, request: AccessBundleGrantRequest, idempotencyKey?: string) =>
  mutate<AccessBundleGrantChange>("POST", `/api/v1/access/bundles/${encodeURIComponent(id)}/grants`, request, idempotencyKey);
export const ungrantAccessBundle = (id: string, grantID: string, reason?: string, idempotencyKey?: string) =>
  mutate<AccessBundleGrantChange>(
    "DELETE",
    `/api/v1/access/bundles/${encodeURIComponent(id)}/grants/${encodeURIComponent(grantID)}${query({ reason })}`,
    undefined,
    idempotencyKey,
  );
// OD-9: a bundle's standing approvals for its delegated accounts.
export const accessBundleStandingApprovals = async (id: string) =>
  (await req<AccessBundleStandingApprovalList>(`/api/v1/access/bundles/${encodeURIComponent(id)}/standing-approvals`)).items ?? [];
export const grantAccessBundleStandingApproval = (id: string, request: AccessBundleStandingApprovalRequest, idempotencyKey?: string) =>
  mutate<AccessBundleStandingApproval>("POST", `/api/v1/access/bundles/${encodeURIComponent(id)}/standing-approvals`, request, idempotencyKey);
export const revokeAccessBundleStandingApproval = (id: string, approvalID: string, reason: string, idempotencyKey?: string) =>
  mutate<AccessBundleStandingApprovalRevoked>(
    "POST",
    `/api/v1/access/bundles/${encodeURIComponent(id)}/standing-approvals/${encodeURIComponent(approvalID)}/revoke`,
    { reason },
    idempotencyKey,
  );
export const accessAuthority = (principal: string) => req<AccessAuthority>(`/api/v1/access/authority${query({ principal })}`);
export const issueAccessRun = (request: AccessRunRequest, idempotencyKey?: string) =>
  mutate<AccessRunIssued>("POST", "/api/v1/access/runs", request, idempotencyKey);
export const accessRuns = (filter: { principal?: string; bundle?: string; limit?: number } = {}) => req<AccessRunList>(`/api/v1/access/runs${query(filter)}`);
export const revokeAccessRun = (id: string, idempotencyKey?: string) =>
  mutate<AccessRun>("POST", `/api/v1/access/runs/${encodeURIComponent(id)}/revoke`, undefined, idempotencyKey);
export const accessActivity = (filter: AccessActivityFilter & { limit?: number; cursor?: string } = {}) =>
  req<AccessActivityList>(`/api/v1/access/activity${query(filter)}`);
export const exportAccessActivity = (filter: AccessActivityFilter = {}) => req<AccessActivityExport>(`/api/v1/access/activity/export${query(filter)}`);
