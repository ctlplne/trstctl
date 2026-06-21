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
  AIAnswer as GenAIAnswer,
  AIQueryRequest,
  APIToken,
  APITokenCreateRequest,
  APITokenCreateResponse,
  APITokenList,
  Approval as GenApproval,
  ApprovalRequest,
  AuditBundle,
  AuditEvent as GenAuditEvent,
  Certificate as GenCertificate,
  CertificateIngest,
  CertificateList,
  ConnectorCatalog,
  ConnectorCatalogItem,
  ConnectorDelivery,
  ConnectorDeliveryList,
  CredentialRisk as GenCredentialRisk,
  CredentialRiskList,
  DiscoveryFinding,
  DiscoveryFindingList,
  DiscoveryRun,
  DiscoveryRunList,
  DiscoveryRunRequest,
  DiscoverySchedule,
  DiscoveryScheduleList,
  DiscoveryScheduleRequest,
  DiscoverySource,
  DiscoverySourceList,
  DiscoverySourceRequest,
  GraphImpact,
  GraphNode,
  GraphQueryResult,
  GraphReachable,
  GraphResponse,
  IncidentExecution,
  IncidentExecutionList,
  IncidentExecutionRequest,
  Owner as GenOwner,
  OwnerRequest,
  Profile as GenProfile,
  ProfileRequest,
  Issuer as GenIssuer,
  IssuerRequest,
  Identity as GenIdentity,
  IdentityRequest,
  TransitionRequest,
  Agent as GenAgent,
  EnrollmentToken as GenEnrollmentToken,
  MCPToolCall,
  MCPToolList,
  MCPToolResult,
  MachineLoginRequest,
  MachineLoginResponse,
  Member,
  MemberList,
  MemberRequest,
  OffboardMemberRequest,
  OffboardMemberResponse,
  OIDCMappingStatus,
  PKISecret,
  PKISecretRequest,
  RCARequest,
  RoleList,
  RotationRun,
  RotationRunList,
  SecretMeta,
  SecretMetaList,
  SecretRequest,
  SecretValue,
  ShareRedeemRequest,
  ShareRequest,
  ShareToken,
  ShareValue,
} from "./api-types.gen";

// Re-export the generated, contract-bound resource types under the names the SPA uses.
export type Certificate = GenCertificate;
export type CertificatePage = CertificateList;
export type CertificateIngestRequest = CertificateIngest;
export type Owner = GenOwner;
export type Issuer = GenIssuer;
export type Identity = GenIdentity;
export type Agent = GenAgent;
export type EnrollmentToken = GenEnrollmentToken;
export type AIAnswer = GenAIAnswer;
export type CredentialRisk = GenCredentialRisk;
export type Approval = GenApproval;
export type AuditEvent = GenAuditEvent;
export type Profile = GenProfile;
export type IssueCertificateInput = {
  name: string;
  ownerId?: string;
  issuerId?: string;
};
export type {
  AuditBundle,
  DiscoveryFinding,
  DiscoveryFindingList,
  DiscoveryRun,
  DiscoveryRunList,
  DiscoveryRunRequest,
  DiscoverySchedule,
  DiscoveryScheduleList,
  DiscoveryScheduleRequest,
  DiscoverySource,
  DiscoverySourceList,
  DiscoverySourceRequest,
  ConnectorCatalog,
  ConnectorCatalogItem,
  ConnectorDelivery,
  ConnectorDeliveryList,
  GraphImpact,
  GraphNode,
  GraphQueryResult,
  GraphReachable,
  GraphResponse,
  IncidentExecution,
  IncidentExecutionList,
  IncidentExecutionRequest,
  MachineLoginRequest,
  MachineLoginResponse,
  Member,
  MemberList,
  MemberRequest,
  OffboardMemberRequest,
  OffboardMemberResponse,
  OIDCMappingStatus,
  APIToken,
  APITokenCreateRequest,
  APITokenCreateResponse,
  APITokenList,
  PKISecret,
  PKISecretRequest,
  RotationRun,
  RotationRunList,
  RoleList,
  SecretMeta,
  SecretMetaList,
  SecretRequest,
  SecretValue,
  ShareRedeemRequest,
  ShareRequest,
  ShareToken,
  ShareValue,
};
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

function isUnsafeMethod(method: string | undefined): boolean {
  const m = (method ?? "GET").toUpperCase();
  return m !== "GET" && m !== "HEAD" && m !== "OPTIONS" && m !== "TRACE";
}

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return undefined;
}

function csrfHeaders(method: string | undefined): Record<string, string> {
  if (!isUnsafeMethod(method)) return {};
  const token = readCookie("trstctl_csrf");
  return token ? { "X-CSRF-Token": token } : {};
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

export interface AuditQuery {
  type?: string;
  since?: string;
  until?: string;
  asOf?: number;
  q?: string;
  limit?: number;
}

export interface RiskQuery {
  sort?: "score" | "expiry";
  minScore?: number;
  privilege?: number;
  owner?: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const method = init?.method;
  const res = await fetch(path, {
    credentials: "include",
    ...init,
    headers: { Accept: "application/json", ...csrfHeaders(method), ...(init?.headers ?? {}) },
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

/** postRead sends a read-only POST. These endpoints accept structured bodies but do
 * not mutate state, so they deliberately do not carry Idempotency-Key. */
function postRead<T>(path: string, body?: unknown): Promise<T> {
  return req<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function firstCertificateIdentityRequest(input: IssueCertificateInput, ownerId: string): IdentityRequest {
  return {
    kind: "x509_certificate",
    name: input.name,
    owner_id: ownerId,
    ...(input.issuerId ? { issuer_id: input.issuerId } : {}),
  };
}

/** Api is the client surface the UI depends on; it is mockable in tests. The
 * request inputs are the OpenAPI-generated request bodies (OwnerRequest,
 * IssuerRequest, IdentityRequest, TransitionRequest) so a mutation cannot send a
 * field the server does not accept — the same contract guarantee as the responses. */
export interface Api {
  me(): Promise<Me>;
  certificates(): Promise<Certificate[]>;
  certificatePage(options?: {
    limit?: number;
    cursor?: string;
    expiringBefore?: string;
  }): Promise<CertificatePage>;
  getCertificate(id: string): Promise<Certificate>;
  ingestCertificate(input: CertificateIngestRequest): Promise<Certificate>;
  owners(): Promise<Owner[]>;
  createOwner(input: OwnerRequest): Promise<Owner>;
  issuers(): Promise<Issuer[]>;
  createIssuer(input: IssuerRequest): Promise<Issuer>;
  identities(): Promise<Identity[]>;
  getIdentity(id: string): Promise<Identity>;
  createIdentity(input: IdentityRequest): Promise<Identity>;
  transitionIdentity(id: string, to: TransitionRequest["to"], reason?: string): Promise<Identity>;
  approveIdentityAction(id: string, action: ApprovalRequest["action"]): Promise<Approval>;
  /** issueCertificate is the one-call convenience the wizard and the "issue"
   * action use: it ensures an owner, creates the identity, and issues it. */
  issueCertificate(input: IssueCertificateInput): Promise<Identity>;
  agents(): Promise<Agent[]>;
  createEnrollmentToken(): Promise<EnrollmentToken>;
  discoverySources(options?: { limit?: number; cursor?: string }): Promise<DiscoverySourceList>;
  createDiscoverySource(input: DiscoverySourceRequest): Promise<DiscoverySource>;
  discoverySchedules(options?: { limit?: number; cursor?: string }): Promise<DiscoveryScheduleList>;
  createDiscoverySchedule(input: DiscoveryScheduleRequest): Promise<DiscoverySchedule>;
  discoveryRuns(options?: { limit?: number; cursor?: string }): Promise<DiscoveryRunList>;
  getDiscoveryRun(id: string): Promise<DiscoveryRun>;
  startDiscoveryRun(input: DiscoveryRunRequest): Promise<DiscoveryRun>;
  discoveryFindings(options?: { limit?: number; cursor?: string; runId?: string }): Promise<DiscoveryFindingList>;
  connectorCatalog(): Promise<ConnectorCatalog>;
  connectorDeliveries(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<ConnectorDeliveryList>;
  rotationRuns(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<RotationRunList>;
  executeIncident(input: IncidentExecutionRequest): Promise<IncidentExecution>;
  incidentExecutions(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<IncidentExecutionList>;
  getIncidentExecution(id: string): Promise<IncidentExecution>;
  risk(options?: RiskQuery): Promise<CredentialRisk[]>;
  profiles(): Promise<Profile[]>;
  getProfileVersion(name: string, version: number): Promise<Profile>;
  createProfile(input: ProfileRequest): Promise<Profile>;
  accessRoles(): Promise<RoleList>;
  oidcMappingStatus(): Promise<OIDCMappingStatus>;
  members(options?: { limit?: number; cursor?: string; includeOffboarded?: boolean }): Promise<MemberList>;
  upsertMember(subject: string, input: MemberRequest): Promise<Member>;
  offboardMember(subject: string, input: OffboardMemberRequest): Promise<OffboardMemberResponse>;
  apiTokens(options?: { limit?: number; cursor?: string; subject?: string; includeRevoked?: boolean }): Promise<APITokenList>;
  createAPIToken(input: APITokenCreateRequest): Promise<APITokenCreateResponse>;
  revokeAPIToken(id: string): Promise<void>;
  auditEvents(options?: AuditQuery): Promise<AuditEvent[]>;
  exportAudit(options?: AuditQuery): Promise<AuditBundle>;
  graph(): Promise<GraphResponse>;
  graphBlastRadius(id: string): Promise<GraphImpact>;
  graphReachable(id: string): Promise<GraphReachable>;
  graphQuery(query: string): Promise<GraphQueryResult>;
  aiQuery(input: AIQueryRequest): Promise<AIAnswer>;
  aiRCA(input: RCARequest): Promise<AIAnswer>;
  mcpTools(): Promise<MCPToolList>;
  callMCPTool(tool: string, input: MCPToolCall): Promise<MCPToolResult>;
  secretPage(options?: { limit?: number; cursor?: string }): Promise<SecretMetaList>;
  createSecret(input: SecretRequest): Promise<SecretMeta>;
  getSecret(name: string): Promise<SecretValue>;
  rotateSecret(name: string, input: SecretRequest): Promise<SecretMeta>;
  deleteSecret(name: string): Promise<void>;
  issuePKISecret(input: PKISecretRequest): Promise<PKISecret>;
  machineLogin(input: MachineLoginRequest): Promise<MachineLoginResponse>;
  createShare(input: ShareRequest): Promise<ShareToken>;
  redeemShare(input: ShareRedeemRequest): Promise<ShareValue>;
}

export const api: Api = {
  me: () => req<Me>("/auth/me"),
  certificatePage: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    if (options?.expiringBefore) qs.set("expiring_before", options.expiringBefore);
    const suffix = qs.toString();
    return req<CertificatePage>(`/api/v1/certificates${suffix ? `?${suffix}` : ""}`);
  },
  certificates: () =>
    api.certificatePage().then((r) => r.items ?? []),
  getCertificate: (id) => req<Certificate>(`/api/v1/certificates/${encodeURIComponent(id)}`),
  ingestCertificate: (input) => mutate<Certificate>("POST", "/api/v1/certificates", input),
  owners: () => req<{ items: Owner[] }>("/api/v1/owners").then((r) => r.items ?? []),
  createOwner: (input) => mutate<Owner>("POST", "/api/v1/owners", input),
  issuers: () => req<{ items: Issuer[] }>("/api/v1/issuers").then((r) => r.items ?? []),
  createIssuer: (input) => mutate<Issuer>("POST", "/api/v1/issuers", input),
  identities: () => req<{ items: Identity[] }>("/api/v1/identities").then((r) => r.items ?? []),
  getIdentity: (id) => req<Identity>(`/api/v1/identities/${encodeURIComponent(id)}`),
  createIdentity: (input) => mutate<Identity>("POST", "/api/v1/identities", input),
  transitionIdentity: (id, to, reason) =>
    mutate<Identity>("POST", `/api/v1/identities/${encodeURIComponent(id)}/transitions`, { to, reason }),
  approveIdentityAction: (id, action) =>
    mutate<Approval>("POST", `/api/v1/identities/${encodeURIComponent(id)}/approvals`, { action }),
  issueCertificate: async (input) => {
    let ownerId = input.ownerId;
    if (!ownerId) {
      const owner = await api.createOwner({ kind: "workload", name: input.name });
      ownerId = owner.id;
    }
    const identity = await api.createIdentity(firstCertificateIdentityRequest(input, ownerId));
    return api.transitionIdentity(identity.id, "issued", "first issuance via UI");
  },
  agents: () => req<{ agents: Agent[] }>("/api/v1/agents").then((r) => r.agents ?? []),
  createEnrollmentToken: () => mutate<EnrollmentToken>("POST", "/api/v1/agents/enrollment-tokens"),
  discoverySources: (options) =>
    req<DiscoverySourceList>(`/api/v1/discovery/sources${pageQueryString(options)}`),
  createDiscoverySource: (input) => mutate<DiscoverySource>("POST", "/api/v1/discovery/sources", input),
  discoverySchedules: (options) =>
    req<DiscoveryScheduleList>(`/api/v1/discovery/schedules${pageQueryString(options)}`),
  createDiscoverySchedule: (input) => mutate<DiscoverySchedule>("POST", "/api/v1/discovery/schedules", input),
  discoveryRuns: (options) =>
    req<DiscoveryRunList>(`/api/v1/discovery/runs${pageQueryString(options)}`),
  getDiscoveryRun: (id) => req<DiscoveryRun>(`/api/v1/discovery/runs/${encodeURIComponent(id)}`),
  startDiscoveryRun: (input) => mutate<DiscoveryRun>("POST", "/api/v1/discovery/runs", input),
  discoveryFindings: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    if (options?.runId) qs.set("run_id", options.runId);
    const suffix = qs.toString();
    return req<DiscoveryFindingList>(`/api/v1/discovery/findings${suffix ? `?${suffix}` : ""}`);
  },
  connectorCatalog: () => req<ConnectorCatalog>("/api/v1/connectors/catalog"),
  connectorDeliveries: (options) =>
    req<ConnectorDeliveryList>(`/api/v1/connectors/deliveries${pageQueryString(options, options?.identityId)}`),
  rotationRuns: (options) =>
    req<RotationRunList>(`/api/v1/lifecycle/rotation-runs${pageQueryString(options, options?.identityId)}`),
  executeIncident: (input) => mutate<IncidentExecution>("POST", "/api/v1/incidents/executions", input),
  incidentExecutions: (options) =>
    req<IncidentExecutionList>(`/api/v1/incidents/executions${pageQueryString(options, options?.identityId)}`),
  getIncidentExecution: (id) => req<IncidentExecution>(`/api/v1/incidents/executions/${encodeURIComponent(id)}`),
  risk: (options) =>
    req<CredentialRiskList>(`/api/v1/risk/credentials${riskQueryString(options)}`).then((r) => r.credentials ?? []),
  profiles: () => req<{ items: Profile[] }>("/api/v1/profiles").then((r) => r.items ?? []),
  getProfileVersion: (name, version) =>
    req<Profile>(`/api/v1/profiles/${encodeURIComponent(name)}/versions/${version}`),
  createProfile: (input) => mutate<Profile>("POST", "/api/v1/profiles", input),
  accessRoles: () => req<RoleList>("/api/v1/access/roles"),
  oidcMappingStatus: () => req<OIDCMappingStatus>("/api/v1/access/oidc-mapping"),
  members: (options) => req<MemberList>(`/api/v1/access/members${accessMembersQueryString(options)}`),
  upsertMember: (subject, input) =>
    mutate<Member>("PUT", `/api/v1/access/members/${encodeURIComponent(subject)}`, input),
  offboardMember: (subject, input) =>
    mutate<OffboardMemberResponse>("POST", `/api/v1/access/members/${encodeURIComponent(subject)}/offboard`, input),
  apiTokens: (options) => req<APITokenList>(`/api/v1/access/api-tokens${apiTokensQueryString(options)}`),
  createAPIToken: (input) => mutate<APITokenCreateResponse>("POST", "/api/v1/access/api-tokens", input),
  revokeAPIToken: (id) => mutate<void>("DELETE", `/api/v1/access/api-tokens/${encodeURIComponent(id)}`),
  auditEvents: (options) =>
    req<{ events: AuditEvent[] }>(`/api/v1/audit/events${auditQueryString(options)}`).then((r) => r.events ?? []),
  exportAudit: (options) => req<AuditBundle>(`/api/v1/audit/export${auditQueryString(options)}`),
  graph: () => req<GraphResponse>("/api/v1/graph"),
  graphBlastRadius: (id) => req<GraphImpact>(`/api/v1/graph/blast-radius/${encodeURIComponent(id)}`),
  graphReachable: (id) => req<GraphReachable>(`/api/v1/graph/reachable/${encodeURIComponent(id)}`),
  graphQuery: (query) => postRead<GraphQueryResult>("/api/v1/graph/query", { query }),
  aiQuery: (input) => postRead<AIAnswer>("/api/v1/ai/query", input),
  aiRCA: (input) => postRead<AIAnswer>("/api/v1/ai/rca", input),
  mcpTools: () => req<MCPToolList>("/api/v1/mcp/tools"),
  callMCPTool: (tool, input) =>
    postRead<MCPToolResult>(`/api/v1/mcp/tools/${encodeURIComponent(tool)}`, input),
  secretPage: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    const suffix = qs.toString();
    return req<SecretMetaList>(`/api/v1/secrets/store${suffix ? `?${suffix}` : ""}`);
  },
  createSecret: (input) => mutate<SecretMeta>("POST", "/api/v1/secrets/store", input),
  getSecret: (name) => req<SecretValue>(`/api/v1/secrets/store/${encodeURIComponent(name)}`),
  rotateSecret: (name, input) =>
    mutate<SecretMeta>("PUT", `/api/v1/secrets/store/${encodeURIComponent(name)}`, input),
  deleteSecret: (name) => mutate<void>("DELETE", `/api/v1/secrets/store/${encodeURIComponent(name)}`),
  issuePKISecret: (input) => mutate<PKISecret>("POST", "/api/v1/secrets/pki", input),
  machineLogin: (input) => mutate<MachineLoginResponse>("POST", "/api/v1/secrets/login", input),
  createShare: (input) => mutate<ShareToken>("POST", "/api/v1/secrets/shares", input),
  redeemShare: (input) => mutate<ShareValue>("POST", "/api/v1/secrets/shares/redeem", input),
};

/** loginURL is where the browser is sent to begin the OIDC flow. */
export const loginURL = "/auth/login";

function auditQueryString(options?: AuditQuery): string {
  const qs = new URLSearchParams();
  qs.set("limit", String(options?.limit ?? 50));
  if (options?.type) qs.set("type", options.type);
  if (options?.since) qs.set("since", options.since);
  if (options?.until) qs.set("until", options.until);
  if (options?.asOf != null) qs.set("as_of", String(options.asOf));
  if (options?.q) qs.set("q", options.q);
  return `?${qs.toString()}`;
}

function riskQueryString(options?: RiskQuery): string {
  const qs = new URLSearchParams();
  if (options?.sort) qs.set("sort", options.sort);
  if (options?.minScore != null) qs.set("min_score", String(options.minScore));
  if (options?.privilege != null) qs.set("privilege", String(options.privilege));
  if (options?.owner) qs.set("owner", options.owner);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function accessMembersQueryString(options?: { limit?: number; cursor?: string; includeOffboarded?: boolean }): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (options?.includeOffboarded) qs.set("include_offboarded", "true");
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function apiTokensQueryString(options?: { limit?: number; cursor?: string; subject?: string; includeRevoked?: boolean }): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (options?.subject) qs.set("subject", options.subject);
  if (options?.includeRevoked) qs.set("include_revoked", "true");
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function pageQueryString(options?: { limit?: number; cursor?: string }, identityId?: string): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (identityId) qs.set("identity_id", identityId);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

/** identityState returns the credential's lifecycle state. The served contract
 * (OpenAPI Identity) names this field `status`; this helper keeps the call sites
 * decoupled from the field name so a future contract change is a one-line edit here. */
export function identityState(i: Identity): string {
  return i.status ?? "";
}
