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
  ActiveActiveIssuancePlan,
  AIAnswer as GenAIAnswer,
  AIStatus as GenAIStatus,
  AIQueryRequest,
  ACMEDNS01ProviderCatalog,
  ACMEDNS01ProviderCatalogItem,
  ACMEDNS01ProviderConfig,
  ACMEDNS01ProviderConfigList,
  APIToken,
  APITokenCreateRequest,
  APITokenCreateResponse,
  APITokenList,
  Approval as GenApproval,
  ApprovalRequest,
  AuditBundle,
  AuditEvent as GenAuditEvent,
  BreakglassBundle,
  BreakglassIssueRequest,
  BreakglassIssueResponse,
  BreakglassReconcileRequest,
  BreakglassReconcileResponse,
  CAAuthority,
  CAAuthorityRotation,
  CAAuthorityRotationRequest,
  CAAuthorityRekeyRequest,
  CADiscoveryInventory,
  CodeSigningKeylessRequest,
  CodeSigningRequest,
  CodeSigningSignature,
  CBOMAsset as GenCBOMAsset,
  CBOMInventory,
  CBOMMigrationProgress,
  CBOMScan,
  CBOMScanRequest,
  CACeremonyStartRequest,
  CACreateOfflineIntermediateCSRRequest,
  CAImportExistingRequest,
  CAImportOfflineIntermediateRequest,
  CAImportOfflineRootRequest,
  CAIntermediateCSR,
  CAKeyCeremony,
  ComplianceEvidencePack,
  ComplianceInventoryReport,
  ComplianceReportSchedule,
  ComplianceReportScheduleList,
  ComplianceReportScheduleRequest,
  Certificate as GenCertificate,
  CertificateHealthDashboard as GenCertificateHealthDashboard,
  CertificateIngest,
  CertificateList,
  CRLDistribution,
  CRLDistributionList,
  CTLogSubmission,
  CTLogSubmissionRequest,
  ConnectorCatalog,
  ConnectorCatalogItem,
  ConnectorDelivery,
  ConnectorDeliveryList,
  ConnectorTargetActionRequest,
  CredentialRisk as GenCredentialRisk,
  ContextualRiskPriorities as GenContextualRiskPriorities,
  ContextualRiskPriority as GenContextualRiskPriority,
  DeploymentTarget,
  DeploymentTargetList,
  DeploymentTargetRequest,
  EndpointBinding,
  EndpointBindingRequest,
  CredentialRiskList,
  DiscoveryFinding,
  DiscoveryFindingList,
  DiscoveryFindingTriageRequest,
  DiscoveryMonitoring,
  DiscoveryRun,
  DiscoveryRunList,
  DiscoveryRunRequest,
  DiscoverySchedule,
  DiscoveryScheduleList,
  DiscoveryScheduleRequest,
  DiscoverySource,
  DiscoverySourceList,
  DiscoverySourceRequest,
  EnterpriseSupportStatus,
  GraphImpact,
  GraphNode,
  GraphQueryResult,
  GraphReachable,
  GraphResponse,
  ITSMTicket,
  KubernetesCSRSupport,
  KubernetesTrustBundleDistribution,
  KubernetesSecretOperator,
  FleetReissuanceActionRequest,
  FleetReissuanceEvidence,
  FleetReissuanceRequest,
  FleetReissuanceRun,
  FleetReissuanceRunList,
  IncidentExecution,
  IncidentExecutionList,
  IncidentExecutionRequest,
  ResponseIntegrationDispatch,
  ResponseIntegrationDispatchRequest,
  RemediationPlaybook,
  RemediationPlaybookCatalog,
  RemediationPlaybookRun,
  RemediationPlaybookRunList,
  RemediationPlaybookRunRequest,
  Owner as GenOwner,
  OwnerRequest,
  Profile as GenProfile,
  ProfileRequest,
  Issuer as GenIssuer,
  IssuerRequest,
  Identity as GenIdentity,
  IdentityConnectorTargetRequest,
  IdentityRequest,
  TransitionRequest,
  Agent as GenAgent,
  Attestation as GenAttestation,
  AttestedSVID as GenAttestedSVID,
  AttestedSVIDRequest,
  SSHAttestedUserCert,
  SSHAttestedUserCertRequest,
  SSHHostRetireRequest,
  SSHHostRetirement,
  SSHRevokeCertificateRequest,
  SSHStatus,
  SSHTrustRollout,
  SSHTrustRolloutRequest,
  BrokerAgentIdentity as GenBrokerAgentIdentity,
  BrokerAgentIdentityRequest,
  EnrollmentToken as GenEnrollmentToken,
  MCPToolCall,
  MCPToolList,
  MCPToolResult,
  MachineLoginRequest,
  MachineLoginResponse,
  ManagedKey,
  ManagedKeyGenerateRequest,
  ManagedOfferingStatus,
  ManagedTenant,
  ManagedTenantProvisionRequest,
  MDMSCEPPolicyList,
  MDMSCEPStatus,
  ScaleOrchestrationPlan,
  Member,
  MemberList,
  MemberRequest,
  NHIDecommissionRequest,
  NHIDecommissionResponse,
  NHIInventory,
  NHIInventoryItem,
  NHIComplianceReport,
  NHIOverPrivilegePosture,
  NHIStaticPosture,
  NHIStalePosture,
  OwnershipAttribution,
  OwnershipAttributionItem,
  NHIReviewCampaign,
  NHIReviewCampaignList,
  NHIReviewCampaignStartRequest,
  NHIReviewDecisionRequest,
  NHIReviewItem,
  Notification,
  NotificationChannel,
  NotificationChannelList,
  NotificationChannelTest,
  NotificationChannelTestRequest,
  NotificationList,
  NotificationRoutingPolicy,
  NotificationRoutingPolicyList,
  NotificationRoutingPolicyRequest,
  OffboardMemberRequest,
  OffboardMemberResponse,
  OIDCMappingStatus,
  PKISecret,
  PKISecretRequest,
  PolicyDryRun,
  PolicyDryRunRequest,
  PQCMigration,
  PQCMigrationRequest,
  PQCMigrationRollback,
  PQCMigrationRollbackRequest,
  PrivacyCatalog,
  PrivacyRetentionRun,
  PrivacyRetentionRunList,
  PrivacySubjectErasure,
  PrivacySubjectErasureList,
  PrivacySubjectErasureRequest,
  RCARequest,
  RoleList,
  RotationRun,
  RotationRunList,
  ServiceNowTicketRequest,
  SecretMeta,
  SecretMetaList,
  SecretApproval as GenSecretApproval,
  SecretApprovalRequest as GenSecretApprovalRequest,
  DynamicLease,
  DynamicLeaseRequest,
  DynamicLeaseRenewRequest,
  EphemeralAPIKey,
  EphemeralAPIKeyRequest,
  ExternalCA as GenExternalCA,
  ExternalCAList,
  SecretImportRequest,
  SecretRecoverRequest,
  SecretRequest,
  SecretRepositoryScanPosture,
  SecretRepositoryWebhookReceipt,
  SecretRepositoryWebhookRequest,
  SecretScan,
  SecretScanRequest,
  ThirdPartySecretScanIngestRequest,
  ThirdPartySecretScanPosture,
  ThirdPartySecretScanReceipt,
  SecretSync,
  SecretSyncRequest,
  SecretSyncTargetCatalog,
  SecretValue,
  ShareRedeemRequest,
  ShareRequest,
  ShareToken,
  ShareValue,
  TransitCiphertext,
  TransitDecryptRequest,
  TransitEncryptRequest,
  TransitHMAC,
  TransitHMACRequest,
  TransitKey,
  TransitKeyRequest,
  TransitPlaintext,
  TransitRewrapRequest,
  TransitRotateRequest,
  TransitSignRequest,
  TransitSignature,
  TransitVerify,
  TransitVerifyRequest,
} from "./api-types.gen";

// Re-export the generated, contract-bound resource types under the names the SPA uses.
export type Certificate = GenCertificate;
export type CertificateHealthDashboard = GenCertificateHealthDashboard;
export type CertificatePage = CertificateList;
export type CertificateIngestRequest = CertificateIngest;
export type CTSubmission = CTLogSubmission;
export type CTSubmissionRequest = CTLogSubmissionRequest;
export type Owner = GenOwner;
export type Issuer = GenIssuer;
export type ExternalCA = GenExternalCA;
export type CADiscovery = CADiscoveryInventory;
export type Identity = GenIdentity;
export type Agent = GenAgent;
export type EnrollmentToken = GenEnrollmentToken;
export type Attestation = GenAttestation;
export type AttestedSVID = GenAttestedSVID;
export type BrokerAgentIdentity = GenBrokerAgentIdentity;
export type CBOMAsset = GenCBOMAsset;
export type AIAnswer = GenAIAnswer;
export type AIStatus = GenAIStatus;
export type CredentialRisk = GenCredentialRisk;
export type ContextualRiskPriorities = GenContextualRiskPriorities;
export type ContextualRiskPriority = GenContextualRiskPriority;
export type Approval = GenApproval;
export type SecretApproval = GenSecretApproval;
export type SecretApprovalAction = GenSecretApprovalRequest["action"];
export type AuditEvent = GenAuditEvent;
export type Profile = GenProfile;
export type IssueCertificateInput = {
  name: string;
  ownerId?: string;
  issuerId?: string;
};
export type {
  ActiveActiveIssuancePlan,
  AuditBundle,
  BreakglassBundle,
  BreakglassIssueRequest,
  BreakglassIssueResponse,
  BreakglassReconcileRequest,
  BreakglassReconcileResponse,
  CodeSigningKeylessRequest,
  CodeSigningRequest,
  CodeSigningSignature,
  DiscoveryFinding,
  DiscoveryFindingList,
  DiscoveryFindingTriageRequest,
  DiscoveryMonitoring,
  DiscoveryRun,
  DiscoveryRunList,
  DiscoveryRunRequest,
  DiscoverySchedule,
  DiscoveryScheduleList,
  DiscoveryScheduleRequest,
  DiscoverySource,
  DiscoverySourceList,
  DiscoverySourceRequest,
  EnterpriseSupportStatus,
  ACMEDNS01ProviderCatalog,
  ACMEDNS01ProviderCatalogItem,
  ACMEDNS01ProviderConfig,
  ACMEDNS01ProviderConfigList,
  MDMSCEPPolicyList,
  MDMSCEPStatus,
  CRLDistribution,
  CRLDistributionList,
  ConnectorCatalog,
  ConnectorCatalogItem,
  ConnectorDelivery,
  ConnectorDeliveryList,
  ConnectorTargetActionRequest,
  DeploymentTarget,
  DeploymentTargetList,
  DeploymentTargetRequest,
  IdentityConnectorTargetRequest,
  CBOMInventory,
  CBOMMigrationProgress,
  CBOMScan,
  CBOMScanRequest,
  CAAuthority,
  CAAuthorityRotation,
  CAAuthorityRotationRequest,
  CACeremonyStartRequest,
  CACreateOfflineIntermediateCSRRequest,
  CAImportExistingRequest,
  CAImportOfflineIntermediateRequest,
  CAImportOfflineRootRequest,
  CAIntermediateCSR,
  CAKeyCeremony,
  ComplianceEvidencePack,
  ComplianceInventoryReport,
  ComplianceReportSchedule,
  ComplianceReportScheduleList,
  ComplianceReportScheduleRequest,
  GraphImpact,
  GraphNode,
  GraphQueryResult,
  GraphReachable,
  GraphResponse,
  FleetReissuanceActionRequest,
  FleetReissuanceEvidence,
  FleetReissuanceRequest,
  FleetReissuanceRun,
  FleetReissuanceRunList,
  IncidentExecution,
  IncidentExecutionList,
  IncidentExecutionRequest,
  ResponseIntegrationDispatch,
  ResponseIntegrationDispatchRequest,
  RemediationPlaybook,
  RemediationPlaybookCatalog,
  RemediationPlaybookRun,
  RemediationPlaybookRunList,
  RemediationPlaybookRunRequest,
  ITSMTicket,
  KubernetesCSRSupport,
  KubernetesTrustBundleDistribution,
  KubernetesSecretOperator,
  MachineLoginRequest,
  MachineLoginResponse,
  ManagedKey,
  ManagedKeyGenerateRequest,
  ManagedOfferingStatus,
  ManagedTenant,
  ManagedTenantProvisionRequest,
  ScaleOrchestrationPlan,
  Member,
  MemberList,
  MemberRequest,
  NHIDecommissionRequest,
  NHIDecommissionResponse,
  NHIInventory,
  NHIInventoryItem,
  NHIComplianceReport,
  NHIOverPrivilegePosture,
  NHIStaticPosture,
  NHIStalePosture,
  OwnershipAttribution,
  OwnershipAttributionItem,
  NHIReviewCampaign,
  NHIReviewCampaignList,
  NHIReviewCampaignStartRequest,
  NHIReviewDecisionRequest,
  NHIReviewItem,
  Notification,
  NotificationChannel,
  NotificationChannelList,
  NotificationChannelTest,
  NotificationChannelTestRequest,
  NotificationList,
  NotificationRoutingPolicy,
  NotificationRoutingPolicyList,
  NotificationRoutingPolicyRequest,
  OffboardMemberRequest,
  OffboardMemberResponse,
  OIDCMappingStatus,
  APIToken,
  APITokenCreateRequest,
  APITokenCreateResponse,
  APITokenList,
  PolicyDryRun,
  PolicyDryRunRequest,
  PKISecret,
  PKISecretRequest,
  PQCMigration,
  PQCMigrationRequest,
  PQCMigrationRollback,
  PQCMigrationRollbackRequest,
  PrivacyCatalog,
  PrivacyRetentionRun,
  PrivacyRetentionRunList,
  PrivacySubjectErasure,
  PrivacySubjectErasureList,
  PrivacySubjectErasureRequest,
  RotationRun,
  RotationRunList,
  RoleList,
  ServiceNowTicketRequest,
  SecretImportRequest,
  SecretMeta,
  SecretMetaList,
  DynamicLease,
  DynamicLeaseRequest,
  DynamicLeaseRenewRequest,
  EphemeralAPIKey,
  EphemeralAPIKeyRequest,
  IssuerRequest,
  SecretRecoverRequest,
  SecretRequest,
  SecretRepositoryScanPosture,
  SecretRepositoryWebhookReceipt,
  SecretRepositoryWebhookRequest,
  SecretScan,
  SecretScanRequest,
  ThirdPartySecretScanIngestRequest,
  ThirdPartySecretScanPosture,
  ThirdPartySecretScanReceipt,
  SecretSync,
  SecretSyncRequest,
  SecretSyncTargetCatalog,
  SecretValue,
  ShareRedeemRequest,
  ShareRequest,
  ShareToken,
  ShareValue,
  SSHAttestedUserCert,
  SSHAttestedUserCertRequest,
  SSHHostRetireRequest,
  SSHHostRetirement,
  SSHRevokeCertificateRequest,
  SSHStatus,
  SSHTrustRollout,
  SSHTrustRolloutRequest,
  TransitCiphertext,
  TransitDecryptRequest,
  TransitEncryptRequest,
  TransitHMAC,
  TransitHMACRequest,
  TransitKey,
  TransitKeyRequest,
  TransitPlaintext,
  TransitRewrapRequest,
  TransitRotateRequest,
  TransitSignRequest,
  TransitSignature,
  TransitVerify,
  TransitVerifyRequest,
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
    super(status === 429 ? `rate limited (429)${retryAfterSeconds != null ? ` — retry in ${retryAfterSeconds}s` : ""}` : `request failed (${status})`);
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
  roles?: string[];
  permissions?: string[];
  locale?: string;
  time_zone?: string;
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

export interface ProtocolRuntimeStatus {
  protocol: string;
  endpoint: string;
  enabled: boolean;
  served: boolean;
  status_code?: number;
  detail?: string;
}

export interface ProtocolRuntimeStatusList {
  source: "public_responder_probe";
  checked_at: string;
  items: ProtocolRuntimeStatus[];
}

export type EditionTier = "community" | "enterprise" | "provider";
export type EditionState = "community" | "active" | "grace" | "read_only";
export type FeatureMode = "enabled" | "read_only" | "off";

export interface EditionFeature {
  name: string;
  tier: EditionTier;
  licensed: boolean;
  mode: FeatureMode;
}

export interface FIPSStatus {
  module_active: boolean;
  required: boolean;
  self_test_passed: boolean;
  capability_id?: string;
  validated_module_path?: boolean;
  standard?: string;
  module?: string;
  build_target?: string;
  runtime_activation?: string[];
  ci_gate?: string;
  crypto_boundary?: string;
  product_certification_residual?: string;
}

export interface EditionsInfo {
  tier: EditionTier;
  state: EditionState;
  customer?: string;
  license_id?: string;
  expires_at?: string;
  read_only_at?: string;
  tenant_band?: number;
  features: EditionFeature[];
  fips: FIPSStatus;
}

interface ProtocolProbeSpec {
  protocol: string;
  endpoint: string;
  method?: "GET" | "HEAD";
  accept?: string;
  methodMismatchMeansServed?: boolean;
  successDetail: string;
  methodMismatchDetail?: string;
}

const protocolStatusProbes: ProtocolProbeSpec[] = [
  {
    protocol: "acme",
    endpoint: "/directory",
    accept: "application/json",
    successDetail: "ACME directory responded.",
  },
  {
    protocol: "est",
    endpoint: "/.well-known/est/cacerts",
    accept: "application/pkcs7-mime, application/pkcs7, */*",
    successDetail: "EST CA-certs responder returned a chain.",
  },
  {
    protocol: "scep",
    endpoint: "/scep?operation=GetCACaps",
    accept: "text/plain, */*",
    successDetail: "SCEP capabilities responder returned caps.",
  },
  {
    protocol: "cmp",
    endpoint: "/cmp",
    method: "GET",
    methodMismatchMeansServed: true,
    successDetail: "CMP responder accepted the probe.",
    methodMismatchDetail: "CMP route is mounted and expects a PKIMessage request.",
  },
  {
    protocol: "ssh",
    endpoint: "/ssh/ca",
    accept: "text/plain, */*",
    successDetail: "SSH CA public-key endpoint responded.",
  },
  {
    protocol: "tsa",
    endpoint: "/tsa",
    method: "GET",
    methodMismatchMeansServed: true,
    successDetail: "TSA responder accepted the probe.",
    methodMismatchDetail: "TSA route is mounted and expects a timestamp request.",
  },
];

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

async function protocolProbe(spec: ProtocolProbeSpec): Promise<ProtocolRuntimeStatus> {
  try {
    const res = await fetch(spec.endpoint, {
      method: spec.method ?? "GET",
      credentials: "include",
      headers: { Accept: spec.accept ?? "*/*" },
    });
    const methodMismatchServed = spec.methodMismatchMeansServed === true && res.status === 405;
    const ok = res.ok || methodMismatchServed;
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: ok,
      served: ok,
      status_code: res.status,
      detail: ok
        ? methodMismatchServed
          ? (spec.methodMismatchDetail ?? "Responder is mounted and expects a protocol request.")
          : spec.successDetail
        : protocolProbeFailureDetail(res),
    };
  } catch {
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: false,
      served: false,
      detail: "Responder probe failed before an HTTP status was returned.",
    };
  }
}

function protocolProbeFailureDetail(res: Response): string {
  if (res.status === 404) return "Responder path was not mounted by this control plane.";
  if (res.status === 503) return "Responder is mounted but currently unavailable.";
  if (res.status === 401 || res.status === 403) return "Responder rejected the browser session.";
  return res.statusText || `Responder returned HTTP ${res.status}.`;
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
  logout(): Promise<void>;
  editions(): Promise<EditionsInfo>;
  enterpriseSupportStatus(): Promise<EnterpriseSupportStatus>;
  managedOfferingStatus(): Promise<ManagedOfferingStatus>;
  scaleOrchestration(): Promise<ScaleOrchestrationPlan>;
  activeActiveIssuance(): Promise<ActiveActiveIssuancePlan>;
  provisionManagedTenant(input: ManagedTenantProvisionRequest): Promise<ManagedTenant>;
  certificates(): Promise<Certificate[]>;
  certificatePage(options?: { limit?: number; cursor?: string; expiringBefore?: string }): Promise<CertificatePage>;
  certificateHealth(): Promise<CertificateHealthDashboard>;
  crlDistributions(): Promise<CRLDistributionList>;
  submitCertificateTransparency(input: CTSubmissionRequest): Promise<CTSubmission>;
  acmeDNS01Providers(): Promise<ACMEDNS01ProviderCatalog>;
  acmeDNS01ProviderConfigs(): Promise<ACMEDNS01ProviderConfigList>;
  getCertificate(id: string): Promise<Certificate>;
  ingestCertificate(input: CertificateIngestRequest): Promise<Certificate>;
  owners(): Promise<Owner[]>;
  createOwner(input: OwnerRequest): Promise<Owner>;
  issuers(): Promise<Issuer[]>;
  createIssuer(input: IssuerRequest): Promise<Issuer>;
  externalCAs(): Promise<ExternalCA[]>;
  caDiscoveryInventory(): Promise<CADiscovery>;
  identities(): Promise<Identity[]>;
  nhiInventory(): Promise<NHIInventory>;
  nhiOverPrivilegePosture(): Promise<NHIOverPrivilegePosture>;
  nhiStalePosture(): Promise<NHIStalePosture>;
  nhiStaticPosture(): Promise<NHIStaticPosture>;
  decommissionNHI(input: NHIDecommissionRequest): Promise<NHIDecommissionResponse>;
  ownershipAttribution(): Promise<OwnershipAttribution>;
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
  discoveryMonitoring(): Promise<DiscoveryMonitoring>;
  discoveryFindings(options?: { limit?: number; cursor?: string; runId?: string }): Promise<DiscoveryFindingList>;
  claimDiscoveryFinding(id: string, input: DiscoveryFindingTriageRequest): Promise<DiscoveryFinding>;
  dismissDiscoveryFinding(id: string, input: DiscoveryFindingTriageRequest): Promise<DiscoveryFinding>;
  connectorCatalog(): Promise<ConnectorCatalog>;
  connectorTargets(): Promise<DeploymentTargetList>;
  createConnectorTarget(input: DeploymentTargetRequest): Promise<DeploymentTarget>;
  createEndpointBinding(input: EndpointBindingRequest): Promise<EndpointBinding>;
  bindIdentityConnectorTarget(id: string, input: IdentityConnectorTargetRequest): Promise<Identity>;
  testConnectorTarget(id: string): Promise<ConnectorDelivery>;
  deployConnectorTarget(id: string, input: ConnectorTargetActionRequest): Promise<Identity>;
  rollbackConnectorTarget(id: string, input: ConnectorTargetActionRequest): Promise<ConnectorDelivery>;
  connectorDeliveries(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<ConnectorDeliveryList>;
  rotationRuns(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<RotationRunList>;
  executeIncident(input: IncidentExecutionRequest): Promise<IncidentExecution>;
  dispatchResponseIntegrations(input: ResponseIntegrationDispatchRequest): Promise<ResponseIntegrationDispatch>;
  createServiceNowTicket(input: ServiceNowTicketRequest): Promise<ITSMTicket>;
  incidentExecutions(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<IncidentExecutionList>;
  getIncidentExecution(id: string): Promise<IncidentExecution>;
  remediationPlaybooks(): Promise<RemediationPlaybookCatalog>;
  runRemediationPlaybook(id: string, input: RemediationPlaybookRunRequest): Promise<RemediationPlaybookRun>;
  remediationPlaybookRuns(options?: { limit?: number; cursor?: string; playbookId?: string }): Promise<RemediationPlaybookRunList>;
  getRemediationPlaybookRun(id: string): Promise<RemediationPlaybookRun>;
  startFleetReissuance(input: FleetReissuanceRequest): Promise<FleetReissuanceRun>;
  fleetReissuanceRuns(options?: { limit?: number; cursor?: string; issuerId?: string }): Promise<FleetReissuanceRunList>;
  getFleetReissuanceRun(id: string): Promise<FleetReissuanceRun>;
  pauseFleetReissuance(id: string, input: FleetReissuanceActionRequest): Promise<FleetReissuanceRun>;
  resumeFleetReissuance(id: string, input: FleetReissuanceActionRequest): Promise<FleetReissuanceRun>;
  rollbackFleetReissuance(id: string, input: FleetReissuanceActionRequest): Promise<FleetReissuanceRun>;
  exportFleetReissuanceEvidence(id: string): Promise<FleetReissuanceEvidence>;
  breakglassIssue(input: BreakglassIssueRequest): Promise<BreakglassIssueResponse>;
  breakglassReconcile(input: BreakglassReconcileRequest): Promise<BreakglassReconcileResponse>;
  signCode(input: CodeSigningRequest): Promise<CodeSigningSignature>;
  signCodeKeyless(input: CodeSigningKeylessRequest): Promise<CodeSigningSignature>;
  risk(options?: RiskQuery): Promise<CredentialRisk[]>;
  contextualRiskPriorities(): Promise<ContextualRiskPriorities>;
  profiles(): Promise<Profile[]>;
  getProfileVersion(name: string, version: number): Promise<Profile>;
  createProfile(input: ProfileRequest): Promise<Profile>;
  createCACeremony(input: CACeremonyStartRequest): Promise<CAKeyCeremony>;
  approveCACeremony(id: string): Promise<CAKeyCeremony>;
  importOfflineRootCA(input: CAImportOfflineRootRequest): Promise<CAAuthority>;
  importExistingCA(input: CAImportExistingRequest): Promise<CAAuthority>;
  createOfflineIntermediateCSR(id: string, input: CACreateOfflineIntermediateCSRRequest): Promise<CAIntermediateCSR>;
  importOfflineIntermediateCA(id: string, input: CAImportOfflineIntermediateRequest): Promise<CAAuthority>;
  rotateCAAuthority(id: string, input: CAAuthorityRotationRequest): Promise<CAAuthorityRotation>;
  rekeyCAAuthority(id: string, input: CAAuthorityRekeyRequest): Promise<CAAuthorityRotation>;
  generateManagedKey(input: ManagedKeyGenerateRequest): Promise<ManagedKey>;
  rotateManagedKey(keyId: string): Promise<ManagedKey>;
  revokeManagedKey(keyId: string): Promise<ManagedKey>;
  zeroizeManagedKey(keyId: string): Promise<ManagedKey>;
  accessRoles(): Promise<RoleList>;
  oidcMappingStatus(): Promise<OIDCMappingStatus>;
  members(options?: { limit?: number; cursor?: string; includeOffboarded?: boolean }): Promise<MemberList>;
  upsertMember(subject: string, input: MemberRequest): Promise<Member>;
  offboardMember(subject: string, input: OffboardMemberRequest): Promise<OffboardMemberResponse>;
  nhiReviewCampaigns(options?: { limit?: number; cursor?: string }): Promise<NHIReviewCampaignList>;
  startNHIReviewCampaign(input: NHIReviewCampaignStartRequest): Promise<NHIReviewCampaign>;
  getNHIReviewCampaign(id: string): Promise<NHIReviewCampaign>;
  decideNHIReviewItem(campaignId: string, itemId: string, input: NHIReviewDecisionRequest): Promise<NHIReviewCampaign>;
  apiTokens(options?: { limit?: number; cursor?: string; subject?: string; includeRevoked?: boolean }): Promise<APITokenList>;
  createAPIToken(input: APITokenCreateRequest): Promise<APITokenCreateResponse>;
  revokeAPIToken(id: string): Promise<void>;
  erasePrivacySubject(input: PrivacySubjectErasureRequest): Promise<PrivacySubjectErasure>;
  privacySubjectErasures(options?: { limit?: number; cursor?: string }): Promise<PrivacySubjectErasureList>;
  enforcePrivacyRetention(): Promise<PrivacyRetentionRun>;
  privacyRetentionRuns(options?: { limit?: number; cursor?: string }): Promise<PrivacyRetentionRunList>;
  privacyCatalog(): Promise<PrivacyCatalog>;
  auditEvents(options?: AuditQuery): Promise<AuditEvent[]>;
  exportAudit(options?: AuditQuery): Promise<AuditBundle>;
  complianceEvidencePack(framework: ComplianceEvidencePack["framework"]): Promise<ComplianceEvidencePack>;
  complianceInventoryReport(): Promise<ComplianceInventoryReport>;
  nhiComplianceReport(): Promise<NHIComplianceReport>;
  complianceReportSchedules(options?: { limit?: number; cursor?: string }): Promise<ComplianceReportScheduleList>;
  createComplianceReportSchedule(input: ComplianceReportScheduleRequest): Promise<ComplianceReportSchedule>;
  policyDryRun(input: PolicyDryRunRequest): Promise<PolicyDryRun>;
  graph(): Promise<GraphResponse>;
  graphBlastRadius(id: string): Promise<GraphImpact>;
  graphReachable(id: string): Promise<GraphReachable>;
  graphQuery(query: string): Promise<GraphQueryResult>;
  aiStatus(): Promise<AIStatus>;
  aiQuery(input: AIQueryRequest): Promise<AIAnswer>;
  aiRCA(input: RCARequest): Promise<AIAnswer>;
  mcpTools(): Promise<MCPToolList>;
  callMCPTool(tool: string, input: MCPToolCall): Promise<MCPToolResult>;
  listCBOMAssets(): Promise<CBOMInventory>;
  startCBOMScan(input: CBOMScanRequest): Promise<CBOMScan>;
  issueBrokerAgentIdentity(input: BrokerAgentIdentityRequest): Promise<BrokerAgentIdentity>;
  issueAttestedSVID(input: AttestedSVIDRequest): Promise<AttestedSVID>;
  sshStatus(): Promise<SSHStatus>;
  recordSSHTrustRollout(input: SSHTrustRolloutRequest): Promise<SSHTrustRollout>;
  issueAttestedSSHUserCert(input: SSHAttestedUserCertRequest): Promise<SSHAttestedUserCert>;
  revokeSSHCertificate(input: SSHRevokeCertificateRequest): Promise<SSHStatus>;
  retireSSHHost(input: SSHHostRetireRequest): Promise<SSHHostRetirement>;
  protocolStatuses(): Promise<ProtocolRuntimeStatusList>;
  mdmSCEPStatus(): Promise<MDMSCEPStatus>;
  mdmSCEPPolicies(): Promise<MDMSCEPPolicyList>;
  secretPage(options?: { limit?: number; cursor?: string }): Promise<SecretMetaList>;
  createSecret(input: SecretRequest): Promise<SecretMeta>;
  importSecrets(input: SecretImportRequest): Promise<SecretMetaList>;
  getSecret(name: string, options?: { resolve?: boolean }): Promise<SecretValue>;
  getSecretVersion(name: string, version: number): Promise<SecretValue>;
  recoverSecret(name: string, input: SecretRecoverRequest): Promise<SecretMeta>;
  rotateSecret(name: string, input: SecretRequest): Promise<SecretMeta>;
  deleteSecret(name: string): Promise<void>;
  approveSecretChange(name: string, action: SecretApprovalAction): Promise<SecretApproval>;
  secretRepositoryScanning(): Promise<SecretRepositoryScanPosture>;
  receiveSecretRepositoryWebhook(provider: string, input: SecretRepositoryWebhookRequest): Promise<SecretRepositoryWebhookReceipt>;
  thirdPartySecretScanning(): Promise<ThirdPartySecretScanPosture>;
  ingestThirdPartySecretScan(provider: string, input: ThirdPartySecretScanIngestRequest): Promise<ThirdPartySecretScanReceipt>;
  scanSecrets(input: SecretScanRequest): Promise<SecretScan>;
  syncSecret(input: SecretSyncRequest): Promise<SecretSync>;
  secretSyncTargets(): Promise<SecretSyncTargetCatalog>;
  kubernetesCSRSupport(): Promise<KubernetesCSRSupport>;
  kubernetesTrustBundles(): Promise<KubernetesTrustBundleDistribution>;
  kubernetesSecretOperator(): Promise<KubernetesSecretOperator>;
  issueDynamicLease(input: DynamicLeaseRequest): Promise<DynamicLease>;
  getDynamicLease(leaseId: string): Promise<DynamicLease>;
  renewDynamicLease(leaseId: string, input: DynamicLeaseRenewRequest): Promise<DynamicLease>;
  revokeDynamicLease(leaseId: string): Promise<DynamicLease>;
  issueEphemeralAPIKey(input: EphemeralAPIKeyRequest): Promise<EphemeralAPIKey>;
  issuePKISecret(input: PKISecretRequest): Promise<PKISecret>;
  startPQCMigration(input: PQCMigrationRequest): Promise<PQCMigration>;
  rollbackPQCMigration(runId: string, input: PQCMigrationRollbackRequest): Promise<PQCMigrationRollback>;
  machineLogin(input: MachineLoginRequest): Promise<MachineLoginResponse>;
  createShare(input: ShareRequest): Promise<ShareToken>;
  redeemShare(input: ShareRedeemRequest): Promise<ShareValue>;
  createTransitKey(input: TransitKeyRequest): Promise<TransitKey>;
  rotateTransitKey(input: TransitRotateRequest): Promise<TransitKey>;
  encryptTransit(input: TransitEncryptRequest): Promise<TransitCiphertext>;
  decryptTransit(input: TransitDecryptRequest): Promise<TransitPlaintext>;
  hmacTransit(input: TransitHMACRequest): Promise<TransitHMAC>;
  rewrapTransit(input: TransitRewrapRequest): Promise<TransitCiphertext>;
  signTransit(input: TransitSignRequest): Promise<TransitSignature>;
  verifyTransit(input: TransitVerifyRequest): Promise<TransitVerify>;
  notifications(options?: { limit?: number; cursor?: string; status?: Notification["status"] }): Promise<NotificationList>;
  notificationChannels(): Promise<NotificationChannelList>;
  notificationRoutingPolicies(): Promise<NotificationRoutingPolicyList>;
  createNotificationRoutingPolicy(input: NotificationRoutingPolicyRequest): Promise<NotificationRoutingPolicy>;
  updateNotificationRoutingPolicy(id: string, input: NotificationRoutingPolicyRequest): Promise<NotificationRoutingPolicy>;
  deleteNotificationRoutingPolicy(id: string): Promise<void>;
  testNotificationChannel(id: string, input: NotificationChannelTestRequest): Promise<NotificationChannelTest>;
  markNotificationRead(id: string): Promise<Notification>;
  requeueNotification(id: string): Promise<Notification>;
}

export const api: Api = {
  me: () => req<Me>("/auth/me"),
  logout: () => req<void>("/auth/logout", { method: "POST" }),
  editions: () => req<EditionsInfo>("/api/v1/editions"),
  enterpriseSupportStatus: () => req<EnterpriseSupportStatus>("/api/v1/support/enterprise"),
  managedOfferingStatus: () => req<ManagedOfferingStatus>("/api/v1/managed-offering/status"),
  scaleOrchestration: () => req<ScaleOrchestrationPlan>("/api/v1/scale/orchestration"),
  activeActiveIssuance: () => req<ActiveActiveIssuancePlan>("/api/v1/scale/ha-issuance"),
  provisionManagedTenant: (input) => mutate<ManagedTenant>("POST", "/api/v1/managed-offering/tenants", input),
  certificatePage: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    if (options?.expiringBefore) qs.set("expiring_before", options.expiringBefore);
    const suffix = qs.toString();
    return req<CertificatePage>(`/api/v1/certificates${suffix ? `?${suffix}` : ""}`);
  },
  certificates: () => api.certificatePage().then((r) => r.items ?? []),
  certificateHealth: () => req<CertificateHealthDashboard>("/api/v1/certificates/health"),
  crlDistributions: () => req<CRLDistributionList>("/api/v1/revocation/crls"),
  submitCertificateTransparency: (input) => mutate<CTSubmission>("POST", "/api/v1/revocation/ct-submissions", input),
  acmeDNS01Providers: () => req<ACMEDNS01ProviderCatalog>("/api/v1/acme/dns-01/providers"),
  acmeDNS01ProviderConfigs: () => req<ACMEDNS01ProviderConfigList>("/api/v1/acme/dns-01/provider-configs"),
  mdmSCEPStatus: () => req<MDMSCEPStatus>("/api/v1/mdm/scep/status"),
  mdmSCEPPolicies: () => req<MDMSCEPPolicyList>("/api/v1/mdm/scep/policies"),
  getCertificate: (id) => req<Certificate>(`/api/v1/certificates/${encodeURIComponent(id)}`),
  ingestCertificate: (input) => mutate<Certificate>("POST", "/api/v1/certificates", input),
  owners: () => req<{ items: Owner[] }>("/api/v1/owners").then((r) => r.items ?? []),
  createOwner: (input) => mutate<Owner>("POST", "/api/v1/owners", input),
  issuers: () => req<{ items: Issuer[] }>("/api/v1/issuers").then((r) => r.items ?? []),
  createIssuer: (input) => mutate<Issuer>("POST", "/api/v1/issuers", input),
  externalCAs: () => req<ExternalCAList>("/api/v1/external-cas").then((r) => r.items ?? []),
  caDiscoveryInventory: () => req<CADiscovery>("/api/v1/ca/discovery"),
  identities: () => req<{ items: Identity[] }>("/api/v1/identities").then((r) => r.items ?? []),
  nhiInventory: () => req<NHIInventory>("/api/v1/nhi/inventory"),
  nhiOverPrivilegePosture: () => req<NHIOverPrivilegePosture>("/api/v1/nhi/posture/overprivilege"),
  nhiStalePosture: () => req<NHIStalePosture>("/api/v1/nhi/posture/stale"),
  nhiStaticPosture: () => req<NHIStaticPosture>("/api/v1/nhi/posture/static-credentials"),
  decommissionNHI: (input) => mutate<NHIDecommissionResponse>("POST", "/api/v1/nhi/decommission", input),
  ownershipAttribution: () => req<OwnershipAttribution>("/api/v1/ownership/attribution"),
  getIdentity: (id) => req<Identity>(`/api/v1/identities/${encodeURIComponent(id)}`),
  createIdentity: (input) => mutate<Identity>("POST", "/api/v1/identities", input),
  transitionIdentity: (id, to, reason) => mutate<Identity>("POST", `/api/v1/identities/${encodeURIComponent(id)}/transitions`, { to, reason }),
  approveIdentityAction: (id, action) => mutate<Approval>("POST", `/api/v1/identities/${encodeURIComponent(id)}/approvals`, { action }),
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
  discoverySources: (options) => req<DiscoverySourceList>(`/api/v1/discovery/sources${pageQueryString(options)}`),
  createDiscoverySource: (input) => mutate<DiscoverySource>("POST", "/api/v1/discovery/sources", input),
  discoverySchedules: (options) => req<DiscoveryScheduleList>(`/api/v1/discovery/schedules${pageQueryString(options)}`),
  createDiscoverySchedule: (input) => mutate<DiscoverySchedule>("POST", "/api/v1/discovery/schedules", input),
  discoveryRuns: (options) => req<DiscoveryRunList>(`/api/v1/discovery/runs${pageQueryString(options)}`),
  getDiscoveryRun: (id) => req<DiscoveryRun>(`/api/v1/discovery/runs/${encodeURIComponent(id)}`),
  startDiscoveryRun: (input) => mutate<DiscoveryRun>("POST", "/api/v1/discovery/runs", input),
  discoveryMonitoring: () => req<DiscoveryMonitoring>("/api/v1/discovery/monitoring"),
  discoveryFindings: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    if (options?.runId) qs.set("run_id", options.runId);
    const suffix = qs.toString();
    return req<DiscoveryFindingList>(`/api/v1/discovery/findings${suffix ? `?${suffix}` : ""}`);
  },
  claimDiscoveryFinding: (id, input) => mutate<DiscoveryFinding>("POST", `/api/v1/discovery/findings/${encodeURIComponent(id)}/claim`, input),
  dismissDiscoveryFinding: (id, input) => mutate<DiscoveryFinding>("POST", `/api/v1/discovery/findings/${encodeURIComponent(id)}/dismiss`, input),
  connectorCatalog: () => req<ConnectorCatalog>("/api/v1/connectors/catalog"),
  connectorTargets: () => req<DeploymentTargetList>("/api/v1/connectors/targets"),
  createConnectorTarget: (input) => mutate<DeploymentTarget>("POST", "/api/v1/connectors/targets", input),
  createEndpointBinding: (input) => mutate<EndpointBinding>("POST", "/api/v1/lifecycle/endpoint-bindings", input),
  bindIdentityConnectorTarget: (id, input) => mutate<Identity>("POST", `/api/v1/identities/${encodeURIComponent(id)}/connector-target`, input),
  testConnectorTarget: (id) => mutate<ConnectorDelivery>("POST", `/api/v1/connectors/targets/${encodeURIComponent(id)}/test`),
  deployConnectorTarget: (id, input) => mutate<Identity>("POST", `/api/v1/connectors/targets/${encodeURIComponent(id)}/deploy`, input),
  rollbackConnectorTarget: (id, input) => mutate<ConnectorDelivery>("POST", `/api/v1/connectors/targets/${encodeURIComponent(id)}/rollback`, input),
  connectorDeliveries: (options) => req<ConnectorDeliveryList>(`/api/v1/connectors/deliveries${pageQueryString(options, options?.identityId)}`),
  rotationRuns: (options) => req<RotationRunList>(`/api/v1/lifecycle/rotation-runs${pageQueryString(options, options?.identityId)}`),
  executeIncident: (input) => mutate<IncidentExecution>("POST", "/api/v1/incidents/executions", input),
  dispatchResponseIntegrations: (input) => mutate<ResponseIntegrationDispatch>("POST", "/api/v1/incidents/response-integrations/dispatch", input),
  createServiceNowTicket: (input) => mutate<ITSMTicket>("POST", "/api/v1/itsm/servicenow/tickets", input),
  incidentExecutions: (options) => req<IncidentExecutionList>(`/api/v1/incidents/executions${pageQueryString(options, options?.identityId)}`),
  getIncidentExecution: (id) => req<IncidentExecution>(`/api/v1/incidents/executions/${encodeURIComponent(id)}`),
  remediationPlaybooks: () => req<RemediationPlaybookCatalog>("/api/v1/remediation/playbooks"),
  runRemediationPlaybook: (id, input) => mutate<RemediationPlaybookRun>("POST", `/api/v1/remediation/playbooks/${encodeURIComponent(id)}/runs`, input),
  remediationPlaybookRuns: (options) =>
    req<RemediationPlaybookRunList>(`/api/v1/remediation/playbook-runs${pageQueryString(options, options?.playbookId, "playbook_id")}`),
  getRemediationPlaybookRun: (id) => req<RemediationPlaybookRun>(`/api/v1/remediation/playbook-runs/${encodeURIComponent(id)}`),
  startFleetReissuance: (input) => mutate<FleetReissuanceRun>("POST", "/api/v1/incidents/fleet-reissuance-runs", input),
  fleetReissuanceRuns: (options) =>
    req<FleetReissuanceRunList>(`/api/v1/incidents/fleet-reissuance-runs${pageQueryString(options, options?.issuerId, "issuer_id")}`),
  getFleetReissuanceRun: (id) => req<FleetReissuanceRun>(`/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}`),
  pauseFleetReissuance: (id, input) => mutate<FleetReissuanceRun>("POST", `/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/pause`, input),
  resumeFleetReissuance: (id, input) => mutate<FleetReissuanceRun>("POST", `/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/resume`, input),
  rollbackFleetReissuance: (id, input) =>
    mutate<FleetReissuanceRun>("POST", `/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/rollback`, input),
  exportFleetReissuanceEvidence: (id) => req<FleetReissuanceEvidence>(`/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/evidence`),
  breakglassIssue: (input) => mutate<BreakglassIssueResponse>("POST", "/api/v1/breakglass/issue", input),
  breakglassReconcile: (input) => mutate<BreakglassReconcileResponse>("POST", "/api/v1/breakglass/reconcile", input),
  signCode: (input) => mutate<CodeSigningSignature>("POST", "/api/v1/code-signing/sign", input),
  signCodeKeyless: (input) => mutate<CodeSigningSignature>("POST", "/api/v1/code-signing/keyless", input),
  risk: (options) => req<CredentialRiskList>(`/api/v1/risk/credentials${riskQueryString(options)}`).then((r) => r.credentials ?? []),
  contextualRiskPriorities: () => req<ContextualRiskPriorities>("/api/v1/risk/contextual-priorities"),
  profiles: () => req<{ items: Profile[] }>("/api/v1/profiles").then((r) => r.items ?? []),
  getProfileVersion: (name, version) => req<Profile>(`/api/v1/profiles/${encodeURIComponent(name)}/versions/${version}`),
  createProfile: (input) => mutate<Profile>("POST", "/api/v1/profiles", input),
  createCACeremony: (input) => mutate<CAKeyCeremony>("POST", "/api/v1/ca/ceremonies", input),
  approveCACeremony: (id) => mutate<CAKeyCeremony>("POST", `/api/v1/ca/ceremonies/${encodeURIComponent(id)}/approvals`),
  importOfflineRootCA: (input) => mutate<CAAuthority>("POST", "/api/v1/ca/authorities/offline-roots", input),
  importExistingCA: (input) => mutate<CAAuthority>("POST", "/api/v1/ca/authorities/imported", input),
  createOfflineIntermediateCSR: (id, input) =>
    mutate<CAIntermediateCSR>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/offline-intermediates/csr`, input),
  importOfflineIntermediateCA: (id, input) => mutate<CAAuthority>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/offline-intermediates`, input),
  rotateCAAuthority: (id, input) => mutate<CAAuthorityRotation>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/rotate`, input),
  rekeyCAAuthority: (id, input) => mutate<CAAuthorityRotation>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/rekey`, input),
  generateManagedKey: (input) => mutate<ManagedKey>("POST", "/api/v1/managed-keys", input),
  rotateManagedKey: (keyId) => mutate<ManagedKey>("POST", "/api/v1/managed-keys/rotate", { key_id: keyId }),
  revokeManagedKey: (keyId) => mutate<ManagedKey>("POST", "/api/v1/managed-keys/revoke", { key_id: keyId }),
  zeroizeManagedKey: (keyId) => mutate<ManagedKey>("POST", "/api/v1/managed-keys/zeroize", { key_id: keyId }),
  accessRoles: () => req<RoleList>("/api/v1/access/roles"),
  oidcMappingStatus: () => req<OIDCMappingStatus>("/api/v1/access/oidc-mapping"),
  members: (options) => req<MemberList>(`/api/v1/access/members${accessMembersQueryString(options)}`),
  upsertMember: (subject, input) => mutate<Member>("PUT", `/api/v1/access/members/${encodeURIComponent(subject)}`, input),
  offboardMember: (subject, input) => mutate<OffboardMemberResponse>("POST", `/api/v1/access/members/${encodeURIComponent(subject)}/offboard`, input),
  nhiReviewCampaigns: (options) => req<NHIReviewCampaignList>(`/api/v1/access/reviews${pageQueryString(options)}`),
  startNHIReviewCampaign: (input) => mutate<NHIReviewCampaign>("POST", "/api/v1/access/reviews", input),
  getNHIReviewCampaign: (id) => req<NHIReviewCampaign>(`/api/v1/access/reviews/${encodeURIComponent(id)}`),
  decideNHIReviewItem: (campaignId, itemId, input) =>
    mutate<NHIReviewCampaign>("POST", `/api/v1/access/reviews/${encodeURIComponent(campaignId)}/items/${encodeURIComponent(itemId)}/decision`, input),
  apiTokens: (options) => req<APITokenList>(`/api/v1/access/api-tokens${apiTokensQueryString(options)}`),
  createAPIToken: (input) => mutate<APITokenCreateResponse>("POST", "/api/v1/access/api-tokens", input),
  revokeAPIToken: (id) => mutate<void>("DELETE", `/api/v1/access/api-tokens/${encodeURIComponent(id)}`),
  erasePrivacySubject: (input) => mutate<PrivacySubjectErasure>("POST", "/api/v1/privacy/subject-erasures", input),
  privacySubjectErasures: (options) => req<PrivacySubjectErasureList>(`/api/v1/privacy/subject-erasures${pageQueryString(options)}`),
  enforcePrivacyRetention: () => mutate<PrivacyRetentionRun>("POST", "/api/v1/privacy/retention-runs"),
  privacyRetentionRuns: (options) => req<PrivacyRetentionRunList>(`/api/v1/privacy/retention-runs${pageQueryString(options)}`),
  privacyCatalog: () => req<PrivacyCatalog>("/api/v1/privacy/catalog"),
  auditEvents: (options) => req<{ events: AuditEvent[] }>(`/api/v1/audit/events${auditQueryString(options)}`).then((r) => r.events ?? []),
  exportAudit: (options) => req<AuditBundle>(`/api/v1/audit/export${auditQueryString(options)}`),
  complianceEvidencePack: (framework) => req<ComplianceEvidencePack>(`/api/v1/compliance/evidence-packs/${encodeURIComponent(framework)}`),
  complianceInventoryReport: () => req<ComplianceInventoryReport>("/api/v1/compliance/inventory-report"),
  nhiComplianceReport: () => req<NHIComplianceReport>("/api/v1/compliance/nhi-report"),
  complianceReportSchedules: (options) => req<ComplianceReportScheduleList>(`/api/v1/compliance/report-schedules${pageQueryString(options)}`),
  createComplianceReportSchedule: (input) => mutate<ComplianceReportSchedule>("POST", "/api/v1/compliance/report-schedules", input),
  policyDryRun: (input) => mutate<PolicyDryRun>("POST", "/api/v1/policy/dry-run", input),
  graph: () => req<GraphResponse>("/api/v1/graph"),
  graphBlastRadius: (id) => req<GraphImpact>(`/api/v1/graph/blast-radius/${encodeURIComponent(id)}`),
  graphReachable: (id) => req<GraphReachable>(`/api/v1/graph/reachable/${encodeURIComponent(id)}`),
  graphQuery: (query) => postRead<GraphQueryResult>("/api/v1/graph/query", { query }),
  aiStatus: () => req<AIStatus>("/api/v1/ai/status"),
  aiQuery: (input) => postRead<AIAnswer>("/api/v1/ai/query", input),
  aiRCA: (input) => postRead<AIAnswer>("/api/v1/ai/rca", input),
  mcpTools: () => req<MCPToolList>("/api/v1/mcp/tools"),
  callMCPTool: (tool, input) => postRead<MCPToolResult>(`/api/v1/mcp/tools/${encodeURIComponent(tool)}`, input),
  listCBOMAssets: () => req<CBOMInventory>("/api/v1/cbom/assets"),
  startCBOMScan: (input) => mutate<CBOMScan>("POST", "/api/v1/cbom/scans", input),
  issueBrokerAgentIdentity: (input) => mutate<BrokerAgentIdentity>("POST", "/api/v1/broker/agent-identities", input),
  issueAttestedSVID: (input) => mutate<AttestedSVID>("POST", "/api/v1/workloads/attested-issuance", input),
  sshStatus: () => req<SSHStatus>("/api/v1/ssh/status"),
  recordSSHTrustRollout: (input) => mutate<SSHTrustRollout>("POST", "/api/v1/ssh/trust-rollouts", input),
  issueAttestedSSHUserCert: (input) => mutate<SSHAttestedUserCert>("POST", "/api/v1/ssh/attested-user-certs", input),
  revokeSSHCertificate: (input) => mutate<SSHStatus>("POST", "/api/v1/ssh/certificates/revoke", input),
  retireSSHHost: (input) => mutate<SSHHostRetirement>("POST", "/api/v1/ssh/hosts/retire", input),
  protocolStatuses: async () => ({
    source: "public_responder_probe",
    checked_at: new Date().toISOString(),
    items: await Promise.all(protocolStatusProbes.map((spec) => protocolProbe(spec))),
  }),
  secretPage: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    const suffix = qs.toString();
    return req<SecretMetaList>(`/api/v1/secrets/store${suffix ? `?${suffix}` : ""}`);
  },
  createSecret: (input) => mutate<SecretMeta>("POST", "/api/v1/secrets/store", input),
  importSecrets: (input) => mutate<SecretMetaList>("POST", "/api/v1/secrets/store/import", input),
  getSecret: (name, options) => {
    const qs = new URLSearchParams();
    if (options?.resolve) qs.set("resolve", "true");
    const suffix = qs.toString();
    return req<SecretValue>(`/api/v1/secrets/store/${encodeURIComponent(name)}${suffix ? `?${suffix}` : ""}`);
  },
  getSecretVersion: (name, version) =>
    req<SecretValue>(`/api/v1/secrets/store/history/${encodeURIComponent(name)}?version=${encodeURIComponent(String(version))}`),
  recoverSecret: (name, input) => mutate<SecretMeta>("POST", `/api/v1/secrets/store/recover/${encodeURIComponent(name)}`, input),
  rotateSecret: (name, input) => mutate<SecretMeta>("PUT", `/api/v1/secrets/store/${encodeURIComponent(name)}`, input),
  deleteSecret: (name) => mutate<void>("DELETE", `/api/v1/secrets/store/${encodeURIComponent(name)}`),
  approveSecretChange: (name, action) => mutate<SecretApproval>("POST", `/api/v1/secrets/store/approvals/${encodeURIComponent(name)}`, { action }),
  secretRepositoryScanning: () => req<SecretRepositoryScanPosture>("/api/v1/secrets/scans/repositories"),
  receiveSecretRepositoryWebhook: (provider, input) =>
    mutate<SecretRepositoryWebhookReceipt>("POST", `/api/v1/secrets/scans/repositories/${encodeURIComponent(provider)}/webhook`, input),
  thirdPartySecretScanning: () => req<ThirdPartySecretScanPosture>("/api/v1/secrets/scans/third-party"),
  ingestThirdPartySecretScan: (provider, input) =>
    mutate<ThirdPartySecretScanReceipt>("POST", `/api/v1/secrets/scans/third-party/${encodeURIComponent(provider)}/ingest`, input),
  scanSecrets: (input) => mutate<SecretScan>("POST", "/api/v1/secrets/scans", input),
  syncSecret: (input) => mutate<SecretSync>("POST", "/api/v1/secrets/syncs", input),
  secretSyncTargets: () => req<SecretSyncTargetCatalog>("/api/v1/secrets/syncs/targets"),
  kubernetesCSRSupport: () => req<KubernetesCSRSupport>("/api/v1/kubernetes/certificate-signing-requests"),
  kubernetesTrustBundles: () => req<KubernetesTrustBundleDistribution>("/api/v1/kubernetes/trust-bundles"),
  kubernetesSecretOperator: () => req<KubernetesSecretOperator>("/api/v1/secrets/kubernetes-operator"),
  issueDynamicLease: (input) => mutate<DynamicLease>("POST", "/api/v1/secrets/leases", input),
  getDynamicLease: (leaseId) => req<DynamicLease>(`/api/v1/secrets/leases/${encodeURIComponent(leaseId)}`),
  renewDynamicLease: (leaseId, input) => mutate<DynamicLease>("POST", `/api/v1/secrets/leases/${encodeURIComponent(leaseId)}/renew`, input),
  revokeDynamicLease: (leaseId) => mutate<DynamicLease>("POST", `/api/v1/secrets/leases/${encodeURIComponent(leaseId)}/revoke`),
  issueEphemeralAPIKey: (input) => mutate<EphemeralAPIKey>("POST", "/api/v1/ephemeral/api-keys", input),
  issuePKISecret: (input) => mutate<PKISecret>("POST", "/api/v1/secrets/pki", input),
  startPQCMigration: (input) => mutate<PQCMigration>("POST", "/api/v1/pqc/migrations", input),
  rollbackPQCMigration: (runId, input) => mutate<PQCMigrationRollback>("POST", `/api/v1/pqc/migrations/${encodeURIComponent(runId)}/rollback`, input),
  machineLogin: (input) => mutate<MachineLoginResponse>("POST", "/api/v1/secrets/login", input),
  createShare: (input) => mutate<ShareToken>("POST", "/api/v1/secrets/shares", input),
  redeemShare: (input) => mutate<ShareValue>("POST", "/api/v1/secrets/shares/redeem", input),
  createTransitKey: (input) => mutate<TransitKey>("POST", "/api/v1/transit/keys", input),
  rotateTransitKey: (input) => mutate<TransitKey>("POST", "/api/v1/transit/keys/rotate", input),
  encryptTransit: (input) => mutate<TransitCiphertext>("POST", "/api/v1/transit/encrypt", input),
  decryptTransit: (input) => mutate<TransitPlaintext>("POST", "/api/v1/transit/decrypt", input),
  hmacTransit: (input) => mutate<TransitHMAC>("POST", "/api/v1/transit/hmac", input),
  rewrapTransit: (input) => mutate<TransitCiphertext>("POST", "/api/v1/transit/rewrap", input),
  signTransit: (input) => mutate<TransitSignature>("POST", "/api/v1/transit/sign", input),
  verifyTransit: (input) => mutate<TransitVerify>("POST", "/api/v1/transit/verify", input),
  notifications: (options) => req<NotificationList>(`/api/v1/notifications${notificationQueryString(options)}`),
  notificationChannels: () => req<NotificationChannelList>("/api/v1/notification-channels"),
  notificationRoutingPolicies: () => req<NotificationRoutingPolicyList>("/api/v1/notification-routing-policies"),
  createNotificationRoutingPolicy: (input) => mutate<NotificationRoutingPolicy>("POST", "/api/v1/notification-routing-policies", input),
  updateNotificationRoutingPolicy: (id, input) =>
    mutate<NotificationRoutingPolicy>("PUT", `/api/v1/notification-routing-policies/${encodeURIComponent(id)}`, input),
  deleteNotificationRoutingPolicy: (id) => mutate<void>("DELETE", `/api/v1/notification-routing-policies/${encodeURIComponent(id)}`),
  testNotificationChannel: (id, input) => mutate<NotificationChannelTest>("POST", `/api/v1/notification-channels/${encodeURIComponent(id)}/test`, input),
  markNotificationRead: (id) => mutate<Notification>("POST", `/api/v1/notifications/${encodeURIComponent(id)}/read`),
  requeueNotification: (id) => mutate<Notification>("POST", `/api/v1/notifications/${encodeURIComponent(id)}/requeue`),
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

function pageQueryString(options?: { limit?: number; cursor?: string }, scopedId?: string, scopedKey = "identity_id"): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (scopedId) qs.set(scopedKey, scopedId);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function notificationQueryString(options?: { limit?: number; cursor?: string; status?: Notification["status"] }): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (options?.status) qs.set("status", options.status);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

/** identityState returns the credential's lifecycle state. The served contract
 * (OpenAPI Identity) names this field `status`; this helper keeps the call sites
 * decoupled from the field name so a future contract change is a one-line edit here. */
export function identityState(i: Identity): string {
  return i.status ?? "";
}
