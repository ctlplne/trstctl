// Code generated from the served OpenAPI contract by web/scripts/gen-api-types.mjs.
// DO NOT EDIT by hand. Regenerate with: npm run gen:api
//
// Source: internal/api/testdata/openapi.golden.json (pinned == the served spec by the
// Go test TestOpenAPIGolden). These types are the single FE↔BE contract for the trstctl
// console (SURFACE-005 / EXC-WIRE-04); web/src/lib/api.ts is type-checked against them so
// a backend field change that is not reflected here fails the build instead of silently
// desyncing the SPA.
// OpenAPI: 3.1.0  API: trstctl API v1

/* eslint-disable */
export interface AIAnswer {
  citations?: string[];
  grounded?: boolean;
  sufficient: boolean;
  text: string;
}

export interface AIQueryRequest {
  limit?: number;
  question?: string;
  subject?: string;
  surfaces: string[];
}

export interface AIStatus {
  egress: string;
  enabled: boolean;
  endpoint_host?: string;
  mcp_identity?: string;
  model_configured: boolean;
  model_mode: string;
  model_name?: string;
  provider?: string;
  rate_max?: number;
  rate_window_seconds?: number;
  redaction: string;
  residual_refusal_gate: boolean;
  runtime?: string;
}

export interface APIToken {
  created_at: string;
  expires_at?: string;
  id: string;
  revocation_reason?: string;
  revoked_at?: string;
  revoked_by?: string;
  scopes: string[];
  subject: string;
  tenant_id: string;
}

export interface APITokenCreateRequest {
  expires_at?: string;
  scopes: string[];
  subject: string;
}

export interface APITokenCreateResponse {
  created_at: string;
  expires_at?: string;
  id: string;
  scopes: string[];
  subject: string;
  tenant_id: string;
  token: string;
}

export interface APITokenList {
  items: APIToken[];
  next_cursor?: string;
}

export interface APITokenRevokeRequest {
  reason?: string;
}

export interface Agent {
  id: string;
  last_seen_at?: string;
  name: string;
  status: string;
  version?: string;
}

export interface AgentList {
  agents: Agent[];
  next_cursor?: string;
}

export interface Approval {
  action: "issue" | "revoke";
  approvals: number;
  approver: string;
  resource: string;
}

export interface ApprovalRequest {
  action: "issue" | "revoke";
}

export interface AuditBundle {
  bundle: string;
  format: string;
}

export interface AuditEvent {
  actor?: Record<string, unknown>;
  data?: Record<string, unknown>;
  hash?: string;
  id?: string;
  sequence: number;
  tenant_id: string;
  time: string;
  type: string;
}

export interface AuditEventList {
  count?: number;
  events: AuditEvent[];
}

export interface Certificate {
  created_at?: string;
  deployment_location?: string;
  fingerprint: string;
  id: string;
  issuer?: string;
  key_algorithm?: string;
  not_after?: string;
  not_before?: string;
  owner_id?: string;
  revocation_reason?: string;
  revoked_at?: string;
  sans?: string[];
  serial?: string;
  source?: string;
  status: "active" | "superseded" | "revoked";
  subject: string;
  tenant_id: string;
}

export interface CertificateIngest {
  deployment_location?: string;
  owner_id?: string;
  pem: string;
  source?: string;
}

export interface CertificateList {
  items: Certificate[];
  next_cursor?: string;
}

export interface ConnectorCatalog {
  items: ConnectorCatalogItem[];
}

export interface ConnectorCatalogItem {
  delivery_mode: string;
  kind: string;
  name: string;
  rollback: string;
}

export interface ConnectorDelivery {
  attempts: number;
  connector: string;
  created_at: string;
  destination: string;
  detail?: string;
  fingerprint?: string;
  id: string;
  idempotency_key?: string;
  identity_id?: string;
  outbox_id?: number;
  reason?: string;
  rollback_ref?: string;
  status: "unrouted" | "delivered" | "failed";
  target: string;
  tenant_id: string;
  updated_at: string;
}

export interface ConnectorDeliveryList {
  items: ConnectorDelivery[];
  next_cursor?: string;
}

export interface CredentialRisk {
  components: RiskComponents;
  credential_id: string;
  expires_at: string;
  exposure: number;
  kind: string;
  owner_active: boolean;
  privilege: number;
  score: number;
  sensitivity: number;
  subject: string;
}

export interface CredentialRiskList {
  credentials: CredentialRisk[];
}

export interface DiscoveryFinding {
  discovered_at: string;
  fingerprint: string;
  id: string;
  kind: string;
  metadata: Record<string, unknown>;
  provenance: string;
  ref: string;
  risk_score?: number;
  run_id: string;
  source_id: string;
  tenant_id: string;
}

export interface DiscoveryFindingList {
  items: DiscoveryFinding[];
  next_cursor?: string;
}

export interface DiscoveryRun {
  completed_at?: string;
  created_at: string;
  discovered: number;
  dry_run: boolean;
  error?: string;
  failed: number;
  id: string;
  rejected: number;
  requested_by?: string;
  schedule_id?: string;
  source_id: string;
  started_at?: string;
  status: "queued" | "running" | "succeeded" | "partial" | "failed";
  targets: number;
  tenant_id: string;
}

export interface DiscoveryRunList {
  items: DiscoveryRun[];
  next_cursor?: string;
}

export interface DiscoveryRunRequest {
  dry_run?: boolean;
  schedule_id?: string;
  source_id: string;
}

export interface DiscoverySchedule {
  created_at?: string;
  enabled: boolean;
  id: string;
  interval_seconds: number;
  name: string;
  source_id: string;
  tenant_id: string;
  updated_at?: string;
}

export interface DiscoveryScheduleList {
  items: DiscoverySchedule[];
  next_cursor?: string;
}

export interface DiscoveryScheduleRequest {
  enabled?: boolean;
  interval_seconds: number;
  name: string;
  source_id: string;
}

export interface DiscoverySource {
  config: Record<string, unknown>;
  created_at: string;
  id: string;
  kind: "network" | "ssh" | "cloud_certificate" | "secret_store" | "api_key" | "agent" | "manual";
  name: string;
  tenant_id: string;
  updated_at: string;
}

export interface DiscoverySourceList {
  items: DiscoverySource[];
  next_cursor?: string;
}

export interface DiscoverySourceRequest {
  config?: Record<string, unknown>;
  kind: "network" | "ssh" | "cloud_certificate" | "secret_store" | "api_key" | "agent" | "manual";
  name: string;
}

export interface EnrollmentToken {
  enroll_path?: string;
  token: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  type: string;
}

export interface GraphImpact {
  affected: GraphNode[];
  by_kind: Record<string, unknown>;
  node: GraphNode;
}

export interface GraphNode {
  attrs?: Record<string, unknown>;
  id: string;
  kind: string;
  name: string;
}

export interface GraphQueryResult {
  rows: Record<string, unknown>[];
}

export interface GraphReachable {
  from: string;
  nodes: GraphNode[];
}

export interface GraphResponse {
  edges: GraphEdge[];
  nodes: GraphNode[];
}

export interface Identity {
  attributes?: Record<string, unknown>;
  created_at?: string;
  id: string;
  issuer_id?: string;
  kind: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  name: string;
  not_after?: string;
  not_before?: string;
  owner_id: string;
  status: string;
  tenant_id?: string;
}

export interface IdentityList {
  items: Identity[];
  next_cursor?: string;
}

export interface IdentityRequest {
  attributes?: Record<string, unknown>;
  issuer_id?: string;
  kind: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  name: string;
  owner_id: string;
}

export interface IncidentExecution {
  blast_radius: GraphImpact;
  compromised_identity_id: string;
  connector_delivery?: ConnectorDelivery;
  connector_delivery_id?: string;
  created_at: string;
  created_by?: string;
  evidence_bundle?: string;
  evidence_bundle_format?: string;
  failed_targets: string[];
  id: string;
  idempotency_key?: string;
  phase: string;
  reason?: string;
  replacement_identity?: Identity;
  replacement_identity_id?: string;
  revocation_status?: string;
  rollback_refs: string[];
  status: string;
  tenant_id: string;
  updated_at: string;
}

export interface IncidentExecutionList {
  items: IncidentExecution[];
  next_cursor?: string;
}

export interface IncidentExecutionRequest {
  connector?: string;
  delivery_rollback_ref?: string;
  identity_id: string;
  reason?: string;
  replacement_name?: string;
  target?: string;
}

export interface Issuer {
  chain?: string[];
  chainless?: boolean;
  created_at?: string;
  id: string;
  internal?: boolean;
  kind: "x509_ca" | "ssh_ca";
  name: string;
  public_key?: string;
  tenant_id?: string;
}

export interface IssuerList {
  items: Issuer[];
  next_cursor?: string;
}

export interface IssuerRequest {
  chain?: string[];
  internal?: boolean;
  kind: "x509_ca" | "ssh_ca";
  name: string;
  public_key?: string;
}

export interface MCPToolCall {
  subject?: string;
}

export interface MCPToolList {
  identity?: string;
  read_only: boolean;
  tools: string[];
}

export interface MCPToolResult {
  citations?: string[];
  text: string;
  tool: string;
}

export interface MachineLoginRequest {
  credential: string;
  method?: string;
}

export interface MachineLoginResponse {
  expires_at: string;
  method: string;
  principal: string;
  scopes: string[];
  session_id: string;
}

export interface ManagedKey {
  algorithm: string;
  key_id: string;
  public_der?: string;
  state: string;
  version: number;
}

export interface ManagedKeyActionRequest {
  key_id: string;
}

export interface ManagedKeyGenerateRequest {
  algorithm: string;
}

export interface Member {
  created_at: string;
  display_name?: string;
  email?: string;
  offboard_reason?: string;
  offboarded_at?: string;
  offboarded_by?: string;
  roles: string[];
  source: string;
  status: "active" | "offboarded";
  subject: string;
  tenant_id: string;
  updated_at: string;
}

export interface MemberList {
  items: Member[];
  next_cursor?: string;
}

export interface MemberRequest {
  display_name?: string;
  email?: string;
  roles: string[];
  source?: string;
}

export interface OIDCMappingStatus {
  allow_default_tenant: boolean;
  claim_is_tenant: boolean;
  default_roles?: string[];
  default_tenant?: string;
  enabled: boolean;
  groups_claim?: string;
  tenant_claim?: string;
  tenant_mappings: OIDCTenantMapping[];
}

export interface OIDCTenantMapping {
  claim?: string;
  group?: string;
  roles?: string[];
  subject?: string;
  tenant_id: string;
}

export interface OffboardMemberRequest {
  reason?: string;
}

export interface OffboardMemberResponse {
  member: Member;
  revoked_token_count: number;
  rotation_evidence: string;
}

export interface OutboxCircuit {
  destination: string;
  failures: number;
  last_error?: string;
  open_until?: string;
  state: "closed" | "open" | "half-open";
  tenant_id: string;
  updated_at: string;
}

export interface OutboxCircuitList {
  items: OutboxCircuit[];
  next_cursor?: string;
}

export interface Owner {
  created_at?: string;
  email?: string;
  id: string;
  kind: "user" | "team" | "workload" | "service";
  name: string;
  tenant_id: string;
}

export interface OwnerList {
  items: Owner[];
  next_cursor?: string;
}

export interface OwnerRequest {
  email?: string;
  kind: "user" | "team" | "workload" | "service";
  name: string;
}

export interface PKISecret {
  certificate: string;
  common_name?: string;
  private_key: string;
  serial: string;
}

export interface PKISecretRequest {
  common_name: string;
  ttl_seconds?: number;
}

export interface PrivacyCatalog {
  items: PrivacyCatalogEntry[];
}

export interface PrivacyCatalogEntry {
  category: string;
  erasure: string;
  id: string;
  location: string;
  owner: string;
  purpose: string;
  retention_class: string;
}

export interface PrivacyErasureSelectors {
  attestation_ids?: string[];
  certificate_fingerprints?: string[];
  identity_ids?: string[];
  owner_ids?: string[];
  ssh_key_ids?: string[];
}

export interface PrivacyRetentionCutoffs {
  access_terminal_before: string;
  agent_stale_before: string;
  approval_actor_before: string;
  attestation_evidence_before: string;
  certificate_terminal_before: string;
  identity_terminal_before: string;
  owner_inactive_before: string;
  profile_actor_before: string;
  ssh_stale_before: string;
}

export interface PrivacyRetentionRun {
  counts: Record<string, unknown>;
  cutoffs: PrivacyRetentionCutoffs;
  enforced_at: string;
  requested_by_ref?: string;
  run_id: string;
}

export interface PrivacyRetentionRunList {
  items: PrivacyRetentionRun[];
  next_cursor?: string;
}

export interface PrivacySubjectErasure {
  counts: Record<string, unknown>;
  erased_at: string;
  reason?: string;
  requested_by_ref?: string;
  selectors: PrivacyErasureSelectors;
  subject_ref: string;
}

export interface PrivacySubjectErasureList {
  items: PrivacySubjectErasure[];
  next_cursor?: string;
}

export interface PrivacySubjectErasureRequest {
  reason?: string;
  subject: string;
}

export interface PrivacySubjectExport {
  api_tokens?: Record<string, unknown>[];
  approvals?: Record<string, unknown>[];
  attestations?: Record<string, unknown>[];
  certificates?: Record<string, unknown>[];
  counts: Record<string, unknown>;
  generated_at: string;
  identities?: Record<string, unknown>[];
  owners?: Record<string, unknown>[];
  ssh_keys?: Record<string, unknown>[];
  subject: string;
  subject_ref: string;
  tenant_id: string;
  tenant_members?: Record<string, unknown>[];
}

export interface PrivacySubjectExportRequest {
  subject: string;
}

export interface Problem {
  detail?: string;
  instance?: string;
  status?: number;
  title?: string;
  type?: string;
}

export interface Profile {
  active?: boolean;
  created_by?: string;
  id: string;
  name: string;
  spec?: Record<string, unknown>;
  version: number;
}

export interface ProfileList {
  items: Profile[];
  next_cursor?: string;
}

export interface ProfileRequest {
  name: string;
  spec: Record<string, unknown>;
}

export interface RCARequest {
  question: string;
  subject?: string;
}

export interface RiskComponents {
  age: number;
  exposure: number;
  owner: number;
  privilege: number;
  rotation: number;
  sensitivity: number;
}

export interface Role {
  name: string;
  permissions: string[];
}

export interface RoleList {
  items: Role[];
  next_cursor?: string;
}

export interface RotationRun {
  completed_at?: string;
  created_at: string;
  error?: string;
  id: string;
  idempotency_key?: string;
  identity_id: string;
  outbox_id?: number;
  predecessor_fingerprint?: string;
  reason?: string;
  rollback_ref?: string;
  status: "running" | "succeeded" | "failed";
  successor_fingerprint?: string;
  tenant_id: string;
  trigger: string;
  updated_at: string;
}

export interface RotationRunList {
  items: RotationRun[];
  next_cursor?: string;
}

export interface SecretMeta {
  created_at?: string;
  name: string;
  updated_at?: string;
  version: number;
}

export interface SecretMetaList {
  items: SecretMeta[];
  next_cursor?: string;
}

export interface SecretRequest {
  name: string;
  value: string;
}

export interface SecretValue {
  name: string;
  value: string;
  version?: number;
}

export interface ShareRedeemRequest {
  token: string;
}

export interface ShareRequest {
  ttl_seconds?: number;
  value: string;
}

export interface ShareToken {
  expires_at?: string;
  token: string;
}

export interface ShareValue {
  value: string;
}

export interface TransitionRequest {
  reason?: string;
  to: "issued" | "deployed" | "renewing" | "revoked" | "retired";
}
