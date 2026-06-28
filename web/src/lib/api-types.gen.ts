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
  mcp_write_tools?: boolean;
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

export interface AgentCertRevocation {
  agent?: string;
  agent_id: string;
  fingerprint?: string;
  reason?: string;
  revoked_at: string;
  serial?: string;
}

export interface AgentCertRevocationRequest {
  agent?: string;
  fingerprint?: string;
  reason?: string;
  serial?: string;
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

export interface Attestation {
  claims?: Record<string, unknown>;
  id: string;
  method: string;
  selectors: string[];
  subject: string;
  verified_at: string;
}

export interface AttestedSVID {
  attestation: Attestation;
  certificate_pem: string;
  credential_id: string;
  not_after: string;
  subject: string;
}

export interface AttestedSVIDRequest {
  method: "aws_iid" | "azure_imds" | "gcp_iit" | "github_oidc" | "k8s_sat" | "tpm";
  payload_base64: string;
  public_key_pem: string;
  ttl_seconds?: number;
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

export interface BreakglassBundle {
  approvals: string[];
  cert_der: string;
  issued_at: string;
  reason: string;
  request_id: string;
  signature: string;
  subject: string;
}

export interface BreakglassReconcileRequest {
  bundles: BreakglassBundle[];
}

export interface BreakglassReconcileResponse {
  reconciled: number;
}

export interface BrokerAgentIdentity {
  agent_id: string;
  attestation: Attestation;
  certificate_id: string;
  certificate_pem: string;
  credential_id: string;
  node_id: string;
  not_after: string;
  scopes: string[];
  subject: string;
}

export interface BrokerAgentIdentityRequest {
  agent_id: string;
  method: string;
  payload_base64: string;
  public_key_pem: string;
  scopes: string[];
  ttl_seconds?: number;
}

export interface BulkRevokeItem {
  error?: string;
  id: string;
  status: "revoked" | "skipped" | "failed";
}

export interface BulkRevokeRequest {
  certificate_ids?: string[];
  identity_ids?: string[];
  ids?: string[];
  issuer_id?: string;
  kind?: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  owner_id?: string;
  reason: "unspecified" | "keyCompromise" | "caCompromise" | "affiliationChanged" | "superseded" | "cessationOfOperation" | "certificateHold" | "removeFromCRL" | "privilegeWithdrawn" | "aaCompromise";
  status?: "requested" | "issued" | "deployed" | "renewing" | "revoked" | "retired";
}

export interface BulkRevokeResult {
  items: BulkRevokeItem[];
  total_failed: number;
  total_matched: number;
  total_revoked: number;
  total_skipped: number;
}

export interface CAAuthority {
  certificate_pem: string;
  common_name: string;
  created_at: string;
  extended_key_usages?: string[];
  id: string;
  kind: string;
  max_path_len: number;
  not_after?: string;
  parent_id?: string;
  permitted_dns_names?: string[];
  serial: string;
  signer_handle: string;
  status: string;
  tenant_id: string;
}

export interface CAAuthorityList {
  items: CAAuthority[];
  next_cursor?: string;
}

export interface CACeremonyStartRequest {
  csr_pem?: string;
  operation: "create_root" | "create_intermediate" | "issue_intermediate_csr";
  parent_id?: string;
  spec: CASpec;
  threshold: number;
}

export interface CACreateIntermediateRequest {
  ceremony_id: string;
  parent_id: string;
  spec: CASpec;
}

export interface CACreateRootRequest {
  ceremony_id: string;
  spec: CASpec;
}

export interface CAIssueIntermediateRequest {
  ceremony_id: string;
  csr_pem: string;
  spec: CASpec;
}

export interface CAIssueLeafRequest {
  csr_pem: string;
  ttl_seconds?: number;
}

export interface CAIssuedIntermediate {
  certificate_pem: string;
  not_after: string;
  serial: string;
}

export interface CAIssuedLeaf {
  certificate_pem: string;
  not_after: string;
  serial: string;
}

export interface CAKeyCeremony {
  approvals: number;
  created_at: string;
  id: string;
  opener?: string;
  purpose: string;
  status: string;
  tenant_id: string;
  threshold: number;
}

export interface CASpec {
  common_name: string;
  extended_key_usages?: string[];
  max_path_len?: number;
  permitted_dns_domains?: string[];
  signature_algorithm?: string;
  ttl_seconds?: number;
}

export interface CBOMAsset {
  algorithm?: string;
  cipher?: string;
  id: string;
  key_bits?: number;
  kind: string;
  library?: string;
  location: string;
  migration_generation: string;
  migration_standard: string;
  migration_target: string;
  out_of_policy: boolean;
  protocol?: string;
  quantum_vulnerable: boolean;
  reasons?: string[];
  strength: string;
}

export interface CBOMInventory {
  items: CBOMAsset[];
  migration_progress: CBOMMigrationProgress;
}

export interface CBOMMigrationProgress {
  out_of_policy_assets: number;
  percent_migrated: number;
  post_quantum_ready_assets: number;
  quantum_vulnerable_assets: number;
  total_assets: number;
}

export interface CBOMReport {
  failed: number;
  findings: number;
  out_of_policy: number;
  quantum_vulnerable: number;
  sources: number;
  weak: number;
}

export interface CBOMScan {
  migration_progress: CBOMMigrationProgress;
  report: CBOMReport;
}

export interface CBOMScanRequest {
  host_configs?: string[];
  tls_endpoints?: string[];
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

export interface CodeSigningKeylessRequest {
  artifact_type: string;
  digest: string;
  fulcio_issuer?: string;
  fulcio_san?: string;
  identity_method: string;
  identity_payload: string;
}

export interface CodeSigningRequest {
  artifact_type: string;
  digest: string;
  key_id: string;
}

export interface CodeSigningSignature {
  algorithm: string;
  artifact_type: string;
  fulcio_issuer?: string;
  fulcio_san?: string;
  key_id?: string;
  public_key_der: string;
  signature: string;
  transparency_destination?: string;
}

export interface ComplianceEvidencePack {
  format: string;
  framework: "pci-dss" | "hipaa" | "soc2" | "fedramp" | "cnsa-2.0";
  public_key_der: string;
  signed_export: Record<string, unknown>;
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
  managed_identity_id?: string;
  metadata: Record<string, unknown>;
  provenance: string;
  ref: string;
  risk_score?: number;
  run_id: string;
  source_id: string;
  tenant_id: string;
  triage_actor?: string;
  triage_reason?: string;
  triage_status?: "unmanaged" | "investigating" | "managed" | "dismissed";
  triaged_at?: string;
}

export interface DiscoveryFindingList {
  items: DiscoveryFinding[];
  next_cursor?: string;
}

export interface DiscoveryFindingTriageRequest {
  managed_identity_id?: string;
  reason?: string;
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
  kind: "network" | "ssh" | "cloud_certificate" | "cloud_secret" | "ct_log" | "drift" | "secret_store" | "api_key" | "agent" | "manual" | "nhi_cross_surface" | "oauth_grant" | "nhi_behavior" | "k8s_ingress_gateway";
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
  kind: "network" | "ssh" | "cloud_certificate" | "cloud_secret" | "ct_log" | "drift" | "secret_store" | "api_key" | "agent" | "manual" | "nhi_cross_surface" | "oauth_grant" | "nhi_behavior" | "k8s_ingress_gateway";
  name: string;
}

export interface DynamicLease {
  credential?: string;
  expires_at: string;
  id: string;
  issued_at: string;
  provider: string;
  role: string;
  state: string;
}

export interface DynamicLeaseRenewRequest {
  extend_seconds: number;
}

export interface DynamicLeaseRequest {
  provider: string;
  role: string;
  ttl_seconds: number;
}

export interface EditionFeature {
  licensed: boolean;
  mode: "enabled" | "read_only" | "off";
  name: string;
  tier: "community" | "enterprise" | "provider";
}

export interface EditionsInfo {
  customer?: string;
  expires_at?: string;
  features: EditionFeature[];
  fips: FIPSStatus;
  license_id?: string;
  read_only_at?: string;
  state: "community" | "active" | "grace" | "read_only";
  tenant_band?: number;
  tier: "community" | "enterprise" | "provider";
}

export interface EnrollmentToken {
  enroll_path?: string;
  token: string;
}

export interface EphemeralAPIKey {
  created_at: string;
  expires_at: string;
  id: string;
  scopes: string[];
  subject: string;
  tenant_id: string;
  token: string;
}

export interface EphemeralAPIKeyRequest {
  scopes: string[];
  subject: string;
  ttl_seconds: number;
}

export interface EphemeralApproval {
  action: string;
  approvals: number;
  approver: string;
  resource: string;
}

export interface EphemeralApprovalRequest {
  action: "issue";
}

export interface EphemeralCredential {
  approvals: number;
  attestation: Attestation;
  certificate_id?: string;
  certificate_pem?: string;
  credential_id?: string;
  expires_at: string;
  not_after?: string;
  request_id: string;
  required_approvals: number;
  state: "awaiting_approval" | "issued";
  subject: string;
}

export interface EphemeralCredentialRequest {
  method: string;
  payload_base64: string;
  public_key_pem: string;
  request_id: string;
  ttl_seconds?: number;
}

export interface ExternalCA {
  id: string;
  name: string;
  status: string;
  type: string;
}

export interface ExternalCAIssueRequest {
  csr_pem: string;
  dns_names: string[];
  profile_name?: string;
  requested_ekus?: string[];
  ttl_seconds?: number;
}

export interface ExternalCAIssuedCertificate {
  certificate_pem: string;
  issuer: string;
  not_after: string;
  serial: string;
}

export interface ExternalCAList {
  items: ExternalCA[];
  next_cursor?: string;
}

export interface FIPSStatus {
  module_active: boolean;
  required: boolean;
  self_test_passed: boolean;
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

export interface ITSMTicket {
  created_at: string;
  destination: string;
  id: string;
  idempotency_key: string;
  outbox_id: number;
  provider: string;
  status: string;
  table: string;
  tenant_id: string;
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
  authority_id?: string;
  csr_pem?: string;
  previous_serial?: string;
  reason?: string;
  subject?: string;
  ttl_seconds?: number;
}

export interface MCPToolList {
  identity?: string;
  read_only: boolean;
  tools: string[];
}

export interface MCPToolResult {
  certificate_pem?: string;
  citations?: string[];
  not_after?: string;
  serial?: string;
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

export interface Notification {
  attempts: number;
  certificate_id?: string;
  created_at: string;
  delivered_at?: string;
  destination: string;
  detail?: string;
  id: string;
  idempotency_key?: string;
  kind?: string;
  last_error?: string;
  not_after?: string;
  read_at?: string;
  routing_policy_id?: string;
  serial?: string;
  severity?: "low" | "informational" | "warning" | "critical";
  status: "pending" | "sent" | "dead" | "read";
  subject?: string;
  tenant_id: string;
  threshold_days?: number;
}

export interface NotificationList {
  items: Notification[];
  next_cursor?: string;
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

export interface PAMPostgresCredential {
  dsn: string;
  username: string;
}

export interface PAMSSHCredential {
  certificate: string;
  key_id: string;
  principal: string;
  serial: number;
  valid_before: string;
}

export interface PAMSession {
  attestation: Attestation;
  audit?: Record<string, unknown>;
  ended_at?: string;
  expires_at: string;
  id: string;
  postgres?: PAMPostgresCredential;
  reason?: string;
  requested_by: string;
  role: string;
  ssh?: PAMSSHCredential;
  started_at: string;
  status: string;
  subject: string;
  target_id: string;
  target_type: string;
}

export interface PAMSessionList {
  items: PAMSession[];
  next_cursor?: string;
}

export interface PAMSessionRequest {
  method: string;
  payload_base64: string;
  reason?: string;
  role: string;
  ssh_principal?: string;
  ssh_public_key?: string;
  target_id: string;
  target_type: "postgres" | "ssh";
  ttl_seconds?: number;
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

export interface PQCMigration {
  effective_algorithm: string;
  migration_progress: CBOMMigrationProgress;
  protocol: string;
  queued: number;
  queued_at: string;
  rollback_configured: boolean;
  run_id: string;
  target_algorithm: string;
}

export interface PQCMigrationRequest {
  asset_ids: string[];
  protocol?: string;
  rollback_on_failure?: boolean;
  target_algorithm: string;
}

export interface PQCMigrationRollback {
  migration_progress: CBOMMigrationProgress;
  queued: number;
  queued_at: string;
  reason: string;
  run_id: string;
}

export interface PQCMigrationRollbackRequest {
  asset_ids: string[];
  reason?: string;
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

export interface SecretImportRequest {
  prefix?: string;
  values: Record<string, unknown>;
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

export interface SecretRecoverRequest {
  at: string;
}

export interface SecretRequest {
  name: string;
  value: string;
}

export interface SecretRotation {
  completed: boolean;
  error?: string;
  failed_phase?: string;
  key: string;
  new_ref: string;
  old_ref: string;
  rollback_attempted: boolean;
  rollback_error?: string;
  rollback_failed: boolean;
  rolled_back: boolean;
}

export interface SecretRotationRequest {
  key: string;
  old_ref: string;
  provider: string;
}

export interface SecretScan {
  engine_version: string;
  findings: SecretScanFinding[];
  findings_count: number;
  rules_active: number;
  run_id: string;
  scanner: string;
}

export interface SecretScanFinding {
  credential_ref: string;
  file: string;
  line: number;
  rule_id: string;
}

export interface SecretScanRequest {
  path: string;
}

export interface SecretSync {
  delivered: boolean;
  enqueued: boolean;
  name: string;
  remote_key: string;
  target: string;
}

export interface SecretSyncRequest {
  name: string;
  remote_key?: string;
  target: string;
}

export interface SecretValue {
  name: string;
  value: string;
  version?: number;
}

export interface ServiceNowTicketRequest {
  allow_private_endpoint?: boolean;
  category?: string;
  correlation_id?: string;
  description?: string;
  impact?: string;
  instance_url: string;
  short_description: string;
  table?: "incident" | "change_request" | "sc_task";
  token_ref: string;
  urgency?: string;
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

export interface TransitCiphertext {
  ciphertext: string;
  version: number;
}

export interface TransitDecryptRequest {
  aad?: string;
  ciphertext: string;
  key: string;
}

export interface TransitEncryptRequest {
  aad?: string;
  key: string;
  plaintext: string;
}

export interface TransitHMAC {
  hmac: string;
}

export interface TransitHMACRequest {
  data: string;
  key: string;
}

export interface TransitKey {
  kind: string;
  name: string;
  version: number;
}

export interface TransitKeyRequest {
  kind: string;
  name: string;
}

export interface TransitPlaintext {
  plaintext: string;
}

export interface TransitRewrapRequest {
  aad?: string;
  ciphertext: string;
  key: string;
}

export interface TransitRotateRequest {
  name: string;
}

export interface TransitSignRequest {
  key: string;
  message: string;
}

export interface TransitSignature {
  public_der: string;
  signature: string;
}

export interface TransitVerify {
  valid: boolean;
}

export interface TransitVerifyRequest {
  message: string;
  public_der: string;
  signature: string;
}

export interface TransitionRequest {
  reason?: string;
  to: "issued" | "deployed" | "renewing" | "revoked" | "retired";
}
