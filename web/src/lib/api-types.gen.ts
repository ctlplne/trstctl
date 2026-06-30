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
export interface ACMEDNS01CAARecord {
  flag?: number;
  issuer_domain: string;
  name?: string;
  tag: string;
}

export interface ACMEDNS01Preflight {
  checks: ACMEDNS01PreflightCheck[];
  config_id: string;
  domain: string;
  failed_checks: string[];
  method_rationale?: string;
  ready: boolean;
  record_name: string;
  selected_method: string;
  wildcard: boolean;
}

export interface ACMEDNS01PreflightCheck {
  detail: string;
  name: string;
  status: "pass" | "fail" | "skipped";
}

export interface ACMEDNS01PreflightRequest {
  caa_lookup_error?: string;
  caa_records?: ACMEDNS01CAARecord[];
  config_id: string;
  domain: string;
  expected_txt?: string;
  method_override?: "http-01" | "dns-01" | "tls-alpn-01";
  observed_cname?: string;
  observed_txt?: string[];
  port80_reachable?: boolean;
}

export interface ACMEDNS01ProviderCatalog {
  items: ACMEDNS01ProviderCatalogItem[];
}

export interface ACMEDNS01ProviderCatalogItem {
  capabilities: string[];
  conformance: string;
  credential_reference_fields: string[];
  display_name: string;
  kind: string;
  name: string;
  notes?: string;
  propagation_preflight: boolean;
  provider_package: string;
  secret_fields: string[];
  served: boolean;
}

export interface ACMEDNS01ProviderConfig {
  allow_wildcards?: boolean;
  allowed_methods: string[];
  caa_issuer_domain?: string;
  challenge_domain?: string;
  config: Record<string, unknown>;
  created_at: string;
  credential_refs: Record<string, unknown>;
  delegation_target?: string;
  id: string;
  name: string;
  provider: string;
  secret_handling: string;
  tenant_id: string;
  updated_at: string;
  zone?: string;
}

export interface ACMEDNS01ProviderConfigList {
  items: ACMEDNS01ProviderConfig[];
}

export interface ACMEDNS01ProviderConfigRequest {
  allow_wildcards?: boolean;
  allowed_methods?: ("http-01" | "dns-01" | "tls-alpn-01")[];
  caa_issuer_domain?: string;
  challenge_domain?: string;
  config?: Record<string, unknown>;
  credential_refs?: Record<string, unknown>;
  delegation_target?: string;
  name: string;
  provider: string;
  zone?: string;
}

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

export interface AccessChangeDecision {
  approver_subject: string;
  decided_at: string;
  decision: "approved" | "denied";
  decision_evidence_refs: string[];
  reason?: string;
  request_id: string;
}

export interface AccessChangeDecisionRequest {
  approver_subject?: string;
  decision: "approved" | "denied";
  decision_evidence_refs?: string[];
  reason?: string;
}

export interface AccessChangeRequest {
  approval_count: number;
  change_ref: string;
  change_system: string;
  change_url?: string;
  completed_at?: string;
  created_at: string;
  decisions?: AccessChangeDecision[];
  display_name: string;
  entitlement: string;
  evidence_refs: string[];
  id: string;
  nhi_id: string;
  nhi_kind: string;
  owner_ref?: string;
  reason: string;
  requested_action: "grant" | "modify" | "revoke" | "rotate" | "deploy" | "break_glass";
  requester_subject: string;
  required_approvals: number;
  resource: string;
  risk: string;
  status: "pending" | "approved" | "denied";
  tenant_id: string;
  updated_at: string;
}

export interface AccessChangeRequestCreateRequest {
  change_ref: string;
  change_system?: string;
  change_url?: string;
  display_name?: string;
  entitlement: string;
  evidence_refs?: string[];
  id?: string;
  nhi_id: string;
  nhi_kind: string;
  owner_ref?: string;
  reason: string;
  requested_action: "grant" | "modify" | "revoke" | "rotate" | "deploy" | "break_glass";
  requester_subject?: string;
  required_approvals?: number;
  resource: string;
  risk?: string;
}

export interface AccessChangeRequestList {
  items: AccessChangeRequest[];
  next_cursor?: string;
}

export interface ActiveActiveIssuancePlan {
  architecture_invariants: string[];
  capability: string;
  evidence_refs: string[];
  failover_runbook: RegionalFailoverStep[];
  generated_at: string;
  issuance_lanes: RegionalIssuanceLane[];
  operator_actions: string[];
  regions: IssuanceRegion[];
  release_gates: ScaleReleaseGate[];
  residuals: string[];
  rpo_seconds: number;
  rto_seconds: number;
  served: boolean;
  tenant_write_fences: TenantWriteFence[];
  topology: string;
  write_model: string;
}

export interface Agent {
  discovery_capabilities: AgentDiscoveryCapability[];
  id: string;
  inventory_report_path: string;
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

export interface AgentDiscoveryCapability {
  label: string;
  metadata_only: boolean;
  private_key_bytes: boolean;
  reported_over: string;
  source_kind: string;
}

export interface AgentList {
  agents: Agent[];
  next_cursor?: string;
}

export interface AlertRecipient {
  display_name?: string;
  email?: string;
  kind: string;
  roles?: string[];
  subject: string;
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

export interface BreakglassIssueRequest {
  approvals: string[];
  csr_der: string;
  reason: string;
  request_id: string;
  subject: string;
  ttl_seconds?: number;
}

export interface BreakglassIssueResponse {
  audit_event_type: string;
  bundle: BreakglassBundle;
  reconciled: number;
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
  replaces_id?: string;
  serial: string;
  signer_handle: string;
  status: string;
  tenant_id: string;
}

export interface CAAuthorityList {
  items: CAAuthority[];
  next_cursor?: string;
}

export interface CAAuthorityRekeyRequest {
  ceremony_id: string;
  reason?: string;
  ttl_seconds?: number;
}

export interface CAAuthorityRotation {
  active_issue_path: string;
  issue_path: string;
  overlap_issuers: CAAuthorityRotationIssuer[];
  predecessor: CAAuthority;
  successor: CAAuthority;
}

export interface CAAuthorityRotationIssuer {
  authority_id: string;
  issue_path: string;
  role: string;
  status: string;
}

export interface CAAuthorityRotationRequest {
  reason?: string;
  successor_id: string;
}

export interface CACeremonyStartRequest {
  authority_id?: string;
  certificate_pem?: string;
  csr_pem?: string;
  operation: "create_root" | "import_offline_root" | "import_existing_ca" | "create_intermediate" | "create_offline_intermediate" | "issue_intermediate_csr" | "rekey_ca";
  parent_id?: string;
  signer_handle?: string;
  spec: CASpec;
  threshold: number;
}

export interface CACreateIntermediateRequest {
  ceremony_id: string;
  parent_id: string;
  spec: CASpec;
}

export interface CACreateOfflineIntermediateCSRRequest {
  ceremony_id: string;
  spec: CASpec;
}

export interface CACreateRootRequest {
  ceremony_id: string;
  spec: CASpec;
}

export interface CADiscoveryInventory {
  items: CADiscoveryItem[];
  summary: CADiscoverySummary;
}

export interface CADiscoveryItem {
  discovery_methods: string[];
  id: string;
  import_path?: string;
  inventory_path: string;
  issuance_path?: string;
  managed: boolean;
  name: string;
  not_after?: string;
  parent_id?: string;
  scope: "public" | "private";
  serial?: string;
  source: "external_ca_registry" | "ca_hierarchy";
  source_id: string;
  status: string;
  type: string;
}

export interface CADiscoverySummary {
  authority_count: number;
  external_registry_count: number;
  private_count: number;
  public_count: number;
}

export interface CAImportExistingRequest {
  ceremony_id: string;
  certificate_pem: string;
  signer_handle: string;
  spec: CASpec;
}

export interface CAImportOfflineIntermediateRequest {
  ceremony_id: string;
  certificate_pem: string;
  spec: CASpec;
}

export interface CAImportOfflineRootRequest {
  ceremony_id: string;
  certificate_pem: string;
  spec: CASpec;
}

export interface CAIntermediateCSR {
  ceremony_id: string;
  csr_pem: string;
  parent_id: string;
  signer_handle: string;
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

export interface CRLDistribution {
  ca_id: string;
  delta_base_number?: number;
  delta_url?: string;
  full_number: number;
  full_url: string;
  next_update: string;
  revoked_count: number;
  shard_count: number;
  shards: CRLDistributionShard[];
  tenant_id: string;
  this_update: string;
}

export interface CRLDistributionList {
  items: CRLDistribution[];
  next_cursor?: string;
}

export interface CRLDistributionShard {
  index: number;
  revoked_count: number;
  url: string;
}

export interface CTLogSubmission {
  capability: string;
  logs: CTLogSubmissionLog[];
  queued: number;
  residuals?: CTLogSubmissionNote[];
}

export interface CTLogSubmissionLog {
  certificate_queued: boolean;
  certificate_submission_id?: string;
  log_url: string;
  precertificate_queued: boolean;
  precertificate_submission_id?: string;
}

export interface CTLogSubmissionNote {
  code: string;
  detail: string;
}

export interface CTLogSubmissionRequest {
  allow_private_endpoint?: boolean;
  certificate_pem: string;
  chain_pem?: string[];
  logs: string[];
  operator_correlation_ref?: string;
  precertificate_pem?: string;
  submission_profile?: string;
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

export interface CertificateExpiryBucket {
  count: number;
  name: "expired" | "expiring_7d" | "expiring_30d" | "expiring_90d" | "later" | "unknown";
}

export interface CertificateHealthDashboard {
  expiring: CertificateHealthItem[];
  expiring_path: string;
  expiry_buckets: CertificateExpiryBucket[];
  generated_at: string;
  inventory_path: string;
  source_breakdown: CertificateSourceHealth[];
  summary: CertificateHealthSummary;
}

export interface CertificateHealthItem {
  days_remaining: number;
  deployment_location?: string;
  externally_issued: boolean;
  fingerprint: string;
  id: string;
  not_after?: string;
  source: string;
  status: "active" | "superseded" | "revoked";
  subject: string;
}

export interface CertificateHealthSummary {
  active: number;
  discovered_count: number;
  expired: number;
  expiring_30d: number;
  expiring_7d: number;
  expiring_90d: number;
  external_source_count: number;
  health: "ok" | "warning" | "critical";
  imported_count: number;
  revoked: number;
  superseded: number;
  total: number;
  unknown_expiry_count: number;
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

export interface CertificateSourceHealth {
  count: number;
  expired: number;
  expiring_30d: number;
  external: boolean;
  source: string;
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
  framework: "pci-dss" | "hipaa" | "soc2" | "nist-800-53" | "nist-csf-2.0" | "fedramp" | "cmmc-2.0" | "cnsa-2.0" | "fips-140" | "common-criteria" | "cabf-br" | "webtrust" | "etsi" | "eidas" | "nis2";
  public_key_der: string;
  signed_export: Record<string, unknown>;
}

export interface ComplianceInventoryReport {
  capability: string;
  evidence_refs: string[];
  frameworks: string[];
  generated_at: string;
  report_types: string[];
  routes: string[];
  schedules: ComplianceReportSchedule[];
  summary: ComplianceInventorySummary;
}

export interface ComplianceInventorySummary {
  certificates: number;
  crypto_assets: number;
  discovery_schedules: number;
  enabled_report_schedules: number;
  frameworks_supported: number;
  inventory_rows: number;
  report_schedules: number;
  report_types_supported: number;
}

export interface ComplianceReportSchedule {
  created_at: string;
  delivery: "audit_export";
  enabled: boolean;
  framework: "pci-dss" | "hipaa" | "soc2" | "nist-800-53" | "nist-csf-2.0" | "fedramp" | "cmmc-2.0" | "cnsa-2.0" | "fips-140" | "common-criteria" | "cabf-br" | "webtrust" | "etsi" | "eidas" | "nis2";
  id: string;
  interval_seconds: number;
  name: string;
  next_run_at: string;
  recipient_ref?: string;
  report_type: "framework_evidence_pack" | "inventory_snapshot" | "cbom_posture" | "audit_summary" | "nhi_compliance_mapping";
  tenant_id: string;
  updated_at: string;
}

export interface ComplianceReportScheduleList {
  items: ComplianceReportSchedule[];
  next_cursor?: string;
}

export interface ComplianceReportScheduleRequest {
  delivery?: "audit_export";
  enabled?: boolean;
  framework: "pci-dss" | "hipaa" | "soc2" | "nist-800-53" | "nist-csf-2.0" | "fedramp" | "cmmc-2.0" | "cnsa-2.0" | "fips-140" | "common-criteria" | "cabf-br" | "webtrust" | "etsi" | "eidas" | "nis2";
  interval_seconds: number;
  name: string;
  recipient_ref?: string;
  report_type: "framework_evidence_pack" | "inventory_snapshot" | "cbom_posture" | "audit_summary" | "nhi_compliance_mapping";
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
  status: "unrouted" | "delivered" | "failed" | "test_succeeded" | "rollback_recorded";
  target: string;
  tenant_id: string;
  updated_at: string;
}

export interface ConnectorDeliveryList {
  items: ConnectorDelivery[];
  next_cursor?: string;
}

export interface ConnectorTargetActionRequest {
  identity_id: string;
  reason?: string;
}

export interface ContextualRiskPriorities {
  capability: string;
  coverage: string[];
  generated_at: string;
  priorities: ContextualRiskPriority[];
  summary: ContextualRiskSummary;
}

export interface ContextualRiskPriority {
  base_score: number;
  blast_radius: number;
  components: RiskComponents;
  contextual_score: number;
  credential_blast_radius: number;
  credential_id: string;
  crypto_asset_blast_radius: number;
  evidence_refs: string[];
  expires_at: string;
  kind: string;
  owner_active: boolean;
  priority_reasons: string[];
  privilege: number;
  rank: number;
  recommended_action: string;
  resource_blast_radius: number;
  sensitivity: number;
  severity: "critical" | "high" | "medium" | "low";
  subject: string;
  weak_crypto_context: number;
  workload_blast_radius: number;
}

export interface ContextualRiskSummary {
  critical: number;
  high: number;
  high_blast_radius: number;
  low: number;
  medium: number;
  near_expiry: number;
  orphaned: number;
  priorities: number;
  recommendations: number;
  total_analyzed: number;
  weak_crypto_context: number;
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

export interface DeploymentTarget {
  config: Record<string, unknown>;
  connector: string;
  created_at: string;
  id: string;
  name: string;
  tenant_id: string;
}

export interface DeploymentTargetList {
  items: DeploymentTarget[];
  next_cursor?: string;
}

export interface DeploymentTargetRequest {
  config?: Record<string, unknown>;
  connector: string;
  name: string;
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
  owner?: string;
  reason?: string;
  tags?: string[];
  team?: string;
}

export interface DiscoveryMonitoring {
  findings_path: string;
  repository_path: string;
  runs_path: string;
  schedules_path: string;
  sources: DiscoveryMonitoringSource[];
  sources_path: string;
  summary: DiscoveryMonitoringSummary;
}

export interface DiscoveryMonitoringSource {
  certificate_inventory_count: number;
  completed_run_count: number;
  failed_run_count: number;
  finding_count: number;
  findings_path: string;
  kind: "network" | "ssh" | "cloud_certificate" | "cloud_secret" | "ct_log" | "drift" | "secret_store" | "api_key" | "agent" | "manual" | "nhi_cross_surface" | "oauth_grant" | "service_account" | "nhi_behavior" | "credential_compromise" | "k8s_ingress_gateway";
  last_discovery_at?: string;
  last_run_completed_at?: string;
  last_run_error: string;
  last_run_id: string;
  last_run_status: string;
  monitoring_interval_seconds: number;
  name: string;
  open_finding_count: number;
  repository_path: string;
  run_count: number;
  schedule_id: string;
  scheduled: boolean;
  source_id: string;
  updated_at: string;
}

export interface DiscoveryMonitoringSummary {
  active_monitoring_count: number;
  certificate_inventory_count: number;
  completed_run_count: number;
  failed_run_count: number;
  finding_count: number;
  open_finding_count: number;
  run_count: number;
  scheduled_source_count: number;
  source_count: number;
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
  kind: "network" | "ssh" | "cloud_certificate" | "cloud_secret" | "ct_log" | "drift" | "secret_store" | "api_key" | "agent" | "manual" | "nhi_cross_surface" | "oauth_grant" | "service_account" | "nhi_behavior" | "credential_compromise" | "k8s_ingress_gateway";
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
  kind: "network" | "ssh" | "cloud_certificate" | "cloud_secret" | "ct_log" | "drift" | "secret_store" | "api_key" | "agent" | "manual" | "nhi_cross_surface" | "oauth_grant" | "service_account" | "nhi_behavior" | "credential_compromise" | "k8s_ingress_gateway";
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

export interface EndpointBinding {
  identity: Identity;
  queued_lifecycle_intents: string[];
  renewal_intent: string;
  target: DeploymentTarget;
}

export interface EndpointBindingRequest {
  identity_name: string;
  owner_id: string;
  reason?: string;
  target?: DeploymentTargetRequest;
  target_id?: string;
}

export interface EnrollmentToken {
  enroll_path?: string;
  token: string;
}

export interface EnterpriseProfessionalService {
  deliverables: string[];
  engagement_model: string;
  id: string;
  name: string;
}

export interface EnterpriseSupportSLATarget {
  applies_to: string;
  escalation: string;
  initial_response_sla: string;
  severity: string;
  target_restore: string;
  update_cadence_sla: string;
}

export interface EnterpriseSupportStatus {
  capability: string;
  contract_boundary: string;
  evidence_refs: string[];
  license_feature: string;
  license_state: "community" | "active" | "grace" | "read_only";
  professional_services: EnterpriseProfessionalService[];
  served: boolean;
  sla_targets: EnterpriseSupportSLATarget[];
  support_mode: "enabled" | "read_only" | "off";
  support_tiers: EnterpriseSupportTier[];
  tier: "community" | "enterprise" | "provider";
}

export interface EnterpriseSupportTier {
  contract_boundary: string;
  coverage: string;
  escalation: string;
  id: string;
  initial_response_sla: string;
  license_mode: "enabled" | "read_only" | "off";
  name: string;
  update_cadence_sla: string;
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

export interface FIPSAlgorithmMode {
  algorithm: string;
  approved: boolean;
  mode: string;
  module_boundary: string;
  use: string;
}

export interface FIPSCustodyValidationCertificate {
  boundary: string;
  certificate_ref: string;
  provider: string;
  required_for_approved_mode: boolean;
  status: string;
  validation_scope: string;
}

export interface FIPSNonFIPSFence {
  action: string;
  algorithms: string[];
  evidence_ref: string;
  reason: string;
  status_under_fips: string;
  surface: string;
}

export interface FIPSRegulatedDeploymentProfile {
  approved_algorithms: FIPSAlgorithmMode[];
  build_target?: string;
  capability_id: string;
  crypto_boundary?: string;
  evidence_refs?: string[];
  go_fips_module?: string;
  go_fips_module_selector: string;
  hsm_kms_validation_certificates: FIPSCustodyValidationCertificate[];
  module_active?: boolean;
  non_fips_fences: FIPSNonFIPSFence[];
  operator_required_artifacts?: string[];
  product_certification_residual?: string;
  product_certification_status?: string;
  profile_id: string;
  runtime_assertions?: string[];
  self_test_passed?: boolean;
  standard: string;
}

export interface FIPSStatus {
  build_target?: string;
  capability_id?: string;
  ci_gate?: string;
  crypto_boundary?: string;
  module?: string;
  module_active: boolean;
  product_certification_residual?: string;
  regulated_deployment_profile?: FIPSRegulatedDeploymentProfile;
  required: boolean;
  runtime_activation?: string[];
  self_test_passed: boolean;
  standard?: string;
  validated_module_path?: boolean;
}

export interface FleetReissuanceActionRequest {
  reason?: string;
  rollback_ref?: string;
}

export interface FleetReissuanceBatch {
  health_gate?: string;
  identity_ids: string[];
  index: number;
  replacement_identity_ids: string[];
  status: string;
}

export interface FleetReissuanceEvidence {
  evidence_bundle: string;
  evidence_bundle_format: string;
  exported_at: string;
  failed_targets?: string[];
  rollback_refs: string[];
  run_id: string;
}

export interface FleetReissuanceHealthGate {
  name: string;
  status: string;
}

export interface FleetReissuanceRequest {
  batch_size?: number;
  connector?: string;
  evidence_hint?: string;
  health_gates?: FleetReissuanceHealthGate[];
  issuer_id: string;
  reason?: string;
  rollback_ref?: string;
  target?: string;
}

export interface FleetReissuanceRun {
  affected_identity_ids: string[];
  batch_count: number;
  batch_size: number;
  batches: FleetReissuanceBatch[];
  connector?: string;
  connector_deliveries?: ConnectorDelivery[];
  connector_delivery_ids?: string[];
  created_at: string;
  created_by?: string;
  evidence_bundle?: string;
  evidence_bundle_format?: string;
  failed_targets?: string[];
  graph_impact: GraphImpact;
  health_gates: FleetReissuanceHealthGate[];
  id: string;
  idempotency_key?: string;
  issuer_id: string;
  phase: string;
  reason?: string;
  replacement_identities?: Identity[];
  replacement_identity_ids: string[];
  revoked_identity_ids: string[];
  rollback_refs: string[];
  status: string;
  target?: string;
  tenant_id: string;
  updated_at: string;
}

export interface FleetReissuanceRunList {
  items: FleetReissuanceRun[];
  next_cursor?: string;
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

export interface IdentityConnectorTargetRequest {
  target_id: string;
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

export interface IssuanceRegion {
  datastore: string;
  event_stream: string;
  health_signal: string;
  id: string;
  region: string;
  role: string;
  signer: string;
  writable_scope: string;
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

export interface KubernetesCSRSupport {
  api_group: string;
  api_version: string;
  architecture_controls: string[];
  capability: string;
  controller_flow: string[];
  evidence_refs: string[];
  generated_at: string;
  rbac_rules: KubernetesCSRSupportRule[];
  recommended_next_actions: string[];
  residuals: string[];
  resource: string;
  served: boolean;
  signer_names: string[];
  status_fields: string[];
}

export interface KubernetesCSRSupportRule {
  api_group: string;
  resource: string;
  verbs: string[];
}

export interface KubernetesSecretOperator {
  architecture_controls: string[];
  capability: string;
  crds: KubernetesSecretOperatorCRD[];
  evidence_refs: string[];
  generated_at: string;
  recommended_next_actions: string[];
  reload_workloads: string[];
  residuals: string[];
  secret_handling: string;
  served: boolean;
  sync_flow: string[];
}

export interface KubernetesSecretOperatorCRD {
  api_group: string;
  api_version: string;
  evidence_ref: string;
  kind: string;
  owns: string[];
  plural: string;
  status: string;
}

export interface KubernetesTrustBundleDistribution {
  api_group: string;
  api_version: string;
  architecture_controls: string[];
  capability: string;
  controller_flow: string[];
  distribution_targets: string[];
  evidence_refs: string[];
  generated_at: string;
  rbac_rules: KubernetesCSRSupportRule[];
  recommended_next_actions: string[];
  residuals: string[];
  resource: string;
  served: boolean;
  status_fields: string[];
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

export interface MDMSCEPChallengeRotated {
  policy: MDMSCEPPolicy;
}

export interface MDMSCEPPolicy {
  challenge_mode: string;
  created_at: string;
  enabled: boolean;
  expected_audience?: string;
  id: string;
  last_rotated_at?: string;
  name: string;
  profile_guidance: Record<string, unknown>;
  provider: string;
  rotation_version: number;
  scep_endpoint: string;
  scep_profile: string;
  tenant_id: string;
  trust_anchor_refs: Record<string, unknown>;
  updated_at: string;
}

export interface MDMSCEPPolicyList {
  items: MDMSCEPPolicy[];
}

export interface MDMSCEPPolicyRequest {
  challenge_mode?: "intune-jws" | "hmac-dynamic";
  enabled?: boolean;
  expected_audience?: string;
  name: string;
  profile_guidance?: Record<string, unknown>;
  provider: "intune" | "jamf";
  scep_endpoint: string;
  scep_profile: string;
  trust_anchor_refs?: Record<string, unknown>;
}

export interface MDMSCEPStatus {
  policies: MDMSCEPPolicy[];
  runtime_gate: string;
  runtime_note: string;
  telemetry: MDMSCEPTelemetry;
}

export interface MDMSCEPTelemetry {
  allowed: number;
  denied: number;
  last_event_timestamp?: string;
  last_failure_reason?: string;
  last_transaction_id?: string;
  replay_rejected: number;
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
  extractable?: boolean;
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

export interface ManagedOfferingStatus {
  deployment_model: string;
  event_type: string;
  idempotency_required: boolean;
  license_state: "community" | "active" | "grace" | "read_only";
  mutation_path: string;
  provider_plane_mode: "enabled" | "read_only" | "off";
  served: boolean;
  tenant_band?: number;
  tier: "community" | "enterprise" | "provider";
}

export interface ManagedTenant {
  created_at: string;
  data_residency?: string;
  deployment_model: string;
  event_sequence: number;
  managed: boolean;
  name: string;
  plan?: string;
  provider_tenant_id: string;
  provisioned_by?: string;
  region?: string;
  slo_tier?: string;
  support_tier?: string;
  tenant_id: string;
}

export interface ManagedTenantProvisionRequest {
  data_residency?: string;
  name: string;
  plan?: string;
  region?: string;
  slo_tier?: string;
  support_tier?: string;
  tenant_id: string;
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

export interface NHIComplianceControl {
  control_id: string;
  evidence_refs: string[];
  finding_count: number;
  framework: "nist-800-53" | "nist-csf-2.0" | "pci-dss-4.0" | "dora" | "iso-27001" | "fedramp" | "cmmc-2.0" | "eidas" | "nis2";
  posture_signals: string[];
  residual?: string;
  status: "evidenced" | "evidenced_with_operator_attestation";
  title: string;
}

export interface NHIComplianceFramework {
  evidence_sources: string[];
  id: "nist-800-53" | "nist-csf-2.0" | "pci-dss-4.0" | "dora" | "iso-27001" | "fedramp" | "cmmc-2.0" | "eidas" | "nis2";
  mapping_status: "served";
  name: string;
  version: string;
}

export interface NHIComplianceReport {
  audit_ready: boolean;
  capability: string;
  controls: NHIComplianceControl[];
  evidence_refs: string[];
  format: string;
  frameworks: NHIComplianceFramework[];
  generated_at: string;
  report_types: string[];
  residuals: string[];
  routes: string[];
  summary: NHIComplianceSummary;
}

export interface NHIComplianceSummary {
  audit_evidence_refs: number;
  controls_mapped: number;
  frameworks_supported: number;
  inventory_kinds: number;
  operator_attestation_needed: number;
  overprivileged_findings: number;
  stale_findings: number;
  static_credential_findings: number;
  total_nhis: number;
}

export interface NHIDecommissionItem {
  action: "revoked" | "retired" | "skipped" | "failed";
  error?: string;
  evidence_refs?: string[];
  from: string;
  identity_id: string;
  kind: string;
  name: string;
  owner_id: string;
  signal_type: "departure" | "vendor_term" | "inactivity";
  to: string;
}

export interface NHIDecommissionRequest {
  reason?: string;
  revocation_reason?: string;
  signals: NHIDecommissionSignal[];
}

export interface NHIDecommissionResponse {
  capability: string;
  coverage: string[];
  items: NHIDecommissionItem[];
  reason: string;
  summary: NHIDecommissionSummary;
}

export interface NHIDecommissionSignal {
  evidence_refs?: string[];
  identity_id?: string;
  inactive_before?: string;
  owner_id?: string;
  owner_name?: string;
  subject?: string;
  type: "departure" | "vendor_term" | "inactivity";
  vendor_name?: string;
}

export interface NHIDecommissionSummary {
  failed: number;
  retired: number;
  revoked: number;
  skipped: number;
  total_matched: number;
}

export interface NHIInventory {
  coverage: string[];
  generated_at: string;
  items: NHIInventoryItem[];
  summary: Record<string, unknown>;
}

export interface NHIInventoryItem {
  created_at: string;
  discovered_at?: string;
  display_name: string;
  fingerprint?: string;
  id: string;
  kind: string;
  metadata: Record<string, unknown>;
  not_after?: string;
  not_before?: string;
  owner_id?: string;
  provenance?: string;
  ref?: string;
  risk_score?: number;
  source: string;
  status: string;
  tenant_id: string;
}

export interface NHIOverPrivilegeFinding {
  display_name: string;
  evidence_refs: string[];
  finding_types: string[];
  granted_scopes: string[];
  inventory_id: string;
  kind: string;
  last_used_at?: string;
  owner_id?: string;
  recommendation: string;
  recommended_scopes: string[];
  ref?: string;
  risk_score: number;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  status: string;
  unused_ratio: number;
  unused_scopes: string[];
  used_scopes: string[];
}

export interface NHIOverPrivilegePosture {
  capability: string;
  coverage: string[];
  findings: NHIOverPrivilegeFinding[];
  generated_at: string;
  summary: NHIOverPrivilegeSummary;
}

export interface NHIOverPrivilegeSummary {
  critical: number;
  high: number;
  least_privilege_plans: number;
  low: number;
  medium: number;
  overprivileged: number;
  total_analyzed: number;
  unused_grants: number;
  wildcard_grants: number;
}

export interface NHIPolicyCompliance {
  capability: string;
  coverage: string[];
  evidence_refs: string[];
  findings: NHIPolicyComplianceFinding[];
  generated_at: string;
  recommended_actions: string[];
  summary: NHIPolicyComplianceSummary;
}

export interface NHIPolicyComplianceFinding {
  allowed_geos?: string[];
  allowed_scopes?: string[];
  business_purpose?: string;
  credential_age_days?: number;
  disallowed_geos?: string[];
  disallowed_scopes?: string[];
  display_name: string;
  evidence_refs: string[];
  expires_at?: string;
  granted_scopes?: string[];
  inventory_id: string;
  kind: string;
  last_rotated_at?: string;
  max_ttl_days?: number;
  observed_geos?: string[];
  owner_id?: string;
  policy_status: "compliant" | "violating";
  recommendation: string;
  remaining_ttl_days?: number;
  risk_score: number;
  rotation_cadence_days?: number;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  status: string;
  violation_types: string[];
}

export interface NHIPolicyComplianceSummary {
  business_purpose_missing: number;
  compliant: number;
  critical: number;
  expiry_violations: number;
  geo_violations: number;
  high: number;
  low: number;
  medium: number;
  rotation_violations: number;
  scope_violations: number;
  total_analyzed: number;
  violations: number;
}

export interface NHIReviewCampaign {
  certified_count: number;
  completed_at?: string;
  created_at: string;
  due_at?: string;
  exception_count: number;
  id: string;
  item_count: number;
  items?: NHIReviewItem[];
  name: string;
  pending_count: number;
  requested_by: string;
  reviewer_subject: string;
  revoked_count: number;
  scope: string;
  status: "open" | "completed";
  tenant_id: string;
  updated_at: string;
}

export interface NHIReviewCampaignList {
  items: NHIReviewCampaign[];
  next_cursor?: string;
}

export interface NHIReviewCampaignStartRequest {
  due_at?: string;
  id?: string;
  items: NHIReviewItemRequest[];
  name: string;
  reviewer_subject?: string;
  scope?: string;
}

export interface NHIReviewDecisionRequest {
  decision: "certified" | "revoked" | "exception";
  decision_evidence_refs?: string[];
  reason?: string;
  reviewer_subject?: string;
}

export interface NHIReviewItem {
  created_at: string;
  decided_at?: string;
  decision_by?: string;
  decision_evidence_refs?: string[];
  decision_reason?: string;
  display_name: string;
  entitlement: string;
  evidence_refs: string[];
  item_id: string;
  nhi_id: string;
  nhi_kind: string;
  owner_ref?: string;
  resource: string;
  risk: string;
  status: "pending" | "certified" | "revoked" | "exception";
  updated_at: string;
}

export interface NHIReviewItemRequest {
  display_name?: string;
  entitlement: string;
  evidence_refs?: string[];
  item_id?: string;
  nhi_id: string;
  nhi_kind: string;
  owner_ref?: string;
  resource: string;
  risk?: string;
}

export interface NHIShadowFinding {
  discovered_at: string;
  display_name: string;
  evidence_refs: string[];
  finding_id: string;
  fingerprint?: string;
  kind: string;
  managed_identity_id?: string;
  owner_status: "owned_metadata" | "ownerless";
  provenance: string;
  recommendation: string;
  ref: string;
  risk_score: number;
  run_id: string;
  severity: "critical" | "high" | "medium" | "low";
  source_id: string;
  surface?: string;
  system?: string;
  triage_status: "unmanaged" | "investigating";
}

export interface NHIShadowPosture {
  capability: string;
  coverage: string[];
  evidence_refs: string[];
  findings: NHIShadowFinding[];
  generated_at: string;
  recommended_actions: string[];
  summary: NHIShadowSummary;
}

export interface NHIShadowSummary {
  critical: number;
  findings: number;
  high: number;
  investigating: number;
  kind_counts: Record<string, unknown>;
  low: number;
  medium: number;
  ownerless: number;
  surface_counts: Record<string, unknown>;
  total_analyzed: number;
  unmanaged: number;
  unregistered: number;
}

export interface NHIStaleFinding {
  activity_age_days: number;
  created_age_days: number;
  created_at: string;
  display_name: string;
  evidence_refs: string[];
  finding_types: string[];
  inventory_id: string;
  kind: string;
  last_activity_at?: string;
  last_seen_at?: string;
  last_used_at?: string;
  owner_id?: string;
  owner_status: "owned" | "subject_bound" | "orphaned";
  recommendation: string;
  ref?: string;
  risk_score: number;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  status: string;
}

export interface NHIStalePosture {
  capability: string;
  coverage: string[];
  findings: NHIStaleFinding[];
  generated_at: string;
  summary: NHIStaleSummary;
  thresholds: NHIStaleThresholds;
}

export interface NHIStaleSummary {
  critical: number;
  dormant: number;
  findings: number;
  high: number;
  low: number;
  medium: number;
  orphaned: number;
  recommendations: number;
  stale: number;
  total_analyzed: number;
  unused: number;
}

export interface NHIStaleThresholds {
  dormant_activity_days: number;
  stale_activity_days: number;
  unused_no_activity_days: number;
}

export interface NHIStaticFinding {
  created_at: string;
  credential_age_days: number;
  display_name: string;
  evidence_refs: string[];
  expires_at?: string;
  finding_types: string[];
  inventory_id: string;
  kind: string;
  last_rotated_at?: string;
  owner_id?: string;
  owner_status: "owned" | "subject_bound" | "orphaned";
  recommendation: string;
  ref?: string;
  risk_score: number;
  rotation_age_days: number;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  status: string;
  ttl_days: number;
}

export interface NHIStaticPosture {
  capability: string;
  coverage: string[];
  findings: NHIStaticFinding[];
  generated_at: string;
  summary: NHIStaticSummary;
  thresholds: NHIStaticThresholds;
}

export interface NHIStaticSummary {
  critical: number;
  findings: number;
  high: number;
  long_lived: number;
  low: number;
  medium: number;
  no_expiry: number;
  recommendations: number;
  rotation_overdue: number;
  static_credentials: number;
  total_analyzed: number;
}

export interface NHIStaticThresholds {
  long_lived_credential_days: number;
  no_expiry_minimum_age_days: number;
  rotation_overdue_days: number;
}

export interface Notification {
  attempts: number;
  certificate_id?: string;
  created_at: string;
  delivered_at?: string;
  destination: string;
  detail?: string;
  escalation_recipients?: AlertRecipient[];
  id: string;
  idempotency_key?: string;
  kind?: string;
  last_error?: string;
  not_after?: string;
  owner_email?: string;
  owner_id?: string;
  owner_name?: string;
  read_at?: string;
  routing_policy_id?: string;
  serial?: string;
  severity?: "low" | "informational" | "warning" | "critical";
  status: "pending" | "sent" | "dead" | "read";
  subject?: string;
  tenant_id: string;
  threshold_days?: number;
}

export interface NotificationChannel {
  category: string;
  configured: boolean;
  delivery: string;
  description?: string;
  id: string;
  label: string;
}

export interface NotificationChannelList {
  items: NotificationChannel[];
  next_cursor?: string;
}

export interface NotificationChannelTest {
  channel_id: string;
  credential_ref?: string;
  destination: string;
  idempotency_key: string;
  outbox_id: number;
  queued_at: string;
  secret_handling: string;
  status: "queued";
}

export interface NotificationChannelTestRequest {
  credential_ref?: string;
  detail?: string;
  owner_email?: string;
  routing_policy_id?: string;
  severity?: "low" | "informational" | "warning" | "critical";
  subject?: string;
}

export interface NotificationDigestPreview {
  interval_seconds: number;
  next_run_at: string;
  timezone: string;
}

export interface NotificationList {
  items: Notification[];
  next_cursor?: string;
}

export interface NotificationRoutingPolicy {
  channels_by_severity: Record<string, unknown>;
  created_at: string;
  default_channels: string[];
  digest_interval_seconds: number;
  digest_preview: NotificationDigestPreview;
  digest_timezone: string;
  id: string;
  name: string;
  owner_email?: string;
  owner_ref?: string;
  tenant_id: string;
  updated_at: string;
}

export interface NotificationRoutingPolicyList {
  items: NotificationRoutingPolicy[];
  next_cursor?: string;
}

export interface NotificationRoutingPolicyRequest {
  channels_by_severity?: Record<string, unknown>;
  default_channels?: string[];
  digest_interval_seconds?: number;
  digest_timezone?: string;
  id?: string;
  name: string;
  owner_email?: string;
  owner_ref?: string;
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

export interface OwnershipAttribution {
  coverage: string[];
  generated_at: string;
  items: OwnershipAttributionItem[];
  summary: Record<string, unknown>;
}

export interface OwnershipAttributionItem {
  attribution_evidence: string[];
  attribution_source: string;
  attribution_status: "attributed" | "orphaned";
  created_at: string;
  discovered_at?: string;
  display_name: string;
  id: string;
  kind: string;
  owner?: OwnershipAttributionOwner;
  ref?: string;
  source: string;
  tenant_id: string;
}

export interface OwnershipAttributionOwner {
  email?: string;
  id: string;
  kind: "user" | "team" | "workload" | "service" | "vendor";
  name: string;
  tenant_id: string;
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

export interface PolicyDryRun {
  allow: boolean;
  audit_event: string;
  deny: boolean;
  error?: string;
  idempotency_key: string;
  input_summary: PolicyDryRunInputSummary;
  kind: "lifecycle" | "abac";
  module_sha256: string;
  package: string;
  query: string;
  reason?: string;
  trace: PolicyDryRunTrace[];
  valid: boolean;
}

export interface PolicyDryRunInputSummary {
  action?: string;
  actor?: string;
  permission?: string;
  profile?: string;
  subject?: string;
  tenant_id: string;
}

export interface PolicyDryRunRequest {
  input?: Record<string, unknown>;
  kind?: "lifecycle" | "abac";
  module?: string;
  trace_limit?: number;
}

export interface PolicyDryRunTrace {
  location?: string;
  message?: string;
  node?: string;
  op: string;
  parent_id?: number;
  query_id: number;
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

export interface RegionalFailoverStep {
  action: string;
  gate: string;
  id: string;
  trigger: string;
}

export interface RegionalIssuanceLane {
  accepted_traffic: string;
  backpressure_signal: string;
  event_append: string;
  id: string;
  mutation_fence: string;
  outbox_mode: string;
  recovery: string;
  region: string;
  signer_mode: string;
}

export interface RemediationPlaybook {
  action: string;
  capability: string;
  evidence_sources: string[];
  external_effect: string;
  id: string;
  name: string;
  required_inputs: string[];
  status: string;
  summary: string;
}

export interface RemediationPlaybookCatalog {
  capability: string;
  generated_at: string;
  items: RemediationPlaybook[];
  status: string;
}

export interface RemediationPlaybookRun {
  action: string;
  connector?: string;
  connector_delivery?: ConnectorDelivery;
  connector_delivery_id?: string;
  created_at: string;
  created_by?: string;
  evidence_refs: string[];
  id: string;
  idempotency_key?: string;
  inventory_id?: string;
  outbox_id?: number;
  phase: string;
  playbook_id: string;
  reason?: string;
  rollback_refs: string[];
  scope_delta: Record<string, unknown>;
  status: string;
  target?: string;
  target_identity_id?: string;
  tenant_id: string;
  updated_at: string;
}

export interface RemediationPlaybookRunList {
  items: RemediationPlaybookRun[];
  next_cursor?: string;
}

export interface RemediationPlaybookRunRequest {
  connector?: string;
  inventory_id?: string;
  reason?: string;
  recommended_scopes?: string[];
  remove_scopes?: string[];
  replacement_name?: string;
  rollback_ref?: string;
  target?: string;
  target_identity_id?: string;
}

export interface ResponseIntegrationDestinationRequest {
  allow_private_endpoint?: boolean;
  channel?: string;
  endpoint_url?: string;
  id?: string;
  instance_url?: string;
  issue_type?: string;
  project_key?: string;
  provider: "splunk" | "jira" | "slack" | "servicenow";
  table?: "incident" | "change_request" | "sc_task";
  token_ref?: string;
}

export interface ResponseIntegrationDispatch {
  created_at: string;
  destinations: ResponseIntegrationQueuedDestination[];
  id: string;
  idempotency_key: string;
  status: string;
  tenant_id: string;
}

export interface ResponseIntegrationDispatchRequest {
  correlation_id?: string;
  destinations: ResponseIntegrationDestinationRequest[];
  evidence_refs?: string[];
  incident_id?: string;
  remediation_run_id?: string;
  severity?: "low" | "informational" | "warning" | "critical";
  summary?: string;
  title: string;
}

export interface ResponseIntegrationQueuedDestination {
  destination: string;
  id: string;
  idempotency_key: string;
  outbox_id: number;
  provider: string;
  status: string;
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

export interface SSHAttestedUserCert {
  approver: string;
  attestation: Attestation;
  certificate: string;
  force_command?: string;
  key_id: string;
  principals: string[];
  serial: number;
  source_addresses?: string[];
  subject: string;
  valid_before: string;
}

export interface SSHAttestedUserCertRequest {
  approver: string;
  force_command?: string;
  key_id?: string;
  method: "aws_iid" | "azure_imds" | "gcp_iit" | "github_oidc" | "k8s_sat" | "tpm";
  payload_base64: string;
  principals?: string[];
  public_key: string;
  source_addresses?: string[];
  ttl_seconds?: number;
}

export interface SSHHostRetireRequest {
  host: string;
  identity_id?: string;
  reason?: string;
  run_id?: string;
  source_id?: string;
}

export interface SSHHostRetirement {
  host: string;
  id: string;
  identity_id?: string;
  reason?: string;
  recorded_at: string;
  run_id?: string;
  source_id?: string;
  status: "retired";
  tenant_id: string;
}

export interface SSHRevokeCertificateRequest {
  key_id?: string;
  reason?: string;
  serial?: number;
}

export interface SSHStatus {
  attestors?: string[];
  authority_key?: string;
  krl_version: number;
  revoked_count: number;
  served: boolean;
  tenant_id: string;
}

export interface SSHTrustRollout {
  candidate_ca_fingerprint?: string;
  confirmed: boolean;
  health_command?: string;
  id: string;
  recorded_at: string;
  reload_command?: string;
  rollback_plan?: string;
  source_id?: string;
  status: "planned" | "validating" | "health_passed" | "rolled_back" | "failed";
  target_hosts: string[];
  tenant_id: string;
}

export interface SSHTrustRolloutRequest {
  candidate_ca_fingerprint?: string;
  confirmed: boolean;
  health_command?: string;
  reload_command?: string;
  rollback_plan?: string;
  source_id?: string;
  status: "planned" | "validating" | "health_passed" | "rolled_back" | "failed";
  target_hosts: string[];
}

export interface ScaleBackpressureRule {
  applies_to: string;
  id: string;
  limit: string;
  reject_mode: string;
  signal: string;
}

export interface ScaleBand {
  capacity_tier: string;
  id: string;
  managed_credential: string;
  topology: string;
}

export interface ScaleCapacityTier {
  control_plane_cpu: string;
  control_plane_memory_gib: number;
  estimated_cost_per_credential_usd: number;
  estimated_monthly_cost_usd: number;
  events_per_day: number;
  id: string;
  jetstream_gib_30_day: number;
  managed_credentials: number;
  name: string;
  notes: string;
  postgres_gib_30_day: number;
  signer_cpu: string;
  signer_memory_gib: number;
  tenants: number;
}

export interface ScaleDatastorePosture {
  jetstream: string;
  outbox: string;
  postgres: string;
  rls: string;
}

export interface ScaleExecutionLane {
  architecture_invariant: string;
  backpressure_signal: string;
  bulkhead_env: string[];
  external_side_effect: string;
  failure_mode: string;
  hot_path_slo: string;
  id: string;
  measurement: string;
  operator_control: string;
  queue: string;
  replay_source: string;
  scale_trigger: string;
  subsystem: string;
  worker_pool: string;
}

export interface ScaleHotPathSLO {
  benchmark: string;
  capacity_ref: string;
  error_budget_percent: number;
  hot_path: string;
  id: string;
  max_projection_lag_events: number;
  max_queue_saturation: number;
  min_throughput_per_second: number;
  owner: string;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  surface: string;
}

export interface ScaleOrchestrationPlan {
  backpressure_policy: ScaleBackpressureRule[];
  capability: string;
  datastore: ScaleDatastorePosture;
  estimated_daily_event_load: number;
  estimated_monthly_cost_usd: number;
  evidence_refs: string[];
  execution_lanes: ScaleExecutionLane[];
  generated_at: string;
  hot_path_slos: ScaleHotPathSLO[];
  measurement_artifacts: string[];
  operator_actions: string[];
  projection_replay: ScaleProjectionPosture;
  release_gates: ScaleReleaseGate[];
  residuals: string[];
  selected_capacity_tier: ScaleCapacityTier;
  served: boolean;
  shard_plan: ScaleShardPlan[];
  signer: ScaleSignerPosture;
  target_credential_bands: ScaleBand[];
  tenant_isolation: ScaleTenantIsolation;
  unit_economics: ScaleUnitEconomics;
}

export interface ScaleProjectionPosture {
  max_lag_events: number;
  rebuild_source: string;
  replay_floor_events_per_second: number;
}

export interface ScaleReleaseGate {
  artifact: string;
  command: string;
  id: string;
  required: boolean;
}

export interface ScaleShardPlan {
  applies_to: string;
  id: string;
  max_shard_count: number;
  partition_key: string;
  publication_surface: string;
  target_shard_size: number;
}

export interface ScaleSignerPosture {
  process_model: string;
  scaling: string;
  transport: string;
}

export interface ScaleTenantIsolation {
  evidence_refs: string[];
  query_rule: string;
  storage_enforcement: string;
}

export interface ScaleUnitEconomics {
  estimated_cost_per_credential_usd: number;
  events_per_day: number;
  jetstream_gib_30_day: number;
  postgres_gib_30_day: number;
}

export interface SecretApproval {
  action: "rotate" | "recover" | "delete";
  approvals: number;
  approver: string;
  resource: string;
}

export interface SecretApprovalRequest {
  action: "rotate" | "recover" | "delete";
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

export interface SecretRepositoryScanGate {
  artifact: string;
  command: string;
  id: string;
  required: boolean;
}

export interface SecretRepositoryScanPosture {
  architecture_controls: string[];
  capability: string;
  event_flow: string[];
  evidence_refs: string[];
  generated_at: string;
  minimum_rules_active: number;
  operator_actions: string[];
  providers: SecretRepositoryScanProvider[];
  queue_model: string;
  redaction_model: string;
  release_gates: SecretRepositoryScanGate[];
  residuals: string[];
  scanner: string;
  served: boolean;
  webhook_paths: string[];
}

export interface SecretRepositoryScanProvider {
  auth_mode: string;
  id: string;
  ingest_mode: string;
  name: string;
  outbox_mode: string;
  realtime_triggers: string[];
  ref_types: string[];
  secret_handling: string;
}

export interface SecretRepositoryWebhookReceipt {
  capability: string;
  discovery_run_path: string;
  outbox_destination: string;
  provider: string;
  queued: boolean;
  repository: string;
  run_id: string;
  scanner: string;
  source_id: string;
  status: string;
}

export interface SecretRepositoryWebhookRequest {
  checkout_path?: string;
  clone_url?: string;
  commit_sha?: string;
  credential_ref?: string;
  event?: string;
  ref?: string;
  repository: string;
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
  capabilities: string[];
  custom_rules: boolean;
  engine_version: string;
  findings: SecretScanFinding[];
  findings_count: number;
  mode: string;
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
  custom_rules_path?: string;
  mode?: string;
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

export interface SecretSyncTarget {
  auth_mode: string;
  capabilities: string[];
  configured: boolean;
  delivery_mode: string;
  id: string;
  name: string;
  platform: string;
  secret_handling: string;
  wire_format: string;
}

export interface SecretSyncTargetCatalog {
  capability: string;
  configured_targets: string[];
  evidence_refs: string[];
  generated_at: string;
  outbox_mode: string;
  residuals: string[];
  served: boolean;
  targets: SecretSyncTarget[];
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

export interface TenantWriteFence {
  conflict_outcome: string;
  evidence: string;
  id: string;
  mechanism: string;
  scope: string;
}

export interface ThirdPartySecretScanIngestRequest {
  artifact_kind?: string;
  artifact_path: string;
  credential_ref?: string;
  event?: string;
  source: string;
}

export interface ThirdPartySecretScanPosture {
  architecture_controls: string[];
  capability: string;
  event_flow: string[];
  evidence_refs: string[];
  generated_at: string;
  ingest_paths: string[];
  minimum_rules_active: number;
  operator_actions: string[];
  providers: ThirdPartySecretScanProvider[];
  queue_model: string;
  redaction_model: string;
  release_gates: SecretRepositoryScanGate[];
  residuals: string[];
  scanner: string;
  served: boolean;
}

export interface ThirdPartySecretScanProvider {
  artifact_kinds: string[];
  id: string;
  ingest_mode: string;
  name: string;
  outbox_mode: string;
  secret_handling: string;
}

export interface ThirdPartySecretScanReceipt {
  capability: string;
  discovery_run_path: string;
  outbox_destination: string;
  provider: string;
  queued: boolean;
  run_id: string;
  scanner: string;
  source: string;
  source_id: string;
  status: string;
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
