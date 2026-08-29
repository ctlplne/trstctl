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
export interface ACMEARICertificatePosture {
  ari_certificate_id?: string;
  certificate_id: string;
  certificate_status: "active" | "superseded" | "revoked";
  consumed_at?: string;
  identity_id?: string;
  identity_name?: string;
  publication_status: "published" | "not_published" | "identifier_unavailable";
  rotation_run_id?: string;
  scheduler_consumed: boolean;
  scheduler_source: "ari" | "fixed_threshold" | "manual" | "none" | "unknown_scheduler";
  scheduler_status: "pending" | "running" | "succeeded" | "failed" | "not_applicable";
  suggested_window?: ACMEARIWindow;
}

export interface ACMEARIPosture {
  generated_at: string;
  items: ACMEARICertificatePosture[];
  next_cursor?: string;
  publication_endpoint: string;
  publication_status: "served" | "not_served";
  scheduler_status: "enabled" | "disabled";
  served: boolean;
  summary: ACMEARIPostureSummary;
}

export interface ACMEARIPostureSummary {
  affected_certificates: number;
  published: number;
  scheduler_consumed: number;
  scheduler_failed: number;
  scheduler_pending: number;
}

export interface ACMEARIWindow {
  end: string;
  start: string;
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
  admission_state?: string;
  capabilities: string[];
  conformance: string;
  credential_reference_fields: string[];
  display_name: string;
  kind: string;
  name: string;
  notes?: string;
  propagation_preflight: boolean;
  provenance?: string;
  provider_package: string;
  secret_fields: string[];
  served: boolean;
}

export interface ACMEDNS01ProviderConfig {
  allow_upstream_dv?: boolean;
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
  allow_upstream_dv?: boolean;
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

export interface ACMEDeviceAttestationPolicy {
  allowed_algorithms?: number[];
  allowed_identifiers?: string[];
  attestation_roots_pem?: string[];
  enabled?: boolean;
  format?: "tpm";
  max_age?: string;
}

export interface ACMEEABCredential {
  accounts_bound: number;
  allowed_identifiers?: string[];
  disabled_by_operator: boolean;
  disabled_in_config: boolean;
  key_id: string;
  last_used_at?: string;
  max_orders?: number;
  not_after?: string;
  orders_created: number;
  orders_denied: number;
  reason?: string;
  state: "active" | "disabled" | "expired" | "exhausted";
}

export interface ACMEEABPosture {
  generated_at: string;
  items: ACMEEABCredential[];
  required: boolean;
  served: boolean;
}

export interface ACMEOperatorAction {
  detail: string;
  kind: "activate_eval_profile" | "connect_acme_client" | "repair_prerequisites" | "repair_startup_configuration";
  label: string;
  method?: string;
  path?: string;
}

export interface ACMEOperatorPlan {
  activation_available: boolean;
  activation_mode: "startup_configuration" | "eval_profile_event";
  activation_required: boolean;
  blockers: string[];
  challenge_methods: ("http-01" | "dns-01" | "tls-alpn-01")[];
  directory_path: "/directory";
  dns01_provider_configs: number;
  eab_active: number;
  eab_configured: number;
  eab_required: boolean;
  generated_at: string;
  issuing_profile: string;
  issuing_profile_ready: boolean;
  next_action: ACMEOperatorAction;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  served: boolean;
  tenant_bound: boolean;
  warnings: string[];
}

export interface ACMEUpstreamAuthorization {
  challenge_type?: string;
  expires_at?: string;
  identifier: string;
  issuer: string;
  last_reused_at?: string;
  last_validated_at?: string;
  never_validated: boolean;
  reuse_count: number;
  validate_count: number;
}

export interface ACMEUpstreamAuthorizationList {
  guidance: string;
  items: ACMEUpstreamAuthorization[];
  never_validated_count: number;
}

export interface ADCSAgentRestrictions {
  source: string;
  state: "enabled" | "disabled" | "unobserved";
}

export interface ADCSAuditReference {
  digest: string;
  event_id: string;
  event_type: string;
  observed_at: string;
  sequence: number;
}

export interface ADCSComplianceDrift {
  agent_id: string;
  changes: ADCSTemplateDriftChange[];
  direction: "worse" | "better" | "neutral";
  domain: string;
  lifecycle: ADCSTemplateLifecycleChange[];
  observed_by: string;
  reference: ADCSAuditReference;
  run_id: string;
  source_id: string;
  worsened: boolean;
}

export interface ADCSComplianceEvidence {
  drift: ADCSComplianceDrift[];
  observations: ADCSComplianceObservation[];
}

export interface ADCSComplianceObservation {
  agent_id: string;
  agent_name: string;
  directory_verified: boolean;
  domain: string;
  findings: ADCSRuleFinding[];
  inventory: ADCSObservedInventory;
  reference: ADCSAuditReference;
  run_id: string;
  source_id: string;
}

export interface ADCSDatabaseIngest {
  ca_config: string;
  last_error?: string;
  rows: Record<string, unknown>[];
  source?: string;
}

export interface ADCSDatabaseList {
  guidance: string;
  items: ADCSDatabaseSummary[];
}

export interface ADCSDatabaseSummary {
  ca_config: string;
  denied: number;
  failed: number;
  ingested_at?: string;
  issued: number;
  last_error?: string;
  pending: number;
  revoked: number;
  rows_read: number;
  rows_rejected: number;
  source?: string;
  total: number;
  unknown: number;
  unparsed: number;
}

export interface ADCSDriftHistory {
  items: ADCSTemplateDrift[];
}

export interface ADCSEnrollmentEndpoint {
  authentication: string[];
  extended_protection: "enabled" | "disabled" | "unobserved";
  http_status?: number;
  kind: "web_enrollment" | "ndes" | "ndes_admin";
  state: "anonymous_access" | "authentication_required" | "redirected" | "not_found" | "unreachable" | "reachable_other";
  tls_verified: boolean;
  url: string;
}

export interface ADCSEnrollmentService {
  agent_restriction_source: string;
  agent_restriction_state: "enabled" | "disabled" | "unobserved";
  dns_name?: string;
  domain: string;
  endpoints: ADCSEnrollmentEndpoint[];
  enrollment_web_services: string[];
  findings: ADCSTemplateFinding[];
  observed_at: string;
  observed_by: string;
  service: string;
  worst_severity: "" | "medium" | "high" | "critical";
}

export interface ADCSFindingEvidence {
  attribute: string;
  observed: string;
}

export interface ADCSInventorySource {
  last_run_completed_at?: string;
  last_run_created_at?: string;
  last_run_error?: string;
  last_run_id?: string;
  last_run_status: "pending" | "running" | "succeeded" | "failed";
  monitoring_interval_seconds?: number;
  name: string;
  schedule_enabled: boolean;
  schedule_id?: string;
  source_id: string;
}

export interface ADCSObservedInventory {
  enrollment_services: ADCSObservedService[];
  templates: ADCSObservedTemplate[];
}

export interface ADCSObservedService {
  agent_restrictions: ADCSAgentRestrictions;
  dns_name?: string;
  endpoints?: ADCSEnrollmentEndpoint[];
  enrollment_web_services?: string[];
  name: string;
  templates?: string[];
}

export interface ADCSObservedTemplate {
  display_name?: string;
  ekus?: string[];
  enrollee_supplies_san: boolean;
  enrollee_supplies_subject: boolean;
  enrollment_principals?: string[];
  exportable_key: boolean;
  name: string;
  oid?: string;
  published_by?: string[];
  requires_manager_approval: boolean;
  schema_version?: number;
}

export interface ADCSPosture {
  critical: number;
  enrollment_services: ADCSEnrollmentService[];
  guidance: string;
  high: number;
  medium: number;
  observed: boolean;
  sources?: ADCSInventorySource[];
  templates: ADCSTemplate[];
}

export interface ADCSRuleFinding {
  evidence?: ADCSFindingEvidence[];
  id: string;
  published: boolean;
  remediation: string;
  resource: string;
  resource_kind: "template" | "enrollment_service";
  severity: "medium" | "high" | "critical";
  summary: string;
  template: string;
}

export interface ADCSTemplate {
  display_name?: string;
  domain: string;
  enrollment_principals?: string[];
  findings: ADCSTemplateFinding[];
  observed_at: string;
  observed_by?: string;
  published_by: string[];
  schema_version?: number;
  template: string;
  worst_severity: "" | "medium" | "high" | "critical";
}

export interface ADCSTemplateDrift {
  agent_id: string;
  changes: ADCSTemplateDriftChange[];
  direction: "worse" | "better" | "neutral";
  domain: string;
  id: string;
  lifecycle: ADCSTemplateLifecycleChange[];
  observed_at: string;
  observed_by: string;
  run_id: string;
  source_id: string;
  worsened: boolean;
}

export interface ADCSTemplateDriftChange {
  after?: string;
  attribute?: string;
  before?: string;
  change: string;
  direction: "worse" | "better" | "neutral";
  template: string;
}

export interface ADCSTemplateFinding {
  evidence?: ADCSFindingEvidence[];
  id: string;
  published?: boolean;
  remediation: string;
  severity: "medium" | "high" | "critical";
  summary: string;
}

export interface ADCSTemplateLifecycleChange {
  lifecycle: "added" | "removed";
  now_dangerous?: boolean;
  template: string;
  was_dangerous?: boolean;
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
  pii_egress: string;
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
  enrollment_proxy: AgentEnrollmentProxyStatus;
  id: string;
  inventory_report_path: string;
  last_seen_at?: string;
  name: string;
  offboard_reason?: string;
  offboarded_at?: string;
  offboarded_by?: string;
  presence: AgentPresence;
  relay_capabilities: AgentRelayCapability[];
  role_source: "certificate" | "unreported";
  roles: ("host" | "network")[];
  status: string;
  version?: string;
  workload_api: AgentWorkloadAPIStatus;
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
  enable_flags?: string[];
  label: string;
  metadata_only: boolean;
  private_key_bytes: boolean;
  reported_over: string;
  source_kind: string;
}

export interface AgentEnrollmentProxyStatus {
  detail: string;
  forwarded_requests: number;
  healthy_upstreams: number;
  last_failover_at?: string;
  last_forwarded_at?: string;
  public_url?: string;
  refused_requests: number;
  reported_at?: string;
  segment?: string;
  state: "serving" | "degraded" | "unavailable" | "unverified" | "not_serving" | "unreported";
  unhealthy_upstreams: number;
  unknown_upstreams: number;
  upstream_failures: number;
}

export interface AgentJobPosture {
  claimable_kinds: string[];
  generated_at: string;
  queues: AgentJobQueue[];
  receipts: AgentJobReceipts;
  redemptions: AgentJobRedemptions;
  served: boolean;
}

export interface AgentJobQueue {
  claimed: number;
  enabled: boolean;
  kind: string;
  oldest_unclaimed_seconds?: number;
  pending: number;
}

export interface AgentJobReceipts {
  last_rejected_at?: string;
  last_rejected_reason?: string;
  rejected: number;
  verified: number;
}

export interface AgentJobRedemptions {
  live: number;
  oldest_live_seconds?: number;
  total: number;
}

export interface AgentList {
  agents: Agent[];
  next_cursor?: string;
}

export interface AgentOffboardRequest {
  reason?: string;
}

export interface AgentOffboardResponse {
  agent: Agent;
  revocation_evidence: string;
}

export interface AgentPresence {
  detail: string;
  evaluated_at: string;
  fresh_until?: string;
  online: boolean;
  state: "online" | "stale" | "unreported" | "offboarded" | "clock_skew";
}

export interface AgentRelayCapability {
  connectors: string[];
  enable_flags?: string[];
  kind: string;
}

export interface AgentRingInput {
  agent_id: string;
  ring?: "canary" | "early" | "broad" | "";
}

export interface AgentUpgradeCampaign {
  active: boolean;
  current_ring?: string;
  dispatch_round?: number;
  dispatched_ring?: string;
  guidance: string;
  halted_at_ring?: string;
  id?: string;
  observe_only?: boolean;
  reason?: string;
  rings: Record<string, unknown>;
  status?: "pending" | "running" | "halted" | "paused" | "complete";
  target_version?: string;
  versions: Record<string, unknown>;
}

export interface AgentUpgradeCampaignInput {
  artifacts?: UpgradeArtifact[];
  target_version: string;
}

export interface AgentWorkloadAPIStatus {
  detail: string;
  reported_at?: string;
  state: "serving" | "not_serving" | "unreported";
  svids_issued: number;
}

export interface AlertRecipient {
  display_name?: string;
  email?: string;
  kind: string;
  roles?: string[];
  subject: string;
}

export interface Approval {
  action: "issue" | "rotate" | "revoke" | "sign";
  approval_count: number;
  approvals: number;
  approver: string;
  id: string;
  intent_digest: string;
  required_approvals: number;
  resource: string;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
}

export interface ApprovalDecision {
  action: "issue" | "create" | "rotate" | "revoke" | "sign" | "recover" | "delete" | "managedkey:rotate" | "managedkey:revoke" | "managedkey:zeroize";
  approval_count: number;
  approvals: number;
  approver: string;
  id: string;
  intent_digest: string;
  required_approvals: number;
  resource: string;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
}

export interface ApprovalDecisionInput {
  intent_digest: string;
}

export interface ApprovalDenialInput {
  intent_digest: string;
  reason: string;
}

export interface ApprovalRequest {
  action: "issue" | "rotate" | "revoke" | "sign";
  intent_digest: string;
  request_id: string;
}

export interface ApprovalRequestList {
  items: PendingApprovalRequest[];
  next_cursor?: string;
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

export interface AuditAnchor {
  anchored_at: string;
  chain_head: string;
  detail?: string;
  kind: "" | "rfc3161";
  token?: AuditTimestampToken;
}

export interface AuditBundle {
  anchor: AuditAnchor;
  bundle: string;
  chain_head: string;
  format: "jws";
  schema_version: number;
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

export interface AuditFeed {
  allow_private_endpoint: boolean;
  attempts: number;
  batch_size: number;
  collector_request_id?: string;
  enabled: boolean;
  endpoint_url: string;
  id: string;
  interval_seconds: number;
  lag_records: number;
  last_attempt_at?: string;
  last_batch_id?: string;
  last_batch_record_count: number;
  last_batch_start_sequence: number;
  last_delivered_at?: string;
  last_delivered_sequence: number;
  last_error_code?: string;
  last_queued_sequence: number;
  name: string;
  next_attempt_at?: string;
  next_run_at: string;
  private_egress_cidrs: string[];
  provider: "splunk-hec" | "sentinel";
  status: "not_started" | "queued" | "delivering" | "retrying" | "delivered" | "failed";
  tenant_id: string;
  token_ref: string;
  updated_at: string;
}

export interface AuditFeedList {
  count?: number;
  items: AuditFeed[];
}

export interface AuditFeedPreview {
  capability: string;
  current_updated_at?: string;
  effect_free: boolean;
  endpoint_host: string;
  execution_external_effects: string[];
  execution_writes: string[];
  existing_configuration: boolean;
  feed_id: string;
  guidance: string;
  normalized_request: AuditFeedRequest;
  prerequisites: string[];
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  verification_steps: string[];
  warnings: string[];
}

export interface AuditFeedRequest {
  allow_private_endpoint?: boolean;
  batch_size: number;
  enabled: boolean;
  endpoint_url: string;
  interval_seconds: number;
  name: string;
  private_egress_cidrs?: string[];
  provider: "splunk-hec" | "sentinel";
  token_ref: string;
}

export interface AuditTimestampInfo {
  gen_time: string;
  hash_algorithm: string;
  hashed_message: string;
  policy: string;
  serial_number: number;
  version: number;
}

export interface AuditTimestampToken {
  der: string;
  info: AuditTimestampInfo;
  signature: string;
  tsa_cert: string;
}

export interface AuditVerificationKeySet {
  keys: { e: string; kid: string; kty: string; n: string }[];
}

export interface Brand {
  custom: boolean;
  login_message?: string;
  logo_data_uri?: string;
  product_name: string;
  token_overrides?: Record<string, unknown>;
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

export interface BreakglassCeremony {
  approvals: number;
  created_at: string;
  id: string;
  opener?: string;
  purpose: string;
  status: string;
  tenant_id: string;
  threshold: number;
}

export interface BreakglassCrossSign {
  ceremony_id: string;
  certificate_pem: string;
  issuer_signer_handle: string;
  target_sha256: string;
}

export interface BreakglassCrossSignRequest {
  ceremony_id?: string;
  certificate_pem: string;
}

export interface BreakglassIssueExecutionRequest {
  ceremony_id: string;
  csr_der: string;
  reason: string;
  request_id: string;
  subject: string;
  ttl_seconds?: number;
}

export interface BreakglassIssueIntentRequest {
  csr_der: string;
  reason: string;
  request_id: string;
  subject: string;
  ttl_seconds?: number;
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

export interface BreakglassRotation {
  active_certificate_pem: string;
  active_signer_handle: string;
  ceremony_id: string;
  new_signed_by_previous_pem: string;
  previous_certificate_pem: string;
  previous_signed_by_new_pem: string;
  previous_signer_handle: string;
  request_digest: string;
}

export interface BreakglassRotationIntent {
  reason: string;
  ttl_seconds: number;
}

export interface BreakglassRotationRequest {
  ceremony_id: string;
  reason: string;
  ttl_seconds: number;
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
  task_envelope_digest?: string;
}

export interface BrokerAgentIdentityRequest {
  agent_id: string;
  method: string;
  payload_base64: string;
  public_key_pem: string;
  scopes: string[];
  task_envelope_base64?: string;
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
  status?: "requested" | "issued" | "deployed" | "renewing" | "renewal_failed" | "revoked" | "retired";
}

export interface BulkRevokeResult {
  items: BulkRevokeItem[];
  total_failed: number;
  total_matched: number;
  total_revoked: number;
  total_skipped: number;
}

export interface BulkheadPool {
  capacity: number;
  completed: number;
  name: string;
  panicked: number;
  queued: number;
  rejected: number;
  saturation_percent: number;
  submitted: number;
  workers: number;
}

export interface BulkheadStats {
  pools: BulkheadPool[];
  served: boolean;
}

export interface CAAuthority {
  certificate_pem: string;
  common_name: string;
  created_at: string;
  extended_key_usages?: string[];
  horizon?: CAAuthorityHorizon;
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

export interface CAAuthorityHorizon {
  band_months?: number;
  expired: boolean;
  leaf_validity_days: number;
  months_remaining: number;
  renew_by?: string;
  severity: "low" | "informational" | "warning" | "critical";
  validity_compressed: boolean;
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

export interface CAAuthorityRotationPlanPreview {
  capability: "F48";
  changes: string[];
  operation: "rotate_ca";
  predecessor: CACeremonyPlanAuthority;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  reason: string;
  request_fingerprint: string;
  required_permission: "issuers:write";
  risks: string[];
  successor: CACeremonyPlanAuthority;
  verification_steps: string[];
}

export interface CAAuthorityRotationRequest {
  reason?: string;
  successor_id: string;
}

export interface CACeremonyPlanAuthority {
  common_name: string;
  id: string;
  kind: string;
  status: string;
}

export interface CACeremonyPlanPreview {
  approval_threshold: number;
  authority?: CACeremonyPlanAuthority;
  capability: "F48";
  changes: string[];
  normalized_spec: CASpec;
  operation: "create_root" | "import_offline_root" | "import_existing_ca" | "create_intermediate" | "create_offline_intermediate" | "issue_intermediate_csr" | "rekey_ca" | "cross_sign_ca" | "import_offline_cross_sign" | "rekey_offline_root";
  parent?: CACeremonyPlanAuthority;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  request_fingerprint: string;
  required_permission: string;
  risks: string[];
  sensitive_inputs: string[];
  verification_steps: string[];
}

export interface CACeremonyStartRequest {
  authority_id?: string;
  certificate_pem?: string;
  cross_certificate_pem?: string;
  csr_pem?: string;
  operation: "create_root" | "import_offline_root" | "import_existing_ca" | "create_intermediate" | "create_offline_intermediate" | "issue_intermediate_csr" | "rekey_ca" | "cross_sign_ca" | "import_offline_cross_sign" | "rekey_offline_root";
  parent_id?: string;
  reason?: string;
  reverse_cross_certificate_pem?: string;
  signer_handle?: string;
  spec: CASpec;
  target_certificate_pem?: string;
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

export interface CACrossSign {
  ceremony_id: string;
  certificate_pem: string;
  imported: boolean;
  issuer_authority_id: string;
  target_sha256: string;
}

export interface CACrossSignRequest {
  ceremony_id: string;
  certificate_pem: string;
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

export interface CAOfflineCrossSignImportRequest {
  ceremony_id: string;
  cross_certificate_pem: string;
  target_certificate_pem: string;
}

export interface CAOfflineRootRekey {
  ceremony_id: string;
  new_signed_by_previous_pem: string;
  previous_signed_by_new_pem: string;
  rotation: CAAuthorityRotation;
}

export interface CAOfflineRootRekeyRequest {
  ceremony_id: string;
  new_signed_by_previous_pem: string;
  previous_signed_by_new_pem: string;
  reason: string;
  spec: CASpec;
  successor_certificate_pem: string;
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

export interface CMDBReconcileSchedule {
  allow_private_endpoint?: boolean;
  changed_count: number;
  ci_query?: string;
  configured: boolean;
  coverage_complete: boolean;
  coverage_status: "not_configured" | "paused" | "not_started" | "in_progress" | "failed" | "complete";
  enabled: boolean;
  execution?: "relay" | "";
  expected_count?: number;
  guidance: string;
  instance_url?: string;
  interval_seconds?: number;
  last_attempt_at?: string;
  last_error?: string;
  last_run_at?: string;
  next_cursor?: string;
  pages_completed: number;
  read_count: number;
  removed_count: number;
  sweep_id?: string;
  sweep_started_at?: string;
  token_ref?: string;
}

export interface CMPQualification {
  binding_mode: "subject-bound" | "registration-authority";
  blockers: string[];
  checked_at: string;
  checks: CMPQualificationCheck[];
  client_trust_anchor_count: number;
  effect_free: boolean;
  endpoint: string;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  profile: string;
  proof: string[];
  ready: boolean;
}

export interface CMPQualificationCheck {
  detail: string;
  id: string;
  label: string;
  passed: boolean;
  recovery?: string;
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
  private_egress_cidrs?: string[];
  submission_profile?: string;
}

export interface CTMonitoring {
  capability: string;
  findings: DiscoveryFinding[];
  findings_path: string;
  logs: CTMonitoringLog[];
  notification_destination: string;
  outbox_backed_alerts: boolean;
  retired_logs: CTMonitoringLog[];
  run?: DiscoveryRun;
  runs_path: string;
  source?: DiscoverySource;
  sources_path: string;
  summary: CTMonitoringSummary;
  watched_domains: string[];
  watchlist_path: string;
}

export interface CTMonitoringLog {
  last_error?: string;
  last_polled_at?: string;
  next_index: number;
  retired_at?: string;
  status: "never" | "succeeded" | "failed";
  url: string;
}

export interface CTMonitoringRequest {
  allow_private_endpoint?: boolean;
  dry_run?: boolean;
  logs: string[];
  max_batch?: number;
  name?: string;
  private_egress_cidrs?: string[];
  run_now?: boolean;
  source_id?: string;
  watched_domains: string[];
}

export interface CTMonitoringSummary {
  failed_log_count: number;
  finding_count: number;
  log_count: number;
  open_finding_count: number;
  outbox_alert_channel_count: number;
  retired_log_count: number;
  source_count: number;
  unexpected_issuance_count: number;
  watched_domain_count: number;
}

export interface CapabilityLicensePosture {
  state: "community" | "active" | "grace" | "read_only";
  tier: "community" | "enterprise" | "provider";
}

export interface CapabilityRuntimeOperation {
  code?: "not_implemented" | "dependency_not_configured";
  detail?: string;
  operation_id: string;
  state: "allowed" | "scoped" | "denied" | "unavailable";
}

export interface CapabilityUnavailableAction {
  code: "not_attached" | "not_implemented" | "dependency_not_configured";
  detail: string;
  operation_id: string;
}

export interface CapabilityView {
  contract_schema_version: number;
  enforcement_note: string;
  items: CapabilityViewItem[];
  license: CapabilityLicensePosture;
  operations: CapabilityRuntimeOperation[];
  schema_version: number;
}

export interface CapabilityViewActions {
  allowed: string[];
  denied: string[];
  scoped: string[];
  unavailable: CapabilityUnavailableAction[];
}

export interface CapabilityViewItem {
  actions: CapabilityViewActions;
  authorization_state: "catalog_only" | "none" | "scoped" | "partial" | "full";
  capability_id: string;
  classification: "primary" | "supporting";
  console_route: string;
  dependencies: string[];
  dependency_state: "none" | "documented_not_runtime_verified";
  edition: "core" | "core_with_licensed_extensions";
  maturity: "absent" | "api_cli_only" | "observe_only" | "partial_workflow" | "complete_vertical_slice";
  name: string;
  purpose: string;
  release_blocking: boolean;
  runtime_state: "catalog_only" | "unavailable" | "partially_available" | "available";
  stages: CapabilityViewStage[];
  tool: "discover" | "certificates" | "workloads_machines" | "secrets" | "software_trust" | "operations" | "platform_integrations";
}

export interface CapabilityViewStage {
  completion: "complete" | "not_applicable" | "intentional_api_only" | "blocked" | "missing";
  name: "discover" | "understand" | "configure" | "preview" | "execute" | "observe" | "recover" | "verify" | "automate";
  reason?: string;
}

export interface Certificate {
  created_at?: string;
  custody_summary?: string;
  deployment_location?: string;
  fingerprint: string;
  id: string;
  issuer?: string;
  key_algorithm?: string;
  key_exportable?: "" | "exportable" | "non_exportable";
  key_generated_by?: string;
  key_origin?: "" | "requester" | "host_agent" | "device" | "control_plane" | "signer";
  key_storage?: "" | "locked_memory" | "file" | "os_store" | "pkcs11" | "device_bound" | "service";
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

export interface CertificateCustodySummary {
  exportability: CustodyExportabilityCounts;
  origins: CustodyOriginCounts;
  recorded: number;
  storage: CustodyStorageCounts;
  total: number;
  unrecorded: number;
  unrecorded_certificates: UnrecordedCustodyCertificate[];
}

export interface CertificateExpiryBucket {
  count: number;
  name: "expired" | "expiring_7d" | "expiring_30d" | "expiring_90d" | "expiring_180d" | "expiring_1y" | "expiring_2y" | "expiring_3y" | "later" | "unknown";
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
  expiring_180d?: number;
  expiring_1y?: number;
  expiring_2y?: number;
  expiring_30d: number;
  expiring_3y?: number;
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

export interface CertificateProfileSpec {
  acme_auth_mode?: "public_trust" | "trust_authenticated";
  acme_device_attestation?: ACMEDeviceAttestationPolicy;
  allowed_dns_suffixes?: string[];
  allowed_ekus?: string[];
  allowed_email_domains?: string[];
  allowed_ip_cidrs?: string[];
  allowed_key_algorithms?: string[];
  allowed_protocols?: string[];
  allowed_uri_prefixes?: string[];
  max_validity?: string;
  min_ecdsa_bits?: number;
  min_rsa_bits?: number;
  name?: string;
  requires_approval?: boolean;
  version?: number;
}

export interface CertificateSourceHealth {
  count: number;
  expired: number;
  expiring_30d: number;
  external: boolean;
  source: string;
}

export interface CloudSecretManagerIntegration {
  architecture_controls: string[];
  capability: string;
  configured_providers: string[];
  configured_sync_targets: string[];
  discovery_mode: string;
  evidence_refs: string[];
  generated_at: string;
  outbox_mode: string;
  providers: CloudSecretManagerProvider[];
  recommended_next_actions: string[];
  residuals: string[];
  secret_handling: string;
  served: boolean;
  summary: CloudSecretManagerSummary;
}

export interface CloudSecretManagerProvider {
  capabilities: string[];
  discovery_configured: boolean;
  discovery_read_ops: string[];
  discovery_source_count: number;
  discovery_source_kind?: string;
  discovery_supported: boolean;
  evidence_refs: string[];
  id: string;
  name: string;
  platform: string;
  secret_handling: string;
  sync_configured: boolean;
  sync_supported: boolean;
  sync_target_id?: string;
  sync_write_operation?: string;
}

export interface CloudSecretManagerSummary {
  configured_connections: number;
  discovery_configured: number;
  discovery_supported: number;
  fully_configured: number;
  sync_configured: number;
  sync_supported: number;
  total_providers: number;
}

export interface CodeSigningIdentity {
  created_at: string;
  last_error?: string;
  mode: "managed" | "keyless";
  operation_id: string;
  request_hash: string;
  status: string;
  transparency: "verified" | "pending" | "failed" | "not-published";
  transparency_error?: string;
  updated_at: string;
}

export interface CodeSigningIdentityList {
  items: CodeSigningIdentity[];
  not_published_count: number;
  total: number;
  verified_count: number;
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
  adcs: ADCSComplianceEvidence;
  crypto_readiness: CryptoReadiness;
  custody: CertificateCustodySummary;
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
  relay_plugins?: RelayPluginRuntime[];
  relay_plugins_next_cursor?: string;
}

export interface ConnectorCatalogItem {
  capabilities: string[];
  delivery_mode: string;
  device_proven: boolean;
  executes_rollback?: boolean;
  kind: string;
  name: string;
  native: boolean;
  relay_parity?: ConnectorRelayParity;
  replay_safety: "at-most-once" | "reconciled";
  rollback: string;
  support?: ConnectorSupportRow;
  target_vantage: "control_plane" | "host_agent" | "network_relay";
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
  status: "queued" | "delivered" | "failed" | "verified" | "verify_failed" | "config_validated" | "rollback_recorded" | "rollback_queued" | "rolled_back" | "rollback_refused" | "rollback_failed" | "dry_run_queued" | "dry_run_planned" | "dry_run_blocked" | "test_succeeded";
  target: string;
  tenant_id: string;
  updated_at: string;
}

export interface ConnectorDeliveryList {
  items: ConnectorDelivery[];
  next_cursor?: string;
}

export interface ConnectorRelayParity {
  cp_retained?: boolean;
  detail: string;
  disposition?: "migrated" | "architecture_exception" | "unimplemented";
  met: string[];
  missing: string[];
  outstanding: string[];
  relay_migrated: boolean;
  scope_note?: string;
}

export interface ConnectorSupportRow {
  api_contract: string;
  detail: string;
  hardware_tested: boolean;
  known_limits: string[];
  proven_operations: string[];
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
  urgent_summary: UrgentRiskSummary;
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

export interface CryptoDependent {
  edge: string;
  node: GraphNode;
  via: GraphNode;
}

export interface CryptoReadiness {
  coverage_guidance: string;
  dataset_digest: string;
  format: string;
  items: CryptoReadinessRow[];
  tenant_id: string;
  unlocated: number;
  urgent: number;
}

export interface CryptoReadinessAction {
  campaign_id: string;
  deadline: string;
  disposition: string;
  evidence_digests: string[];
  evidence_refs: string[];
  name: string;
  owner: string;
  readiness_digest: string;
  readiness_status: string;
  stale: boolean;
  status: string;
  wave: string;
}

export interface CryptoReadinessExport {
  csv: string;
  dataset: CryptoReadiness;
  dataset_digest: string;
  ndjson: string;
  public_jwks: Record<string, unknown>;
  signed_export: string;
}

export interface CryptoReadinessRow {
  actions: CryptoReadinessAction[];
  asset: GraphNode;
  dependents?: CryptoDependent[];
  exhibitors?: GraphNode[];
  out_of_policy: boolean;
  owners?: string[];
  quantum_vulnerable: boolean;
  recommendation: string;
  unlocated: boolean;
}

export interface CustodyExportabilityCounts {
  exportable: number;
  non_exportable: number;
}

export interface CustodyOriginCounts {
  control_plane: number;
  device: number;
  host_agent: number;
  requester: number;
  signer: number;
}

export interface CustodyStorageCounts {
  device_bound: number;
  file: number;
  locked_memory: number;
  os_store: number;
  pkcs11: number;
  service: number;
}

export interface DRArtifactFailure {
  detail: string;
  name: string;
  required: boolean;
}

export interface DRDrill {
  artifacts_restored: string[];
  completed_at?: string;
  detail: string;
  event_log_healthy: boolean;
  events_restored: number;
  full_set_restored: boolean;
  id?: string;
  limitations: string[];
  outcome: "restored" | "failed" | "skipped";
  postgres_records_restored: number;
  postgres_tables_restored: Record<string, unknown>;
  ran_at: string;
  rpo_seconds: number;
  rto_seconds: number;
  server_healthy: boolean;
  signature?: string;
  signature_verified?: boolean;
  signed_evidence?: Record<string, unknown>;
  signer_algorithm?: string;
  signer_healthy: boolean;
  signer_key_id?: string;
  store_healthy: boolean;
  verification_jwks?: Record<string, unknown>;
}

export interface DRPosture {
  artifacts_checked: number;
  artifacts_unverifiable: number;
  backup_configured: boolean;
  detail: string;
  drill_history?: DRDrill[];
  failures?: DRArtifactFailure[];
  guidance: string;
  last_backup_at?: string;
  last_drill?: DRDrill;
  last_verified_at?: string;
  verified: boolean;
}

export interface DeploymentEntitlementInfo {
  bundled_non_production_deployments: number;
  deployment_id?: string;
  environment: "production" | "non_production";
  legacy_unbound: boolean;
  non_production_slots_remaining: number;
  production_units_consumed: number;
  registered_non_production_deployments: number;
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

export interface DeploymentTriState {
  delivered: number;
  unverified: number;
  verified: number;
  verified_percent: number;
  verify_failed: number;
}

export interface DiscoveryCapability {
  configuration: DiscoveryCapabilityField[];
  console_stages: string[];
  data_handling: string;
  documentation_ref: string;
  edition: string;
  execution: string;
  kind: "adcs" | "agent" | "api_key" | "cloud_certificate" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "k8s_ingress_gateway" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "secret_store" | "service_account" | "ssh";
  label: string;
  lifecycle: string[];
  permission: string;
  providers?: DiscoveryCapabilityProvider[];
  purpose: string;
  route: string;
  setup_surface: "source_wizard" | "contextual";
  tool: string;
}

export interface DiscoveryCapabilityCatalog {
  items: DiscoveryCapability[];
  schema_version: number;
}

export interface DiscoveryCapabilityField {
  advanced?: boolean;
  description: string;
  label: string;
  path: string;
  required: boolean;
  secret_ref?: boolean;
  type: string;
}

export interface DiscoveryCapabilityProvider {
  fields: string[];
  id: string;
  label: string;
  least_privilege: string;
  preferred_credential: string;
}

export interface DiscoveryCoverage {
  classes: DiscoveryCoverageClass[];
  generated_at: string;
  observed: number;
  provenance: DiscoveryProvenanceSummary;
  segment_coverage_percent: number;
  segments: DiscoverySegmentCoverage[];
  structurally_unobservable: number;
  unknowns: DiscoveryUnknown[];
  unobserved: number;
}

export interface DiscoveryCoverageClass {
  action?: string;
  class: string;
  last_observed_at?: string;
  observed_by?: string[];
  reason?: string;
  source_kinds?: string[];
  status: string;
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
  blocked_reasons?: string[];
  certificate_inventory_count: number;
  completed_run_count: number;
  connection_origin?: string;
  execution_ready?: boolean;
  failed_run_count: number;
  finding_count: number;
  findings_path: string;
  kind: "adcs" | "agent" | "api_key" | "cloud_certificate" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "k8s_ingress_gateway" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "secret_store" | "service_account" | "ssh";
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

export interface DiscoveryPlanPreview {
  applied_exclusions?: string[];
  blocked_reasons: string[];
  child_job_count: number;
  concurrency: number;
  connection_origin: string;
  data_handling: string;
  estimated_upper_seconds: number;
  excluded_target_count: number;
  execution: string;
  kind: "adcs" | "agent" | "api_key" | "cloud_certificate" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "k8s_ingress_gateway" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "secret_store" | "service_account" | "ssh";
  normalized_target_count: number;
  normalized_targets?: string[];
  permission: string;
  preview_truncated: boolean;
  protocol?: string;
  queue_depth: number;
  ready?: boolean;
  segment?: string;
  side_effects: boolean;
}

export interface DiscoveryProvenanceSummary {
  never_observed: number;
  observed: number;
  stale: number;
  stale_after_hours: number;
  total: number;
}

export interface DiscoveryRun {
  blocked: number;
  completed_at?: string;
  created_at: string;
  discovered: number;
  dry_run: boolean;
  error?: string;
  executed_by_agent_id?: string;
  execution: "control_plane" | "relay";
  failed: number;
  id: string;
  rejected: number;
  requested_by?: string;
  required_agent_id?: string;
  required_agent_role?: string;
  retry_of_run_id?: string;
  schedule_id?: string;
  segment?: string;
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

export interface DiscoverySegment {
  created_at: string;
  excluded: boolean;
  exclusion_reason?: string;
  id: string;
  last_found_count: number;
  last_swept_at?: string;
  last_swept_by?: string;
  name: string;
  ranges: string[];
  staleness_hours: number;
}

export interface DiscoverySegmentCoverage {
  exclusion_reason?: string;
  last_found_count?: number;
  last_swept_at?: string;
  last_swept_by?: string;
  name: string;
  ranges: string[];
  staleness_hours: number;
  status: "swept" | "stale" | "never" | "excluded";
}

export interface DiscoverySegmentRequest {
  excluded?: boolean;
  exclusion_reason?: string;
  name: string;
  ranges: string[];
  staleness_hours?: number;
}

export interface DiscoverySource {
  config: Record<string, unknown>;
  created_at: string;
  id: string;
  kind: "adcs" | "agent" | "api_key" | "cloud_certificate" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "k8s_ingress_gateway" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "secret_store" | "service_account" | "ssh";
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
  kind: "adcs" | "agent" | "api_key" | "cloud_certificate" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "k8s_ingress_gateway" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "secret_store" | "service_account" | "ssh";
  name: string;
}

export interface DiscoveryUnknown {
  action?: string;
  detail: string;
  kind: "segment_never_swept" | "segment_stale" | "segment_excluded" | "segment_read_failed" | "class_unobservable" | "inventory_unobserved";
  subject: string;
}

export interface DriftRemediation {
  capability: string;
  dashboard_path: string;
  findings: DriftRemediationFinding[];
  findings_path: string;
  runs_path: string;
  sources_path: string;
  summary: DriftRemediationSummary;
}

export interface DriftRemediationDecision {
  decision: string;
  evidence_refs: string[];
  finding: DriftRemediationFinding;
}

export interface DriftRemediationDecisionRequest {
  decision: "investigate" | "mark_managed" | "dismiss";
  managed_identity_id?: string;
  owner?: string;
  reason?: string;
  tags?: string[];
  team?: string;
}

export interface DriftRemediationFinding {
  actual_mode?: string;
  available_decisions: string[];
  credential_class: string;
  drift_type: "deleted" | "replaced" | "relocated" | "permission_changed" | "unknown";
  evidence_refs: string[];
  expected_mode?: string;
  finding_id: string;
  fingerprint: string;
  metadata: Record<string, unknown>;
  provenance: string;
  recommended_action: string;
  ref: string;
  risk_score: number;
  run_id: string;
  source_id: string;
  source_name: string;
  triage_actor?: string;
  triage_reason?: string;
  triage_status: "unmanaged" | "investigating" | "managed" | "dismissed";
  triaged_at?: string;
}

export interface DriftRemediationSummary {
  certificate_count: number;
  deleted_count: number;
  dismissed_count: number;
  finding_count: number;
  investigating_count: number;
  open_finding_count: number;
  permission_changed_count: number;
  relocated_count: number;
  remediated_count: number;
  remediation_decision_count: number;
  replaced_count: number;
  secret_count: number;
  source_count: number;
  ssh_key_count: number;
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

export interface EdgeDelegation {
  attested_key_sha256?: string;
  ca_id: string;
  certificate_pem?: string;
  common_name: string;
  csr_key_sha256: string;
  custody_assurance: "hardware_key_attested" | "host_attested_operator_claim" | "host_attested_software_exception";
  excluded_dns_domains?: string[];
  host: string;
  id: string;
  key_exportable: boolean;
  key_provider: "tpm2" | "pkcs11" | "software";
  key_storage: "device_bound" | "pkcs11" | "file";
  not_after: string;
  not_before: string;
  permitted_dns_domains: string[];
  revoke_reason?: string;
  revoked_at?: string;
  segment_id: string;
  serial: string;
  status: "active" | "revoked" | "expired";
}

export interface EdgeDelegationDetail {
  delegation: EdgeDelegation;
  issuances?: EdgeIssuance[];
}

export interface EdgeDelegationList {
  guidance: string;
  items: EdgeDelegation[];
}

export interface EdgeDelegationMintInput {
  attestation_credential_json: string;
  ca_id: string;
  common_name?: string;
  csr_der: string;
  host: string;
  key_provider?: "tpm2" | "pkcs11" | "software";
  segment_id: string;
  ttl_seconds?: number;
}

export interface EdgeDelegationRevokeInput {
  reason?: string;
}

export interface EdgeIssuance {
  dns_names?: string[];
  issued_at: string;
  not_after: string;
  not_before: string;
  reconciled_at: string;
  serial: string;
  subject: string;
  violation?: string;
  within_constraints: boolean;
}

export interface EdgeReconcileInput {
  certificates_pem: string[];
  host?: string;
}

export interface EdgeReconcileResult {
  already: number;
  guidance?: string;
  reconciled: number;
  rejected: number;
  violations: number;
}

export interface EdgeSegmentPolicy {
  allowed_key_providers: ("tpm2" | "pkcs11" | "software")[];
  attestation_roots: number;
  enabled: boolean;
  excluded_dns_domains?: string[];
  permitted_dns_domains?: string[];
  segment_id: string;
  segment_name?: string;
  updated_at: string;
}

export interface EdgeSegmentPolicyInput {
  allowed_key_providers?: ("tpm2" | "pkcs11" | "software")[];
  attestation_roots_pem?: string[];
  enabled: boolean;
  excluded_dns_domains?: string[];
  permitted_dns_domains?: string[];
  segment_id?: string;
}

export interface EdgeSegmentPolicyList {
  guidance: string;
  items: EdgeSegmentPolicy[];
}

export interface EditionFeature {
  licensed: boolean;
  mode: "enabled" | "read_only" | "off";
  name: string;
  tier: "community" | "enterprise" | "provider";
}

export interface EditionPackaging {
  billable_unit: string;
  bundled_non_production_deployments: number;
  category_label: string;
  certificate_counters_classification: string;
  editions: EditionPackagingEntry[];
  evidence_rail: string[];
  managed_boundary: string;
  meters: UsageMeterDefinition[];
  no_ephemeral_identity_billing: boolean;
  no_per_certificate_billing: boolean;
  non_production_support_posture: string;
  positioning: string;
  pricing_posture: string;
  provider_billing_unit: string;
  reference_price_bands: ReferencePriceBand[];
}

export interface EditionPackagingEntry {
  billing: string;
  buyer_fit: string;
  column: string;
  id: string;
  included: string[];
  license_boundary: string;
  name: string;
}

export interface EditionsInfo {
  customer?: string;
  deployment_entitlement?: DeploymentEntitlementInfo;
  expires_at?: string;
  features: EditionFeature[];
  fips: FIPSStatus;
  license_id?: string;
  managed_customer_band?: number;
  packaging: EditionPackaging;
  read_only_at?: string;
  rights?: ("self_host" | "managed_service" | "resale")[];
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

export interface EndpointCustodySummary {
  control_plane_generated: number;
  host_generated: number;
  migrated_percent: number;
  targets: number;
}

export interface EndpointKeyCustody {
  connector: string;
  detail: string;
  enabled: boolean;
  executor: "agent" | "control_plane";
  key_bytes_leave_control_plane: boolean;
  last_executed_at?: string;
  last_executed_by_agent?: string;
  last_executed_outcome?: string;
  name: string;
  origin: "host_agent" | "control_plane";
  target_id: string;
}

export interface EndpointKeyCustodyList {
  guidance: string;
  items: EndpointKeyCustody[];
  summary: EndpointCustodySummary;
}

export interface EndpointVerification {
  address: string;
  agent_common_name?: string;
  checked_chain: boolean;
  checked_sans: boolean;
  detail?: string;
  endpoint_id: string;
  evidence_digest?: string;
  expected_fingerprint?: string;
  last_checked_at?: string;
  last_good_at?: string;
  mismatch?: "fingerprint" | "sans" | "chain" | "expired" | "not_yet_valid";
  not_after?: string;
  observed_fingerprint?: string;
  stale_for_seconds?: number;
  status: "verified" | "diverged" | "unreachable" | "not_checked";
  vantage: "local" | "relay";
}

export interface EndpointVerificationList {
  guidance: string;
  items: EndpointVerification[];
  summary: EndpointVerificationSummary;
}

export interface EndpointVerificationSummary {
  diverged: number;
  endpoints: number;
  unreachable: number;
  verified: number;
  verified_percent: number;
}

export interface EnrollmentDiagnostic {
  actionable: boolean;
  cause: string;
  count: number;
  endpoint_ref?: string;
  expected_fingerprint?: string;
  id: string;
  identity_ref?: string;
  observed_at: string;
  operation_ref?: string;
  protocol: "acme" | "est" | "scep" | "cmp" | "adcs";
  remediation?: string;
  step: string;
  summary: string;
  verification_address?: string;
  verification_agent?: string;
  verification_checked_at?: string;
  verification_endpoint_id?: string;
  verification_evidence_digest?: string;
  verification_kind?: "endpoint.verify";
  verification_queued_at?: string;
  verification_result_path?: string;
  verification_server_name?: string;
  verification_status?: "queued" | "verified" | "diverged" | "unreachable";
}

export interface EnrollmentDiagnosticList {
  guidance: string;
  items: EnrollmentDiagnostic[];
  unknown_count: number;
}

export interface EnrollmentDiagnosticSupportAggregate {
  actionable: boolean;
  cause: string;
  count: number;
  protocol: "acme" | "est" | "scep" | "cmp" | "adcs";
}

export interface EnrollmentDiagnosticVerification {
  diagnostic_id: string;
  queued_at: string;
  result_path: string;
  status: "queued";
  verification_endpoint_id: string;
}

export interface EnrollmentDiagnosticsSupportAddendum {
  rows: EnrollmentDiagnosticSupportAggregate[];
  schema_version: number;
  unknown_count: number;
}

export interface EnrollmentPlanPreview {
  agent_server: string;
  agent_server_name: string;
  allowed_identity?: string;
  blocked_reasons: string[];
  data_handling: string;
  enroll_path: string;
  ready: boolean;
  renewal_authentication: string;
  renewal_path: string;
  renewal_ready: boolean;
  required_permissions: string[];
  roles: ("host" | "network")[];
  side_effects: boolean;
}

export interface EnrollmentToken {
  agent_server: string;
  agent_server_name: string;
  enroll_path?: string;
  roles: ("host" | "network")[];
  token: string;
}

export interface EnrollmentTokenRequest {
  allowed_identity?: string;
  roles?: ("host" | "network")[];
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
  action: "issue";
  approval_count: number;
  approvals: number;
  approver: string;
  id: string;
  intent_digest: string;
  required_approvals: number;
  resource: string;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
}

export interface EphemeralApprovalRequest {
  action: "issue";
  intent_digest: string;
  request_id: string;
}

export interface EphemeralCredential {
  approval_request_id: string;
  approvals: number;
  attestation: Attestation;
  certificate_id?: string;
  certificate_pem?: string;
  credential_id?: string;
  expires_at: string;
  intent_digest: string;
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
  status: "halted" | "planned" | "queued" | "waiting_verification" | "executed" | "failed" | "completed";
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
  cohorts: MigrationRunStartWave[];
  issuer_id: string;
  mode: "live" | "game_day";
  reason?: string;
  replacement_authority_id: string;
  rollback_ref?: string;
}

export interface FleetReissuanceRun {
  affected_identity_ids: string[];
  batch_count: number;
  batch_size: number;
  batches: FleetReissuanceBatch[];
  candidate_trust_hosts: string[];
  candidate_trust_store_ids: string[];
  connector?: string;
  connector_deliveries?: ConnectorDelivery[];
  connector_delivery_ids?: string[];
  created_at: string;
  created_by?: string;
  evidence_bundle?: string;
  evidence_bundle_format?: string;
  exact_trust_hosts: string[];
  exact_trust_store_ids: string[];
  failed_targets?: string[];
  graph_impact: GraphImpact;
  halted_reason?: string;
  health_gates: FleetReissuanceHealthGate[];
  id: string;
  idempotency_key?: string;
  issuer_id: string;
  migration_run_id?: string;
  mode: "legacy" | "live" | "game_day";
  next_batch_index: number;
  phase: string;
  plan_digest?: string;
  reason?: string;
  replacement_authority_id?: string;
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
  confidence?: string;
  from: string;
  source?: string;
  to: string;
  type: string;
}

export interface GraphEvidencePath {
  edges: GraphEdge[];
  nodes: GraphNode[];
  target: GraphNode;
}

export interface GraphImpact {
  affected: GraphNode[];
  by_kind: Record<string, unknown>;
  node: GraphNode;
  paths: GraphEvidencePath[];
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
  paths: GraphEvidencePath[];
}

export interface GraphResponse {
  edges: GraphEdge[];
  nodes: GraphNode[];
}

export interface GraphTrustStores {
  candidate_host_count?: number;
  candidate_hosts?: GraphNode[];
  candidate_store_count?: number;
  candidate_stores?: GraphNode[];
  guidance: string;
  host_count: number;
  hosts: GraphNode[];
  issuer: string;
  store_count: number;
  stores: GraphNode[];
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

export interface IdempotencyResultProtectionReadout {
  failure?: string;
  fleet_ready: boolean;
  indeterminate_results: number;
  legacy_dynamic_remaining: number;
  pending_results: number;
  raw_v0_remaining: number;
  recovery: string;
  sealed_only_floor: boolean;
  sealed_results: number;
  state: "unavailable" | "empty" | "ready_for_ratchet" | "partial" | "failed" | "recovery_required" | "complete";
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

export interface IdentityTransitionPreview {
  capability: string;
  event_type: string;
  execution_external_effects: string[];
  execution_writes: string[];
  expected_version: number;
  from: string;
  guidance: string;
  identity_id: string;
  identity_kind: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  identity_name: string;
  owner_id: string;
  owner_name?: string;
  prerequisites: string[];
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  request_fingerprint: string;
  required_permission: string;
  side_effect: boolean;
  side_effect_destination?: string;
  to: string;
  verification_steps: string[];
  warnings: string[];
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

export interface IssuanceDecisionInput {
  identity_id?: string;
  reason?: string;
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

export interface IssuanceRequest {
  created_at: string;
  decided_at?: string;
  decided_by?: string;
  decision_reason?: string;
  expires_at: string;
  id: string;
  identity_id?: string;
  issued_at?: string;
  issued_by?: string;
  justification?: string;
  origin?: string;
  owner_id?: string;
  profile?: string;
  requester: string;
  status: "requested" | "approved" | "denied" | "expired" | "cancelled" | "issued";
  subject: string;
  tenant_id: string;
  ticket_ref?: string;
}

export interface IssuanceRequestInput {
  csr_pem?: string;
  justification?: string;
  origin?: string;
  owner_id: string;
  profile?: string;
  subject: string;
  ticket_ref?: string;
}

export interface IssuanceRequestList {
  guidance: string;
  items: IssuanceRequest[];
  open: number;
}

export interface IssuanceRequestPreparation {
  csr_pem?: string;
  identity: Identity;
  issue_idempotency_key: string;
  request: IssuanceRequest;
}

export interface IssuanceRequestPreview {
  approval_permission: string;
  approval_required: boolean;
  blockers: string[];
  csr_supplied: boolean;
  guidance: string;
  issuance_permissions: string[];
  key_origin: "requester_csr" | "deprecated_control_plane_generation";
  owner_id: string;
  owner_kind?: string;
  owner_name?: string;
  preview_external_effects: string[];
  preview_writes: string[];
  profile?: string;
  profile_name?: string;
  profile_version?: number;
  ready: boolean;
  requester: string;
  steps: string[];
  subject: string;
  submission_effects: string[];
  warnings: string[];
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

export interface IssuerCapability {
  discover: boolean;
  evidence?: string;
  issue: boolean;
  issue_proven?: boolean;
  issuer: string;
  key_handling: "requester_csr" | "authority_generated";
  renew: boolean;
  revoke: boolean;
  revoke_note?: string;
  unattended_dv: boolean;
  unattended_dv_note?: string;
  validation: "acme_challenge" | "account_scoped" | "organizational" | "internal";
}

export interface IssuerCapabilityMatrix {
  guidance: string;
  issuers: IssuerCapability[];
  revoke_capable_count: number;
  unattended_dv_capable_count: number;
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
  controllers?: KubernetesPostureController[];
  evidence_refs: string[];
  generated_at: string;
  last_sync?: string;
  objects?: KubernetesPostureObject[];
  rbac_rules: KubernetesCSRSupportRule[];
  recommended_next_actions: string[];
  residuals: string[];
  resource: string;
  served: boolean;
  signer_names: string[];
  status_fields: string[];
  summary?: KubernetesPostureSummary;
}

export interface KubernetesCSRSupportRule {
  api_group: string;
  resource: string;
  verbs: string[];
}

export interface KubernetesPostureController {
  cluster_id: string;
  controller_id: string;
  failed: number;
  failure_code?: string;
  last_sync: string;
  observed: number;
  pending: number;
  ready: number;
  reconcile_complete: boolean;
  report_id: string;
  stale: boolean;
}

export interface KubernetesPostureObject {
  cluster_id: string;
  controller_id: string;
  name: string;
  namespace?: string;
  public_hash?: string;
  reason: string;
  resource_version: string;
  state: "ready" | "pending" | "failed";
  uid: string;
}

export interface KubernetesPostureSummary {
  complete_controllers: number;
  controllers: number;
  failed: number;
  observed: number;
  pending: number;
  ready: number;
  stale_controllers: number;
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
  controllers?: KubernetesPostureController[];
  distribution_targets: string[];
  evidence_refs: string[];
  generated_at: string;
  last_sync?: string;
  objects?: KubernetesPostureObject[];
  rbac_rules: KubernetesCSRSupportRule[];
  recommended_next_actions: string[];
  residuals: string[];
  resource: string;
  served: boolean;
  status_fields: string[];
  summary?: KubernetesPostureSummary;
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

export interface MDMDevice {
  device_name?: string;
  identity_id?: string;
  install_detail?: string;
  install_state: "ok" | "failed" | "unknown";
  mdm: "intune" | "jamf";
  mdm_device_id: string;
  observed_at?: string;
  renewal_at_risk?: boolean;
  renewal_detail?: string;
  renewal_not_after?: string;
  serial_number?: string;
  transaction_id?: string;
}

export interface MDMDeviceList {
  failed: number;
  guidance: string;
  items: MDMDevice[];
  renewal_at_risk?: number;
  unobserved: number;
}

export interface MDMDeviceTrace {
  guidance: string;
  trace: { broke_at?: string; device_id?: string; device_name?: string; mdm?: string; mdm_device_id?: string; serial_number?: string; steps: MDMTraceStep[]; summary: string; transaction_id?: string };
}

export interface MDMPollSchedule {
  base_url?: string;
  configured: boolean;
  enabled: boolean;
  execution?: "relay" | "";
  filter?: string;
  guidance: string;
  interval_seconds?: number;
  last_error?: string;
  last_run_at?: string;
  mdm?: "intune" | "jamf";
  renewal_window_days?: number;
  token_ref?: string;
}

export interface MDMPollScheduleInput {
  base_url: string;
  enabled?: boolean;
  execution?: "relay" | "";
  filter?: string;
  interval_seconds: number;
  mdm: "intune" | "jamf";
  renewal_window_days?: number;
  token_ref: string;
}

export interface MDMPollScheduleList {
  guidance: string;
  items: MDMPollSchedule[];
}

export interface MDMSCEPChallengeRotated {
  policy: MDMSCEPPolicy;
}

export interface MDMSCEPChallengeRotationPreview {
  blockers: string[];
  capability: string;
  current_version: number;
  durable_writes: string[];
  effect_free: boolean;
  next_version: number;
  outside_calls: string[];
  policy_id: string;
  policy_name: string;
  ready: boolean;
  recovery_steps: string[];
  secret_data_handling: string;
  signer_calls: number;
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

export interface MDMSCEPPolicyPreview {
  blockers: string[];
  capability: string;
  challenge_mode: "intune-jws" | "hmac-dynamic";
  durable_writes: string[];
  effect_free: boolean;
  enabled: boolean;
  expected_audience?: string;
  name: string;
  operation: "create" | "update";
  outside_calls: string[];
  policy_id?: string;
  profile_guidance: Record<string, unknown>;
  provider: "intune" | "jamf";
  ready: boolean;
  recovery_steps: string[];
  scep_endpoint: string;
  scep_profile: string;
  secret_data_handling: string;
  signer_calls: number;
  trust_anchor_reference_keys: string[];
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

export interface MDMTraceStep {
  at?: string;
  detail?: string;
  outcome: "ok" | "failed" | "pending" | "unknown";
  source?: string;
  stage: "requested" | "issued" | "installed" | "renewing";
}

export interface MachineAuthMethod {
  allow_unexpiring?: boolean;
  allowed_accounts?: string[];
  allowed_arns?: string[];
  allowed_azure_tenants?: string[];
  allowed_namespaces?: string[];
  allowed_projects?: string[];
  allowed_service_accounts?: string[];
  audience?: string;
  disabled?: boolean;
  issuer?: string;
  jwks_configured: boolean;
  name: string;
  principal_prefix?: string;
  required_claims?: Record<string, unknown>;
  scopes?: string[];
  scopes_by_principal?: Record<string, unknown>;
  scopes_claim?: string;
  source: string;
  subject_claim?: string;
  tenant_claim?: string;
  type: string;
}

export interface MachineAuthMethodList {
  items: MachineAuthMethod[];
  next_cursor?: string;
}

export interface MachineAuthMethodOverride {
  disabled: boolean;
  name: string;
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

export interface MachineSession {
  expires_at: string;
  id: string;
  issued_at: string;
  method: string;
  principal: string;
  revoked_at?: string;
  revoked_by?: string;
  scopes?: string[];
  status: "active" | "expired" | "revoked";
}

export interface MachineSessionList {
  items: MachineSession[];
  next_cursor?: string;
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

export interface ManagedKeyApproval {
  action: "managedkey:rotate" | "managedkey:revoke" | "managedkey:zeroize";
  approvals: number;
  approver: string;
  resource: string;
}

export interface ManagedKeyApprovalRequest {
  action: "rotate" | "revoke" | "zeroize";
  intent_digest: string;
  key_id: string;
  request_id: string;
}

export interface ManagedKeyCustodyPlan {
  blockers: string[];
  configuration_mode: "startup_static";
  configured_provider: "" | "aws" | "azure-key-vault" | "gcp-kms" | "pkcs11" | "tpm2" | "yubihsm2";
  enabled: boolean;
  lifecycle_attached: boolean;
  providers: ManagedKeyCustodyProvider[];
  ready: boolean;
  restart_required: boolean;
  secret_delivery: "file_reference_only";
  security_boundary: string;
}

export interface ManagedKeyCustodyProvider {
  custody: string;
  id: "aws" | "azure-key-vault" | "gcp-kms" | "pkcs11" | "tpm2" | "yubihsm2";
  label: string;
  requirements: ManagedKeyCustodyRequirement[];
}

export interface ManagedKeyCustodyRequirement {
  description: string;
  environment_variable: string;
  key: string;
  kind: "value" | "secret_file";
  label: string;
  required: boolean;
}

export interface ManagedKeyGenerateRequest {
  algorithm: "RSA-2048" | "RSA-3072" | "RSA-4096" | "ECDSA-P256" | "ECDSA-P384" | "ECDSA-P521";
}

export interface ManagedKeyGenerationPreview {
  algorithm: string;
  approval_required: boolean;
  blockers: string[];
  configuration_mode: "startup_static";
  effect_free: boolean;
  execution_external_effects: string[];
  execution_writes: string[];
  extractable: boolean;
  preview_external_effects: string[];
  preview_writes: string[];
  private_key_location: string;
  proof: string[];
  provider: "aws" | "azure-key-vault" | "gcp-kms" | "pkcs11" | "tpm2" | "yubihsm2";
  provider_label: string;
  ready: boolean;
  required_permission: string;
  requirements: ManagedKeyCustodyRequirement[];
  restart_required: boolean;
}

export interface ManagedKeyGenerationPreviewRequest {
  algorithm: "RSA-2048" | "RSA-3072" | "RSA-4096" | "ECDSA-P256" | "ECDSA-P384" | "ECDSA-P521";
  provider: "aws" | "azure-key-vault" | "gcp-kms" | "pkcs11" | "tpm2" | "yubihsm2";
}

export interface ManagedOfferingStatus {
  billing_unit: string;
  deployment_model: string;
  event_type: string;
  idempotency_required: boolean;
  license_state: "community" | "active" | "grace" | "read_only";
  managed_boundary: string;
  managed_customer_band?: number;
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

export interface MigrationAssessRequest {
  min_trust_percent?: number;
  plan_id?: string;
  require_full_trust?: boolean;
  waves: { id: string; members: string[]; ordinal: number }[];
}

export interface MigrationAssessedWave {
  blocked?: string[];
  guidance?: string;
  id: string;
  members: string[];
  ordinal: number;
}

export interface MigrationAssessment {
  guidance: string;
  members: number;
  migratable: number;
  plan_id: string;
  unknowns: MigrationUnknown[];
  waves: MigrationAssessedWave[];
}

export interface MigrationMemberBinding {
  connector: string;
  issuing_authority_id: string;
  predecessor_certificate_id: string;
  predecessor_fingerprint: string;
  required_agent_id: string;
  subject_common_name: string;
  subject_dns_names: string[];
  successor_fingerprint?: string;
  target: string;
  target_config: Record<string, unknown>;
  target_id: string;
  target_revision: string;
  trust_anchor_fingerprint: string;
  trust_anchor_path: string;
  trust_anchor_pem: string;
  verify_address: string;
  verify_server_name?: string;
}

export interface MigrationRun {
  halt_reason?: string;
  id: string;
  pause_reason?: string;
  plan_id?: string;
  rollback_attempt?: number;
  rollback_stage?: string;
  rollback_wave_id?: string;
  status: "planned" | "running" | "paused" | "halted" | "rolling_back" | "rolled_back" | "complete";
  waves: MigrationRunWave[];
}

export interface MigrationRunActionRequest {
  reason?: string;
}

export interface MigrationRunList {
  items: MigrationRun[];
  next_cursor?: string;
}

export interface MigrationRunMember {
  binding: MigrationMemberBinding;
  identity_id: string;
  rollback_successor_verdict?: string;
  rollback_trust_verdict?: string;
  successor_verdict?: string;
  trust_verdict?: string;
}

export interface MigrationRunStartMember {
  agent_id: string;
  identity_id: string;
  trust_anchor_path: string;
}

export interface MigrationRunStartRequest {
  new_authority_id: string;
  plan_id: string;
  waves: MigrationRunStartWave[];
}

export interface MigrationRunStartWave {
  id: string;
  members: MigrationRunStartMember[];
  ordinal: number;
}

export interface MigrationRunWave {
  halt_reason?: string;
  id: string;
  members: MigrationRunMember[];
  ordinal: number;
  phase: string;
  started: boolean;
}

export interface MigrationUnknown {
  detail: string;
  kind: "no_trust_store_observed" | "no_verification_address" | "no_deployment_target";
  member: string;
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

export interface NHIExposureFinding {
  auth_mode: string;
  callback_urls: string[];
  display_name: string;
  environment?: string;
  evidence_refs: string[];
  exposure_level: string;
  finding_types: string[];
  inventory_id: string;
  kind: string;
  network_surface: string;
  owner_id?: string;
  owner_status: "owned" | "subject_bound" | "orphaned";
  public_endpoints: string[];
  recommendation: string;
  ref?: string;
  risk_score: number;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  status: string;
  transport_security: string;
}

export interface NHIExposurePosture {
  capability: string;
  coverage: string[];
  findings: NHIExposureFinding[];
  generated_at: string;
  summary: NHIExposureSummary;
}

export interface NHIExposureSummary {
  critical: number;
  findings: number;
  high: number;
  insecure_transport: number;
  internet_exposed: number;
  low: number;
  medium: number;
  missing_network_policy: number;
  public_callbacks: number;
  recommendations: number;
  total_analyzed: number;
  weak_authentication: number;
  wildcard_reachability: number;
}

export interface NHIInventory {
  coverage: string[];
  generated_at: string;
  items: NHIInventoryItem[];
  record_summary: NHIInventoryRecordSummary;
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

export interface NHIInventoryRecordSummary {
  agent_records: number;
  api_token_records: number;
  certificate_records: number;
  counting_mode: "durable_source_records_not_unique_credentials";
  discovery_finding_records: number;
  managed_identity_records: number;
  total_records: number;
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
  channel_type?: string;
  configured: boolean;
  credential_ref?: string;
  delivery: string;
  description?: string;
  enabled: boolean;
  endpoint_configured?: boolean;
  id: string;
  label: string;
  secret_handling?: string;
  source?: string;
}

export interface NotificationChannelList {
  items: NotificationChannel[];
  next_cursor?: string;
}

export interface NotificationChannelRequest {
  channel_type?: string;
  credential_ref?: string;
  enabled?: boolean;
  endpoint_url?: string;
  id?: string;
  label?: string;
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
  scope_kind: "manual" | "global" | "workspace" | "owner" | "asset";
  scope_ref?: string;
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
  scope_kind?: "manual" | "global" | "workspace" | "owner" | "asset";
  scope_ref?: string;
}

export interface NotificationRoutingPreview {
  delivery_ready: boolean;
  effective_channels: string[];
  explanation: string;
  matched_policy?: NotificationRoutingPolicy;
  missing_channels: string[];
  resolution_order: string[];
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

export interface OutboxReconciliationConflict {
  candidate_destination: string;
  candidate_effect_lane: string;
  candidate_payload_sha256: string;
  candidate_required_agent_id?: string;
  candidate_required_agent_role?: string;
  detected_at: string;
  existing_destination: string;
  existing_effect_lane: string;
  existing_outbox_id: number;
  existing_payload_sha256: string;
  existing_required_agent_id?: string;
  existing_required_agent_role?: string;
  id: string;
  idempotency_key: string;
  reason: string;
  source_event_id: string;
  source_event_sequence: number;
  source_event_type: string;
  status: "quarantined";
  tenant_id: string;
}

export interface OutboxReconciliationConflictList {
  guidance: string;
  items: OutboxReconciliationConflict[];
}

export interface Owner {
  application_id?: string;
  business_unit?: string;
  created_at?: string;
  email?: string;
  environment?: string;
  escalation_chain: string[];
  id: string;
  kind: "user" | "team" | "workload" | "service" | "vendor";
  name: string;
  ownership_attestation_due_at?: string;
  ownership_attested: boolean;
  ownership_complete: boolean;
  ownership_current: boolean;
  ownership_source?: string;
  ownership_source_observed_at?: string;
  ownership_source_ref?: string;
  ownership_verified_at?: string;
  ownership_verified_by?: string;
  service?: string;
  tenant_id: string;
}

export interface OwnerList {
  items: Owner[];
  next_cursor?: string;
}

export interface OwnerRemediationAcceptRequest {
  connector?: string;
  reason?: string;
  recommended_scopes?: string[];
  remove_scopes?: string[];
  rollback_ref?: string;
  target?: string;
}

export interface OwnerRemediationAction {
  action: string;
  connector: string;
  connector_delivery_id?: string;
  display_name: string;
  evidence_refs: string[];
  id: string;
  inventory_id: string;
  kind: string;
  owner_email?: string;
  owner_id: string;
  owner_name: string;
  playbook_id: string;
  reason: string;
  recommendation: string;
  recommended_scopes: string[];
  remediation_run_id?: string;
  remove_scopes: string[];
  risk_score: number;
  rollback_ref: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  status: string;
  target: string;
  target_identity_id?: string;
}

export interface OwnerRemediationQueue {
  capability: string;
  evidence_refs: string[];
  generated_at: string;
  items: OwnerRemediationAction[];
  status: string;
  summary: OwnerRemediationSummary;
}

export interface OwnerRemediationRun {
  action: OwnerRemediationAction;
  capability: string;
  remediation_run: RemediationPlaybookRun;
  status: string;
}

export interface OwnerRemediationSummary {
  accepted: number;
  critical: number;
  high: number;
  low: number;
  medium: number;
  open: number;
  total: number;
}

export interface OwnerRequest {
  application_id?: string;
  business_unit?: string;
  email?: string;
  environment?: string;
  escalation_chain?: string[];
  kind: "user" | "team" | "workload" | "service" | "vendor";
  name: string;
  service?: string;
}

export interface OwnershipAssignmentRequest {
  inventory_ids: string[];
  owner_id: string;
  reason: string;
}

export interface OwnershipAssignmentResult {
  assigned: string[];
  assigned_at: string;
  assigned_by: string;
  owner_id: string;
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

export interface OwnershipConflict {
  current_attested: boolean;
  current_source?: string;
  current_value?: string;
  field: string;
  id?: string;
  incoming_ref?: string;
  incoming_source?: string;
  incoming_value?: string;
  owner_id?: string;
  why?: string;
}

export interface OwnershipConflictList {
  guidance: string;
  items: OwnershipConflict[];
  refused: number;
}

export interface OwnershipException {
  active: boolean;
  expires_at: string;
  granted_at: string;
  granted_by: string;
  id: string;
  identity_id: string;
  reason: string;
  revocation_reason?: string;
  revoked_at?: string;
  revoked_by?: string;
}

export interface OwnershipExceptionList {
  items: OwnershipException[];
  next_cursor?: string;
}

export interface OwnershipExceptionRequest {
  expires_at: string;
  reason: string;
}

export interface OwnershipExceptionRevokeRequest {
  reason: string;
}

export interface OwnershipImportResult {
  applied: number;
  conflicts: OwnershipConflict[];
  detail: string;
  guidance: string;
  unchanged: number;
}

export interface OwnershipResolveInput {
  resolution: string;
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
  common_name: string;
  private_key?: string;
  serial: string;
}

export interface PKISecretRequest {
  common_name?: string;
  csr_pem?: string;
  ttl_seconds?: number;
}

export interface PQCMigrationCampaign {
  automated_execution_available: boolean;
  automated_execution_note: string;
  closed_at?: string;
  closure?: PQCMigrationCampaignClosure;
  created_at: string;
  deadline: string;
  excepted_count: number;
  finding_count: number;
  findings?: PQCMigrationCampaignFinding[];
  id: string;
  name: string;
  owner: string;
  pending_count: number;
  readiness_criteria: string[];
  readiness_evidence_refs: string[];
  readiness_status: "pending" | "passed" | "blocked";
  remediated_count: number;
  status: "open" | "closed";
  tenant_id: string;
  updated_at: string;
  wave: string;
}

export interface PQCMigrationCampaignCloseRequest {
  closed_by?: string;
}

export interface PQCMigrationCampaignClosure {
  format: string;
  public_jwks: Record<string, unknown>;
  signed_closure: string;
}

export interface PQCMigrationCampaignFinding {
  algorithm?: string;
  cipher?: string;
  disposition: "pending" | "remediated" | "excepted";
  disposition_reason?: string;
  dispositioned_at?: string;
  evidence_digests: string[];
  evidence_refs: string[];
  finding_digest: string;
  finding_id: string;
  key_bits?: number;
  kind: string;
  location: string;
  protocol?: string;
  readiness_digest?: string;
  remediation_method?: string;
}

export interface PQCMigrationCampaignList {
  items: PQCMigrationCampaign[];
  next_cursor?: string;
}

export interface PQCMigrationCampaignReadinessRequest {
  evidence_refs?: string[];
  status: "pending" | "passed" | "blocked";
}

export interface PQCMigrationCampaignStartRequest {
  deadline: string;
  finding_ids: string[];
  id?: string;
  name: string;
  owner: string;
  readiness_criteria: string[];
  wave: string;
}

export interface PQCMigrationCampaignUpdateRequest {
  deadline?: string;
  owner?: string;
  readiness_criteria?: string[];
  readiness_evidence_refs?: string[];
  readiness_status?: "pending" | "passed" | "blocked";
  wave?: string;
}

export interface PQCMigrationFindingDispositionRequest {
  disposition: "remediated" | "excepted";
  evidence_digests: string[];
  evidence_refs?: string[];
  method: string;
  reason: string;
}

export interface PendingApprovalRequest {
  action: "issue" | "create" | "rotate" | "revoke" | "sign" | "recover" | "delete" | "managedkey:rotate" | "managedkey:revoke" | "managedkey:zeroize";
  approval_count: number;
  created_at: string;
  evidence_refs: string[];
  expires_at: string;
  from_state?: string;
  id: string;
  intent_digest: string;
  reason?: string;
  requester: string;
  required_approvals: number;
  resource_id: string;
  resource_kind: "identity" | "secret" | "managed_key" | "code_signing" | "ephemeral";
  resource_name: string;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
  target_version: string;
  to_state?: string;
}

export interface PlatformAirGap {
  buyer_evidence_receipts: string[];
  capability: string;
  cloud_ai_fail_closed: boolean;
  data_residency_controls: string[];
  evidence_refs: string[];
  no_phone_home_default: boolean;
  public_telemetry_fail_closed: boolean;
  runtime_egress_guard: boolean;
  served: boolean;
}

export interface PlatformDistributionStatus {
  air_gap: PlatformAirGap;
  buyer_evidence_receipts: string[];
  capabilities: string[];
  capability: string;
  control_plane_lineage: string;
  core_audit_and_export: boolean;
  default_evaluation_mode: string;
  evidence_refs: string[];
  offline_license_verifier: boolean;
  production_mode: string;
  release_gates: string[];
  run_modes: PlatformRunMode[];
  served: boolean;
  supported_host_archives: PlatformHostArchive[];
}

export interface PlatformHostArchive {
  evaluation_only: boolean;
  os_arch: string;
  postgres_version: string;
  runtime_check: string;
  runtime_pin: string;
}

export interface PlatformRunMode {
  evidence_refs: string[];
  id: string;
  intended_use: string;
  label: string;
  nats_mode: string;
  packaging: string;
  postgres_mode: string;
  signer_process_model: string;
  tenant_isolation: string;
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

export interface PolicyVersion {
  activated_at?: string;
  activated_by?: string;
  active: boolean;
  audit_event?: string;
  change_ref?: string;
  created_at?: string;
  created_by?: string;
  description?: string;
  evidence_refs: string[];
  id: string;
  idempotency_key?: string;
  kind: "lifecycle";
  module?: string;
  module_sha256: string;
  package: string;
  query: string;
  rollback_from_id?: string;
  rollback_to_id?: string;
  rolled_back_at?: string;
  status: "draft" | "active" | "inactive" | "rolled_back";
  tenant_id: string;
  updated_at?: string;
}

export interface PolicyVersionActionRequest {
  evidence_refs?: string[];
  reason: string;
}

export interface PolicyVersionList {
  active?: PolicyVersion;
  counts: PolicyVersionListSummary;
  items: PolicyVersion[];
}

export interface PolicyVersionListSummary {
  active: number;
  draft: number;
  inactive: number;
  rolled_back: number;
  total: number;
}

export interface PolicyVersionRequest {
  change_ref?: string;
  description?: string;
  evidence_refs?: string[];
  id?: string;
  kind?: "lifecycle";
  module: string;
}

export interface PrivacyArchiveErasureAttestation {
  action: "deleted" | "legal_hold" | "cryptographic_shred";
  artifact_type: "backup" | "signed_audit_archive";
  artifact_uri?: string;
  attestation_id: string;
  attested_at: string;
  evidence_refs: string[];
  held_until?: string;
  reason?: string;
  requested_by_ref?: string;
  subject_ref: string;
}

export interface PrivacyArchiveErasureAttestationList {
  items: PrivacyArchiveErasureAttestation[];
  next_cursor?: string;
}

export interface PrivacyArchiveErasureAttestationRequest {
  action: "deleted" | "legal_hold" | "cryptographic_shred";
  artifact_type: "backup" | "signed_audit_archive";
  artifact_uri?: string;
  evidence_refs?: string[];
  held_until?: string;
  reason?: string;
  subject: string;
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
  agent_ids?: string[];
  agent_offboard_actor_ids?: string[];
  agent_offboard_reason_ids?: string[];
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
  code?: string;
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
  spec?: CertificateProfileSpec;
  version: number;
}

export interface ProfileApprovalResponse {
  approval_id: string;
  resource: string;
  state: string;
}

export interface ProfileList {
  items: Profile[];
  next_cursor?: string;
}

export interface ProfileRequest {
  name: string;
  spec: CertificateProfileSpec;
}

export interface ProfileRestorePreview {
  active_version: number;
  capability: "certificate_profile_recovery";
  changes: string[];
  name: string;
  next_version: number;
  operation: "restore_as_new_version";
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  reason: string;
  request_fingerprint: string;
  required_permission: string;
  risks: string[];
  source_spec: CertificateProfileSpec;
  source_spec_digest: string;
  source_version: number;
  verification_steps: string[];
}

export interface ProfileRestoreRequest {
  expected_active_version: number;
  reason: string;
}

export interface ProtocolProfileStatus {
  active: boolean;
  profile: "eval";
  protocols: string[];
}

export interface RCARequest {
  question: string;
  subject?: string;
}

export interface ReferencePriceBand {
  annual_usd: number;
  id: string;
  label: string;
  unit: string;
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

export interface RelayPluginEntry {
  digest: string;
  execution_context: "network_relay_wasm";
  grants: RelayPluginGrant[];
  name: string;
  publisher: string;
}

export interface RelayPluginGrant {
  capability: "fs.read" | "fs.write" | "net.dial";
  constraints: string[];
}

export interface RelayPluginRuntime {
  agent_id: string;
  agent_name: string;
  agent_status: string;
  metadata_only: boolean;
  plugins: RelayPluginEntry[];
  reported_at: string;
  signature_verified: boolean;
  signer_fingerprint: string;
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

export interface RenewalSLO {
  breached: boolean;
  budget_remaining_percent: number;
  failed: number;
  guidance: string;
  observed_percent: number;
  succeeded: number;
  target_percent: number;
  total: number;
  window_days: number;
}

export interface ResponseIntegrationDestinationRequest {
  allow_private_endpoint?: boolean;
  channel?: string;
  endpoint_url?: string;
  id?: string;
  instance_url?: string;
  issue_type?: string;
  private_egress_cidrs?: string[];
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

export interface RetirementChecklist {
  accounted: number;
  blocked: boolean;
  destruction_record?: string;
  guidance: string;
  key_id: string;
  outstanding: RetirementDependent[];
  refusal_record?: string;
  retirement_status?: string;
  total: number;
}

export interface RetirementDependent {
  detail?: string;
  kind: string;
  ref: string;
}

export interface RevocationCachePosture {
  guidance: string;
  items: RevocationCacheStatus[];
  observed: boolean;
  summary: RevocationCacheSummary;
}

export interface RevocationCacheStatus {
  agent_id: string;
  agent_name: string;
  cache_id: string;
  cached_responses: number;
  detail_code?: string;
  fresh: boolean;
  issuer_fingerprint: string;
  last_validated_at?: string;
  local_path: string;
  metadata_only: boolean;
  next_update?: string;
  protocol: "crl" | "ocsp";
  refused_requests: number;
  reported_at: string;
  segment: string;
  served_requests: number;
  signature_verified: boolean;
  signer_fingerprint: string;
  status: "fresh" | "stale" | "empty" | "error";
  this_update?: string;
}

export interface RevocationCacheSummary {
  caches: number;
  empty: number;
  error: number;
  fresh: number;
  stale: number;
}

export interface RevocationEndpointHealth {
  certificate_fingerprint: string;
  certificate_id: string;
  certificate_serial: string;
  certificate_subject: string;
  detail_code: string;
  endpoint: string;
  evidence_digest: string;
  issuer_fingerprint?: string;
  issuer_subject: string;
  latency_ms: number;
  next_update?: string;
  observed_at: string;
  observed_by_agent_id: string;
  observed_by_agent_name: string;
  probe_id: string;
  protocol: "crl" | "ocsp";
  responder_subject?: string;
  response_status?: "good" | "revoked" | "unknown";
  revoked_count?: number;
  signature_verified: boolean;
  status: "fresh" | "expiring" | "stale" | "unreachable" | "unparseable";
  target_key: string;
  this_update?: string;
}

export interface RevocationHealth {
  guidance: string;
  items: RevocationEndpointHealth[];
  observed: boolean;
  summary: RevocationHealthSummary;
}

export interface RevocationHealthSummary {
  endpoints: number;
  expiring: number;
  fresh: number;
  stale: number;
  unparseable: number;
  unreachable: number;
}

export interface RiskComponents {
  age: number;
  exposure: number;
  owner: number;
  privilege: number;
  rotation: number;
  sensitivity: number;
}

export interface RogueCertificateFinding {
  certificate_id?: string;
  discovered_at?: string;
  discovery_id?: string;
  dns_names?: string[];
  evidence_refs: string[];
  finding_types: string[];
  fingerprint?: string;
  id: string;
  issuer?: string;
  kind: "rogue_certificate" | "non_compliant_certificate";
  lifetime_days?: number;
  log_index?: number;
  log_url?: string;
  matched_domain?: string;
  not_after?: string;
  not_before?: string;
  owner_id?: string;
  policy_max_days?: number;
  policy_status: "rogue" | "non_compliant";
  recommendation: string;
  risk_score: number;
  run_id?: string;
  serial?: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  source_id?: string;
  status?: string;
  subject: string;
}

export interface RogueCertificatePosture {
  capability: string;
  coverage: string[];
  evidence_refs: string[];
  findings: RogueCertificateFinding[];
  generated_at: string;
  recommended_actions: string[];
  summary: RogueCertificateSummary;
}

export interface RogueCertificateSummary {
  critical: number;
  ct_unexpected: number;
  expired_active: number;
  findings: number;
  high: number;
  issuer_missing: number;
  lifetime_violations: number;
  low: number;
  medium: number;
  non_compliant: number;
  owner_missing: number;
  recommendations: number;
  rogue: number;
  total_analyzed: number;
  weak_key: number;
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

export interface SSHFleetHost {
  first_observed: string;
  key_types: string[];
  keys: number;
  last_observed: string;
  location: string;
  orphaned_keys: number;
  sources: string[];
  standing_keys: number;
  under_ca: boolean;
}

export interface SSHFleetInventory {
  host_count: number;
  hosts: SSHFleetHost[];
  hosts_not_under_ca: number;
  key_count: number;
  orphaned_key_count: number;
  standing_key_count: number;
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
  approval_count: number;
  approvals: number;
  approver: string;
  id: string;
  intent_digest: string;
  required_approvals: number;
  resource: string;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
}

export interface SecretApprovalRequest {
  action: "rotate" | "recover" | "delete";
  intent_digest: string;
  request_id: string;
}

export interface SecretCreateRequest {
  name: string;
  owner_id?: string;
  value: string;
}

export interface SecretImportRequest {
  prefix?: string;
  values: Record<string, unknown>;
}

export interface SecretMeta {
  created_at?: string;
  name: string;
  owner_id?: string;
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

export interface SecretRotateRequest {
  value: string;
}

export interface SecretRotation {
  completed: boolean;
  error?: string;
  failed_phase?: string;
  key: string;
  new_ref: string;
  old_ref: string;
  queued: boolean;
  rollback_attempted: boolean;
  rollback_error?: string;
  rollback_failed: boolean;
  rolled_back: boolean;
}

export interface SecretRotationDueRun {
  complete: boolean;
  deferred: SecretRotationScheduleDeferred[];
  failed_schedule_id?: string;
  partial: boolean;
  ran: number;
  run_limit_reached: boolean;
  runs: SecretRotationScheduleRun[];
  scan_limit_reached: boolean;
  scanned: number;
  system_error?: string;
}

export interface SecretRotationRequest {
  key: string;
  old_ref: string;
  provider: string;
  remote_key?: string;
  target?: string;
  ttl_seconds?: number;
}

export interface SecretRotationSchedule {
  created_at: string;
  enabled: boolean;
  id: string;
  interval_seconds: number;
  key: string;
  last_error?: string;
  last_new_ref?: string;
  last_run_at?: string;
  last_run_id?: string;
  last_run_status: "" | "completed" | "queued" | "failed" | "rolled_back" | "rollback_failed" | "retire_pending" | "delivery_failed" | "unsupported";
  name: string;
  next_run_at: string;
  old_ref: string;
  provider: string;
  tenant_id: string;
  updated_at: string;
}

export interface SecretRotationScheduleDeferred {
  due_at: string;
  error?: string;
  reason: "approval_pending" | "command_in_flight" | "command_claimed" | "config_revision_unanchored";
  schedule_id: string;
}

export interface SecretRotationScheduleList {
  items: SecretRotationSchedule[];
  next_cursor?: string;
}

export interface SecretRotationScheduleRequest {
  enabled?: boolean;
  interval_seconds: number;
  key: string;
  name: string;
  next_run_at?: string;
  old_ref: string;
  provider: string;
}

export interface SecretRotationScheduleRun {
  due_at: string;
  error?: string;
  ran_at: string;
  reconciled: boolean;
  rotation: SecretRotation;
  run_id: string;
  schedule_id: string;
  status: "completed" | "queued" | "failed" | "rolled_back" | "rollback_failed" | "retire_pending" | "delivery_failed" | "unsupported";
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

export interface SecretSyncWorkloadIdentitySource {
  allowed_remote_key_prefixes: string[];
  audience: string;
  azure_tenant_id: string;
  client_id: string;
  created_at: string;
  enabled: boolean;
  id: string;
  last_exchange_at?: string;
  last_failure_at?: string;
  name: string;
  provider: "aws" | "gcp" | "azure";
  role_arn: string;
  service_account: string;
  status: "ready" | "active" | "disabled" | "offline_disabled" | "exchange_failed";
  status_reason: string;
  subject: string;
  target_id: string;
  target_scope: string;
  tenant_id: string;
  token_expires_at?: string;
  trust_source_id: string;
  updated_at: string;
  workload_proof_ref: string;
}

export interface SecretSyncWorkloadIdentitySourceList {
  items: SecretSyncWorkloadIdentitySource[];
  next_cursor?: string;
}

export interface SecretSyncWorkloadIdentitySourceRequest {
  allowed_remote_key_prefixes?: string[];
  audience: string;
  azure_tenant_id?: string;
  client_id?: string;
  enabled?: boolean;
  name: string;
  provider?: "aws" | "gcp" | "azure";
  role_arn?: string;
  service_account?: string;
  subject: string;
  target_id: string;
  target_scope?: string;
  trust_source_id: string;
  workload_proof_ref: string;
}

export interface SecretValue {
  name: string;
  value: string;
  version?: number;
}

export interface SecretWorkloadInjection {
  annotations: string[];
  architecture_controls: string[];
  capability: string;
  crd: SecretWorkloadInjectionCRD;
  evidence_refs: string[];
  generated_at: string;
  modes: SecretWorkloadInjectionMode[];
  recommended_next_actions: string[];
  residuals: string[];
  secret_handling: string;
  served: boolean;
  sidecar_command: string[];
  sync_dependency: string;
  workload_kinds: string[];
}

export interface SecretWorkloadInjectionCRD {
  api_group: string;
  api_version: string;
  evidence_ref: string;
  kind: string;
  owns: string[];
  plural: string;
  status: string;
}

export interface SecretWorkloadInjectionMode {
  capabilities: string[];
  delivered_by: string;
  id: string;
  name: string;
  secret_handling: string;
  workload_change: string;
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

export interface SystemDependency {
  error?: string;
  name: string;
  ready: boolean;
}

export interface SystemReadout {
  build_date: string;
  commit: string;
  dependencies: SystemDependency[];
  deployment?: DeploymentTriState;
  fips_module_active: boolean;
  go_version: string;
  idempotency_results: IdempotencyResultProtectionReadout;
  signer_mode: "child" | "external" | "none";
  started_at: string;
  uptime_seconds: number;
  version: string;
}

export interface TenantKeyDomainMigrateRequest {
  wrapper_id: string;
  wrapper_kind?: "local_file";
}

export interface TenantKeyDomainSealReceipt {
  accepted: boolean;
  operation_id: string;
  state: string;
  status_url: string;
}

export interface TenantKeyDomainStatus {
  domain_id?: string;
  failure?: string;
  failure_code?: string;
  generation?: number;
  last_transition_actor?: string;
  last_transition_at?: string;
  last_transition_evidence_refs: string[];
  last_transition_type?: string;
  legacy_history_exposure: string;
  local_wrapper_zero_egress: boolean;
  migration_stage?: string;
  operation_id?: string;
  operation_kind?: string;
  operation_status?: string;
  progress_completed: number;
  progress_total: number;
  protection_mode: string;
  recovery: string;
  remote_wrapper_state: string;
  retryable: boolean;
  served: boolean;
  state: string;
  wrapper_id?: string;
  wrapper_kind?: string;
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

export interface TicketIntakeInput {
  allow_private_endpoint?: boolean;
  enabled?: boolean;
  instance_url: string;
  interval_seconds: number;
  jira_project?: string;
  justification_field?: string;
  private_egress_cidrs?: string[];
  profile_field: string;
  query?: string;
  requester_field?: string;
  sn_table?: "incident" | "sc_req_item" | "sc_request" | "change_request";
  subject_field: string;
  system: "servicenow" | "jira";
  token_ref: string;
}

export interface TicketIntakeSchedule {
  allow_private_endpoint?: boolean;
  configured: boolean;
  coverage_complete: boolean;
  eligible_count: number;
  enabled: boolean;
  expected_count?: number;
  guidance: string;
  instance_url?: string;
  interval_seconds?: number;
  jira_project?: string;
  justification_field?: string;
  last_attempt_at?: string;
  last_error?: string;
  last_run_at?: string;
  next_cursor?: string;
  pages_completed: number;
  private_egress_cidrs?: string[];
  profile_field?: string;
  query?: string;
  read_count: number;
  requester_field?: string;
  skipped_count: number;
  sn_table?: "incident" | "sc_req_item" | "sc_request" | "change_request";
  subject_field?: string;
  sweep_id?: string;
  sweep_started_at?: string;
  system?: "servicenow" | "jira";
  token_ref?: string;
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

export interface TransitKeyList {
  items: TransitKey[];
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
  expected_version?: number;
  reason?: string;
  subject_csr_pem?: string;
  to: "issued" | "deployed" | "renewing" | "renewal_failed" | "revoked" | "retired";
}

export interface UnownedIdentity {
  detail?: string;
  identity_id: string;
  name: string;
  reason: "no_owner" | "owner_missing_application_model" | "ownership_never_attested" | "ownership_attestation_stale";
  status?: string;
}

export interface UnownedQueue {
  counts: Record<string, unknown>;
  guidance: string;
  items: UnownedIdentity[];
  total: number;
}

export interface UnrecordedCustodyCertificate {
  fingerprint: string;
  id: string;
  missing_fields: string[];
  subject: string;
}

export interface UnvaultedSecretDetectionSource {
  capabilities: string[];
  configured_count: number;
  detection_mode: string;
  evidence_refs: string[];
  findings_kind: string;
  id: string;
  name: string;
  secret_handling: string;
  source_kind: string;
}

export interface UnvaultedSecretPosture {
  architecture_controls: string[];
  capability: string;
  configured_sync_targets: string[];
  configured_vaults: string[];
  detection_sources: UnvaultedSecretDetectionSource[];
  evidence_refs: string[];
  generated_at: string;
  recommended_next_actions: string[];
  residuals: string[];
  secret_handling: string;
  served: boolean;
  summary: UnvaultedSecretSummary;
  vault_providers: UnvaultedSecretVaultProvider[];
  workflow: string[];
}

export interface UnvaultedSecretSummary {
  cloud_secret_sources: number;
  leaked_secret_findings: number;
  repository_sources: number;
  sync_targets_configured: number;
  third_party_sources: number;
  vault_providers_supported: number;
  vault_providers_visible: number;
}

export interface UnvaultedSecretVaultProvider {
  augmentation_mode: string;
  capabilities: string[];
  discovery_configured: boolean;
  discovery_source_count: number;
  evidence_refs: string[];
  id: string;
  name: string;
  sync_configured: boolean;
  sync_supported: boolean;
}

export interface UpgradeArtifact {
  arch: string;
  os: string;
  sha256: string;
  url: string;
}

export interface UrgentRiskProjectionSummary {
  analyzed: number;
  critical: number;
  high: number;
}

export interface UrgentRiskSummary {
  contextual_priorities: UrgentRiskProjectionSummary;
  credential_risk: UrgentRiskProjectionSummary;
  critical: number;
  high: number;
  included_projections: string[];
  scope: string;
  status: "complete";
  unique_analyzed: number;
  urgent: number;
}

export interface UsageMeterDefinition {
  classification: string;
  name: string;
  notes?: string;
  primary_billable: boolean;
}

export interface WorkloadAttesterTrustSource {
  audience?: string;
  created_at: string;
  enabled: boolean;
  expected_nonce_base64?: string;
  id: string;
  issuer?: string;
  jwks: Record<string, unknown>;
  last_rotated_at?: string;
  method: "aws_iid" | "azure_imds" | "gcp_iit" | "github_oidc" | "k8s_sat" | "tpm";
  name: string;
  revoked_at?: string;
  revoked_reason?: string;
  root_certs_pem: string[];
  rotation_version: number;
  tenant_id: string;
  updated_at: string;
}

export interface WorkloadAttesterTrustSourceList {
  items: WorkloadAttesterTrustSource[];
  next_cursor?: string;
}

export interface WorkloadAttesterTrustSourceRequest {
  audience?: string;
  enabled?: boolean;
  expected_nonce_base64?: string;
  issuer?: string;
  jwks?: Record<string, unknown>;
  method: "aws_iid" | "azure_imds" | "gcp_iit" | "github_oidc" | "k8s_sat" | "tpm";
  name: string;
  root_certs_pem?: string[];
}

export interface WorkloadAttesterTrustSourceRevokeRequest {
  reason?: string;
}

export interface WorkloadAttesterTrustSourceRevoked {
  trust_source: WorkloadAttesterTrustSource;
}

export interface WorkloadAttesterTrustSourceRotateRequest {
  audience?: string;
  expected_nonce_base64?: string;
  issuer?: string;
  jwks?: Record<string, unknown>;
  reason?: string;
  root_certs_pem?: string[];
}

export interface WorkloadAttesterTrustSourceRotated {
  trust_source: WorkloadAttesterTrustSource;
}
