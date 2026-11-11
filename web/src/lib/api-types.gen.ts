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
  upstream_authority_id?: string;
  upstream_error_class?: "not_advertised" | "upstream_timeout" | "upstream_unavailable";
  upstream_fetched_at?: string;
  upstream_next_poll_at?: string;
  upstream_provenance?: "authenticated_issuer" | "issuer_key_id";
  upstream_status?: "not_requested" | "queued" | "ready" | "error" | "unavailable";
  window_source: "served_acme" | "upstream_ca" | "local_estimate" | "none";
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

export interface ACMEAccount {
  certificates: number;
  contact?: string[];
  eab_key_id?: string;
  id: string;
  orders: number;
  status: "valid" | "deactivated";
}

export interface ACMEAccountList {
  generated_at: string;
  items: ACMEAccount[];
  served: boolean;
}

export interface ACMEAuthorization {
  challenges: ACMEChallenge[];
  created_at: string;
  domain: string;
  id: string;
  status: string;
}

export interface ACMEChallenge {
  id: string;
  status: string;
  type: string;
}

export interface ACMEDNS01CAAPolicyEvidence {
  allowed_issuers: string[];
  configured_issuer?: string;
  fail_closed: boolean;
  governing_name?: string;
  recommended_records: string[];
  records: ACMEDNS01CAAPolicyRecord[];
  recovery_steps: string[];
  relevant_tag: "issue" | "issuewild";
  source: "authoritative_live_dns";
  status: "not_configured" | "unrestricted" | "allowed" | "denied" | "lookup_failed";
  wildcard: boolean;
}

export interface ACMEDNS01CAAPolicyRecord {
  flag: number;
  tag: string;
  value: string;
}

export interface ACMEDNS01Preflight {
  caa_policy: ACMEDNS01CAAPolicyEvidence;
  checks: ACMEDNS01PreflightCheck[];
  config_id: string;
  domain: string;
  failed_checks: string[];
  method_rationale?: string;
  ready: boolean;
  record_name: string;
  selected_method: string;
  txt_observation: { error?: string; observed: string[]; record_name: string; source: "caller_supplied" | "live_dns" | "none" };
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
  allowed_methods?: ("http-01" | "dns-01" | "tls-alpn-01" | "dns-persist-01")[];
  caa_issuer_domain?: string;
  challenge_domain?: string;
  config?: Record<string, unknown>;
  credential_refs?: Record<string, unknown>;
  delegation_target?: string;
  name: string;
  provider: string;
  zone?: string;
}

export interface ACMEDNS01QualificationCheck {
  detail: string;
  id: string;
  label: string;
  passed: boolean;
  recovery: string;
}

export interface ACMEDNS01QualificationPreview {
  blockers: string[];
  checks: ACMEDNS01QualificationCheck[];
  config_id: string;
  config_name: string;
  credential_reference_fields: string[];
  domain: string;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_signer_calls: string[];
  execute_writes: string[];
  least_privilege_checklist: string[];
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  provider: string;
  ready: boolean;
  record_name: string;
  recovery_steps: string[];
  secret_data_handling: string;
  wildcard: boolean;
}

export interface ACMEDNS01QualificationRequest {
  domain: string;
}

export interface ACMEDNS01QualificationRun {
  attempts: number;
  cleanup_status: "not_needed" | "pending" | "delivered" | "failed";
  completed_at?: string;
  config_id: string;
  config_name: string;
  domain: string;
  duration_ms: number;
  error_category?: string;
  id: string;
  propagation_status: "not_run" | "pending" | "passed" | "failed";
  provider: string;
  record_name: string;
  recovery_steps: string[];
  secret_data_handling: string;
  stage: "review" | "publish" | "propagation" | "cleanup" | "complete";
  started_at: string;
  status: "running" | "passed" | "failed" | "recovery_required";
}

export interface ACMEDNS01QualificationRunList {
  items: ACMEDNS01QualificationRun[];
}

export interface ACMEDeviceAttestationPolicy {
  allowed_algorithms?: number[];
  allowed_identifiers?: string[];
  attestation_roots_pem?: string[];
  enabled?: boolean;
  format?: "tpm";
  max_age?: string;
}

export interface ACMEDomainValidationActivity {
  authorization_status: "pending" | "valid";
  challenge_methods: ("http-01" | "dns-01" | "tls-alpn-01" | "device-attest-01")[];
  created_at: string;
  domain: string;
  order_id: string;
  order_status: "pending" | "ready" | "processing" | "valid";
  validated_method?: "http-01" | "dns-01" | "tls-alpn-01" | "device-attest-01";
  validation_skipped: boolean;
}

export interface ACMEEABCredential {
  accounts_bound: number;
  allowed_identifiers?: string[];
  disabled_by_operator: boolean;
  disabled_in_config: boolean;
  hmac_key_ref?: string;
  key_id: string;
  last_used_at?: string;
  max_orders?: number;
  not_after?: string;
  orders_created: number;
  orders_denied: number;
  profile?: string;
  reason?: string;
  state: "active" | "disabled" | "expired" | "exhausted" | "unavailable";
}

export interface ACMEEABPolicyUpdate {
  allowed_identifiers?: string[];
  max_orders?: number;
  not_after?: string;
  profile?: string;
}

export interface ACMEEABPosture {
  generated_at: string;
  items: ACMEEABCredential[];
  required: boolean;
  served: boolean;
}

export interface ACMEEABRotationRequest {
  hmac_key_ref: string;
  successor_key_id: string;
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
  issuing_profile_auth_mode: "public_trust" | "trust_authenticated";
  issuing_profile_ready: boolean;
  next_action: ACMEOperatorAction;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  served: boolean;
  tenant_bound: boolean;
  validation_activity: ACMEDomainValidationActivity[];
  warnings: string[];
}

export interface ACMEOrder {
  account_id: string;
  auth_mode?: string;
  authorizations: ACMEAuthorization[];
  certificate_fingerprint?: string;
  certificate_id?: string;
  certificate_record_id?: string;
  certificate_serial?: string;
  created_at: string;
  id: string;
  identifiers: string[];
  profile?: string;
  replaces?: string;
  revoked: boolean;
  status: string;
}

export interface ACMEOrderList {
  account_id?: string;
  generated_at: string;
  items: ACMEOrder[];
  served: boolean;
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

export interface ADCSDatabaseCollectRequest {
  ca_config: string;
  relay_agent_id: string;
}

export interface ADCSDatabaseCollection {
  attempts: number;
  ca_config: string;
  collection_id: string;
  completed_at?: string;
  last_error?: string;
  relay_agent_id: string;
  requested_at?: string;
  status: "queued" | "running" | "collected" | "failed";
}

export interface ADCSDatabaseIngest {
  ca_config: string;
  last_error?: string;
  rows: Record<string, unknown>[];
  source?: string;
}

export interface ADCSDatabaseList {
  collections: ADCSDatabaseCollection[];
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

export interface ADCSDecision {
  approval_request_id: string;
  ca_config: string;
  decided_at?: string;
  decision: "approve" | "deny";
  disposition?: string;
  failure?: string;
  id: string;
  issuer_id: string;
  queued_at: string;
  reason: string;
  request_id: number;
  requested_by: string;
  serial?: string;
  status: "queued" | "decided" | "failed";
}

export interface ADCSDecisionApproval {
  approval_count: number;
  approval_intent_digest: string;
  approval_request_id: string;
  ca_config: string;
  decision: "approve" | "deny";
  expires_at: string;
  issuer_id: string;
  reason: string;
  request_id: number;
  required_approvals: number;
  status: string;
}

export interface ADCSDecisionList {
  items: ({ approval_request_id: string; ca_config: string; decided_at?: string; decision: "approve" | "deny"; disposition?: string; failure?: string; id: string; issuer_id: string; queued_at: string; reason: string; request_id: number; requested_by: string; serial?: string; status: "queued" | "decided" | "failed" })[];
}

export interface ADCSDecisionRequest {
  decision: "approve" | "deny";
  reason: string;
}

export interface ADCSDecisionStart {
  approval_intent_digest: string;
  approval_request_id: string;
}

export interface ADCSDriftHistory {
  items: ADCSTemplateDrift[];
}

export interface ADCSEndpointProbeCoverage {
  complete: boolean;
  next_offset: number;
  offset: number;
  plan_digest: string;
  reason?: "invalid_directory_hostname" | "outside_configured_dns_suffixes";
  state: "in_page" | "not_in_page" | "host_unassessed";
  targets_on_page: number;
  total_targets: number;
}

export interface ADCSEndpointProbePage {
  complete: boolean;
  host_issues: ({ enrollment_service: string; reason: "invalid_directory_hostname" | "outside_configured_dns_suffixes" })[];
  next_offset: number;
  offset: number;
  plan_digest: string;
  targets: ADCSEndpointProbeTarget[];
  total_targets: number;
}

export interface ADCSEndpointProbeTarget {
  enrollment_service: string;
  kind: "web_enrollment" | "ndes" | "ndes_admin";
  source: "configured" | "ldap_dns" | "configured_and_ldap_dns";
  url: string;
}

export interface ADCSEnrollmentACL {
  allowed: string[];
  denied: string[];
  unassessed_aces: number;
}

export interface ADCSEnrollmentEndpoint {
  authentication: string[];
  extended_protection: "enabled" | "disabled" | "unobserved";
  http_status?: number;
  kind: "web_enrollment" | "ndes" | "ndes_admin";
  not_checked_reason?: "deadline_or_cancellation";
  source?: "configured" | "ldap_dns" | "configured_and_ldap_dns";
  state: "anonymous_access" | "authentication_required" | "redirected" | "not_found" | "unreachable" | "reachable_other" | "not_checked";
  tls_verified: boolean;
  url: string;
}

export interface ADCSEnrollmentMember {
  dn: string;
  kind: "user" | "computer";
  path: string[];
  sid: string;
  via_trustees: string[];
}

export interface ADCSEnrollmentMembership {
  budget_exceeded?: boolean;
  domain_dn: string;
  limitations: string[];
  matching_rule: "1.2.840.113556.1.4.1941";
  members: ADCSEnrollmentMember[];
  observed_at: string;
  state: "complete" | "incomplete";
  trustees: ADCSEnrollmentTrustee[];
}

export interface ADCSEnrollmentService {
  agent_restriction_source: string;
  agent_restriction_state: "enabled" | "disabled" | "unobserved";
  dns_name?: string;
  domain: string;
  endpoint_probe?: ADCSEndpointProbeCoverage;
  endpoints: ADCSEnrollmentEndpoint[];
  enrollment_web_services: string[];
  findings: ADCSTemplateFinding[];
  observed_at: string;
  observed_by: string;
  service: string;
  worst_severity: "" | "medium" | "high" | "critical";
}

export interface ADCSEnrollmentTrustee {
  direct_member_dns?: string[];
  dn?: string;
  nodes?: ADCSMembershipNode[];
  positive_control: boolean;
  sid: string;
  state: "complete" | "unresolved" | "read_failed" | "invalid_identity" | "non_security_group" | "membership_unconfirmed" | "incomplete_search" | "incomplete_attributes" | "ambiguous_identity" | "matching_rule_unconfirmed";
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

export interface ADCSIssuerHealth {
  id: string;
  issued_in_window: number;
  last_failure_at?: string;
  last_failure_cause?: string;
  last_failure_remediation?: string;
  last_failure_summary?: string;
  last_success_at?: string;
  name: string;
  status: "healthy" | "degraded" | "failing" | "idle";
}

export interface ADCSIssuerHealthList {
  guidance: string;
  items: ADCSIssuerHealth[];
  window_days: number;
}

export interface ADCSMembershipNode {
  dn: string;
  kind: "group" | "user" | "computer";
  parents?: string[];
  security_group?: boolean;
  sid: string;
}

export interface ADCSModernizeChange {
  code: string;
  detail: string;
}

export interface ADCSModernizePlan {
  blockers: string[];
  capability: string;
  changes: ADCSModernizeChange[];
  dns_suffix: string;
  domain: string;
  effect_free: boolean;
  profile_name: string;
  ready: boolean;
  spec: CertificateProfileSpec;
  template: string;
}

export interface ADCSModernizeRequest {
  dns_suffix?: string;
  domain: string;
  profile_name?: string;
  template: string;
}

export interface ADCSModernizeResult {
  approval_id?: string;
  changes: ADCSModernizeChange[];
  profile?: Profile;
  state: "created" | "awaiting_approval";
}

export interface ADCSObservedInventory {
  endpoint_probe_page?: ADCSEndpointProbePage;
  enrollment_services: ADCSObservedService[];
  templates: ADCSObservedTemplate[];
}

export interface ADCSObservedService {
  agent_restrictions: ADCSAgentRestrictions;
  dns_name?: string;
  endpoint_probe?: ADCSEndpointProbeCoverage;
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
  enrollment_acl?: ADCSEnrollmentACL;
  enrollment_membership?: ADCSEnrollmentMembership;
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
  enrollment_service_limit_reached?: boolean;
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
  enrollment_membership?: ADCSEnrollmentMembership;
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

export interface AWSHoneyAccount {
  account_id: string;
  id: string;
  max_ttl_seconds: number;
  poll_interval_seconds: number;
  regions: string[];
  trail?: { accounts: string[]; bucket: string; organization_id?: string; read?: { last_object_at?: string; objects: number; records: number; refused: number; uses: number } };
}

export interface AWSHoneyAccountCatalog {
  accounts: AWSHoneyAccount[];
  detection_scope: string;
}

export interface AWSHoneyScan {
  cycle: number;
  delivery_attempts?: number;
  delivery_error?: string;
  delivery_status?: string;
  gap_since?: string;
  honey_id: string;
  last_success_at?: string;
  page: number;
  region: string;
  watermark: string;
  window_end?: string;
  window_start?: string;
}

export interface AWSHoneyToken {
  alarm_generation?: number;
  aws_access_key_id: string;
  aws_account_config_id: string;
  aws_account_id: string;
  aws_lease_id: string;
  aws_poll_interval_seconds: number;
  aws_regions: string[];
  created_at: string;
  id: string;
  kind: "aws";
  name: string;
  placement: string;
  state: "active" | "triggered" | "retiring" | "retirement_failed" | "revoked" | "failed";
  trigger_method?: string;
  trigger_path?: string;
  triggered_at?: string;
}

export interface AWSHoneyTokenCreateRequest {
  account_id: string;
  name: string;
  placement: string;
  preview_fingerprint?: string;
  ttl_seconds: number;
}

export interface AWSHoneyTokenCreateResponse {
  access_key_id: string;
  alarm_generation?: number;
  aws_access_key_id: string;
  aws_account_config_id: string;
  aws_account_id: string;
  aws_lease_id: string;
  aws_poll_interval_seconds: number;
  aws_regions: string[];
  created_at: string;
  id: string;
  kind: string;
  name: string;
  placement: string;
  secret_access_key: string;
  state: string;
}

export interface AWSHoneyTokenDetail {
  alarm_generation?: number;
  aws_access_key_id?: string;
  aws_account_config_id?: string;
  aws_account_id?: string;
  aws_lease_id?: string;
  aws_poll_interval_seconds?: number;
  aws_regions?: string[];
  created_at: string;
  id: string;
  kind: string;
  lease: DynamicLease;
  monitoring: AWSHoneyScan[];
  name: string;
  placement: string;
  state: string;
  trigger_method?: string;
  trigger_path?: string;
  triggered_at?: string;
  uses: AWSHoneyUse[];
}

export interface AWSHoneyTokenList {
  items: AWSHoneyToken[];
  next_cursor?: string;
}

export interface AWSHoneyTokenPreview {
  account_attachment_id: string;
  aws_account_id: string;
  detection_scope: string;
  effect_free: boolean;
  iam_actions: string[];
  name: string;
  placement: string;
  preview_fingerprint: string;
  ready: boolean;
  recovery: string;
  regions: string[];
  remote_authority_checked: boolean;
  ttl_seconds: number;
  verification: string;
}

export interface AWSHoneyUse {
  account_id?: string;
  detected_at: string;
  error_code?: string;
  event_category?: string;
  event_id: string;
  event_name: string;
  event_source: string;
  event_time: string;
  found_in: "lookup" | "trail";
  recipient_account_id?: string;
  region: string;
  source_ip_address: string;
  user_agent: string;
}

export interface AccessActivityExport {
  excludes: string[];
  fields: string[];
  filters: { bundle?: string; principal?: string; q?: string };
  generated_at: string;
  items: ({ action: "saved" | "deleted" | "granted" | "ungranted" | "run_issued" | "run_revoked" | "run_used"; actor?: string; at: string; bundle_ids: string[]; bundle_names: string[]; detail?: string; grant_id?: string; principal?: string; run_id?: string })[];
  kind: string;
  rows: number;
  truncated: boolean;
}

export interface AccessActivityList {
  items: ({ action: "saved" | "deleted" | "granted" | "ungranted" | "run_issued" | "run_revoked" | "run_used"; actor?: string; at: string; bundle_ids: string[]; bundle_names: string[]; detail?: string; grant_id?: string; principal?: string; run_id?: string })[];
  next_cursor: string;
}

export interface AccessAuthority {
  bounds: { lasting: string; max_run_ttl_seconds: number; outage: string; revocation: string };
  computed_at: string;
  grants: ({ bundle_id: string; expires_at?: string; granted_at: string; granted_by: string; id: string; live: boolean; principal: string; principal_type: "user" | "machine"; removed_at?: string; removed_by?: string; removed_reason?: string })[];
  permissions: { permission: string; via: { bundle_id: string; bundle_name: string; expires_at?: string; grant_id: string }[] }[];
  principal: string;
  runs: ({ bundle_ids: string[]; bundle_names: string[]; chain: ({ actor: string; at: string; detail: string; step: "bundle_saved" | "granted" | "run_issued" })[]; effective: string[]; expires_at: string; grant_ids: string[]; id: string; issued_at: string; issued_by: string; label?: string; permissions: string[]; principal: string; revoked_at?: string; revoked_by?: string; status: "active" | "no_authority" | "expired" | "revoked" })[];
}

export interface AccessBundle {
  access_targets: ({ roles: string[]; target_id: string; target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" })[];
  active_runs: number;
  audiences: ("custom_agent" | "ci" | "mcp_server")[];
  created_at: string;
  created_by: string;
  description: string;
  grants?: ({ bundle_id: string; expires_at?: string; granted_at: string; granted_by: string; id: string; live: boolean; principal: string; principal_type: "user" | "machine"; removed_at?: string; removed_by?: string; removed_reason?: string })[];
  id: string;
  live_grants: number;
  max_run_ttl_seconds: number;
  name: string;
  permissions: string[];
  revision: number;
  runs?: ({ bundle_ids: string[]; bundle_names: string[]; chain: ({ actor: string; at: string; detail: string; step: "bundle_saved" | "granted" | "run_issued" })[]; effective: string[]; expires_at: string; grant_ids: string[]; id: string; issued_at: string; issued_by: string; label?: string; permissions: string[]; principal: string; revoked_at?: string; revoked_by?: string; status: "active" | "no_authority" | "expired" | "revoked" })[];
  updated_at: string;
}

export interface AccessBundleDeleted {
  deleted: boolean;
  deleted_at: string;
  grants_affected: number;
  id: string;
  name: string;
  runs_affected: number;
}

export interface AccessBundleGrantChange {
  authority: { bounds: { lasting: string; max_run_ttl_seconds: number; outage: string; revocation: string }; computed_at: string; grants: ({ bundle_id: string; expires_at?: string; granted_at: string; granted_by: string; id: string; live: boolean; principal: string; principal_type: "user" | "machine"; removed_at?: string; removed_by?: string; removed_reason?: string })[]; permissions: { permission: string; via: { bundle_id: string; bundle_name: string; expires_at?: string; grant_id: string }[] }[]; principal: string; runs: ({ bundle_ids: string[]; bundle_names: string[]; chain: ({ actor: string; at: string; detail: string; step: "bundle_saved" | "granted" | "run_issued" })[]; effective: string[]; expires_at: string; grant_ids: string[]; id: string; issued_at: string; issued_by: string; label?: string; permissions: string[]; principal: string; revoked_at?: string; revoked_by?: string; status: "active" | "no_authority" | "expired" | "revoked" })[] };
  grant: { bundle_id: string; expires_at?: string; granted_at: string; granted_by: string; id: string; live: boolean; principal: string; principal_type: "user" | "machine"; removed_at?: string; removed_by?: string; removed_reason?: string };
}

export interface AccessBundleGrantRequest {
  expires_at?: string;
  principal: string;
  principal_type: "user" | "machine";
}

export interface AccessBundleList {
  items: ({ access_targets: ({ roles: string[]; target_id: string; target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" })[]; active_runs: number; audiences: ("custom_agent" | "ci" | "mcp_server")[]; created_at: string; created_by: string; description: string; grants?: ({ bundle_id: string; expires_at?: string; granted_at: string; granted_by: string; id: string; live: boolean; principal: string; principal_type: "user" | "machine"; removed_at?: string; removed_by?: string; removed_reason?: string })[]; id: string; live_grants: number; max_run_ttl_seconds: number; name: string; permissions: string[]; revision: number; runs?: ({ bundle_ids: string[]; bundle_names: string[]; chain: ({ actor: string; at: string; detail: string; step: "bundle_saved" | "granted" | "run_issued" })[]; effective: string[]; expires_at: string; grant_ids: string[]; id: string; issued_at: string; issued_by: string; label?: string; permissions: string[]; principal: string; revoked_at?: string; revoked_by?: string; status: "active" | "no_authority" | "expired" | "revoked" })[]; updated_at: string })[];
}

export interface AccessBundleRequest {
  access_targets?: ({ roles: string[]; target_id: string; target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" })[];
  audiences?: ("custom_agent" | "ci" | "mcp_server")[];
  description?: string;
  max_run_ttl_seconds?: number;
  name: string;
  permissions: string[];
  revision?: number;
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

export interface AccessRun {
  bundle_ids: string[];
  bundle_names: string[];
  chain: ({ actor: string; at: string; detail: string; step: "bundle_saved" | "granted" | "run_issued" })[];
  effective: string[];
  expires_at: string;
  grant_ids: string[];
  id: string;
  issued_at: string;
  issued_by: string;
  label?: string;
  permissions: string[];
  principal: string;
  revoked_at?: string;
  revoked_by?: string;
  status: "active" | "no_authority" | "expired" | "revoked";
}

export interface AccessRunIssued {
  bounds: { lasting: string; max_run_ttl_seconds: number; outage: string; revocation: string };
  launch: { ci: string; custom_agent: string; mcp_server: string; server_env: string; token_env: string };
  run: { bundle_ids: string[]; bundle_names: string[]; chain: ({ actor: string; at: string; detail: string; step: "bundle_saved" | "granted" | "run_issued" })[]; effective: string[]; expires_at: string; grant_ids: string[]; id: string; issued_at: string; issued_by: string; label?: string; permissions: string[]; principal: string; revoked_at?: string; revoked_by?: string; status: "active" | "no_authority" | "expired" | "revoked" };
  token: string;
}

export interface AccessRunList {
  items: ({ bundle_ids: string[]; bundle_names: string[]; chain: ({ actor: string; at: string; detail: string; step: "bundle_saved" | "granted" | "run_issued" })[]; effective: string[]; expires_at: string; grant_ids: string[]; id: string; issued_at: string; issued_by: string; label?: string; permissions: string[]; principal: string; revoked_at?: string; revoked_by?: string; status: "active" | "no_authority" | "expired" | "revoked" })[];
}

export interface AccessRunRequest {
  bundle_ids: string[];
  label?: string;
  permissions?: string[];
  principal?: string;
  ttl_seconds?: number;
}

export interface ActiveActiveIssuancePlan {
  architecture_invariants: string[];
  capability: string;
  evidence_refs: string[];
  evidence_scope: "reference_architecture";
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
  capabilities_reported_at?: string;
  capability_source: "reported" | "server_census";
  claim_quota?: number;
  claim_quota_reached?: boolean;
  clock_skew?: AgentClockSkew;
  discovery_capabilities: AgentDiscoveryCapability[];
  enrollment_proxy: AgentEnrollmentProxyStatus;
  id: string;
  inventory_report_path: string;
  last_seen_at?: string;
  live_claims?: AgentLiveClaim[];
  name: string;
  offboard_reason?: string;
  offboarded_at?: string;
  offboarded_by?: string;
  presence: AgentPresence;
  relay_capabilities: AgentRelayCapability[];
  reported_capabilities?: AgentReportedCapability[];
  reported_executor_version?: string;
  reported_host_profile_error?: string;
  reported_host_tls_probe?: boolean;
  reported_pending_report_error?: string;
  reported_relay_ca_bundle?: { error?: string; loaded_at: string; sha256: string };
  reported_relay_egress?: { allow: string[]; restricted: boolean; truncated?: boolean };
  reported_ssh_trust_readiness?: SSHTrustReadiness;
  role_grant?: AgentRoleGrant;
  role_source: "certificate" | "unreported";
  roles: ("host" | "network" | "observer" | "gateway" | "session-observer")[];
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

export interface AgentClockSkew {
  detail: string;
  observed_at: string;
  skew_seconds: number;
  state: "ok" | "warning" | "unreported";
  threshold_seconds: number;
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

export interface AgentLiveClaim {
  attempt: number;
  job_id: number;
  kind: string;
  lease_expires_at: string;
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

export interface AgentReportedCapability {
  connectors: string[];
  enabled: boolean;
  kind: string;
  missing_flags: string[];
}

export interface AgentRingAutoAssignInput {
  canary_count?: number;
  early_percent?: number;
}

export interface AgentRingAutoAssignedAgent {
  agent_id: string;
  name: string;
}

export interface AgentRingAutoAssignment {
  assigned: number;
  broad_count: number;
  canary: AgentRingAutoAssignedAgent[];
  early_count: number;
  rule: string;
}

export interface AgentRingInput {
  agent_id: string;
  ring?: "canary" | "early" | "broad" | "";
}

export interface AgentRoleGrant {
  applied_at?: string;
  applied_serial?: string;
  detail: string;
  event_id: string;
  granted_at: string;
  roles: ("host" | "network" | "observer" | "gateway" | "session-observer")[];
  state: "pending" | "applied";
}

export interface AgentRoleGrantRequest {
  reason?: string;
  roles: ("host" | "network" | "observer" | "gateway" | "session-observer")[];
}

export interface AgentUpgradeCampaign {
  active: boolean;
  current_ring?: string;
  dispatch_round?: number;
  dispatched_ring?: string;
  functional_checks?: { failed: number; passed: number; pending: number };
  guidance: string;
  halted_at_ring?: string;
  id?: string;
  observe_only?: boolean;
  reason?: string;
  rings: Record<string, unknown>;
  soak_seconds?: number;
  status?: "pending" | "running" | "halted" | "paused" | "complete";
  target_version?: string;
  versions: Record<string, unknown>;
}

export interface AgentUpgradeCampaignInput {
  artifacts?: UpgradeArtifact[];
  soak_seconds?: number;
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
  action: "issue" | "create" | "rotate" | "revoke" | "sign" | "recover" | "delete" | "managedkey:rotate" | "managedkey:revoke" | "managedkey:zeroize" | "revoke_key" | "tighten_policy" | "replace_key" | "reconcile";
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
  action: "issue" | "create" | "rotate" | "revoke" | "sign" | "recover" | "delete" | "managedkey:rotate" | "managedkey:revoke" | "managedkey:zeroize" | "revoke_key" | "tighten_policy" | "replace_key" | "reconcile";
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

export interface ArchiveLegalHold {
  applied_at?: string;
  id: string;
  object: string;
  placed_at: string;
  placed_by: string;
  reason: string;
  released_at?: string;
  report_run_id?: string;
  status: "pending" | "applied" | "release_pending" | "released" | "failed";
  status_detail?: string;
}

export interface ArchiveLegalHoldList {
  items: ArchiveLegalHold[];
  next_cursor?: string;
}

export interface ArchiveLegalHoldRequest {
  object: string;
  reason: string;
}

export interface AssuranceApproval {
  evidence_id: string;
  intent_digest: string;
  request_id: string;
  requester: string;
  required_approvals: number;
}

export interface AssuranceAuditReference {
  at: string;
  event_id: string;
  hash: string;
  sequence: number;
  type: string;
}

export interface AssuranceCredential {
  certificate_id: string;
  fingerprint: string;
  identity_ids: string[];
  issuer: string;
  not_after?: string;
  not_before?: string;
  sans: string[];
  serial: string;
  status: string;
  subject: string;
}

export interface AssuranceDeployment {
  at: string;
  basis: "recorded" | "observed" | "signed_observation";
  connector: string;
  destination: string;
  evidence_id: string;
  identity_id?: string;
  reason?: string;
  rollback_ref?: string;
  status: string;
  target: string;
}

export interface AssuranceDiscovery {
  basis: "recorded" | "observed" | "signed_observation";
  evidence_id: string;
  location: string;
  observed_at: string;
  provenance?: string;
  source: string;
  source_kind: string;
}

export interface AssuranceExternalObservation {
  at: string;
  basis: "recorded" | "observed" | "signed_observation";
  endpoint: string;
  evidence_id: string;
  expected_fingerprint?: string;
  health: "healthy" | "degraded" | "unhealthy" | "unknown";
  observer: string;
  reachable: boolean;
  served_fingerprint?: string;
  vantage?: string;
  verdict: "match" | "mismatch" | "unreachable" | "unexpected";
}

export interface AssuranceIssuance {
  approval?: AssuranceApproval;
  basis: "recorded" | "observed" | "signed_observation";
  ca: string;
  evidence_id: string;
  external_ca_id?: string;
  issued_at?: string;
  issued_by_trstctl: boolean;
  key_origin?: string;
  profile?: AssuranceProfile;
  source: string;
}

export interface AssuranceLink {
  certificate_id: string;
  fingerprint: string;
  not_after?: string;
  status: string;
}

export interface AssuranceOwner {
  basis: "recorded" | "observed" | "signed_observation";
  evidence_id: string;
  kind: string;
  name: string;
  owner_id: string;
}

export interface AssuranceProfile {
  evidence_id: string;
  name: string;
  spec_digest: string;
  version: number;
}

export interface AssuranceRecord {
  absent: ("discovery" | "owner" | "issuance" | "deployment" | "verification" | "renewal" | "revocation")[];
  audit: AssuranceAuditReference[];
  credential: AssuranceCredential;
  deployments: AssuranceDeployment[];
  discovery: AssuranceDiscovery[];
  external_observations: AssuranceExternalObservation[];
  format: "trstctl.credential-assurance-record/v1";
  generated_at: string;
  independently_observed: ("discovery" | "owner" | "issuance" | "deployment" | "verification" | "renewal" | "revocation")[];
  issuance: AssuranceIssuance;
  owner?: AssuranceOwner;
  recorded_only: ("discovery" | "owner" | "issuance" | "deployment" | "verification" | "renewal" | "revocation")[];
  renewals: AssuranceRenewals;
  revocation?: AssuranceRevocation;
  tenant_id: string;
  truncated: string[];
  verifications: AssuranceVerification[];
}

export interface AssuranceRenewalRun {
  basis: "recorded" | "observed" | "signed_observation";
  completed_at?: string;
  evidence_id: string;
  identity_id: string;
  predecessor_fingerprint: string;
  role: "predecessor" | "successor";
  started_at: string;
  status: string;
  successor_fingerprint: string;
  trigger: string;
}

export interface AssuranceRenewals {
  predecessor?: AssuranceLink;
  runs: AssuranceRenewalRun[];
  successors: AssuranceLink[];
}

export interface AssuranceRevocation {
  basis: "recorded" | "observed" | "signed_observation";
  evidence_id: string;
  reason: string;
  revoked_at: string;
}

export interface AssuranceVerification {
  address?: string;
  agent?: string;
  at: string;
  basis: "recorded" | "observed" | "signed_observation";
  checked_chain: boolean;
  checked_sans: boolean;
  endpoint?: string;
  evidence_id: string;
  expected_fingerprint: string;
  mismatch?: string;
  outcome: "verified" | "verify_failed" | "mismatch" | "unreachable";
  served_fingerprint?: string;
  signer_fingerprint?: string;
  target?: string;
  transcript_digest?: string;
  vantage: "local" | "relay" | "agent" | "connector";
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
  spiffe_id?: string;
  subject: string;
}

export interface AttestedSVIDPreview {
  attestation_verification: string;
  blockers: string[];
  capability: string;
  data_handling: string[];
  default_ttl_seconds: number;
  effect_free: boolean;
  effective_ttl_seconds: number;
  execution_external_effects: string[];
  execution_signer_calls: string[];
  execution_writes: string[];
  max_ttl_seconds: number;
  method: string;
  payload_sha256: string;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  public_key_sha256: string;
  ready: boolean;
  recovery_steps: string[];
  requested_ttl_seconds: number;
  requester: string;
  required_permission: string;
  steps: string[];
  supported_methods: string[];
  trust_domain: string;
  ttl_clamped: boolean;
  ttl_defaulted: boolean;
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

export interface AuditAnchorConsistency {
  from_size: number;
  path: string[];
}

export interface AuditAnchorInclusion {
  leaf_index: number;
  path: string[];
  record_sequence: number;
}

export interface AuditAnchorLogProof {
  consistency?: AuditAnchorConsistency;
  inclusions: AuditAnchorInclusion[];
  signed_head: string;
}

export interface AuditAnchoringStatus {
  anchor_count: number;
  anchors: AuditChainAnchor[];
  cadence_seconds: number;
  detail?: string;
  last_anchored_at?: string;
  last_run_at?: string;
  state: "anchoring" | "failing" | "off" | "unlicensed";
  verification: string;
}

export interface AuditArchiveDownload {
  bundle: string;
  chain_head: string;
  first_record: number;
  format: "jws";
  last_record: number;
  prev_hash: string;
  segment_id: string;
  sha256: string;
}

export interface AuditArchiveSegment {
  archived_at: string;
  boundary_sequence: number;
  chain_head: string;
  first_record: number;
  id: string;
  last_record: number;
}

export interface AuditArchiveSegmentList {
  items: AuditArchiveSegment[];
}

export interface AuditArchivedPrefix {
  chain_head: string;
  record_count: number;
}

export interface AuditBundle {
  anchor: AuditAnchor;
  anchor_log?: AuditAnchorLogProof;
  bundle: string;
  chain_head: string;
  format: "jws";
  schema_version: number;
  validation?: AuditValidation;
}

export interface AuditChainAnchor {
  anchored_at: string;
  chain_head: string;
  through_sequence: number;
  token_serial: number;
  token_sha256: string;
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
  archived_prefix?: AuditArchivedPrefix;
  count?: number;
  events: AuditEvent[];
  prev_hash?: string;
  readable_events?: AuditReadableEvent[];
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
  provider: "splunk-hec" | "sentinel" | "syslog" | "elastic";
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
  provider: "splunk-hec" | "sentinel" | "syslog" | "elastic";
  token_ref: string;
}

export interface AuditReadableEvent {
  actor?: Record<string, unknown>;
  data?: Record<string, unknown>;
  id: string;
  sensitive_erased?: boolean;
  sequence: number;
}

export interface AuditTSAStatus {
  ocsp: string;
  serial: string;
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

export interface AuditValidation {
  captured_at: string;
  tsa_status: AuditTSAStatus[];
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

export interface BreakglassAuthorityReceipt {
  ceremony_id: string;
  completed_at: string;
  cross_sign?: BreakglassCrossSign;
  event_sequence: number;
  kind: "rotation" | "cross_sign";
  request_digest: string;
  rotation?: BreakglassRotation;
  subject: string;
  tenant_id: string;
}

export interface BreakglassAuthorityReceiptList {
  items: BreakglassAuthorityReceipt[];
  next_cursor: string;
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

export interface BreakglassIssuePlanPreview {
  approval_threshold: number;
  blockers: string[];
  capability: "F34";
  configured_operator_count: number;
  csr_common_name: string;
  csr_dns_names: string[];
  csr_email_addresses: string[];
  csr_ip_addresses: string[];
  csr_sha256: string;
  csr_uris: string[];
  effect_free: boolean;
  effective_ttl_seconds: number;
  execution_external_effects: string[];
  execution_signer_calls: string[];
  execution_writes: string[];
  operation: "issue_breakglass";
  prerequisites: BreakglassPrerequisite[];
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  ready: boolean;
  reason: string;
  recovery_steps: string[];
  request_fingerprint: string;
  request_id: string;
  requested_ttl_seconds: number;
  required_permission: string;
  subject: string;
  verification_steps: string[];
}

export interface BreakglassIssueReceipt {
  bundle?: BreakglassBundle;
  ceremony_id: string;
  event_sequence: number;
  issued_at: string;
  request_digest: string;
  request_id: string;
  subject: string;
  tenant_id: string;
}

export interface BreakglassIssueReceiptList {
  items: BreakglassIssueReceipt[];
  next_cursor: string;
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

export interface BreakglassPrerequisite {
  detail: string;
  id: string;
  ready: boolean;
  remediation?: string;
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
  spiffe_id?: string;
  subject: string;
  task_envelope_digest?: string;
}

export interface BrokerAgentIdentityHistory {
  certificate_id: string;
  certificate_subject: string;
  current_owner_id?: string;
  fingerprint: string;
  generated_at: string;
  issuance?: BrokerIssuanceFacts;
  lifecycle_status: string;
  metadata_state: "recorded" | "unavailable";
  not_after?: string;
  not_before?: string;
  projection_state: "current" | "catching_up" | "blocked" | "unknown";
  recorded_at: string;
  serial: string;
  spiffe_id?: string;
  state: "valid" | "not_yet_valid" | "expired" | "revoked" | "superseded" | "unknown";
  state_reason: string;
}

export interface BrokerAgentIdentityHistoryList {
  generated_at: string;
  history_scope: "broker_issued_certificates";
  items: BrokerAgentIdentityHistory[];
  next_cursor: string;
  projection_state: "current" | "catching_up" | "blocked" | "unknown";
}

export interface BrokerAgentIdentityPreview {
  agent_id: string;
  attestation_verification: string;
  blockers: string[];
  capability: string;
  data_handling: string[];
  default_ttl_seconds: number;
  effect_free: boolean;
  effective_ttl_seconds: number;
  execution_external_effects: string[];
  execution_signer_calls: string[];
  execution_writes: string[];
  max_ttl_seconds: number;
  method: string;
  payload_sha256: string;
  policy_evaluation: string;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  public_key_sha256: string;
  ready: boolean;
  recovery_steps: string[];
  requested_ttl_seconds: number;
  requester: string;
  required_permission: string;
  scopes: string[];
  steps: string[];
  supported_methods: string[];
  task_envelope_sha256: string;
  task_envelope_verification: string;
  trust_domain: string;
  ttl_clamped: boolean;
  ttl_defaulted: boolean;
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

export interface BrokerAgentIdentityRevokeRequest {
  reason: string;
}

export interface BrokerAgentIdentityRevokeResult {
  items: BulkRevokeItem[];
  runs: string[];
  sessions: { id: string; role: string; status: string; target_id: string; target_type: string }[];
  total_failed: number;
  total_matched: number;
  total_queued?: number;
  total_revoked: number;
  total_skipped: number;
}

export interface BrokerIssuanceFacts {
  agent_id: string;
  effective_ttl_seconds: number;
  method: string;
  owner_id: string;
  requested_by?: string;
  requested_ttl_seconds: number;
  scopes: string[];
  subject: string;
  task_envelope_digest?: string;
}

export interface BulkRevokeItem {
  error?: string;
  id: string;
  status: "revoked" | "queued" | "skipped" | "failed";
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
  total_queued?: number;
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
  key_algorithm?: string;
  kind: string;
  max_path_len: number;
  not_after?: string;
  parent_id?: string;
  permitted_dns_names?: string[];
  possession_proof?: "self_signature" | "signer_challenge" | "offline_signature" | "not_proven";
  replaces_id?: string;
  revocation_reason?: "key_compromise" | "ca_compromise" | "affiliation_changed" | "superseded" | "cessation_of_operation" | "privilege_withdrawn";
  revoked_at?: string;
  rollover_draft?: CARolloverDraft;
  serial: string;
  signer_handle: string;
  status: string;
  tenant_id: string;
}

export interface CAAuthorityHorizon {
  band_months?: number;
  expired: boolean;
  expiry_unknown: boolean;
  leaf_validity_days: number;
  months_remaining: number;
  renew_by?: string;
  severity: "low" | "informational" | "warning" | "critical";
  truncated_leaf_ids?: string[];
  truncated_leaves?: number;
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

export interface CAAuthorityRevocation {
  authority: CAAuthority;
  ceremony_id: string;
  follow_up: string[];
  parent_id?: string;
  reason: "key_compromise" | "ca_compromise" | "affiliation_changed" | "superseded" | "cessation_of_operation" | "privilege_withdrawn";
  revoked_at: string;
  revoked_on_parent_crl: boolean;
  signer_revoked: boolean;
}

export interface CAAuthorityRevokeRequest {
  ceremony_id: string;
  reason: "key_compromise" | "ca_compromise" | "affiliation_changed" | "superseded" | "cessation_of_operation" | "privilege_withdrawn";
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

export interface CACeremonyCancelRequest {
  reason: string;
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
  operation: "create_root" | "import_offline_root" | "import_existing_ca" | "prepare_existing_ca" | "create_intermediate" | "create_offline_intermediate" | "issue_intermediate_csr" | "rekey_ca" | "cross_sign_ca" | "import_offline_cross_sign" | "rekey_offline_root" | "release_managed_ca_leaf" | "revoke_ca" | "import_ca_key";
  parent?: CACeremonyPlanAuthority;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  release_review?: CAReleaseCeremonyReview;
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
  dependent_id?: string;
  expected_certificate_sha256?: string;
  operation: "create_root" | "import_offline_root" | "import_existing_ca" | "prepare_existing_ca" | "create_intermediate" | "create_offline_intermediate" | "issue_intermediate_csr" | "rekey_ca" | "cross_sign_ca" | "import_offline_cross_sign" | "rekey_offline_root" | "release_managed_ca_leaf" | "revoke_ca" | "import_ca_key";
  parent_id?: string;
  reason?: string;
  reverse_cross_certificate_pem?: string;
  risk_accepted?: boolean;
  signer_handle?: string;
  spec?: CASpec;
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

export interface CAExistingImportCSR {
  ceremony_id: string;
  csr_pem: string;
  issuer_sha256: string;
  parent_id?: string;
  signer_handle: string;
}

export interface CAImportExistingRequest {
  ceremony_id: string;
  certificate_pem: string;
  parent_id?: string;
  signer_handle: string;
  spec: CASpec;
}

export interface CAImportKeyRequest {
  ceremony_id: string;
  certificate_pem: string;
  parent_id?: string;
  sealed_key: string;
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
  possession_signature?: string;
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
  ttl_seconds: number;
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
  close_reason?: string;
  closed_at?: string;
  closed_by?: string;
  created_at: string;
  id: string;
  opener?: string;
  purpose: string;
  release_review?: CAReleaseCeremonyReview;
  status: string;
  tenant_id: string;
  threshold: number;
}

export interface CAKeyImportOffer {
  ceremony_id: string;
  expected_public_key: string;
  operation_id: string;
  public_key: string;
  signer_handle: string;
  suite: string;
  tenant_id: string;
}

export interface CAKeyImportOfferRequest {
  ceremony_id: string;
  certificate_pem: string;
  parent_id?: string;
  spec: CASpec;
}

export interface CALeafEvaluation {
  allowed: boolean;
  ca_id: string;
  effective_ttl_seconds?: number;
  reason?: string;
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

export interface CAPrepareExistingImportCSRRequest {
  ceremony_id: string;
  certificate_pem: string;
  parent_id?: string;
  spec: CASpec;
}

export interface CAReleaseCeremonyReview {
  certificate_id: string;
  certificate_sha256: string;
  key_id: string;
  not_after?: string;
  reason: string;
  revocation_event_id?: string;
  revocation_sequence?: number;
  risk_accepted: boolean;
  serial: string;
  source_event_id: string;
  source_sequence: number;
  subject?: string;
}

export interface CARolloverDraft {
  approvals: number;
  band_months: number;
  ceremony_id?: string;
  ceremony_status?: "pending" | "completed" | "cancelled";
  drafted_at: string;
  not_after: string;
  not_drafted_reason?: string;
  preview_fingerprint?: string;
  reason?: string;
  threshold: number;
  ttl_seconds?: number;
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
  certificate_fingerprint?: string;
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

export interface CBOMCycloneDXExport {
  bom: Record<string, unknown>;
  bom_sha256: string;
  components: number;
  public_jwks: Record<string, unknown>;
  signed_bom: string;
  spec_version: "1.6";
}

export interface CBOMImport {
  asset_ids: string[];
  components: number;
  findings: number;
  replayed: boolean;
  run_id: string;
  serial_number?: string;
  source: string;
  version: number;
}

export interface CBOMImportDocument {
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
  observed_asset_ids: string[];
  report: CBOMReport;
}

export interface CBOMScanPreview {
  blockers: string[];
  capability: string;
  durable_writes: string[];
  effect_free: boolean;
  finding_write_limit: number;
  host_file_byte_limit: number;
  host_file_read_limit: number;
  host_read_selector_count: number;
  host_reads: string[];
  normalized_request: CBOMScanRequest;
  outbox_calls: number;
  outside_calls: string[];
  per_endpoint_timeout_seconds: number;
  queue_depth: number;
  ready: boolean;
  recovery_steps: string[];
  safety_notes: string[];
  signer_calls: number;
  source_count: number;
  tls_connection_limit: number;
  worker_limit: number;
}

export interface CBOMScanRequest {
  host_configs?: string[];
  tls_endpoints?: string[];
}

export interface CMDBCertificateExport {
  attempts: number;
  binding_id: string;
  certificate_id: string;
  fingerprint: string;
  id: string;
  last_error?: string;
  receipt?: { binding_digest: string; binding_id: string; certificate_id: string; certificate_status: string; checked_at: string; fingerprint: string; operation_id: string; sys_id: string; values_digest: string };
  status: string;
  verified_at?: string;
}

export interface CMDBCertificateExportBinding {
  data_source: string;
  enabled: boolean;
  id: string;
}

export interface CMDBCertificateExportBindingList {
  items: CMDBCertificateExportBinding[];
  next_cursor?: string;
}

export interface CMDBCertificateExportInput {
  binding_id: string;
  certificate_id: string;
}

export interface CMDBReconcileRunNow {
  detail: string;
  schedule: CMDBReconcileSchedule;
  started: boolean;
  sweep_id?: string;
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

export interface CMDBReconcileScheduleInput {
  allow_private_endpoint?: boolean;
  ci_query?: string;
  enabled?: boolean;
  execution?: "relay";
  instance_url: string;
  interval_seconds: number;
  token_ref: string;
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
  log_public_keys?: Record<string, unknown>;
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
  next_cursor?: string;
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
  accepted_risk_count: number;
  dismissed_count: number;
  failed_log_count: number;
  finding_count: number;
  investigating_count: number;
  log_count: number;
  managed_count: number;
  open_finding_count: number;
  outbox_alert_channel_count: number;
  overdue_count: number;
  regressed_count: number;
  remediated_count: number;
  retired_log_count: number;
  source_count: number;
  triage_counts: Record<string, unknown>;
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
  certificate_bytes_held?: boolean;
  created_at?: string;
  custody_summary?: string;
  deployment_location?: string;
  der_recovery?: CertificateDERRecoveryRecord;
  expected_ephemeral_expiry?: boolean;
  fingerprint: string;
  id: string;
  identity_ids?: string[];
  issuer?: string;
  key_algorithm?: string;
  key_exportable?: "" | "exportable" | "non_exportable";
  key_generated_by?: string;
  key_observations?: CertificateKeyObservation[];
  key_origin?: "" | "requester" | "host_agent" | "device" | "appliance" | "control_plane" | "signer";
  key_origin_derivation?: "protocol_enrollment" | "pqc_migration_reissue" | "identity_issuance" | "identity_renewal" | "kubernetes_auto_issuance" | "ephemeral_credential" | "attested_svid" | "agent_broker" | "external_ca_order";
  key_origin_proof_event_id?: string;
  key_storage?: "" | "locked_memory" | "sealed_store" | "file" | "os_store" | "pkcs11" | "device_bound" | "service" | "kubernetes_secret" | "appliance";
  kubernetes_provenance?: KubernetesCertificateProvenance[];
  not_after?: string;
  not_before?: string;
  owner_id?: string;
  revocation_observations?: RevocationEndpointHealth[];
  revocation_pending?: boolean;
  revocation_reason?: string;
  revoked_at?: string;
  sans?: string[];
  serial?: string;
  source?: string;
  status: "active" | "superseded" | "revoked";
  subject: string;
  tenant_id: string;
  transparency?: CertificateTransparencyEntry[];
}

export interface CertificateAssuranceRecord {
  public_jwks: Record<string, unknown>;
  record: AssuranceRecord;
  record_sha256: string;
  rendering: string;
  signed_record: string;
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

export interface CertificateDERRecovery {
  certificate_id: string;
  detail?: string;
  evidence?: string;
  fingerprint: string;
  method: "ca_ledger" | "endpoint";
  outcome: "recovered" | "already_held" | "not_found" | "mismatch" | "unreachable";
}

export interface CertificateDERRecoveryRecord {
  evidence: string;
  method: "ca_ledger" | "endpoint";
  recovered_at: string;
}

export interface CertificateDERRecoveryRequest {
  allow_private_endpoint?: boolean;
  method: "ca_ledger" | "endpoint";
  private_egress_cidrs?: string[];
}

export interface CertificateExpiryBucket {
  count: number;
  name: "expired" | "expiring_7d" | "expiring_30d" | "expiring_90d" | "expiring_180d" | "expiring_1y" | "expiring_2y" | "expiring_3y" | "later" | "unknown" | "expected_ephemeral";
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
  expected_ephemeral: number;
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

export interface CertificateKeyAttestation {
  attestation_certificate_sha256: string;
  binding: string;
  certificate_id: string;
  certificate_pem: string;
  credential: string;
  fingerprint: string;
  format: "tpm-webauthn";
  public_key_sha256: string;
  source: "acme_device_attest";
  trusted_roots_sha256: string;
  verified_at: string;
  verify: string;
}

export interface CertificateKeyObservation {
  agent: string;
  encrypted: boolean;
  file_mode?: string;
  first_observed: string;
  key_format?: string;
  last_observed: string;
  path: string;
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
  public_tls?: boolean;
  requires_approval?: boolean;
  upstream_external_ca?: string;
  version?: number;
}

export interface CertificateSourceHealth {
  count: number;
  expired: number;
  expiring_30d: number;
  external: boolean;
  source: string;
}

export interface CertificateTransparencyEntry {
  entry_type: "certificate" | "precertificate";
  inclusion_checked_at?: string;
  inclusion_reason?: string;
  inclusion_status: "pending" | "verified" | "not_included" | "proof_invalid" | "not_checked";
  leaf_index?: number;
  log_id?: string;
  log_url: string;
  root_hash?: string;
  sct_reason?: string;
  sct_status: "verified" | "invalid" | "unverified";
  sct_timestamp: string;
  submission_id: string;
  tree_size?: number;
}

export interface CertificationResult {
  artifact: "access-certification-result";
  result: Record<string, unknown>;
  signature: string;
}

export interface ChangeApplication {
  change_set_digest: string;
  complete: boolean;
  name: string;
  plan_digest: string;
  results: { approval_request_id?: string; error?: string; key: string; kind: string; object_id?: string; outcome: string; verified: boolean }[];
}

export interface ChangeApplyRequest {
  change_set: { deployment_targets?: { config: unknown; connector: string; enabled?: boolean; key: string; name: string }[]; description?: string; issuers?: { chain?: string[]; internal?: boolean; key: string; kind: string; name: string; public_key?: string }[]; members?: { display_name?: string; email?: string; roles: string[]; subject: string }[]; name: string; owners?: { application_id?: string; business_unit?: string; email?: string; environment?: string; escalation_chain?: string[]; key: string; kind: string; name: string; service?: string }[]; profiles?: { name: string; spec: unknown }[] };
  plan_digest: string;
}

export interface ChangeDraft {
  change_set: { deployment_targets?: { config: unknown; connector: string; enabled?: boolean; key: string; name: string }[]; description?: string; issuers?: { chain?: string[]; internal?: boolean; key: string; kind: string; name: string; public_key?: string }[]; members?: { display_name?: string; email?: string; roles: string[]; subject: string }[]; name: string; owners?: { application_id?: string; business_unit?: string; email?: string; environment?: string; escalation_chain?: string[]; key: string; kind: string; name: string; service?: string }[]; profiles?: { name: string; spec: unknown }[] };
  model: string;
  plan?: { change_set_digest: string; changes: number; items: ({ action: "create" | "update" | "unchanged"; actual_digest?: string; approvals: string[]; credentials: string[]; destinations: string[]; detail?: string; effects: string[]; expected_digest: string; grants: string[]; identities: string[]; key: string; kind: string; object_id?: string; verification: string })[]; name: string; plan_digest: string };
  refused?: string;
}

export interface ChangeDraftRequest {
  request: string;
}

export interface ChangeImpact {
  approvals: { action: string; id: string; identity_id: string; status: string }[];
  identities: { id: string; name: string; owner_id?: string; status: string }[];
  kind: "deployment_target" | "profile";
  name: string;
}

export interface ChangePlan {
  change_set_digest: string;
  changes: number;
  items: ({ action: "create" | "update" | "unchanged"; actual_digest?: string; approvals: string[]; credentials: string[]; destinations: string[]; detail?: string; effects: string[]; expected_digest: string; grants: string[]; identities: string[]; key: string; kind: string; object_id?: string; verification: string })[];
  name: string;
  plan_digest: string;
}

export interface ChangeSet {
  deployment_targets?: { config: unknown; connector: string; enabled?: boolean; key: string; name: string }[];
  description?: string;
  issuers?: { chain?: string[]; internal?: boolean; key: string; kind: string; name: string; public_key?: string }[];
  members?: { display_name?: string; email?: string; roles: string[]; subject: string }[];
  name: string;
  owners?: { application_id?: string; business_unit?: string; email?: string; environment?: string; escalation_chain?: string[]; key: string; kind: string; name: string; service?: string }[];
  profiles?: { name: string; spec: unknown }[];
}

export interface CloudMachineChange {
  adoption?: CloudMachineChangeAdoption;
  approval_request_id: string;
  created_at: string;
  expires_at: string;
  id: string;
  intent: CloudMachineChangeIntent;
  intent_digest: string;
  requested_by: string;
  result?: CloudMachineChangeResult;
  state: "awaiting_approval" | "queued" | "preparing_replacement" | "waiting_adoption" | "verified" | "failed";
  tenant_id: string;
  updated_at: string;
}

export interface CloudMachineChangeAdoption {
  consumer: string;
  event_id: string;
  name: string;
  sequence: number;
  subject: string;
  verified_at: string;
  version: number;
}

export interface CloudMachineChangeIntent {
  access_key_id?: string;
  action: "revoke_key" | "tighten_policy" | "replace_key";
  allow_private_endpoint?: boolean;
  ca_pem?: string;
  consumer?: string;
  consumer_subject?: string;
  endpoint: string;
  finding_fingerprint: string;
  finding_id: string;
  policy_document?: string;
  policy_name?: string;
  policy_sha256?: string;
  principal_arn: string;
  principal_id: string;
  principal_kind: string;
  principal_name: string;
  private_egress_cidrs?: string[];
  reason: string;
  region: string;
  replacement_expected_version?: number;
  replacement_provider_id?: string;
  replacement_provider_revision?: string;
  replacement_role?: string;
  replacement_role_allow_private?: boolean;
  replacement_role_arn?: string;
  replacement_role_authority_fingerprint?: string;
  replacement_role_finding_fingerprint?: string;
  replacement_role_finding_id?: string;
  replacement_role_id?: string;
  replacement_role_source_fingerprint?: string;
  replacement_role_source_id?: string;
  replacement_ttl_seconds?: number;
  required_approvals: number;
  source_fingerprint: string;
  source_id: string;
  writer_session_file_ref: string;
}

export interface CloudMachineChangeList {
  items: CloudMachineChange[];
  next_cursor: string;
}

export interface CloudMachineChangeRequest {
  access_key_id?: string;
  action: "revoke_key" | "tighten_policy" | "replace_key";
  consumer?: string;
  consumer_subject?: string;
  evaluation_index?: number;
  finding_id: string;
  reason: string;
  replacement_provider_id?: string;
  replacement_role?: string;
  replacement_role_finding_id?: string;
  required_approvals?: number;
  ttl_seconds?: number;
  writer_session_file_ref: string;
}

export interface CloudMachineChangeResult {
  checked_at: string;
  effect_uncertain?: boolean;
  error?: string;
  key_absent?: boolean;
  policy_matches?: boolean;
  postcondition?: string;
  preparation_phase?: string;
  replacement_command_id?: string;
  replacement_expires_at?: string;
  replacement_lease_id?: string;
  replacement_native_role_id?: string;
  replacement_version?: number;
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

export interface CodeSigningKeyCSR {
  csr_pem: string;
  key_id: string;
}

export interface CodeSigningKeyCSRRequest {
  common_name: string;
}

export interface CodeSigningKeyCertificate {
  algorithm: string;
  chain_pem: string;
  code_signing_eku: boolean;
  key_id: string;
  leaf_fingerprint: string;
  not_after: string;
  public_key_der: string;
}

export interface CodeSigningKeylessRequest {
  artifact_type: string;
  digest: string;
  fulcio_issuer?: string;
  fulcio_san?: string;
  identity_method: string;
  identity_payload: string;
  preview_fingerprint?: string;
}

export interface CodeSigningPreview {
  approval_required: boolean;
  artifact_type: string;
  blockers: string[];
  capability: string;
  cli_argv: string[];
  configuration_fingerprint: string;
  digest_sha256: string;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  identity_method?: string;
  key_id?: string;
  mode: "key" | "keyless";
  operation: string;
  preview_external_effects: string[];
  preview_reads: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  secret_data_handling: string;
  signing_algorithm?: string;
  transparency_destination?: string;
  verification_steps: string[];
}

export interface CodeSigningRequest {
  artifact_type: string;
  digest: string;
  key_id: string;
  preview_fingerprint?: string;
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

export interface ComplianceReportDispatch {
  channels?: string[];
  ticket?: ComplianceReportTicket;
}

export interface ComplianceReportLegalHoldRequest {
  reason: string;
}

export interface ComplianceReportRun {
  artifact_digest?: string;
  artifact_expired_at?: string;
  artifact_ref?: string;
  artifact_removal_deferred_until?: string;
  artifact_removal_failure?: { attempts: number; next_attempt_at?: string; reason: "refused" | "kept" | "unconfirmed" | "timeout" | "failed"; retrying: boolean };
  attempt: number;
  completed_at?: string;
  created_at: string;
  dispatch?: ComplianceReportRunDispatch;
  due_at: string;
  error_code?: string;
  event_sequence: number;
  framework: string;
  id: string;
  legal_hold?: { at: string; by: string; reason: string; storage?: { detail?: string; id: string; status: "pending" | "applied" | "release_pending" | "released" | "failed" } };
  next_attempt_at?: string;
  report_type: string;
  retry_generation: number;
  schedule_id: string;
  status: "queued" | "retrying" | "failed" | "completed";
  tenant_id: string;
  updated_at: string;
}

export interface ComplianceReportRunDispatch {
  channels?: string[];
  schedule_name: string;
  ticket?: ComplianceReportTicket;
  ticket_skipped?: string;
}

export interface ComplianceReportRunList {
  items: ComplianceReportRun[];
  next_cursor?: string;
}

export interface ComplianceReportSchedule {
  created_at: string;
  delivery: "audit_export";
  dispatch?: ComplianceReportDispatch;
  enabled: boolean;
  framework: "pci-dss" | "hipaa" | "soc2" | "nist-800-53" | "nist-csf-2.0" | "fedramp" | "cmmc-2.0" | "cnsa-2.0" | "fips-140" | "common-criteria" | "cabf-br" | "webtrust" | "etsi" | "eidas" | "nis2";
  id: string;
  interval_seconds: number;
  name: string;
  next_run_at: string;
  recipient_ref?: string;
  report_type: "framework_evidence_pack" | "inventory_snapshot" | "cbom_posture" | "audit_summary" | "nhi_compliance_mapping" | "crypto_risk" | "customer_assurance" | "lifecycle_evidence" | "access_evidence" | "rotation_evidence" | "incident_response_evidence" | "qualification_evidence";
  tenant_id: string;
  updated_at: string;
}

export interface ComplianceReportScheduleList {
  items: ComplianceReportSchedule[];
  next_cursor?: string;
}

export interface ComplianceReportSchedulePreview {
  blockers: string[];
  capability: string;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  normalized_request: ComplianceReportScheduleRequest;
  operation: string;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  secret_data_handling: string;
  verification_steps: string[];
  warnings: string[];
}

export interface ComplianceReportScheduleRequest {
  delivery?: "audit_export";
  dispatch?: ComplianceReportDispatch;
  enabled?: boolean;
  framework: "pci-dss" | "hipaa" | "soc2" | "nist-800-53" | "nist-csf-2.0" | "fedramp" | "cmmc-2.0" | "cnsa-2.0" | "fips-140" | "common-criteria" | "cabf-br" | "webtrust" | "etsi" | "eidas" | "nis2";
  interval_seconds: number;
  name: string;
  recipient_ref?: string;
  report_type: "framework_evidence_pack" | "inventory_snapshot" | "cbom_posture" | "audit_summary" | "nhi_compliance_mapping" | "crypto_risk" | "customer_assurance" | "lifecycle_evidence" | "access_evidence" | "rotation_evidence" | "incident_response_evidence" | "qualification_evidence";
}

export interface ComplianceReportTicket {
  instance_url: string;
  provider: "servicenow";
  table?: "incident" | "change_request" | "sc_task";
  token_ref: string;
}

export interface ConnectorCatalog {
  items: ConnectorCatalogItem[];
  relay_plugins?: RelayPluginRuntime[];
  relay_plugins_next_cursor?: string;
}

export interface ConnectorCatalogItem {
  appliance_key_generation?: boolean;
  capabilities: string[];
  delivery_mode: string;
  device_proven: boolean;
  executes_rollback?: boolean;
  executor?: "host_agent" | "network_relay" | "control_plane" | "none";
  grant_source?: "registry" | "shipped" | "none";
  isolation?: "wasm_sandbox" | "in_process";
  kind: string;
  name: string;
  native: boolean;
  qualification: "discovered" | "implemented" | "served" | "locally-proven" | "vendor-qualified";
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
  status: "containment_queued" | "containment_stopped" | "containment_different_leaf" | "containment_unverified" | "containment_failed" | "cancelled" | "purge_queued" | "purged" | "purge_different_leaf" | "purge_absent" | "purge_failed" | "takedown_queued" | "taken_down" | "takedown_bound" | "takedown_absent" | "takedown_failed" | "trust_anchor_removal_queued" | "trust_anchor_removed" | "trust_anchor_absent" | "trust_anchor_removal_refused" | "trust_anchor_removal_failed" | "takedown_refused" | "queued" | "delivered" | "failed" | "verified" | "verify_failed" | "config_validated" | "rollback_recorded" | "rollback_queued" | "rolled_back" | "rollback_refused" | "rollback_failed" | "dry_run_queued" | "dry_run_planned" | "dry_run_blocked" | "test_succeeded";
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

export interface ConnectorWorkCancellation {
  executing_job_ids: number[];
  recalled_job_ids: number[];
  receipts: ConnectorDelivery[];
  target_id: string;
  withdrawn_job_ids: number[];
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

export interface ControlPlaneKeygen {
  control_plane_identities: number;
  decided: boolean;
  enabled: boolean;
  evidence?: { control_plane_certificates: number; deprecation_events: number; unrecorded_served_certificates: number; workload_api_socket: boolean };
  guidance: string;
  paths: string[];
  reason?: string;
  set_at?: string;
  set_by?: string;
  source?: "registration" | "upgrade" | "operator";
}

export interface ControlPlaneKeygenInput {
  enabled: boolean;
  reason: string;
}

export interface CoverageCandidate {
  address: string;
  last_seen: string;
  observations: number;
  sources: ("certificate_location" | "endpoint_verification" | "external_observation" | "verification_target")[];
}

export interface CoverageCandidates {
  complete: boolean;
  items: CoverageCandidate[];
  note: string;
  window_days: number;
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

export interface CryptoRiskChange {
  from: string;
  key: string;
  to: string;
}

export interface CryptoRiskDeadline {
  assumed?: string;
  deprecated_after?: number;
  disallowed_after?: number;
  rule: string;
  security_bits?: number;
  source: string;
  status: "replace_now" | "deprecated" | "upcoming" | "none";
}

export interface CryptoRiskExport {
  content_type: string;
  csv: string;
  filename: string;
  generated_at: string;
  truncated: boolean;
}

export interface CryptoRiskItem {
  algorithm: string;
  deadline: CryptoRiskDeadline;
  dependents: { by_kind: Record<string, unknown>; count: number; names: string[]; source: "crypto_readiness" | "blast_radius" };
  distrust?: { entry: string; how: string };
  evidence_ids: string[];
  exposures: ("distrusted" | "weak" | "quantum_vulnerable" | "out_of_policy")[];
  key: string;
  key_bits?: number;
  kind: "certificate" | "crypto_asset";
  owners: string[];
  plan: { actions: CryptoRiskPlanAction[]; recommended?: string };
  priority: number;
  priority_reason: string;
  reasons?: string[];
  subject: string;
}

export interface CryptoRiskPlanAction {
  campaign_id: string;
  deadline: string;
  name: string;
  stale: boolean;
  status: string;
  wave?: string;
}

export interface CryptoRiskReport {
  changes: { added: string[]; comparable: boolean; deadline_changed: CryptoRiskChange[]; note?: string; plan_changed: CryptoRiskChange[]; previous_generated_at?: string; priority_changed: CryptoRiskChange[]; resolved: string[] };
  cnsa_2_0: string;
  coverage: string;
  format: string;
  generated_at: string;
  input_limit?: string;
  items: CryptoRiskItem[];
  sources: string[];
  summary: { deprecated: number; distrusted: number; items: number; quantum_vulnerable: number; replace_now: number; upcoming: number; weak: number; with_plan: number; without_plan: number };
  tenant_id: string;
  truncated?: boolean;
}

export interface CustodyExportabilityCounts {
  exportable: number;
  non_exportable: number;
}

export interface CustodyOriginCounts {
  appliance?: number;
  control_plane: number;
  device: number;
  host_agent: number;
  requester: number;
  signer: number;
}

export interface CustodyStorageCounts {
  appliance?: number;
  device_bound: number;
  file: number;
  kubernetes_secret?: number;
  locked_memory: number;
  os_store: number;
  pkcs11: number;
  sealed_store?: number;
  service: number;
}

export interface CustomerAssuranceCertificate {
  id: string;
  not_after?: string;
  owner?: string;
  subject: string;
}

export interface CustomerAssuranceReport {
  brand: { accent: string; custom: boolean; footer?: string; logo_data_uri?: string; product_name: string };
  changes: { comparable: boolean; metrics: { current: number; delta: number; key: string; label: string; previous: number; sentence: string }[]; note?: string; previous_generated_at?: string; previous_period_from?: string; previous_period_through?: string };
  credentials: { added: number; expired_active: number; expiring: number; expiring_soonest: CustomerAssuranceCertificate[]; expiring_within_days: number; failed_deliveries: number; failed_renewals: number; failures: ({ at: string; id: string; kind: "renewal" | "delivery"; reason?: string; status: string; subject: string; via?: string })[]; renewed: number; revoked: number };
  format: string;
  generated_at: string;
  html: string;
  html_sha256: string;
  incidents: { in_period: number; items: ({ evidence?: string; evidence_format?: string; evidence_sha256?: string; id: string; kind: "credential_compromise" | "issuer_compromise"; opened_at: string; phase: string; reason?: string; status: string; updated_at: string })[]; open: number; opened_in_period: number };
  inventory: { active_certificates: number; crypto_assets: number; discovery_inventory_rows: number; owned_certificates: number; ownership_coverage_percent?: number; unowned: CustomerAssuranceCertificate[] };
  limits: string[];
  period_from: string;
  period_through: string;
  summary: string[];
  tenant_id: string;
  tenant_name: string;
  verification: { changed_credentials: number; changed_credentials_truncated?: boolean; endpoint_observations: number; endpoints_checked_in_period: number; endpoints_matching: number; endpoints_mismatched: number; endpoints_unreachable: number; independently_verified: number; not_verified: number; note?: string; recorded_only: number; verified_deliveries: number };
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

export interface DatabaseDecoy {
  created_at: string;
  db_lease_id: string;
  db_provider_id: string;
  db_role: string;
  id: string;
  kind: "database";
  name: string;
  placement: string;
  revoked_at?: string;
  state: "active" | "triggered" | "revoked";
  trigger_method?: string;
  trigger_path?: string;
  triggered_at?: string;
  watch_gap_reason?: string;
  watch_gap_since?: string;
}

export interface DatabaseDecoyCreateRequest {
  name: string;
  placement: string;
  provider: string;
  ttl_seconds: number;
}

export interface DatabaseDecoyCreateResponse {
  created_at: string;
  database: string;
  db_lease_id: string;
  db_provider_id: string;
  db_role: string;
  dsn: string;
  id: string;
  kind: "database";
  name: string;
  placement: string;
  revoked_at?: string;
  state: "active" | "triggered" | "revoked";
  trigger_method?: string;
  trigger_path?: string;
  triggered_at?: string;
  watch_gap_reason?: string;
  watch_gap_since?: string;
}

export interface DatabaseDecoyList {
  items: DatabaseDecoy[];
  next_cursor?: string;
}

export interface DecoySecret {
  created_at: string;
  id: string;
  kind: "secret";
  last_read_at?: string;
  name: string;
  placement: string;
  readers?: number;
  reads?: number;
  revoked_at?: string;
  secret_name: string;
  state: "active" | "triggered" | "revoked";
  trigger_method?: string;
  trigger_path?: string;
  trigger_subject?: string;
  triggered_at?: string;
}

export interface DecoySecretList {
  items: DecoySecret[];
  next_cursor?: string;
}

export interface DecoySecretRegisterRequest {
  name: string;
  placement: string;
  secret_name: string;
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

export interface DeploymentKEKRotateRequest {
  wrapper_id: string;
  wrapper_kind: "local_file" | "pkcs11";
}

export interface DeploymentKEKRotation {
  containers_rewrapped: number;
  containers_verified: number;
  failure?: string;
  failure_code?: string;
  files_rewrapped: number;
  history_events_rewrapped: number;
  next_generation?: number;
  next_wrapper_id?: string;
  next_wrapper_kind?: string;
  operation_id: string;
  stage: "settling" | "hot_state" | "history" | "files" | "verify" | "completed";
  started_at?: string;
  status: "running" | "failed" | "completed";
  tenants_done: number;
  tenants_total: number;
  verified_at?: string;
  verify_passes: number;
}

export interface DeploymentKEKStatus {
  can_rotate: boolean;
  custody: "key_file" | "local_file" | "pkcs11";
  detail: string;
  generation: number;
  previous_generation?: number;
  rotated_at?: string;
  rotation?: DeploymentKEKRotation;
  rotation_authority: "operator_tenant" | "another_tenant" | "not_configured";
  served: boolean;
  wrapper_id?: string;
  wrapper_kind?: string;
}

export interface DeploymentTarget {
  config: Record<string, unknown>;
  connector: string;
  created_at: string;
  enabled: boolean;
  id: string;
  name: string;
  renewal_paused_identities?: string[];
  revision_id: string;
  rollback_readiness?: { identity_id?: string; model: "re-bind" | "host" | "none"; predecessor_fingerprint?: string; predecessor_serial?: string; ready: boolean; reason?: string };
  tenant_id: string;
}

export interface DeploymentTargetList {
  items: DeploymentTarget[];
  next_cursor?: string;
}

export interface DeploymentTargetRequest {
  config?: Record<string, unknown>;
  connector: string;
  enabled?: boolean;
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
  kind: "adcs" | "agent" | "api_key" | "azure_machine_identity" | "cloud_access_key" | "cloud_certificate" | "cloud_kms_key" | "cloud_machine_entitlement" | "cloud_network_path" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "gcp_machine_identity" | "k8s_ingress_gateway" | "load_balancer_tls" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "pam_signin" | "secret_store" | "service_account" | "ssh" | "ssh_trust";
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
  first_seen_at: string;
  id: string;
  kind: string;
  last_seen_at: string;
  managed_identity_id?: string;
  metadata: Record<string, unknown>;
  overdue?: boolean;
  provenance: string;
  ref: string;
  regressed?: boolean;
  removed_at?: string;
  risk_accepted_until?: string;
  risk_score?: number;
  run_id: string;
  secret_move?: { consumer_read_at?: string; consumer_read_version?: number; consumer_reader?: string; history_residue: { commit: string; file: string; line: number; rule_id: string }[]; moved_at: string; moved_by?: string; reference: string; secret_name: string; secret_version: number };
  seen_count: number;
  source_id: string;
  tenant_id: string;
  triage_actor?: string;
  triage_assignee?: string;
  triage_due_at?: string;
  triage_evidence_ref?: string;
  triage_reason?: string;
  triage_status?: "unmanaged" | "investigating" | "managed" | "dismissed" | "remediated" | "accepted_risk";
  triaged_at?: string;
}

export interface DiscoveryFindingList {
  items: DiscoveryFinding[];
  next_cursor?: string;
}

export interface DiscoveryFindingResolutionRequest {
  action: "investigate" | "remediated" | "accept_risk" | "reopen";
  assignee?: string;
  due_at?: string;
  evidence_ref?: string;
  expires_at?: string;
  reason: string;
}

export interface DiscoveryFindingSecretMoveRequest {
  history_residue?: { commit: string; file: string; line: number; rule_id: string }[];
  secret_name: string;
  secret_version: number;
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
  kind: "adcs" | "agent" | "api_key" | "azure_machine_identity" | "cloud_access_key" | "cloud_certificate" | "cloud_kms_key" | "cloud_machine_entitlement" | "cloud_network_path" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "gcp_machine_identity" | "k8s_ingress_gateway" | "load_balancer_tls" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "pam_signin" | "secret_store" | "service_account" | "ssh" | "ssh_trust";
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
  kind: "adcs" | "agent" | "api_key" | "azure_machine_identity" | "cloud_access_key" | "cloud_certificate" | "cloud_kms_key" | "cloud_machine_entitlement" | "cloud_network_path" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "gcp_machine_identity" | "k8s_ingress_gateway" | "load_balancer_tls" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "pam_signin" | "secret_store" | "service_account" | "ssh" | "ssh_trust";
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
  target_results: ({ error?: string; kind: "network" | "ssh" | "cloud_provider" | "k8s_tls_auto_issuance"; status: "succeeded" | "failed" | "blocked" | "rejected" | "not_delivered" | "delivery_queued" | "delivered"; target: string })[];
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
  retired_at?: string;
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
  kind: "adcs" | "agent" | "api_key" | "azure_machine_identity" | "cloud_access_key" | "cloud_certificate" | "cloud_kms_key" | "cloud_machine_entitlement" | "cloud_network_path" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "gcp_machine_identity" | "k8s_ingress_gateway" | "load_balancer_tls" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "pam_signin" | "secret_store" | "service_account" | "ssh" | "ssh_trust";
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
  kind: "adcs" | "agent" | "api_key" | "azure_machine_identity" | "cloud_access_key" | "cloud_certificate" | "cloud_kms_key" | "cloud_machine_entitlement" | "cloud_network_path" | "cloud_secret" | "credential_compromise" | "ct_log" | "drift" | "gcp_machine_identity" | "k8s_ingress_gateway" | "load_balancer_tls" | "manual" | "network" | "nhi_behavior" | "nhi_cross_surface" | "oauth_grant" | "pam_signin" | "secret_store" | "service_account" | "ssh" | "ssh_trust";
  name: string;
}

export interface DiscoveryUnknown {
  action?: string;
  detail: string;
  kind: "segment_never_swept" | "segment_stale" | "segment_excluded" | "segment_read_failed" | "class_unobservable" | "inventory_unobserved" | "addresses_outside_segments";
  subject: string;
}

export interface DistrustedRootRemovalRequest {
  anchor_path: string;
  fingerprint: string;
  reason?: string;
}

export interface DriftRemediation {
  capability: string;
  dashboard_path: string;
  findings: DriftRemediationFinding[];
  findings_path: string;
  next_cursor?: string;
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
  overdue?: boolean;
  provenance: string;
  recommended_action: string;
  ref: string;
  regressed?: boolean;
  risk_accepted_until?: string;
  risk_score: number;
  run_id: string;
  source_id: string;
  source_name: string;
  triage_actor?: string;
  triage_assignee?: string;
  triage_due_at?: string;
  triage_evidence_ref?: string;
  triage_reason?: string;
  triage_status: "unmanaged" | "investigating" | "managed" | "dismissed" | "remediated" | "accepted_risk";
  triaged_at?: string;
}

export interface DriftRemediationSummary {
  accepted_risk_count: number;
  certificate_count: number;
  deleted_count: number;
  dismissed_count: number;
  finding_count: number;
  investigating_count: number;
  open_finding_count: number;
  overdue_count: number;
  permission_changed_count: number;
  regressed_count: number;
  relocated_count: number;
  remediated_count: number;
  remediation_decision_count: number;
  replaced_count: number;
  secret_count: number;
  source_count: number;
  ssh_key_count: number;
  triage_counts: Record<string, unknown>;
}

export interface DynamicLease {
  credential?: string;
  expires_at: string;
  hard_expires_at?: string;
  id: string;
  issued_at: string;
  native_expires_at?: string;
  provider: string;
  requested_by?: string;
  revocation_completed_at?: string;
  revocation_method?: "deny_policy" | "native_expiry";
  revocation_status?: "none" | "pending" | "completed" | "failed";
  revoked_at?: string;
  role: string;
  role_chaining?: boolean;
  state: string;
}

export interface DynamicLeasePreview {
  blockers: string[];
  capability: "F65";
  cli_argv: string[];
  configuration_revision: string;
  effect_free: boolean;
  effective_ttl_seconds: number;
  execute_external_effects: string[];
  execute_writes: string[];
  maximum_ttl_seconds: number;
  operation: "issue_dynamic_secret_lease";
  preview_external_effects: string[];
  preview_writes: string[];
  provider_id: string;
  provider_label: string;
  provider_type: string;
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  requested_ttl_seconds: number;
  required_permission: string;
  role: string;
  secret_data_handling: string;
  verification_steps: string[];
}

export interface DynamicLeaseRenewRequest {
  extend_seconds: number;
}

export interface DynamicLeaseRequest {
  preview_fingerprint?: string;
  provider: string;
  role: string;
  ttl_seconds: number;
}

export interface DynamicSecretConfiguredProvider {
  allowed_roles: string[];
  configuration_revision: string;
  environment?: string;
  id: string;
  label: string;
  maximum_ttl_seconds: number;
  ready: boolean;
  revocation?: "confirmed" | "ttl_only" | "deny_policy";
  type: string;
}

export interface DynamicSecretProviderCatalog {
  blockers: string[];
  capability: "F65";
  configuration_changes_require_restart: boolean;
  configuration_mode: "startup_static";
  configured_providers: DynamicSecretConfiguredProvider[];
  documentation_path: string;
  secret_data_handling: string;
  secret_delivery: "file_or_secret_reference";
  supported_providers: DynamicSecretSupportedProvider[];
}

export interface DynamicSecretProviderRequirement {
  description: string;
  key: string;
  kind: "tenant" | "identifier" | "role_allowlist" | "duration" | "value" | "network_policy" | "credential_reference" | "role_binding";
  label: string;
  required: boolean;
}

export interface DynamicSecretSupportedProvider {
  authority: string;
  label: string;
  purpose: string;
  requirements: DynamicSecretProviderRequirement[];
  revocation: "confirmed" | "ttl_only";
  type: "postgresql" | "mysql" | "mongodb" | "aws-iam" | "aws-sts" | "gcp-iam" | "azure-entra" | "kubernetes" | "redis" | "ldap" | "totp" | "oauth-client-credentials" | "clickhouse" | "elasticsearch" | "rabbitmq" | "tailscale" | "mongodb-atlas" | "kafka" | "couchbase" | "milvus" | "github-app" | "snowflake" | "aws-elasticache" | "aws-memorydb" | "ibm-api-connect" | "mssql" | "azure-sql" | "auth0" | "datadog" | "openai" | "unix" | "cassandra" | "oracle" | "hana" | "openrouter" | "fireworks" | "litellm" | "supabase" | "convex" | "dbt" | "cloudflare" | "cloudflare-r2" | "okta" | "databricks" | "windows" | "iosxe" | "junos" | "eos" | "fortigate" | "bigip" | "redfish" | "esxi" | "vcenter-sso" | "okta-user" | "entra-user" | "google-workspace-user";
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
  renewed_by?: string;
  renewed_from?: string;
  revoke_reason?: string;
  revoked_at?: string;
  segment_id: string;
  serial: string;
  status: "active" | "revoked" | "expired";
  token_attestation?: { pin_policy?: string; root_sha256: string; serial?: string; touch_policy?: string };
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
  pkcs11_attestation_chain_der?: string[];
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
  pkcs11_attestation_roots: number;
  renewal_enabled: boolean;
  renewal_window_days: number;
  require_pkcs11_attestation: boolean;
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
  pkcs11_attestation_roots_pem?: string[];
  renewal_enabled?: boolean;
  renewal_window_days?: number;
  require_pkcs11_attestation?: boolean;
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
  commercial_posture: string;
  editions: EditionPackagingEntry[];
  evidence_rail: string[];
  managed_boundary: string;
  meters: UsageMeterDefinition[];
  no_ephemeral_identity_billing: boolean;
  no_per_certificate_billing: boolean;
  non_production_support_posture: string;
  positioning: string;
  provider_billing_unit: string;
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
  issuer: EndpointIssuer;
  preview_fingerprint: string;
  queued_lifecycle_intents: string[];
  renewal_intent: string;
  replaced_identity_id?: string;
  target: DeploymentTarget;
}

export interface EndpointBindingCustody {
  detail: string;
  key_origin: string;
  private_key_enters_control_plane: boolean;
}

export interface EndpointBindingPlanRequest {
  identity_name: string;
  issuer: EndpointIssuer;
  owner_id: string;
  profile_name?: string;
  reason?: string;
  replace_identity_id?: string;
  subject_key_algorithm?: "ECDSA-P256" | "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";
  target?: DeploymentTargetRequest;
  target_id?: string;
}

export interface EndpointBindingPreview {
  approval_required: boolean;
  capability: string;
  changes: string[];
  custody: EndpointBindingCustody;
  effect_free: boolean;
  existing_identity?: Identity;
  existing_identity_version?: number;
  identity_name: string;
  issuance: { effective_ttl_seconds: number; profile_id?: string; profile_name?: string; profile_spec_digest?: string; profile_version?: number; requested_ttl_seconds: number };
  issuer: EndpointIssuer;
  owner_id: string;
  preview_external_effects: string[];
  preview_writes: string[];
  queued_lifecycle_intents: string[];
  ready: boolean;
  recovery_readiness?: EndpointRecoveryReadiness;
  recovery_steps: string[];
  replaced_identity?: Identity;
  replaced_identity_version?: number;
  request_fingerprint: string;
  subject_key_algorithm?: "ECDSA-P256" | "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";
  target: EndpointBindingTarget;
  verification_steps: string[];
}

export interface EndpointBindingRequest {
  identity_name: string;
  issuer: EndpointIssuer;
  owner_id: string;
  preview_fingerprint: string;
  profile_name?: string;
  reason?: string;
  replace_identity_id?: string;
  subject_key_algorithm?: "ECDSA-P256" | "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";
  target?: DeploymentTargetRequest;
  target_id?: string;
}

export interface EndpointBindingTarget {
  config: Record<string, unknown>;
  connector: string;
  enabled: boolean;
  id?: string;
  name: string;
  revision?: string;
}

export interface EndpointContainmentPreview {
  capability: string;
  certificate_status: string;
  connector: string;
  effect_free: boolean;
  execution_effects: string[];
  expected_fingerprint: string;
  identity_id: string;
  identity_name: string;
  identity_status: string;
  preview_fingerprint: string;
  ready: boolean;
  required_agent_id: string;
  required_permission: string;
  target_enabled: boolean;
  target_id: string;
  target_name: string;
  target_revision: string;
  verification_steps: string[];
  warnings: string[];
}

export interface EndpointContainmentRequest {
  expected_fingerprint: string;
  identity_id: string;
  preview_fingerprint: string;
  reason: string;
  required_agent_id: string;
  target_revision: string;
}

export interface EndpointCustodySummary {
  appliance_generated?: number;
  control_plane_generated: number;
  host_generated: number;
  migrated_percent: number;
  targets: number;
}

export interface EndpointIssuer {
  availability?: string;
  id: string;
  name?: string;
  source: "platform" | "private" | "external";
  type?: string;
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
  origin: "host_agent" | "appliance" | "control_plane";
  target_id: string;
}

export interface EndpointKeyCustodyList {
  guidance: string;
  items: EndpointKeyCustody[];
  summary: EndpointCustodySummary;
}

export interface EndpointRecoveryCheck {
  agent_id: string;
  argv_sha256?: string;
  check_id: string;
  checked_at?: string;
  evidence_digest?: string;
  executable_sha256?: string;
  failure?: string;
  job_id?: number;
  listener?: "none" | "stopped" | "serving" | "serving_revoked" | "unverified";
  recovery?: "pinned" | "no_recovery_action" | "no_binding";
  recovery_action?: string;
  requested_at: string;
  requested_by?: string;
  serving_fingerprint?: string;
  status: "queued" | "checked" | "failed";
  target_id: string;
  target_revision: string;
}

export interface EndpointRecoveryCheckRequest {
  identity_id: string;
}

export interface EndpointRecoveryReadiness {
  check?: EndpointRecoveryCheck;
  contained_at: string;
  contained_fingerprint: string;
  deploy_actions?: string[];
  reasons: string[];
  state: "ready" | "not_ready" | "unchecked" | "queued" | "stale" | "failed";
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
  not_checked: number;
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
  roles: ("host" | "network" | "observer" | "gateway" | "session-observer")[];
  side_effects: boolean;
}

export interface EnrollmentToken {
  agent_server: string;
  agent_server_name: string;
  enroll_path?: string;
  roles: ("host" | "network" | "observer" | "gateway" | "session-observer")[];
  token: string;
}

export interface EnrollmentTokenRequest {
  allowed_identity?: string;
  roles?: ("host" | "network" | "observer" | "gateway" | "session-observer")[];
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

export interface EphemeralAPIKeyPreview {
  blockers: string[];
  capability: string;
  cli_argv: string[];
  effect_free: boolean;
  effective_ttl_seconds: number;
  execute_external_effects: string[];
  execute_writes: string[];
  maximum_ttl_seconds: number;
  minimum_ttl_seconds: number;
  native_secret_store_needed: boolean;
  operation: string;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  requested_ttl_seconds: number;
  required_permission: string;
  scopes: string[];
  subject: string;
  token_data_handling: string;
  verification_steps: string[];
}

export interface EphemeralAPIKeyRequest {
  preview_fingerprint?: string;
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
  spiffe_id?: string;
  state: "awaiting_approval" | "issued";
  subject: string;
}

export interface EphemeralCredentialPreview {
  approval_permission: string;
  approval_required: boolean;
  approval_ttl_seconds: number;
  attestation_verification: string;
  blockers: string[];
  capability: string;
  data_handling: string[];
  default_ttl_seconds: number;
  effect_free: boolean;
  effective_ttl_seconds: number;
  issuance_external_effects: string[];
  issuance_signer_calls: string[];
  issuance_writes: string[];
  max_ttl_seconds: number;
  method: string;
  payload_sha256: string;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  public_key_sha256: string;
  ready: boolean;
  recovery_steps: string[];
  request_id: string;
  request_permission: string;
  requested_ttl_seconds: number;
  requester: string;
  required_approvals: number;
  steps: string[];
  submission_external_effects: string[];
  submission_signer_calls: string[];
  submission_writes: string[];
  supported_methods: string[];
  trust_domain: string;
  ttl_clamped: boolean;
  ttl_defaulted: boolean;
}

export interface EphemeralCredentialRequest {
  method: string;
  payload_base64: string;
  public_key_pem: string;
  request_id: string;
  ttl_seconds?: number;
}

export interface EventProtectionAccepted {
  operation_id: string;
  registration_identity: string;
  retention: string;
  state: string;
}

export interface EventProtectionPlan {
  blockers: string[];
  capability: string;
  custody_configured: boolean;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  normalized_request: EventProtectionRequest;
  operation: string;
  operation_id: string;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  verification_steps: string[];
  warnings: string[];
}

export interface EventProtectionRequest {
  registration_identity: string;
  retention: string;
}

export interface EventProtectionStatus {
  activated_at?: string;
  custody_configured: boolean;
  legacy_events_readable: boolean;
  next_step: string;
  operation_id?: string;
  registration_identity: string;
  requested_at?: string;
  retention?: string;
  state: "not_enabled" | "preparing" | "active";
}

export interface EvidenceReport {
  current_state: Record<string, unknown>;
  format: string;
  kind: "lifecycle_evidence" | "access_evidence" | "rotation_evidence" | "incident_response_evidence" | "qualification_evidence";
  scope: string[];
  sections: { by_type: { count: number; type: string }[]; events: number; name: string; outcomes: Record<string, unknown>; subject_ids: string[]; truncated: boolean }[];
  source_head_sequence: number;
  title: string;
  unobserved: string[];
  window_from: string;
  window_through: string;
}

export interface ExternalCA {
  id: string;
  name: string;
  revokes_by_certificate: boolean;
  revokes_by_serial: boolean;
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

export interface FactoryBatch {
  birth_ttl_seconds: number;
  created_at: string;
  created_by: string;
  delegation_id: string;
  enrolled: number;
  id: string;
  label: string;
  operational_profile?: string;
  over_quota: number;
  quota: number;
  recorded: number;
}

export interface FactoryBatchDetail {
  birth_ttl_seconds: number;
  births: { device_name: string; enrolled: boolean; enrolled_at?: string; fingerprint: string; not_after: string; operational_serial?: string; over_quota: boolean; renewals: number; serial: string }[];
  created_at: string;
  created_by: string;
  delegation_id: string;
  enrolled: number;
  id: string;
  label: string;
  operational_profile?: string;
  over_quota: number;
  quota: number;
  recorded: number;
}

export interface FactoryBatchList {
  items: { birth_ttl_seconds: number; created_at: string; created_by: string; delegation_id: string; enrolled: number; id: string; label: string; operational_profile?: string; over_quota: number; quota: number; recorded: number }[];
}

export interface FactoryBatchRequest {
  birth_ttl_seconds: number;
  delegation_id: string;
  label: string;
  operational_profile?: string;
  quota: number;
}

export interface FactoryManifest {
  batch_id: string;
  birth_ttl_seconds: number;
  delegation_fingerprint: string;
  delegation_id: string;
  est_path: string;
  label: string;
  quota: number;
  tenant_id: string;
}

export interface FactoryReconcileRequest {
  batch_id?: string;
  certificates_pem: string[];
  host?: string;
}

export interface FactoryReconcileResult {
  already: number;
  over_quota: number;
  recorded: number;
  rejected: number;
}

export interface FindingAnnotationRequest {
  reason?: string;
}

export interface FindingAnnotationResult {
  finding_id: string;
  object: Record<string, unknown>;
  provider: "slack" | "jira" | "github" | "gitlab" | "registry";
  request_id: string;
  status: "queued";
}

export interface FirstIssuanceRetry {
  attempt_grant: number;
  attempts: number;
  identity_id: string;
  request_key: string;
  retry_event_id: string;
  state: "pending";
}

export interface FirstIssuanceRetryRequest {
  reason: string;
  request_key: string;
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

export interface FleetReissuancePreview {
  affected_identity_ids: string[];
  blockers: string[];
  candidate_trust_hosts?: string[];
  candidate_trust_store_ids?: string[];
  capability: string;
  durable_writes: string[];
  effect_free: boolean;
  exact_trust_hosts: string[];
  exact_trust_store_ids: string[];
  outside_calls: string[];
  ready: boolean;
  signer_calls: number;
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
  graph_enumeration_live_identities?: number;
  graph_enumeration_missing_identity_ids?: string[];
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
  revocation_publication?: { current?: boolean; expiring?: number; fresh?: number; observed?: boolean; stale?: number; unreachable?: number };
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

export interface GraphAccessGrant {
  approvers: GraphAccessLink[];
  credential: GraphNode;
  grant: GraphEdge;
  holders: GraphAccessLink[];
  path: GraphEvidencePath;
}

export interface GraphAccessLink {
  edge: GraphEdge;
  node: GraphNode;
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

export interface GraphPath {
  from: string;
  path: GraphEvidencePath;
  to: string;
}

export interface GraphQueryRequest {
  query: string;
}

export interface GraphQueryResult {
  rows: Record<string, unknown>[];
}

export interface GraphReachable {
  from: string;
  nodes: GraphNode[];
  paths: GraphEvidencePath[];
}

export interface GraphReachers {
  access: GraphAccessGrant[];
  by_kind: Record<string, unknown>;
  coverage: { not_covered: string[]; note: string; sources: string[] };
  paths: GraphEvidencePath[];
  reachers: GraphNode[];
  target: GraphNode;
}

export interface GraphResponse {
  access_omitted?: boolean;
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

export interface HoneyToken {
  created_at: string;
  id: string;
  kind: "native";
  name: string;
  placement: string;
  revoked_at?: string;
  state: "active" | "triggered" | "revoked";
  trigger_method?: string;
  trigger_path?: string;
  triggered_at?: string;
}

export interface HoneyTokenCreateRequest {
  name: string;
  placement: string;
}

export interface HoneyTokenCreateResponse {
  created_at: string;
  id: string;
  kind: string;
  name: string;
  placement: string;
  state: string;
  token: string;
}

export interface HoneyTokenList {
  items: HoneyToken[];
  next_cursor?: string;
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
  inventory_state?: "requested" | "issued" | "delivered" | "served" | "revoked" | "retired";
  issuer_id?: string;
  kind: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  name: string;
  not_after?: string;
  not_before?: string;
  owner_id: string;
  renewal_failure?: { attempt: number; cause: string; job_id: number };
  renewal_paused?: IdentityRenewalPause[];
  status: string;
  tenant_id?: string;
  terminal_pending?: boolean;
  terminal_target_state?: "revoked" | "retired";
}

export interface IdentityApplicationView {
  actions: ({ action: "recover" | "revoke" | "retire"; available: boolean; method: string; path: string; reason?: string })[];
  alerts: { created_at: string; destination: string; id: string; kind?: string; status: string }[];
  approvals: ({ action: string; changed: ("profile" | "destination" | "issuer" | "identity")[]; created_at: string; expires_at: string; id: string; status: string })[];
  certificate?: { fingerprint: string; id: string; not_after?: string; serial: string; status: string };
  defaults: { connector?: string; issuer_id?: string; issuer_source?: string; owner_id?: string; profile_name?: string };
  destination?: { connector: string; enabled: boolean; last_delivery_at?: string; last_delivery_fingerprint?: string; last_delivery_status?: string; name: string; revision: string; target_id: string };
  identity: Identity;
  inventory_state: "requested" | "issued" | "delivered" | "served" | "revoked" | "retired";
  issuer: { certificate_issuer?: string; id?: string; name?: string; source: "platform" | "private" | "external" };
  owner?: { application?: string; environment?: string; id: string; kind: string; name: string; service?: string };
  profile?: { enrollment_methods: string[]; name: string; requires_approval: boolean; spec_digest: string; version: number };
  renewal: { blockers: string[]; due: boolean; latest_run_status?: string; next_action: string; not_after?: string; source?: string };
  review_plan: ({ action: "approve" | "issue" | "deploy" | "verify"; subject: string })[];
  served?: { at?: string; fingerprint: string; matches_current: boolean; vantage: "connector" | "local" | "relay" };
}

export interface IdentityConnectorTargetRequest {
  target_id: string;
}

export interface IdentityDeploymentEvidence {
  certificate?: Certificate;
  identity_id: string;
  read_at: string;
  receipt?: ConnectorDelivery;
}

export interface IdentityIssuanceResult {
  certificate?: Certificate;
  certificate_pem?: string;
  delivery?: { attempts: number; status: "pending" | "processing" | "delivered" | "failed" | "cancelled" };
  identity_id: string;
  request_key: string;
  retry?: { allowed: boolean; reason: string };
  state: "pending" | "issued" | "failed" | "unavailable" | "cancelled";
}

export interface IdentityList {
  items: Identity[];
  next_cursor?: string;
  summary?: IdentityStatusSummary;
}

export interface IdentityRenewalPause {
  paused_at: string;
  reason: string;
  target_id: string;
}

export interface IdentityRenewalResumeRequest {
  target_id: string;
}

export interface IdentityRequest {
  attributes?: Record<string, unknown>;
  issuer_id?: string;
  kind: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  name: string;
  owner_id: string;
}

export interface IdentityRevocationReport {
  certificates: ({ ca_status: { at?: string; detail: string; state: "confirmed" | "pending" | "failed" | "not_observed" }; certificate_id: string; deployed_material: { at?: string; detail: string; state: "confirmed" | "pending" | "failed" | "not_observed" }; destinations: ({ at: string; now: "replaced" | "removed" | "still_deployed" | "failed"; state: "confirmed" | "pending" | "failed" | "not_observed"; target: string })[]; endpoints: ({ checked_at: string; detail: string; endpoint_id: string; state: "confirmed" | "pending" | "failed" | "not_observed"; vantage: string })[]; existing_sessions: { at?: string; detail: string; state: "confirmed" | "pending" | "failed" | "not_observed" }; fingerprint: string; new_connections: { at?: string; detail: string; state: "confirmed" | "pending" | "failed" | "not_observed" }; reason?: string; revoked_at?: string; serial: string })[];
  identity_id: string;
}

export interface IdentityStatusSummary {
  by_status: Record<string, unknown>;
  total: number;
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
  keygen_refused?: boolean;
  owner_id: string;
  owner_name?: string;
  prerequisites: string[];
  preview_external_effects: string[];
  preview_writes: string[];
  profile_refusal?: string;
  profile_refused?: boolean;
  ready: boolean;
  request_fingerprint: string;
  required_permission: string;
  side_effect: boolean;
  side_effect_destination?: string;
  to: string;
  verification_steps: string[];
  warnings: string[];
}

export interface IncidentCloseRequest {
  resolution: string;
  servicenow?: { allow_private_endpoint?: boolean; instance_url: string; token_ref: string };
}

export interface IncidentClosure {
  closed_at: string;
  closed_by: string;
  incident_id: string;
  resolution: string;
  servicenow?: "queued" | "resolved" | "failed";
  servicenow_error?: string;
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
  issuer?: IssuanceRequestIssuer;
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
  issuer?: EndpointIssuer;
  justification?: string;
  origin?: string;
  owner_id: string;
  profile?: string;
  subject: string;
  ticket_ref?: string;
}

export interface IssuanceRequestIssuer {
  id: string;
  name: string;
  source: "platform" | "private" | "external";
}

export interface IssuanceRequestIssuerList {
  items: EndpointIssuer[];
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
  issuer?: EndpointIssuer;
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

export interface KMIPClient {
  created_at: string;
  detail: string;
  enrolled_at?: string;
  enrollment_expires_at?: string;
  fingerprint?: string;
  id: string;
  name: string;
  not_after?: string;
  state: "awaiting_enrollment" | "enrollment_expired" | "enrolled" | "enrolled_reenrolling";
  subject?: string;
}

export interface KMIPClientEnrollment {
  client: KMIPClient;
  enrollment: { expires_at: string; password: string; username: string };
}

export interface KMIPClientList {
  items: KMIPClient[];
}

export interface KMIPClientRegisterRequest {
  name: string;
}

export interface KMIPPosture {
  address?: string;
  client_registrations: boolean;
  configured: boolean;
  detail: string;
  listening: boolean;
  objects: string[];
  operations: string[];
  profile: string;
  recovery?: string;
  served: boolean;
  state: string;
  tenant_bound: boolean;
  transport: string;
}

export interface KeyCompromiseCertificate {
  authority: string;
  fingerprint: string;
  id: string;
  serial: string;
}

export interface KeyCompromiseExcludedCertificate {
  certificate_status: "active" | "superseded" | "revoked";
  fingerprint: string;
  id: string;
  issuer: string;
  reason: string;
  serial: string;
}

export interface KeyCompromiseExecutionRequest {
  connector: string;
  expected_fingerprint: string;
  expected_version: number;
  identity_id: string;
  preview_fingerprint: string;
  required_agent_id: string;
  target_id: string;
  target_name: string;
  target_revision: string;
}

export interface KeyCompromisePlan {
  capability: string;
  certificates: KeyCompromiseCertificate[];
  effect_free: boolean;
  excluded_certificates: KeyCompromiseExcludedCertificate[];
  execution_effects: string[];
  expected_version: number;
  identity_id: string;
  preview_fingerprint: string;
  ready: boolean;
  required_permissions: string[];
  target: EndpointContainmentPreview;
  verification_steps: string[];
  warnings: string[];
}

export interface KeyCompromisePlanRequest {
  target_id: string;
}

export interface KeyCompromiseResult {
  containment: ConnectorDelivery;
  identity: Identity;
  revocation: KeyCompromiseRevocationAttempt;
}

export interface KeyCompromiseRetryRequest {
  effect: "host" | "ca";
  request_key: string;
}

export interface KeyCompromiseRevocationAttempt {
  attempts: number;
  delivered_at?: string;
  destination: string;
  id: number;
  last_error?: string;
  status: string;
}

export interface KeyVaultDisable {
  certificate_id: string;
  disabled_at?: string;
  failure?: string;
  id: string;
  note: string;
  reason: string;
  requested_at: string;
  requested_by: string;
  resource_id: string;
  revoked: boolean;
  status: "queued" | "disabled" | "failed";
  vault_updated_at?: string;
}

export interface KeyVaultDisableList {
  items: ({ certificate_id: string; disabled_at?: string; failure?: string; id: string; note: string; reason: string; requested_at: string; requested_by: string; resource_id: string; revoked: boolean; status: "queued" | "disabled" | "failed"; vault_updated_at?: string })[];
}

export interface KeyVaultDisableRequest {
  reason: string;
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

export interface KubernetesCertManagerRequests {
  capability: string;
  controllers: KubernetesPostureController[];
  generated_at: string;
  last_sync?: string;
  objects: KubernetesPostureObject[];
  served: boolean;
  summary: KubernetesPostureSummary;
}

export interface KubernetesCertificateProvenance {
  certificate_name: string;
  certificate_uid: string;
  cluster_id: string;
  controller_id: string;
  fingerprint: string;
  namespace: string;
  observed_at: string;
  report_id: string;
  request_name: string;
  request_uid: string;
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
  parent_name?: string;
  parent_uid?: string;
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

export interface KubernetesTrustRollout {
  bundle_sha256: string;
  ca_bundle_pem: string;
  clusters: KubernetesTrustRolloutCluster[];
  config_map_name: string;
  created_at: string;
  id: string;
  key: string;
  name: string;
  namespaces: string[];
  state: "running" | "paused" | "completed" | "superseded";
  updated_at: string;
  verified_clusters: number;
}

export interface KubernetesTrustRolloutCluster {
  canary: boolean;
  cluster_id: string;
  dispatched_at?: string;
  observed_hash?: string;
  position: number;
  reason?: string;
  report_id?: string;
  state: "waiting" | "dispatched" | "verified" | "failed";
  verified_at?: string;
}

export interface KubernetesTrustRolloutList {
  items: KubernetesTrustRollout[];
}

export interface KubernetesTrustRolloutRequest {
  ca_bundle_pem: string;
  clusters: string[];
  config_map_name?: string;
  key?: string;
  name: string;
  namespaces: string[];
}

export interface LifecycleAutomationControl {
  action: "start" | "pause" | "resume" | "retry" | "cancel" | "rollback";
  detail: string;
  state: "available" | "configuration_only" | "automatic" | "conditional" | "unavailable_after_enqueue";
}

export interface LifecycleAutomationItem {
  blockers: string[];
  certificate_id: string;
  due: boolean;
  identity_id: string;
  identity_name: string;
  identity_status: string;
  latest_run_id?: string;
  latest_run_status?: string;
  not_after?: string;
  owner_id: string;
  owner_name: string;
  reason: string;
  renewal_source: "ari" | "fixed_deadline" | "not_due" | "in_flight" | "target_conflict" | "unverified_delivery";
  rollback_ref?: string;
}

export interface LifecycleAutomationPlan {
  capability: string;
  controls: LifecycleAutomationControl[];
  execution_external_effects: string[];
  execution_writes: string[];
  generated_at: string;
  items: LifecycleAutomationItem[];
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  scheduler: LifecycleAutomationScheduler;
  summary: LifecycleAutomationSummary;
  verification_steps: string[];
}

export interface LifecycleAutomationScheduler {
  alert_before: string;
  alert_before_seconds: number;
  ari_first: boolean;
  interval: string;
  interval_seconds: number;
  maintenance_deferral?: string;
  maintenance_window_status: "open" | "closed";
  next_open?: string;
  renew_before: string;
  renew_before_seconds: number;
  status: "running" | "deferred" | "disabled";
}

export interface LifecycleAutomationSummary {
  due_now: number;
  monitored: number;
  outbox_failed: number;
  outbox_pending: number;
  outbox_processing: number;
  renewal_failed: number;
}

export interface MCPFinding {
  attributes?: Record<string, unknown>;
  confidence: "verified" | "observed" | "recorded" | "inferred";
  evidence_ids: string[];
  finding_id: string;
  kind: string;
  observed_at: string;
  source: string;
  summary: string;
}

export interface MCPToolCall {
  authority_id?: string;
  csr_pem?: string;
  identity_id?: string;
  previous_serial?: string;
  reason?: string;
  subject?: string;
  ttl_seconds?: number;
}

export interface MCPToolList {
  descriptions?: Record<string, unknown>;
  identity?: string;
  read_only: boolean;
  result_schema?: Record<string, unknown>;
  tools: string[];
}

export interface MCPToolResult {
  approval_request_id?: string;
  certificate_pem?: string;
  citations?: string[];
  findings: MCPFinding[];
  generated_at: string;
  identity_id?: string;
  not_after?: string;
  outcome?: "queued" | "proposed";
  schema: string;
  serial?: string;
  sufficient?: boolean;
  text: string;
  tool: string;
  truncated?: boolean;
}

export interface MDMCheckIn {
  approval_request_id: string;
  checked_in_at?: string;
  device_id: string;
  device_name?: string;
  failure?: string;
  id: string;
  mdm: "intune" | "jamf";
  provider_status?: number;
  queued_at: string;
  reason: string;
  requested_by: string;
  status: "queued" | "checked_in" | "failed";
}

export interface MDMCheckInApproval {
  approval_count: number;
  approval_intent_digest: string;
  approval_request_id: string;
  device_id: string;
  device_name?: string;
  expires_at: string;
  mdm: "intune" | "jamf";
  reason: string;
  required_approvals: number;
  status: string;
}

export interface MDMCheckInList {
  items: ({ approval_request_id: string; checked_in_at?: string; device_id: string; device_name?: string; failure?: string; id: string; mdm: "intune" | "jamf"; provider_status?: number; queued_at: string; reason: string; requested_by: string; status: "queued" | "checked_in" | "failed" })[];
}

export interface MDMCheckInRequest {
  reason: string;
}

export interface MDMCheckInStart {
  approval_intent_digest: string;
  approval_request_id: string;
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

export interface MDMEntraAppRegistration {
  authority?: string;
  client_id: string;
  directory_tenant_id: string;
}

export interface MDMJamfAPIClient {
  client_id: string;
}

export interface MDMPollSchedule {
  base_url?: string;
  client_credentials?: MDMEntraAppRegistration;
  configured: boolean;
  enabled: boolean;
  execution?: "relay" | "";
  filter?: string;
  guidance: string;
  interval_seconds?: number;
  jamf_api_client?: MDMJamfAPIClient;
  last_error?: string;
  last_run_at?: string;
  mdm?: "intune" | "jamf";
  renewal_window_days?: number;
  required_agent_id?: string;
  token_ref?: string;
}

export interface MDMPollScheduleInput {
  base_url: string;
  client_credentials?: MDMEntraAppRegistration;
  enabled?: boolean;
  execution?: "relay" | "";
  filter?: string;
  interval_seconds: number;
  jamf_api_client?: MDMJamfAPIClient;
  mdm: "intune" | "jamf";
  renewal_window_days?: number;
  required_agent_id?: string;
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
  challenge_credential_ref?: string;
  challenge_mode: string;
  challenge_path?: string;
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
  challenge_credential_configured?: boolean;
  challenge_mode: "intune-jws" | "hmac-dynamic";
  challenge_path?: string;
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
  challenge_credential_ref?: string;
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
  allow_token_reuse?: boolean;
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

export interface MachineLoginPrerequisite {
  detail: string;
  id: string;
  ready: boolean;
  remediation?: string;
}

export interface MachineLoginPreview {
  blockers: string[];
  capability: string;
  cli_argv: string[];
  credential_format: string;
  credential_reuse: string;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  method: MachineAuthMethod;
  operation: string;
  prerequisites: MachineLoginPrerequisite[];
  preview_external_effects: string[];
  preview_reads: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  secret_data_handling: string;
  session_ttl_seconds: number;
  single_use: boolean;
  tenant_binding: string;
  verification_steps: string[];
}

export interface MachineLoginPreviewRequest {
  method?: string;
}

export interface MachineLoginRequest {
  credential: string;
  method?: string;
  preview_fingerprint?: string;
}

export interface MachineLoginResponse {
  expires_at: string;
  method: string;
  principal: string;
  scopes: string[];
  session_id: string;
  token: string;
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
  custody_checked_at?: string;
  custody_status?: "not_checked" | "pending" | "verified" | "unavailable";
  extractable?: boolean;
  key_id: string;
  provider: string;
  public_der?: string;
  state: string;
  version: number;
}

export interface ManagedKeyActionRequest {
  key_id: string;
  provider?: string;
}

export interface ManagedKeyApproval {
  action: "managedkey:rotate" | "managedkey:revoke" | "managedkey:zeroize";
  approvals: number;
  approver: string;
  resource: string;
}

export interface ManagedKeyApprovalProblem {
  approval_request_id?: string;
  code?: string;
  detail?: string;
  instance?: string;
  intent_digest?: string;
  status: number;
  title: string;
  type: string;
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
  configured_providers: ("aws" | "azure-key-vault" | "gcp-kms" | "pkcs11" | "tpm2" | "yubihsm2")[];
  enabled: boolean;
  lifecycle_attached: boolean;
  providers: ManagedKeyCustodyProvider[];
  ready: boolean;
  restart_required: boolean;
  secret_delivery: "file_reference_only";
  security_boundary: string;
  tenant_provider?: "aws" | "azure-key-vault" | "gcp-kms" | "pkcs11" | "tpm2" | "yubihsm2";
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
  provider: "aws" | "azure-key-vault" | "gcp-kms" | "pkcs11" | "tpm2" | "yubihsm2";
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

export interface ManagedKeyOperation {
  action?: string;
  key_id?: string;
  operation_id: string;
  provider?: string;
  result_key_id?: string;
  status: "queued" | "completed" | "failed";
  status_url: string;
  updated_at?: string;
}

export interface ManagedKeyRecord {
  algorithm: string;
  created_at: string;
  custody_checked_at?: string;
  custody_status: "not_checked" | "pending" | "verified" | "unavailable";
  extractable: boolean;
  key_id: string;
  provider: string;
  public_der?: string;
  state: string;
  updated_at: string;
  version: number;
}

export interface ManagedKeyRecordList {
  items: ManagedKeyRecord[];
  next_cursor: string;
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

export interface MigrationApprovalUse {
  action: string;
  evidence_refs?: string[];
  from_state?: string;
  intent_digest: string;
  issuance?: { effective_ttl_seconds: number; profile_id?: string; profile_name?: string; profile_spec_digest?: string; profile_version?: number; requested_ttl_seconds: number };
  reason?: string;
  request_id: string;
  requester: string;
  required_approvals: number;
  resource_id: string;
  resource_kind: string;
  target_version: number;
  to_state?: string;
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
  execution_model?: "host" | "appliance" | "cloud_store";
  issuing_authority_id: string;
  issuing_authority_source?: "platform" | "private" | "external";
  predecessor_certificate_id: string;
  predecessor_external_ca_id?: string;
  predecessor_fingerprint: string;
  predecessor_source?: string;
  required_agent_id?: string;
  subject_common_name: string;
  subject_dns_names: string[];
  subject_email_addresses?: string[];
  subject_ip_addresses?: string[];
  subject_uris?: string[];
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
  approval?: MigrationApprovalUse;
  halt_reason?: string;
  id: string;
  observed_traffic_window_seconds?: number;
  pause_reason?: string;
  plan_id?: string;
  require_observed_traffic?: boolean;
  revoke_predecessors?: boolean;
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
  attempt?: number;
  binding: MigrationMemberBinding;
  identity_id: string;
  live_verified_at?: string;
  revocation_verdict?: string;
  rollback_successor_verdict?: string;
  rollback_trust_verdict?: string;
  successor_verdict?: string;
  traffic_verdict?: string;
  trust_verdict?: string;
}

export interface MigrationRunStartMember {
  agent_id?: string;
  identity_id: string;
  trust_anchor_path?: string;
}

export interface MigrationRunStartPending {
  approval_disposition: string;
  approval_request_id: string;
  detail: string;
  intent_digest: string;
  required_approvals: number;
  status: "pending_approval";
}

export interface MigrationRunStartRequest {
  new_authority_id: string;
  observed_traffic_window_seconds?: number;
  plan_id: string;
  require_observed_traffic?: boolean;
  revoke_predecessors?: boolean;
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

export interface NHIAttackPathRequest {
  inventory_ids?: string[];
  source_id: string;
}

export interface NHIAttackPathResult {
  endpoints: NHIExposureProbeEndpoint[];
  omitted: number;
  requested_at: string;
  run_id: string;
  source_id: string;
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
  action: "revoked" | "retired" | "skipped" | "refused" | "failed";
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
  refused: number;
  retired: number;
  revoked: number;
  skipped: number;
  total_matched: number;
}

export interface NHIExposureAttackPath {
  checked_at: string;
  endpoints: NHIExposureAttackPathAddress[];
  status: "open" | "blocked" | "not_in_account" | "unknown";
}

export interface NHIExposureAttackPathAddress {
  address: string;
  blocked_by?: "route" | "network_acl" | "network_acl_return" | "security_group" | "firewall" | "network_security_group" | "public_ip";
  checked_at: string;
  path?: string[];
  reason?: string;
  resource?: string;
  rule?: string;
  status: "open" | "blocked" | "not_in_account" | "unknown";
}

export interface NHIExposureFinding {
  attack_path?: NHIExposureAttackPath;
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
  reachability?: NHIExposureReachability;
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

export interface NHIExposureProbeEndpoint {
  address: string;
  endpoint: string;
  inventory_id: string;
  server_name?: string;
}

export interface NHIExposureProbeRequest {
  inventory_ids?: string[];
}

export interface NHIExposureProbeResult {
  endpoints: NHIExposureProbeEndpoint[];
  omitted: number;
  requested_at: string;
  run_id: string;
  vantage: "relay";
}

export interface NHIExposureReachability {
  endpoints: NHIExposureReachabilityProbe[];
  probed_at: string;
  status: "reachable" | "unreachable" | "not_public";
}

export interface NHIExposureReachabilityProbe {
  address: string;
  agent?: string;
  error?: string;
  observed_at: string;
  observed_fingerprint?: string;
  outcome: "tls_certificate" | "unparseable_certificate" | "listener_without_tls" | "not_public" | "unreachable";
  reachable: boolean;
  server_name?: string;
}

export interface NHIExposureSummary {
  critical: number;
  findings: number;
  high: number;
  insecure_transport: number;
  internet_exposed: number;
  live_reachable: number;
  low: number;
  medium: number;
  missing_network_policy: number;
  path_open: number;
  path_validated: number;
  probed: number;
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
  privileged_account_records?: number;
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

export interface NHIPostureAutomation {
  capability: string;
  coverage: string[];
  evidence_refs: string[];
  generated_at: string;
  items: NHIPostureAutomationItem[];
  per_tenant_sweep_limit: number;
  policy_evaluated: number;
  policy_evaluation_errors: number;
  policy_module_sha256?: string;
  summary: NHIPostureAutomationSummary;
}

export interface NHIPostureAutomationItem {
  action: "revoke" | "right_size" | "report_only" | "not_applicable";
  detail?: string;
  display_name: string;
  inventory_id: string;
  kind: string;
  last_run?: NHIPostureAutomationRun;
  posture: string[];
  reason?: string;
  remediation?: "revoke" | "right_size";
  rule: string;
  severity?: string;
  status: string;
}

export interface NHIPostureAutomationRun {
  created_at: string;
  id: string;
  phase: string;
  playbook_id: string;
  status: string;
}

export interface NHIPostureAutomationSummary {
  not_applicable: number;
  report_only: number;
  revoke: number;
  right_size: number;
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
  next_review_days?: number;
  reason?: string;
  reviewer_subject?: string;
}

export interface NHIReviewGenerateRequest {
  due_at?: string;
  name: string;
  older_than_days?: number;
  reviewer_subject?: string;
  source: "graph_reachers" | "stale_owner_attestation" | "pam_accounts";
  target?: string;
}

export interface NHIReviewGenerateResponse {
  campaign: NHIReviewCampaign;
  coverage?: { not_covered: string[]; note: string; sources: string[] };
}

export interface NHIReviewItem {
  closed_as?: "revoked" | "gone";
  closed_at?: string;
  closing_evidence?: string;
  created_at: string;
  decided_at?: string;
  decision_by?: string;
  decision_evidence_refs?: string[];
  decision_reason?: string;
  display_name: string;
  entitlement: string;
  evidence_refs: string[];
  item_id: string;
  next_review_at?: string;
  nhi_id: string;
  nhi_kind: string;
  owner_ref?: string;
  resource: string;
  revocation_detail?: string;
  revocation_requested_at?: string;
  revocation_status?: "requested" | "manual" | "failed" | "closed";
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

export interface NHIReviewRevocationRetryRequest {
  reason: string;
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
  accepted_risk: number;
  critical: number;
  findings: number;
  high: number;
  investigating: number;
  kind_counts: Record<string, unknown>;
  low: number;
  medium: number;
  ownerless: number;
  remediated: number;
  removed: number;
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

export interface NHIStaleHandoffItem {
  display_name: string;
  finding_types: string[];
  from_owner_id?: string;
  from_owner_status: string;
  inventory_id: string;
  kind: string;
}

export interface NHIStaleHandoffRequest {
  inventory_ids: string[];
  owner_id: string;
  reason: string;
}

export interface NHIStaleHandoffResult {
  assigned_at: string;
  assigned_by: string;
  items: NHIStaleHandoffItem[];
  notice_queued: boolean;
  owner_id: string;
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
  resolved: number;
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
  certificate_fingerprint?: string;
  certificate_id?: string;
  created_at: string;
  delivered_at?: string;
  deliveries?: NotificationDelivery[];
  deployment_receipt_id?: string;
  deployment_recorded_at?: string;
  destination: string;
  detail?: string;
  escalation_recipients?: AlertRecipient[];
  id: string;
  idempotency_key?: string;
  identity_id?: string;
  kind?: string;
  last_error?: string;
  not_after?: string;
  operation_id?: string;
  owner_email?: string;
  owner_id?: string;
  owner_name?: string;
  read_at?: string;
  renewal_attempt?: number;
  renewal_job_id?: number;
  rotation_run_id?: string;
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

export interface NotificationDelivery {
  attempts: number;
  channel: string;
  delivered_at: string;
  id: string;
  routing_policy_digest?: string;
  routing_policy_id?: string;
  routing_policy_scope?: string;
  routing_source?: "explicit_policy" | "inherited_policy" | "default_policy" | "all_channels" | "channel_test" | "report_schedule";
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

export interface NotificationRoutingPolicyPreview {
  blockers: string[];
  capability: string;
  channels_by_severity: Record<string, unknown>;
  configured_channels: string[];
  default_channels: string[];
  digest_interval_seconds: number;
  digest_timezone: string;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  missing_channels: string[];
  name: string;
  operation: string;
  owner_email?: string;
  owner_ref?: string;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  scope_kind: "manual" | "global" | "workspace" | "owner" | "asset";
  scope_ref?: string;
  secret_data_handling: string;
  verification_steps: string[];
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

export interface OAuthProviderActionRequest {
  reason?: string;
}

export interface OAuthProviderActionResult {
  action: "revoke_grant" | "block_app" | "unblock_app";
  app_id: string;
  finding_id: string;
  principal?: string;
  provider: "okta" | "microsoft" | "google";
  request_id: string;
  status: "queued";
}

export interface OIDCIssuer {
  algorithms: string[];
  discovery_url: string;
  issuer: string;
  jwks_uri: string;
  token_endpoint: string;
  token_lifetime_seconds: number;
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

export interface Observation {
  chain_fingerprints: string[];
  detail: string;
  endpoint: string;
  expected_fingerprint: string;
  health: "healthy" | "degraded" | "unhealthy" | "unknown";
  id: string;
  observed_at: string;
  observer_id: string;
  observer_name: string;
  reachable: boolean;
  recorded_at: string;
  served_fingerprint: string;
  vantage: string;
  verdict: "match" | "mismatch" | "unreachable" | "unexpected";
}

export interface ObservationList {
  items: Observation[];
}

export interface ObservationRequest {
  chain_fingerprints?: string[];
  detail?: string;
  endpoint: string;
  health?: "healthy" | "degraded" | "unhealthy" | "unknown";
  observed_at: string;
  observer_id: string;
  reachable: boolean;
  served_fingerprint?: string;
  vantage?: string;
}

export interface Observer {
  created_at: string;
  credential_ref: string;
  enabled: boolean;
  events_url: string;
  id: string;
  name: string;
  updated_at: string;
}

export interface ObserverList {
  items: Observer[];
}

export interface ObserverRequest {
  credential_ref?: string;
  enabled?: boolean;
  events_url?: string;
  name: string;
}

export interface OffboardMemberRequest {
  reason?: string;
}

export interface OffboardMemberResponse {
  member: Member;
  revoked_token_count: number;
  rotation_evidence: string;
}

export interface OperationLedgerDetail {
  actions: ({ action: "retry" | "rollback"; available: boolean; method?: string; path?: string; reason?: string; scope: string })[];
  chain: ({ at?: string; detail: string; path?: string; state: "done" | "pending" | "failed" | "uncertain" | "not_observed"; step: "request" | "authority" | "external_action" | "receipt" | "observation" | "revocation" })[];
  created_at: string;
  credential_type: string;
  fingerprint?: string;
  id: string;
  observed_vantage?: string;
  outbox?: { attempts: number; id: number; status: string };
  source: "certificate_rotation" | "connector_delivery" | "secret_rotation" | "approval";
  source_status: string;
  state: "reviewed" | "awaiting_approval" | "queued" | "executing" | "delivered" | "verified" | "failed" | "uncertain" | "recovered";
  state_reason: string;
  subject: { id?: string; name: string };
  updated_at: string;
}

export interface OperationLedgerItem {
  created_at: string;
  credential_type: string;
  fingerprint?: string;
  id: string;
  observed_vantage?: string;
  outbox?: { attempts: number; id: number; status: string };
  source: "certificate_rotation" | "connector_delivery" | "secret_rotation" | "approval";
  source_status: string;
  state: "reviewed" | "awaiting_approval" | "queued" | "executing" | "delivered" | "verified" | "failed" | "uncertain" | "recovered";
  state_reason: string;
  subject: { id?: string; name: string };
  updated_at: string;
}

export interface OperationLedgerPage {
  items: OperationLedgerItem[];
  next_cursor?: string;
}

export interface OperationsDashboard {
  backup: { age_seconds?: number; configured: boolean; detail: string; last_backup_at?: string; last_verified_at?: string; state: "ok" | "warning" | "critical" | "unknown"; verified: boolean };
  data_freshness: { detail: string; event_head: number; failed_sequence?: number; lag_events: number; projection_applied: number; state: "ok" | "warning" | "critical" | "unknown" };
  dependencies: { detail?: string; healthy: boolean; name: string }[];
  generated_at: string;
  queues: { detail: string; failed: number; oldest_pending_seconds?: number; pending: number; processing: number; state: "ok" | "warning" | "critical" | "unknown"; stranded: number };
  restore_proof: { completed_at?: string; detail: string; outcome?: string; rpo_seconds?: number; rto_seconds?: number; state: "ok" | "warning" | "critical" | "unknown" };
  signer: { detail: string; healthy: boolean; state: "ok" | "warning" | "critical" | "unknown" };
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

export type OwnershipCSV = string;

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

export interface PAMAccessTemplate {
  command_rules?: PAMCommandRule[];
  desktop_clipboard?: "deny" | "to_target" | "from_target" | "both";
  id: string;
  max_ttl_seconds: number;
  name: string;
  reason: string;
  reauthenticate_within_seconds?: number;
  require_recording: boolean;
  required_approvals: number;
  revision: number;
  saved_at: string;
  saved_by?: string;
  web_sign_in?: PAMWebSignIn;
}

export interface PAMAccessTemplateDeleted {
  deleted: boolean;
  id: string;
}

export interface PAMAccessTemplateList {
  items: PAMAccessTemplate[];
}

export interface PAMAccessTemplateRequest {
  command_rules?: PAMCommandRule[];
  desktop_clipboard?: "deny" | "to_target" | "from_target" | "both";
  max_ttl_seconds: number;
  name: string;
  reason: string;
  reauthenticate_within_seconds?: number;
  require_recording?: boolean;
  required_approvals: number;
  revision?: number;
  web_sign_in?: PAMWebSignIn;
}

export interface PAMAccountActionRequest {
  action: "reassign" | "rotate_disable";
  approval_request_id?: string;
  intent_digest?: string;
  owner_id?: string;
  reason: string;
  request_id: string;
  rotation_old_ref?: string;
}

export interface PAMAccountActionReview {
  approval_count: number;
  approval_request_id: string;
  expires_at: string;
  intent_digest: string;
  request_id: string;
  required_approvals: number;
  status: string;
}

export interface PAMAccountFlag {
  action?: "reassign" | "rotate_disable";
  action_owner_id?: string;
  action_reason?: string;
  action_rotation_id?: string;
  actioned_at?: string;
  actioned_by?: string;
  approval_request_id?: string;
  cleared_at?: string;
  detail?: string;
  flagged_at: string;
  last_used_at?: string;
  owner_id?: string;
  reasons: ("orphaned" | "unused")[];
  status: "open" | "cleared" | "actioned";
  target_id: string;
  target_type: string;
}

export interface PAMAccountFlagList {
  items: PAMAccountFlag[];
}

export interface PAMApprovalRequest {
  approval_count: number;
  approval_request_id: string;
  expires_at: string;
  intent_digest: string;
  request_id: string;
  required_approvals: number;
  role: string;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
  subject: string;
  target_id: string;
  target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" | "netdevice" | "webconsole";
}

export interface PAMAutoApprovalRule {
  applies_to: ("session" | "checkout")[];
  enabled: boolean;
  folders?: string[];
  id: string;
  max_ttl_seconds: number;
  name: string;
  requester_roles?: string[];
  revision: number;
  saved_at: string;
  saved_by?: string;
  target_ids?: string[];
  target_types?: string[];
  ticket_pattern?: string;
  window?: PAMAutoApprovalWindow;
}

export interface PAMAutoApprovalRuleDeleted {
  deleted: boolean;
  id: string;
}

export interface PAMAutoApprovalRuleList {
  items: PAMAutoApprovalRule[];
}

export interface PAMAutoApprovalRuleRequest {
  applies_to: ("session" | "checkout")[];
  enabled: boolean;
  folders?: string[];
  max_ttl_seconds: number;
  name: string;
  requester_roles?: string[];
  revision?: number;
  target_ids?: string[];
  target_types?: string[];
  ticket_pattern?: string;
  window?: PAMAutoApprovalWindow;
}

export interface PAMAutoApprovalWindow {
  days?: ("mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun")[];
  end: string;
  start: string;
  time_zone: string;
}

export interface PAMCheckout {
  account_secret: string;
  approval_request_id: string;
  emergency?: boolean;
  ended_at?: string;
  ended_by?: string;
  expires_at: string;
  provider_id: string;
  reason: string;
  request_id: string;
  requested_by: string;
  revealed_at: string;
  rotation_command_id?: string;
  secret_version: number;
  status: "revealed" | "checked_in" | "expired";
  target_id: string;
  target_type: string;
}

export interface PAMCheckoutList {
  items: PAMCheckout[];
}

export interface PAMCheckoutRequest {
  reason: string;
  request_id: string;
  target_id: string;
  target_type: "postgres" | "mysql" | "windows_local" | "account" | "breakglass";
  template_id?: string;
  ttl_seconds: number;
}

export interface PAMCheckoutReveal {
  checkout: PAMCheckout;
  credential: string;
}

export interface PAMCheckoutRevealRequest {
  approval_request_id: string;
  intent_digest: string;
}

export interface PAMCheckoutReview {
  approval_count: number;
  approval_request_id: string;
  expires_at: string;
  intent_digest: string;
  request_id: string;
  required_approvals: number;
  status: "pending" | "approved" | "denied" | "expired" | "consumed" | "superseded";
}

export interface PAMCommandAction {
  approval_intent_digest?: string;
  approval_request_id?: string;
  attempt: number;
  connection_id: string;
  decided_at: string;
  effective_status: "blocked" | "pending" | "authorized" | "denied" | "expired" | "canceled" | "alerted" | "review_deadline_elapsed";
  id: string;
  job_id: number;
  message_digest: string;
  observed_at: string;
  operations: ("ALTER" | "ANALYZE" | "APPEND" | "ATTACH" | "AUDIT_TAMPERING" | "BACKUP" | "BEGIN" | "BULK_DELETE" | "CALL" | "CHECK" | "CLUSTER" | "COMMENT" | "COMMIT" | "COPY" | "CREATE" | "CREDENTIAL_READ" | "DECR" | "DECRBY" | "DEL" | "DELETE" | "DESCRIBE" | "DETACH" | "DISCARD" | "DO" | "DROP" | "EVAL" | "EVALSHA" | "EXCHANGE" | "EXISTS" | "EXPIRE" | "EXPLAIN" | "FCALL" | "FCALL_RO" | "FLUSH" | "GET" | "GETDEL" | "GRANT" | "HDEL" | "HGET" | "HMGET" | "HMSET" | "HSET" | "INCR" | "INCRBY" | "INSERT" | "KILL" | "LOCK" | "LPOP" | "LPUSH" | "MERGE" | "MGET" | "MOVE" | "MSET" | "OPTIMIZE" | "PERSIST" | "PEXPIRE" | "PRIVILEGE_CHANGE" | "REFRESH" | "REINDEX" | "RENAME" | "RENAMENX" | "REPAIR" | "REPLACE" | "RESET" | "RESTORE" | "REVOKE" | "ROLLBACK" | "RPOP" | "RPUSH" | "SADD" | "SELECT" | "SET" | "SHOW" | "SISMEMBER" | "SMEMBERS" | "SREM" | "START" | "SYSTEM" | "TRUNCATE" | "TTL" | "UNDROP" | "UNLINK" | "UNLOCK" | "UPDATE" | "USE" | "VACUUM" | "WITH" | "ZADD" | "ZREM" | "aggregate" | "atlasversion" | "audit_tampering" | "bash" | "buildinfo" | "bulk_delete" | "bulkwrite" | "chmod" | "chown" | "chpasswd" | "clear" | "collmod" | "collstats" | "command" | "commit" | "configure" | "connectionstatus" | "copy" | "count" | "create" | "createindexes" | "credential_read" | "dbstats" | "dd" | "debug" | "delete" | "diagnose" | "distinct" | "drop" | "dropdatabase" | "dropindexes" | "endsessions" | "env" | "erase" | "exec" | "execute" | "explain" | "find" | "findandmodify" | "format" | "getmore" | "getparameter" | "insert" | "iptables" | "kill" | "killcursors" | "listcollections" | "listdatabases" | "listindexes" | "load" | "mkfs" | "modify" | "mount" | "nft" | "no" | "node" | "passwd" | "perl" | "ping" | "privilege_change" | "python" | "python3" | "reboot" | "reload" | "renamecollection" | "request" | "restart" | "rm" | "rmdir" | "rolesinfo" | "rollback" | "ruby" | "run" | "save" | "scp" | "serverstatus" | "set" | "sftp" | "sh" | "ssh" | "start" | "su" | "sudo" | "systemctl" | "umount" | "update" | "useradd" | "userdel" | "usersinfo" | "validate" | "whatsmyuri" | "write")[];
  ordinal: number;
  phase: string;
  policy_digest: string;
  protocol: string;
  reason: "matched_rule" | "matched_alert_rule" | "unsupported_control" | "uninspectable" | "review_required" | "review_approved" | "review_denied" | "review_expired" | "client_canceled" | "session_ended";
  review_expires_at?: string;
  rule_ids: string[];
  session_id: string;
  source_event_id: string;
  status: "blocked" | "pending" | "authorized" | "denied" | "expired" | "canceled" | "alerted";
}

export interface PAMCommandActionList {
  items: PAMCommandAction[];
  next_cursor?: string;
}

export interface PAMCommandPolicy {
  rules: PAMFrozenCommandRule[];
  template_id: string;
  template_revision: number;
  version: number;
}

export interface PAMCommandRule {
  effect: "block" | "require_approval" | "alert";
  enabled: boolean;
  id: string;
  name: string;
  operations: ("ALTER" | "ANALYZE" | "APPEND" | "ATTACH" | "AUDIT_TAMPERING" | "BACKUP" | "BEGIN" | "BULK_DELETE" | "CALL" | "CHECK" | "CLUSTER" | "COMMENT" | "COMMIT" | "COPY" | "CREATE" | "CREDENTIAL_READ" | "DECR" | "DECRBY" | "DEL" | "DELETE" | "DESCRIBE" | "DETACH" | "DISCARD" | "DO" | "DROP" | "EVAL" | "EVALSHA" | "EXCHANGE" | "EXISTS" | "EXPIRE" | "EXPLAIN" | "FCALL" | "FCALL_RO" | "FLUSH" | "GET" | "GETDEL" | "GRANT" | "HDEL" | "HGET" | "HMGET" | "HMSET" | "HSET" | "INCR" | "INCRBY" | "INSERT" | "KILL" | "LOCK" | "LPOP" | "LPUSH" | "MERGE" | "MGET" | "MOVE" | "MSET" | "OPTIMIZE" | "PERSIST" | "PEXPIRE" | "PRIVILEGE_CHANGE" | "REFRESH" | "REINDEX" | "RENAME" | "RENAMENX" | "REPAIR" | "REPLACE" | "RESET" | "RESTORE" | "REVOKE" | "ROLLBACK" | "RPOP" | "RPUSH" | "SADD" | "SELECT" | "SET" | "SHOW" | "SISMEMBER" | "SMEMBERS" | "SREM" | "START" | "SYSTEM" | "TRUNCATE" | "TTL" | "UNDROP" | "UNLINK" | "UNLOCK" | "UPDATE" | "USE" | "VACUUM" | "WITH" | "ZADD" | "ZREM" | "aggregate" | "atlasversion" | "audit_tampering" | "bash" | "buildinfo" | "bulk_delete" | "bulkwrite" | "chmod" | "chown" | "chpasswd" | "clear" | "collmod" | "collstats" | "command" | "commit" | "configure" | "connectionstatus" | "copy" | "count" | "create" | "createindexes" | "credential_read" | "dbstats" | "dd" | "debug" | "delete" | "diagnose" | "distinct" | "drop" | "dropdatabase" | "dropindexes" | "endsessions" | "env" | "erase" | "exec" | "execute" | "explain" | "find" | "findandmodify" | "format" | "getmore" | "getparameter" | "insert" | "iptables" | "kill" | "killcursors" | "listcollections" | "listdatabases" | "listindexes" | "load" | "mkfs" | "modify" | "mount" | "nft" | "no" | "node" | "passwd" | "perl" | "ping" | "privilege_change" | "python" | "python3" | "reboot" | "reload" | "renamecollection" | "request" | "restart" | "rm" | "rmdir" | "rolesinfo" | "rollback" | "ruby" | "run" | "save" | "scp" | "serverstatus" | "set" | "sftp" | "sh" | "ssh" | "start" | "su" | "sudo" | "systemctl" | "umount" | "update" | "useradd" | "userdel" | "usersinfo" | "validate" | "whatsmyuri" | "write")[];
  protocol: "postgres" | "ssh" | "mysql" | "redis" | "mongodb" | "clickhouse" | "netdevice";
  required_approvals?: number;
  review_ttl_seconds?: number;
  severity?: "warning" | "critical";
}

export interface PAMDependentAccountBinding {
  account_id: string;
  dn: string;
  guid: string;
  name: string;
  provider_id: string;
  sid: string;
}

export interface PAMDependentFamilyCoverage {
  failure?: string;
  family: "services" | "tasks" | "iis";
  status: "complete" | "unavailable";
}

export interface PAMDependentFunctionalProof {
  account_sid: string;
  challenge: string;
  evidence_sha256: string;
  probe_id: string;
  process_id?: number;
  task_instance_id?: string;
}

export interface PAMDependentHostBinding {
  account: PAMDependentAccountBinding;
  agent_id: string;
  enabled: boolean;
  revision: number;
}

export interface PAMDependentInventoryIntent {
  binding: PAMDependentHostBinding;
  binding_digest: string;
  run_id: string;
}

export interface PAMDependentInventoryReport {
  binding_digest: string;
  coverage: PAMDependentFamilyCoverage[];
  observed_at: string;
  pools?: PAMDependentNativePool[];
  run_id: string;
  services?: PAMDependentNativeService[];
  tasks?: PAMDependentNativeTask[];
}

export interface PAMDependentManifestCursor {
  direction: "forward" | "inverse";
  position: PAMDependentManifestPosition;
}

export interface PAMDependentManifestPosition {
  entry_index: number;
  entry_ordinal: number;
  page_number: number;
  stage: "preflight" | "stop" | "update" | "start" | "probe" | "complete";
}

export interface PAMDependentNativePool {
  account_sid: string;
  config_sha256: string;
  encryption_provider: string;
  name: string;
  password_protected: boolean;
  was_started: boolean;
}

export interface PAMDependentNativeService {
  account_sid: string;
  config_sha256: string;
  dependencies?: string[];
  name: string;
  was_running: boolean;
}

export interface PAMDependentNativeTask {
  account_sid: string;
  action_count: number;
  config_sha256: string;
  enabled: boolean;
  logon_type: number;
  path: string;
}

export interface PAMDependentPoolRestartProof {
  account_sid: string;
  config_sha256: string;
  name: string;
  previous_pids: unknown;
  started_observed: boolean;
  stopped_observed: boolean;
  was_started: boolean;
}

export interface PAMDependentProbeBinding {
  probe_id: string;
  ref: PAMDependentRef;
}

export interface PAMDependentRef {
  agent_id: string;
  family: "services" | "tasks" | "iis";
  name: string;
}

export interface PAMDependentRotationHost {
  binding: PAMDependentHostBinding;
  dependents: PAMDependentRef[];
  inventory_digest: string;
  inventory_run_id: string;
  observed_at: string;
}

export interface PAMDependentRotationPlan {
  account: PAMDependentAccountBinding;
  created_at: string;
  digest: string;
  expires_at: string;
  hosts: PAMDependentRotationHost[];
  id: string;
  manifest?: PAMServiceDependentReviewSeal;
  order: PAMDependentRef[];
  secret_name: string;
  version: number;
}

export interface PAMDependentRotationStep {
  account_sid: string;
  action: "preflight" | "stop" | "update" | "start" | "probe";
  challenge?: string;
  deadline: string;
  direction: "forward" | "inverse";
  manifest_position?: PAMDependentManifestPosition;
  not_before: string;
  plan_digest: string;
  pool?: PAMDependentNativePool;
  previous_pids?: number[];
  probe_id: string;
  recovery?: PAMDependentStepRecoveryBinding;
  ref: PAMDependentRef;
  rotation_id: string;
  service?: PAMDependentNativeService;
  step_id: string;
  task?: PAMDependentNativeTask;
}

export interface PAMDependentRuntime {
  account_sid?: string;
  process_id?: number;
  running: boolean;
}

export interface PAMDependentStepRecoveryBinding {
  depth: number;
  previous_step_id: string;
  root_step_id: string;
  version: number;
}

export interface PAMDependentStepReport {
  direction: "forward" | "inverse";
  failure?: string;
  functional?: PAMDependentFunctionalProof;
  observed_at: string;
  plan_digest: string;
  pool_proof?: PAMDependentPoolRestartProof;
  rotation_id: string;
  runtime?: PAMDependentRuntime;
  status: "succeeded" | "failed" | "uncertain";
  step_id: string;
  task_proof?: PAMDependentTaskRunProof;
}

export interface PAMDependentTaskActionResult {
  record_id: number;
  result_code: number;
}

export interface PAMDependentTaskRunProof {
  account_sid: string;
  actions: PAMDependentTaskActionResult[];
  completed_at: string;
  completion_record_id: number;
  instance_id: string;
  path: string;
  start_record_id: number;
  started_at: string;
}

export interface PAMDiscoveredAccount {
  details?: Record<string, unknown>;
  disabled: boolean;
  first_seen_at: string;
  id: string;
  key: string;
  kind: "local_user" | "database_role" | "database_user" | "sql_login" | "directory_user" | "directory_service_account";
  last_seen_at: string;
  name: string;
  privileges: string[];
  provider_id: string;
  removed_at?: string;
  status: "staged" | "imported" | "dismissed";
}

export interface PAMDiscoveredAccountList {
  items: PAMDiscoveredAccount[];
}

export interface PAMDiscoveryChange {
  account: { details?: Record<string, unknown>; disabled: boolean; key: string; kind: "local_user" | "database_role" | "database_user" | "sql_login" | "directory_user" | "directory_service_account"; name: string; privileges: string[] };
  change: "added" | "removed" | "changed";
}

export interface PAMDiscoveryDismissRequest {
  reason: string;
}

export interface PAMDiscoveryImportRequest {
  account_ids: string[];
  approval_request_id?: string;
  folder: string;
  intent_digest?: string;
  reason: string;
  request_id: string;
  template_id?: string;
}

export interface PAMDiscoveryImportReview {
  accounts: number;
  approval_count: number;
  approval_request_id: string;
  expires_at: string;
  intent_digest: string;
  request_id: string;
  required_approvals: number;
  status: "pending" | "approved" | "denied" | "expired" | "consumed" | "superseded";
}

export interface PAMDiscoveryRun {
  accounts: number;
  added: number;
  changed: number;
  changes?: PAMDiscoveryChange[];
  delivery_status?: string;
  failure?: "unreachable" | "rejected" | "expired" | "locked" | "error" | "not_supported" | "too_many" | "source_changed" | "delivery_failed";
  finished_at?: string;
  id: string;
  provider_id: string;
  removed: number;
  requested_by: string;
  started_at: string;
  status: "queued" | "completed" | "failed";
}

export interface PAMDiscoveryRunList {
  items: PAMDiscoveryRun[];
}

export interface PAMDiscoverySource {
  interval_seconds: number;
  last_run?: { accounts: number; added: number; changed: number; changes?: PAMDiscoveryChange[]; delivery_status?: string; failure?: "unreachable" | "rejected" | "expired" | "locked" | "error" | "not_supported" | "too_many" | "source_changed" | "delivery_failed"; finished_at?: string; id: string; provider_id: string; removed: number; requested_by: string; started_at: string; status: "queued" | "completed" | "failed" };
  provider_id: string;
  provider_type: string;
  saved_at: string;
  saved_by?: string;
}

export interface PAMDiscoverySourceDeleted {
  deleted: boolean;
  provider_id: string;
}

export interface PAMDiscoverySourceList {
  items: PAMDiscoverySource[];
}

export interface PAMDiscoverySourceRequest {
  interval_seconds: number;
}

export interface PAMEmergencyCheckout {
  checkout: PAMCheckout;
  credential: string;
  emergency: PAMEmergencyGrant;
  hardware_key_holders?: string[];
}

export interface PAMEmergencyGrant {
  expires_at: string;
  opened_at: string;
  reason: string;
  responder: string;
  review: { notes?: string; outcome?: "justified" | "unjustified"; reviewed_at?: string; reviewer?: string; status: "pending" | "reviewed" };
  role: string;
  session_id: string;
  target_id: string;
  target_type: string;
}

export interface PAMEmergencyGrantList {
  items: PAMEmergencyGrant[];
}

export interface PAMEmergencyResponders {
  subjects: string[];
}

export interface PAMEmergencyReviewRequest {
  notes: string;
  outcome: "justified" | "unjustified";
}

export interface PAMEmergencySessionRequest {
  method: string;
  payload_base64: string;
  reason: string;
  role: string;
  ssh_principal?: string;
  ssh_public_key?: string;
  target_id: string;
  target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" | "netdevice" | "webconsole";
  ttl_seconds?: number;
}

export interface PAMFolder {
  description?: string;
  name: string;
  revision: number;
  saved_at: string;
  saved_by?: string;
  targets: number;
  template_id: string;
}

export interface PAMFolderDeleted {
  deleted: boolean;
  name: string;
}

export interface PAMFolderList {
  items: PAMFolder[];
}

export interface PAMFolderRequest {
  description?: string;
  revision?: number;
  template_id: string;
}

export interface PAMFrozenCommandRule {
  effect: "block" | "require_approval" | "alert";
  id: string;
  operations: ("ALTER" | "ANALYZE" | "APPEND" | "ATTACH" | "AUDIT_TAMPERING" | "BACKUP" | "BEGIN" | "BULK_DELETE" | "CALL" | "CHECK" | "CLUSTER" | "COMMENT" | "COMMIT" | "COPY" | "CREATE" | "CREDENTIAL_READ" | "DECR" | "DECRBY" | "DEL" | "DELETE" | "DESCRIBE" | "DETACH" | "DISCARD" | "DO" | "DROP" | "EVAL" | "EVALSHA" | "EXCHANGE" | "EXISTS" | "EXPIRE" | "EXPLAIN" | "FCALL" | "FCALL_RO" | "FLUSH" | "GET" | "GETDEL" | "GRANT" | "HDEL" | "HGET" | "HMGET" | "HMSET" | "HSET" | "INCR" | "INCRBY" | "INSERT" | "KILL" | "LOCK" | "LPOP" | "LPUSH" | "MERGE" | "MGET" | "MOVE" | "MSET" | "OPTIMIZE" | "PERSIST" | "PEXPIRE" | "PRIVILEGE_CHANGE" | "REFRESH" | "REINDEX" | "RENAME" | "RENAMENX" | "REPAIR" | "REPLACE" | "RESET" | "RESTORE" | "REVOKE" | "ROLLBACK" | "RPOP" | "RPUSH" | "SADD" | "SELECT" | "SET" | "SHOW" | "SISMEMBER" | "SMEMBERS" | "SREM" | "START" | "SYSTEM" | "TRUNCATE" | "TTL" | "UNDROP" | "UNLINK" | "UNLOCK" | "UPDATE" | "USE" | "VACUUM" | "WITH" | "ZADD" | "ZREM" | "aggregate" | "atlasversion" | "audit_tampering" | "bash" | "buildinfo" | "bulk_delete" | "bulkwrite" | "chmod" | "chown" | "chpasswd" | "clear" | "collmod" | "collstats" | "command" | "commit" | "configure" | "connectionstatus" | "copy" | "count" | "create" | "createindexes" | "credential_read" | "dbstats" | "dd" | "debug" | "delete" | "diagnose" | "distinct" | "drop" | "dropdatabase" | "dropindexes" | "endsessions" | "env" | "erase" | "exec" | "execute" | "explain" | "find" | "findandmodify" | "format" | "getmore" | "getparameter" | "insert" | "iptables" | "kill" | "killcursors" | "listcollections" | "listdatabases" | "listindexes" | "load" | "mkfs" | "modify" | "mount" | "nft" | "no" | "node" | "passwd" | "perl" | "ping" | "privilege_change" | "python" | "python3" | "reboot" | "reload" | "renamecollection" | "request" | "restart" | "rm" | "rmdir" | "rolesinfo" | "rollback" | "ruby" | "run" | "save" | "scp" | "serverstatus" | "set" | "sftp" | "sh" | "ssh" | "start" | "su" | "sudo" | "systemctl" | "umount" | "update" | "useradd" | "userdel" | "usersinfo" | "validate" | "whatsmyuri" | "write")[];
  protocol: "postgres" | "ssh" | "mysql" | "redis" | "mongodb" | "clickhouse" | "netdevice";
  required_approvals?: number;
  review_ttl_seconds?: number;
  severity?: "warning" | "critical";
}

export interface PAMGatewayMember {
  address: string;
  agent_id: string;
  draining?: boolean;
  health?: "healthy" | "draining" | "lost" | "offboarded";
  last_seen_at?: string;
  live_sessions: number;
  upgrade_pending?: boolean;
}

export interface PAMGatewayPool {
  members: PAMGatewayMember[];
  name: string;
  revision: number;
  saved_at: string;
  saved_by?: string;
}

export interface PAMGatewayPoolDeleted {
  deleted: boolean;
  name: string;
}

export interface PAMGatewayPoolList {
  items: PAMGatewayPool[];
}

export interface PAMGatewayPoolRequest {
  members: { address: string; agent_id: string; draining?: boolean }[];
  revision?: number;
}

export interface PAMImportedAccount {
  approval_request_id: string;
  folder: string;
  id: string;
  imported_at: string;
  imported_by: string;
  key: string;
  kind: string;
  name: string;
  privileges: string[];
  provider_id: string;
  reason: string;
  request_id: string;
  template_id?: string;
}

export interface PAMImportedAccountList {
  items: PAMImportedAccount[];
}

export interface PAMPostgresCredential {
  dsn: string;
  username: string;
}

export interface PAMQueryRequest {
  sql: string;
}

export interface PAMQueryResult {
  columns: string[];
  command_tag?: string;
  error?: { code: string; message: string };
  rows: string[][];
  truncated?: boolean;
}

export interface PAMReconcilePrincipal {
  dn: string;
  guid: string;
  sid: string;
}

export interface PAMRecording {
  bytes: number;
  chain_head: string;
  chunks: number;
  deleted_at?: string;
  final_received: boolean;
  last_chunk_at: string;
  legal_hold: boolean;
  legal_hold_reason?: string;
  manifest_sha256?: string;
  pending_chunks: number;
  scope?: string;
  sealed_at?: string;
  session_id: string;
  started_at: string;
  status: "recording" | "sealed" | "deleted";
}

export interface PAMRecordingExport {
  frames: Record<string, unknown>[];
  manifest: Record<string, unknown>;
  manifest_signature: string;
  session_id: string;
}

export interface PAMRecordingFrames {
  frames: Record<string, unknown>[];
  next: number;
  session_id: string;
  status: "recording" | "sealed" | "deleted";
}

export interface PAMRecordingIndex {
  items: { conn: number; kind: string; t: number; text?: string }[];
  session_id: string;
  status: "recording" | "sealed" | "deleted";
}

export interface PAMRecordingLegalHoldRequest {
  reason: string;
}

export interface PAMRecordingSearchHit {
  at_millis: number;
  conn: number;
  kind?: string;
  session_id: string;
  session_started_at: string;
  source: "command" | "sql" | "result" | "output" | "index" | "request";
  subject: string;
  target_id: string;
  target_type: string;
  text: string;
}

export interface PAMRecordingSearchResult {
  items: PAMRecordingSearchHit[];
  sessions_searched: number;
  truncated: boolean;
}

export interface PAMRecordingVerification {
  chunks: number;
  problems?: string[];
  scope?: string;
  verified: boolean;
}

export interface PAMRequestProgress {
  approval_count: number;
  approval_request_id: string;
  expires_at: string;
  intent_digest: string;
  request_id: string;
  required_approvals: number;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
}

export interface PAMSSHCredential {
  certificate: string;
  key_id: string;
  principal: string;
  serial: number;
  valid_before: string;
}

export interface PAMServiceDependentHost {
  binding: PAMDependentHostBinding;
  binding_digest: string;
  latest_scan?: PAMServiceDependentScanHead;
  saved_by: string;
  updated_at: string;
}

export interface PAMServiceDependentHostList {
  items: PAMServiceDependentHost[];
  next_cursor?: string;
}

export interface PAMServiceDependentHostRequest {
  enabled: boolean;
}

export interface PAMServiceDependentRecoveryQueued {
  recovery_digest: string;
  step: PAMDependentRotationStep;
}

export interface PAMServiceDependentRecoveryRequest {
  acknowledge_original_outcome: boolean;
  intent_digest: string;
  reason: string;
  recovery_digest: string;
  step_id: string;
}

export interface PAMServiceDependentRecoveryReview {
  current_vault_version: number;
  intent_digest: string;
  previous_report_digest?: string;
  previous_status: "queued" | "failed" | "uncertain";
  previous_step: PAMDependentRotationStep;
  recovery_digest: string;
  retained_generation_version: number;
}

export interface PAMServiceDependentReview {
  actor: string;
  entry_count: number;
  header: PAMServiceDependentReviewHeader;
  header_digest: string;
  host_count: number;
  intent?: PAMServiceDependentRotationIntent;
  intent_digest?: string;
  page_count: number;
  seal?: PAMServiceDependentReviewSeal;
}

export interface PAMServiceDependentReviewEntry {
  host: PAMServiceDependentReviewHost;
  probe_id: string;
  ref: PAMDependentRef;
}

export interface PAMServiceDependentReviewHeader {
  account: PAMDependentAccountBinding;
  created_at: string;
  expected_version: number;
  expires_at: string;
  id: string;
  mode?: "reconcile";
  provider_binding: string;
  reconcile?: PAMReconcilePrincipal;
  secret_name: string;
  version: number;
}

export interface PAMServiceDependentReviewHost {
  binding: PAMDependentHostBinding;
  inventory_digest: string;
  inventory_run_id: string;
  observed_at: string;
}

export interface PAMServiceDependentReviewOpenRequest {
  mode?: "reconcile";
  secret_name: string;
}

export interface PAMServiceDependentReviewPage {
  digest: string;
  entries: unknown;
  header_digest: string;
  hosts: PAMServiceDependentReviewHost[];
  id: string;
  page_number: number;
  previous_digest: string;
  version: number;
}

export interface PAMServiceDependentReviewPageRequest {
  entries?: PAMServiceDependentReviewEntry[];
  header_digest: string;
  hosts?: PAMServiceDependentReviewHost[];
  previous_digest: string;
}

export interface PAMServiceDependentReviewSeal {
  digest: string;
  entry_count: number;
  expires_at: string;
  header_digest: string;
  host_count: number;
  id: string;
  page_count: number;
  tail_digest: string;
  version: number;
}

export interface PAMServiceDependentReviewSealRequest {
  header_digest: string;
  tail_digest: string;
}

export interface PAMServiceDependentRotation {
  actor: string;
  command_id: string;
  created_at: string;
  direction: "forward" | "inverse";
  directory_apply_started: boolean;
  directory_restored: boolean;
  failure?: string;
  id: string;
  intent: PAMServiceDependentRotationIntent;
  intent_digest: string;
  manifest_cursor?: PAMDependentManifestCursor;
  manifest_cursor_sequence?: number;
  manifest_cursor_source_id?: string;
  tenant_epoch: string;
  updated_at: string;
}

export interface PAMServiceDependentRotationIntent {
  expected_version: number;
  mode?: "reconcile";
  plan: PAMDependentRotationPlan;
  probes: PAMDependentProbeBinding[];
  provider_binding: string;
  reconcile?: PAMReconcilePrincipal;
}

export interface PAMServiceDependentRotationPreview {
  intent: PAMServiceDependentRotationIntent;
  intent_digest: string;
}

export interface PAMServiceDependentRotationPreviewRequest {
  mode?: "reconcile";
  order: PAMDependentRef[];
  probes: PAMDependentProbeBinding[];
  secret_name: string;
}

export interface PAMServiceDependentRotationRequest {
  acknowledge_single_phase: boolean;
  approval_intent_digest?: string;
  approval_request_id?: string;
  intent: PAMServiceDependentRotationIntent;
  intent_digest: string;
}

export interface PAMServiceDependentRotationStep {
  attempt?: number;
  delivery_status?: string;
  intent: PAMDependentRotationStep;
  outbox_id?: number;
  queued_at: string;
  receipt_job_id?: number;
  receipt_signature_base64?: string;
  receipt_statement?: string;
  received_at?: string;
  report?: PAMDependentStepReport;
  signer_fingerprint?: string;
  status: "queued" | "succeeded" | "failed" | "uncertain";
}

export interface PAMServiceDependentRotationStepList {
  items: PAMServiceDependentRotationStep[];
  next_cursor?: string;
}

export interface PAMServiceDependentRotationView {
  approval_intent_digest?: string;
  approval_request_id?: string;
  command: SecretStaticRotation;
  recovery_step_id?: string;
  rotation: PAMServiceDependentRotation;
}

export interface PAMServiceDependentScan {
  attempt?: number;
  delivery_status?: string;
  failure?: string;
  id: string;
  intent: PAMDependentInventoryIntent;
  observed_at?: string;
  observed_event_id?: string;
  outbox_id?: number;
  pool_count: number;
  queued_at: string;
  queued_by: string;
  queued_event_id: string;
  receipt_job_id?: number;
  receipt_signature_base64?: string;
  receipt_statement?: string;
  received_at?: string;
  report?: PAMDependentInventoryReport;
  report_digest?: string;
  service_count: number;
  signer_fingerprint?: string;
  status: "queued" | "complete" | "partial" | "retrying" | "failed" | "superseded";
  task_count: number;
}

export interface PAMServiceDependentScanHead {
  agent_id: string;
  binding_digest: string;
  current: boolean;
  delivery_status?: string;
  failure?: string;
  id: string;
  pool_count: number;
  queued_at: string;
  received_at?: string;
  service_count: number;
  status: string;
  task_count: number;
}

export interface PAMServiceReconciliationApproval {
  approval_count: number;
  approval_intent_digest: string;
  approval_request_id: string;
  expires_at: string;
  required_approvals: number;
  status: "pending" | "approved" | "denied" | "expired" | "superseded" | "consumed";
}

export interface PAMServiceReconciliationApprovalRequest {
  intent: PAMServiceDependentRotationIntent;
  intent_digest: string;
  reason: string;
}

export interface PAMServiceReconciliationPendingReview {
  approval: PAMServiceReconciliationApproval;
  created_at: string;
  intent: PAMServiceDependentRotationIntent;
  intent_digest: string;
  queue_pending?: boolean;
  reason: string;
  rotation_id?: string;
}

export interface PAMServiceReconciliationReview {
  created_at: string;
  intent: PAMServiceDependentRotationIntent;
  intent_digest: string;
}

export interface PAMSession {
  attestation?: Attestation;
  audit?: Record<string, unknown>;
  command_policy?: PAMCommandPolicy;
  delivery?: "direct" | "gateway";
  emergency?: PAMEmergencyGrant;
  ended_at?: string;
  expires_at: string;
  gateway?: { address: string; agent_id: string; aws_region?: string; aws_service?: string; ca_pem?: string; spiffe_id: string; ticket?: string };
  gateway_end?: { ended: "deadline" | "recalled"; ended_at: string };
  gateway_lost?: boolean;
  id: string;
  postgres?: PAMPostgresCredential;
  reason?: string;
  requested_by: string;
  revocation_failed_at?: string;
  revocation_failure?: string;
  revocation_reason?: string;
  revocation_requested_at?: string;
  revocation_requested_by?: string;
  role: string;
  ssh?: PAMSSHCredential;
  started_at: string;
  status: string;
  subject: string;
  target_id: string;
  target_type: string;
  uncertain_until?: string;
}

export interface PAMSessionActivationRequest {
  approval_request_id: string;
  browser?: boolean;
  intent_digest: string;
  method: string;
  payload_base64: string;
  reason?: string;
  request_id: string;
  role: string;
  ssh_principal?: string;
  ssh_public_key?: string;
  target_id: string;
  target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" | "netdevice" | "webconsole";
  template_id?: string;
  ttl_seconds?: number;
}

export interface PAMSessionList {
  items: PAMSession[];
  next_cursor?: string;
}

export interface PAMSessionRequest {
  method: string;
  payload_base64: string;
  reason?: string;
  request_id: string;
  role: string;
  ssh_principal?: string;
  ssh_public_key?: string;
  target_id: string;
  target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" | "netdevice" | "webconsole";
  template_id?: string;
  ttl_seconds?: number;
}

export interface PAMSessionRevocationRequest {
  reason: string;
}

export interface PAMSignIn {
  account: string;
  at: string;
  collector?: string;
  earliest?: string;
  explained_by?: { kind: "gateway_session" | "session" | "checkout" | "rotation_check" | "health_check"; ref?: string };
  fingerprint: string;
  key_id?: string;
  last_seen_at: string;
  method?: string;
  provider_id: string;
  ref?: string;
  source?: string;
}

export interface PAMSignInList {
  items: PAMSignIn[];
}

export interface PAMTarget {
  account_secret?: string;
  allowed_roles?: string[];
  disabled_at?: string;
  disabled_by?: string;
  disabled_reason?: string;
  enabled: boolean;
  folder?: string;
  gateway_address?: string;
  gateway_agent_id?: string;
  hardware_key_holders?: string[];
  health?: { attempts: number; checked_at: string; failing_since?: string; not_retried: boolean; status: "healthy" | "rejected" | "expired" | "locked" | "unreachable" | "error" | "not_supported" };
  host?: string;
  host_key_fingerprints?: string[];
  id: string;
  owner_id?: string;
  port?: number;
  principals?: string[];
  provider_id?: string;
  registered_at?: string;
  registered_by?: string;
  source: "operator" | "tenant";
  target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" | "windows_local" | "netdevice" | "account" | "breakglass" | "webconsole";
  web?: PAMWebConsoleRoute;
}

export interface PAMTargetDisableRequest {
  reason: string;
}

export interface PAMTargetFolderRequest {
  folder: string;
}

export interface PAMTargetList {
  items: PAMTarget[];
  next_cursor?: string;
}

export interface PAMTargetRequest {
  account_secret?: string;
  allowed_roles?: string[];
  folder?: string;
  gateway_address?: string;
  gateway_agent_id?: string;
  host?: string;
  host_key_fingerprints?: string[];
  id: string;
  port?: number;
  principals?: string[];
  provider_id?: string;
  target_type: "aws" | "aws-console" | "azure" | "clickhouse" | "gcp" | "kubernetes" | "mongodb" | "mysql" | "postgres" | "rdp" | "redis" | "snowflake" | "ssh" | "windows_local" | "netdevice" | "account" | "breakglass" | "webconsole";
  web?: PAMWebConsoleRoute;
}

export interface PAMTerminal {
  cols?: number;
  id: string;
  rows?: number;
  session_id: string;
}

export interface PAMTerminalInput {
  data: string;
}

export interface PAMTerminalOutput {
  closed?: boolean;
  data: string;
  exit_status?: number;
  next: number;
  truncated?: boolean;
}

export interface PAMTerminalRequest {
  cols: number;
  command?: string[];
  container?: string;
  namespace?: string;
  pod?: string;
  rows: number;
  ssh_command?: string;
}

export interface PAMWebConsoleRoute {
  ca_pem?: string;
  server_name?: string;
  url: string;
}

export interface PAMWebSignIn {
  browser_cookies?: string[];
  header?: string;
  header_prefix?: string;
  login_path?: string;
  mode: "form" | "header" | "basic";
  password_field?: string;
  username_field?: string;
}

export interface PAMWindowsLocalAccount {
  enabled: boolean;
  locked: boolean;
  name: string;
  password_required: boolean;
  sid: string;
}

export interface PAMWindowsLocalAccountHost {
  id: string;
  last_seen_at?: string;
  name: string;
  status: string;
}

export interface PAMWindowsLocalAccountHostList {
  items: PAMWindowsLocalAccountHost[];
  next_cursor?: string;
}

export interface PAMWindowsLocalAccountIntent {
  agent_id: string;
  binding_digest: string;
  run_id: string;
  tenant_id: string;
}

export interface PAMWindowsLocalAccountInventory {
  accounts: PAMWindowsLocalAccount[];
  deleted_members: number;
  external_members: number;
  group_members: number;
  machine: PAMWindowsSAMMachine;
}

export interface PAMWindowsLocalAccountReport {
  binding_digest: string;
  failure?: string;
  inventory?: PAMWindowsLocalAccountInventory;
  observed_at: string;
  run_id: string;
  status: "complete" | "unavailable";
}

export interface PAMWindowsLocalAccountScan {
  attempt?: number;
  delivery_status: string;
  failure?: string;
  id: string;
  intent: PAMWindowsLocalAccountIntent;
  observed_event_id?: string;
  outbox_id?: number;
  queued_at: string;
  queued_by: string;
  queued_event_id: string;
  receipt_job_id?: number;
  receipt_signature_base64?: string;
  receipt_statement?: string;
  received_at?: string;
  report?: PAMWindowsLocalAccountReport;
  report_digest?: string;
  signer_fingerprint?: string;
  status: "queued" | "complete" | "failed" | "retrying";
}

export interface PAMWindowsLocalAccountScanList {
  items: PAMWindowsLocalAccountScan[];
  next_cursor?: string;
}

export interface PAMWindowsSAMMachine {
  name: string;
  role: number;
  sid: string;
}

export interface PKISecret {
  certificate: string;
  certificate_id: string;
  common_name: string;
  private_key?: string;
  serial: string;
}

export type PKISecretLeafPEM = string;

export interface PKISecretLeafRecovery {
  already_recovered: boolean;
  certificate_id: string;
  evidence: "retained_v2_leaf" | "operator_public_leaf";
  fingerprint: string;
  original_event_id: string;
  serial: string;
}

export interface PKISecretPrerequisite {
  detail: string;
  id: string;
  ready: boolean;
  remediation?: string;
}

export interface PKISecretPreview {
  blockers: string[];
  ca_certificate_sha256?: string;
  capability: string;
  cli_argv: string[];
  common_name: string;
  csr_sha256?: string;
  custody_mode: string;
  dns_names: string[];
  effect_free: boolean;
  effective_ttl_seconds: number;
  execute_external_effects: string[];
  execute_writes: string[];
  operation: string;
  prerequisites: PKISecretPrerequisite[];
  preview_external_effects: string[];
  preview_writes: string[];
  profile: string;
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  requested_ttl_seconds: number;
  required_permission: string;
  secret_data_handling: string;
  subject_key_algorithm: string;
  subject_key_bits: number;
  vault_path: string;
  verification_steps: string[];
}

export interface PKISecretRequest {
  common_name?: string;
  csr_pem?: string;
  preview_fingerprint?: string;
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

export interface PQCPilot {
  authority_id?: string;
  created_at: string;
  current_wave: number;
  finished_at?: string;
  halted_at_wave?: string;
  id: string;
  name: string;
  requested_by?: string;
  signed_report?: Record<string, unknown>;
  status: "running" | "halted" | "completed";
  tenant_id: string;
  updated_at: string;
  verdict_summary?: string;
  wave_count: number;
  waves?: PQCPilotWave[];
}

export interface PQCPilotList {
  items: PQCPilot[];
  next_cursor?: string;
}

export interface PQCPilotResult {
  chain_bytes: number;
  detail?: string;
  evidence_digest?: string;
  handshake_ms: number;
  observed_at: string;
  outcome: "negotiated" | "rejected" | "unreachable" | "not_attempted";
  target_id: string;
}

export interface PQCPilotStartRequest {
  authority_id: string;
  id?: string;
  name: string;
  timeout_seconds?: number;
  waves: PQCPilotWaveRequest[];
}

export interface PQCPilotTarget {
  address: string;
  connector?: string;
  fingerprint: string;
  server_name?: string;
  target_id: string;
}

export interface PQCPilotVerdict {
  halt: boolean;
  negotiated: number;
  not_attempted: number;
  ready: boolean;
  rejected: number;
  summary: string;
  unreachable: number;
}

export interface PQCPilotWave {
  assessed_at?: string;
  dispatched_at?: string;
  idempotency_key?: string;
  index: number;
  name: string;
  outbox_id?: number;
  results?: PQCPilotResult[];
  status: "pending" | "probing" | "assessed" | "skipped";
  targets: PQCPilotTarget[];
  verdict?: PQCPilotVerdict;
}

export interface PQCPilotWaveRequest {
  name: string;
  targets: PQCPilotTarget[];
}

export interface PendingApprovalRequest {
  action: "issue" | "create" | "rotate" | "revoke" | "sign" | "recover" | "delete" | "managedkey:rotate" | "managedkey:revoke" | "managedkey:zeroize" | "revoke_key" | "tighten_policy" | "replace_key" | "reconcile";
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
  resource_kind: "identity" | "secret" | "managed_key" | "code_signing" | "ephemeral" | "cloud_machine" | "pam_service_reconcile";
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
  rollback_available?: boolean;
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
  enforcement: { enabled: boolean; module_sha256?: string };
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
  third_party_scan_findings_before?: string;
}

export interface PrivacyRetentionPreview {
  blockers: string[];
  capability: string;
  counts: Record<string, unknown>;
  cutoffs: PrivacyRetentionCutoffs;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  operation: string;
  prerequisites: string[];
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  reviewed_at: string;
  secret_data_handling: string;
  total_records: number;
  verification_steps: string[];
  warnings: string[];
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

export interface PrivacySubjectErasurePreview {
  active_legal_holds: number;
  archive_attestations: number;
  blockers: string[];
  capability: string;
  counts: Record<string, unknown>;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  normalized_request: PrivacySubjectErasureRequest;
  operation: string;
  prerequisites: string[];
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  secret_data_handling: string;
  subject_ref: string;
  total_records: number;
  verification_steps: string[];
  warnings: string[];
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

export interface ProfileEditApprovalDecision {
  approver: string;
  at: string;
  decision: "approve";
}

export interface ProfileEditApprovalDecisionRequest {
  reason?: string;
}

export interface ProfileEditApprovalList {
  items: ProfileEditApprovalRecord[];
  next_cursor?: string;
}

export interface ProfileEditApprovalRecord {
  approvals: ProfileEditApprovalDecision[];
  created_at: string;
  expected_active_version?: number;
  expires_at: string;
  id: string;
  kind: "profile_edit";
  profile_id?: string;
  profile_name: string;
  requester: string;
  required_approvals: number;
  resource: string;
  restore_reason?: string;
  restored_from_version?: number;
  spec: CertificateProfileSpec;
  spec_sha256: string;
  state: "awaiting_approval" | "approved" | "issued" | "denied" | "expired";
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

export interface ProviderAccessConsent {
  approve: boolean;
  decided_at: string;
  grant_id: string;
  reason?: string;
  subject: string;
}

export interface ProviderAccessConsentInput {
  approve: boolean;
  reason?: string;
}

export interface ProviderAccessConsentList {
  items: { approve: boolean; decided_at: string; grant_id: string; reason?: string; subject: string }[];
}

export interface ProviderAccessPolicy {
  approvals: number;
  configured: boolean;
  guidance: string;
  require_tenant_consent: boolean;
  set_at?: string;
  set_by?: string;
}

export interface ProviderAccessPolicyInput {
  approvals?: number;
  require_tenant_consent: boolean;
}

export interface ProviderAccessRequestList {
  items: { approvals: number; denied: boolean; expires_at: string; grant_id: string; operator_email?: string; reason?: string; requested_at: string }[];
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

export interface RehearsalRun {
  candidate: { kind: "identity" | "issuer" | "profile" | "target" | "binary"; ref: string; revision?: string };
  completed_at?: string;
  connector_versions: Record<string, unknown>;
  data_set_digest: string;
  detail?: string;
  expected: { action: string; expect: string; target?: string }[];
  id: string;
  label?: string;
  mode: "static_preview" | "mocked_rehearsal" | "sandbox_execution" | "live_observation";
  observations: ({ effect: string; receipt?: string; source: "preview" | "mock" | "sandbox_receipt" | "live_receipt"; step: number })[];
  scenario_id: string;
  scenario_revision: number;
  started_at: string;
  started_by?: string;
  status: "running" | "completed";
  tool_version: string;
  verdict?: "matched" | "diverged" | "blocked";
}

export interface RehearsalRunList {
  runs: ({ candidate: { kind: "identity" | "issuer" | "profile" | "target" | "binary"; ref: string; revision?: string }; completed_at?: string; connector_versions: Record<string, unknown>; data_set_digest: string; detail?: string; expected: { action: string; expect: string; target?: string }[]; id: string; label?: string; mode: "static_preview" | "mocked_rehearsal" | "sandbox_execution" | "live_observation"; observations: ({ effect: string; receipt?: string; source: "preview" | "mock" | "sandbox_receipt" | "live_receipt"; step: number })[]; scenario_id: string; scenario_revision: number; started_at: string; started_by?: string; status: "running" | "completed"; tool_version: string; verdict?: "matched" | "diverged" | "blocked" })[];
}

export interface RehearsalRunRequest {
  mode: "static_preview" | "mocked_rehearsal" | "sandbox_execution" | "live_observation";
}

export interface RehearsalScenario {
  candidate: { kind: "identity" | "issuer" | "profile" | "target" | "binary"; ref: string; revision?: string };
  created_at: string;
  created_by?: string;
  data_set: { failure?: { code?: string; ref: string; source: string; step?: string }; identity_ids?: string[]; kind: "identities" | "scrubbed_failure"; secret_refs?: string[] };
  id: string;
  kind: "approval_resumption" | "target_outage" | "renewal_failure" | "revoked_credential" | "stale_policy" | "restore" | "retry";
  name: string;
  revision: number;
  steps: { action: string; expect: string; target?: string }[];
  updated_at: string;
}

export interface RehearsalScenarioList {
  scenarios: ({ candidate: { kind: "identity" | "issuer" | "profile" | "target" | "binary"; ref: string; revision?: string }; created_at: string; created_by?: string; data_set: { failure?: { code?: string; ref: string; source: string; step?: string }; identity_ids?: string[]; kind: "identities" | "scrubbed_failure"; secret_refs?: string[] }; id: string; kind: "approval_resumption" | "target_outage" | "renewal_failure" | "revoked_credential" | "stale_policy" | "restore" | "retry"; name: string; revision: number; steps: { action: string; expect: string; target?: string }[]; updated_at: string })[];
}

export interface RehearsalScenarioRequest {
  candidate: { kind: "identity" | "issuer" | "profile" | "target" | "binary"; ref: string; revision?: string };
  data_set: { failure?: { code?: string; ref: string; source: string; step?: string }; identity_ids?: string[]; kind: "identities" | "scrubbed_failure"; secret_refs?: string[] };
  kind: "approval_resumption" | "target_outage" | "renewal_failure" | "revoked_credential" | "stale_policy" | "restore" | "retry";
  name: string;
  steps?: { action: string; expect: string; target?: string }[];
}

export interface RelayPluginEntry {
  digest: string;
  execution_context: "network_relay_wasm";
  grants: RelayPluginGrant[];
  module?: RelayPluginModule;
  name: string;
  publisher: string;
}

export interface RelayPluginGrant {
  capability: "fs.read" | "fs.write" | "net.dial" | "input.read" | "net.http";
  constraints: string[];
}

export interface RelayPluginModule {
  actions: ("deploy" | "test" | "rollback" | "readback" | "revoke")[];
  credentials: string[];
  health: RelayPluginModuleHealth;
  host_api_max: number;
  host_api_min: number;
  idempotency: "replace-by-name" | "create-new" | "read-before-write";
  inputs: RelayPluginModuleInput[];
  memory_pages: number;
  pending_permissions: string[];
  revocation: "delete" | "unbind" | "none";
  state: "loaded" | "awaiting-approval" | "incompatible";
  state_reason?: string;
  timeout_ms: number;
  version: string;
}

export interface RelayPluginModuleHealth {
  calls: number;
  consecutive_failures: number;
  failures: number;
  last_failure?: string;
}

export interface RelayPluginModuleInput {
  description?: string;
  name: string;
  required: boolean;
  secret: boolean;
  type: "string" | "integer" | "boolean";
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
  revocation_reason?: string;
  rollback_ref?: string;
  target?: string;
  target_identity_id?: string;
  verification_timeout_seconds?: number;
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

export interface ReportSigningKey {
  public_key_der: string;
  public_key_pem: string;
  sha256: string;
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
  command_event_id?: string;
  delivery_attempt_limit?: number;
  delivery_attempts?: number;
  delivery_status?: string;
  destruction_record?: string;
  final_epoch?: number;
  guidance: string;
  key_id: string;
  outstanding: RetirementDependent[];
  recovery_action: "none" | "retry_delivery" | "fresh_command";
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
  certificate_listed?: boolean;
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
  scope?: "endpoint" | "certificate";
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

export interface RevocationProbeNow {
  bucket: string;
  guidance: string;
  queued: boolean;
}

export interface RevocationRelayWait {
  attempt: number;
  attempt_queued_at: string;
  ca_config: string;
  issuer_id?: string;
  issuer_name?: string;
  last_error?: string;
  queued_at: string;
  relay: string;
  relay_agent_id: string;
  relay_last_seen_at?: string;
  relay_presence: "never_seen" | "online" | "stale" | "unreported" | "offboarded" | "clock_skew";
  revocation_id: string;
  serial: string;
  state: "waiting_for_relay" | "relay_working";
}

export interface RevocationRelayWaits {
  guidance: string;
  items: RevocationRelayWait[];
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
  distrust?: { entry: string; how: "itself" | "chain" | "issuer_key_id" | "issuer_name"; reason?: string; subject?: string };
  dns_names?: string[];
  evidence_refs: string[];
  finding_types: string[];
  fingerprint?: string;
  id: string;
  installed_on?: RogueInstalledTarget[];
  issuer?: string;
  issuer_revocation?: RogueIssuerRevocation;
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
  policy_violations?: ({ reason?: string; remediation?: "renew"; rule: string; severity: "critical" | "high" | "medium" | "low" })[];
  recommendation: string;
  risk_score: number;
  run_id?: string;
  serial?: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  source_id?: string;
  status?: string;
  subject: string;
  weak_key_reasons?: string[];
}

export interface RogueCertificatePosture {
  capability: string;
  coverage: string[];
  evidence_refs: string[];
  findings: RogueCertificateFinding[];
  generated_at: string;
  policy_evaluated: number;
  policy_evaluation_errors: number;
  policy_module_sha256?: string;
  read_limited?: boolean;
  recommended_actions: string[];
  summary: RogueCertificateSummary;
}

export interface RogueCertificateRevokeRequest {
  authority_id: string;
  discovery_id: string;
  reason: string;
}

export interface RogueCertificateSummary {
  critical: number;
  ct_unexpected: number;
  distrusted_issuer?: number;
  expired_active: number;
  findings: number;
  high: number;
  issuer_missing: number;
  lifetime_violations: number;
  low: number;
  medium: number;
  non_compliant: number;
  owner_missing: number;
  policy_violations?: number;
  recommendations: number;
  rogue: number;
  total_analyzed: number;
  weak_key: number;
}

export interface RogueCertificateTakedownRequest {
  fingerprint: string;
  reason: string;
  target_id: string;
}

export interface RogueInstalledTarget {
  connector: string;
  model: "host_purge" | "appliance_takedown" | "none";
  note?: string;
  target_id: string;
  target_name: string;
}

export interface RogueIssuerRevocation {
  attempts: number;
  authority_id: string;
  discovery_id: string;
  last_error?: string;
  reason: string;
  requested_at?: string;
  revoked_at?: string;
  serial: string;
  status: "queued" | "revoked" | "failed";
}

export interface Role {
  custom?: boolean;
  description?: string;
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
  host_job?: { attempts: number; completed_at?: string; id: number; status: string };
  id: string;
  idempotency_key?: string;
  identity_id: string;
  outbox_id?: number;
  predecessor_fingerprint?: string;
  reason?: string;
  rollback_ref?: string;
  status: "running" | "succeeded" | "failed" | "cancelled";
  successor_fingerprint?: string;
  tenant_id: string;
  trigger: string;
  updated_at: string;
}

export interface RotationRunList {
  items: RotationRun[];
  next_cursor?: string;
}

export interface SPIFFEQualification {
  blockers: string[];
  checked_at: string;
  checks: SPIFFEQualificationCheck[];
  client_boundary: string;
  effect_free: boolean;
  hybrid_svids: boolean;
  local_socket_deprecated: boolean;
  local_workloads_served: boolean;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  proof: string[];
  ready: boolean;
  registration_entry_count: number;
  socket_mode: string;
  socket_uri: string;
  supported_operations: string[];
  transport: "unix";
  trust_domain: string;
}

export interface SPIFFEQualificationCheck {
  detail: string;
  id: string;
  label: string;
  passed: boolean;
  recovery?: string;
}

export interface SPIFFEUpstreamJWTKey {
  expires_at: string;
  key_id: string;
  public_key: string;
  published_at?: string;
  published_by: string;
  tainted: boolean;
}

export interface SPIFFEUpstreamJWTKeyList {
  items: SPIFFEUpstreamJWTKey[];
}

export interface SPIFFEUpstreamJWTKeyRequest {
  expires_at?: string;
  key_id: string;
  public_key: string;
  tainted?: boolean;
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

export interface SSHAttestedUserCertPreview {
  approver: string;
  attestation_verification: "execution_only";
  authority_fingerprint: string;
  blockers: string[];
  capability: string;
  data_handling: string[];
  effect_free: boolean;
  effective_ttl_seconds: number;
  execution_external_effects: string[];
  execution_signer_calls: string[];
  execution_writes: string[];
  force_command: string;
  key_id: string;
  method: string;
  payload_sha256: string;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  principals: string[];
  public_key_fingerprint: string;
  public_key_type: string;
  ready: boolean;
  recovery_steps: string[];
  requested_ttl_seconds: number;
  required_permission: string;
  source_addresses: string[];
  supported_methods: string[];
  ttl_clamped: boolean;
  ttl_defaulted: boolean;
}

export interface SSHAttestedUserCertRequest {
  approver?: string;
  force_command?: string;
  key_id?: string;
  method: "aws_iid" | "azure_imds" | "gcp_iit" | "github_oidc" | "k8s_sat" | "tpm";
  payload_base64: string;
  principals?: string[];
  public_key: string;
  source_addresses?: string[];
  ttl_seconds?: number;
}

export interface SSHCertificate {
  authority_fingerprint: string;
  certificate: string;
  certificate_type: "host" | "user";
  critical_options: Record<string, unknown>;
  extensions: Record<string, unknown>;
  key_id: string;
  krl_version: number;
  principals: string[];
  serial: number;
  valid_before: string;
}

export interface SSHCertificatePreview {
  authority_fingerprint: string;
  blockers: string[];
  capability: string;
  certificate_type: "host" | "user";
  critical_options: Record<string, unknown>;
  effect_free: boolean;
  effective_ttl_seconds: number;
  extensions: Record<string, unknown>;
  issuance_external_effects: string[];
  issuance_signer_calls: string[];
  issuance_writes: string[];
  key_id: string;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  principals: string[];
  public_key_fingerprint: string;
  public_key_type: string;
  ready: boolean;
  recovery_steps: string[];
  requested_ttl_seconds: number;
  secret_data_handling: string[];
  ttl_clamped: boolean;
  ttl_defaulted: boolean;
}

export interface SSHCertificateRequest {
  certificate_type: "host" | "user";
  critical_options?: Record<string, unknown>;
  extensions?: Record<string, unknown>;
  key_id: string;
  principals: string[];
  public_key: string;
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
}

export interface SSHFleetInventory {
  host_count: number;
  host_trust: SSHHostTrustView;
  hosts: SSHFleetHost[];
  key_count: number;
  orphaned_key_count: number;
  standing_key_count: number;
}

export interface SSHHostCertificate {
  ca_fingerprint?: string;
  judgment: "tenant_ca" | "expiring" | "expired" | "not_yet_valid" | "other_ca" | "unverified" | "not_host" | "none" | "missing" | "unreadable" | "relative_path" | "invalid";
  key_fingerprint?: string;
  key_id?: string;
  path: string;
  principals: string[];
  serial?: number;
  signature_verified: boolean;
  valid_after?: string;
  valid_before?: string;
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

export interface SSHHostTrust {
  agent: string;
  agent_id: string;
  authorized_keys_file: string[];
  collection_mode?: "agentless";
  config_read: "read" | "missing" | "unreadable";
  coverage?: string;
  first_observed: string;
  host_certificate: "tenant_ca" | "expiring" | "expired" | "not_yet_valid" | "other_ca" | "unverified" | "not_host" | "none" | "missing" | "unreadable" | "relative_path" | "invalid";
  host_certificates: SSHHostCertificate[];
  krl_version?: number;
  last_observed: string;
  match_blocks: number;
  revocation_list: "served" | "not_served" | "key_list" | "none" | "missing" | "unreadable" | "relative_path" | "invalid";
  revoked_keys_sha256?: string;
  source_id?: string;
  sshd_config: string;
  standing_keys: "off" | "on" | "missing" | "unreadable" | "relative_path" | "invalid";
  target_address?: string;
  trusted_ca_fingerprints: string[];
  user_ca: "tenant_ca" | "tenant_ca_and_other" | "other_ca" | "none" | "missing" | "unreadable" | "relative_path" | "invalid";
}

export interface SSHHostTrustSummary {
  enforces_served_krl: number;
  hosts: number;
  no_user_ca: number;
  served_krl_sha256?: string;
  standing_keys_on: number;
  tenant_ca_configured: boolean;
  tenant_ca_fingerprint?: string;
  tenant_host_certificate: number;
  trusts_other_ca_only: number;
  trusts_tenant_ca: number;
}

export interface SSHHostTrustView {
  hosts: SSHHostTrust[];
  summary: SSHHostTrustSummary;
}

export interface SSHKRLAdoption {
  already_carried: boolean;
  carried: { broadened_to_any_ca: number; key_hashes: number; key_ids: number; keys: number; serial_ranges: number };
  krl: SSHStatus;
  parts: number;
  predecessor_sha256: string;
  predecessor_version: number;
}

export type SSHKRLBinary = string;

export interface SSHKRLFleet {
  hosts: SSHKRLHost[];
  served: { krl_version: number; revoked_count: number; sha256: string };
  stale_after_seconds: number;
  summary: { behind: number; current: number; failing: number; hosts: number; refusing: number; stale: number };
  tenant_id: string;
}

export interface SSHKRLHost {
  agent: string;
  agent_id: string;
  checked_at: string;
  dropped?: { key_hashes: number; key_ids: number; keys: number; serials: number };
  fetched_sha256?: string;
  fetched_version?: number;
  installed_at?: string;
  installed_sha256: string;
  installed_version: number;
  outcome: "current" | "installed" | "refused_not_newer" | "refused_drops_revocations" | "fetch_failed" | "apply_failed";
  poll_every_seconds: number;
  reported_at: string;
  signer_fingerprint: string;
  state: "current" | "behind" | "refusing" | "failing" | "stale";
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

export interface SSHTrustFleetApproval {
  approval_count: number;
  approval_intent_digest: string;
  approval_request_id: string;
  expires_at: string;
  plan: SSHTrustFleetPlan;
  plan_digest: string;
  required_approvals: number;
  status: string;
}

export interface SSHTrustFleetHost {
  agent_id: string;
  attempt?: number;
  checked_at?: string;
  job_id?: number;
  receipt?: SSHTrustFleetReport;
  receipt_event_id?: string;
  skip_reason?: string;
  state: "queued" | "skipped" | "verified" | "failed" | "refused";
}

export interface SSHTrustFleetList {
  items: SSHTrustFleetRollout[];
  next_cursor?: string;
}

export interface SSHTrustFleetPlan {
  ca_fingerprint: string;
  expires_at: string;
  hosts: ({ agent_id: string; readiness_digest?: string; reason?: "disabled" | "unconfirmed" | "misconfigured" | "not_reported" | "stale" | "not_host_role" | "ca_not_staged" | "claims_paused"; state: "ready" | "skipped" })[];
  name: string;
  public_ca_key: string;
  reason: string;
}

export interface SSHTrustFleetPlanInput {
  plan: SSHTrustFleetPlan;
  plan_digest: string;
}

export interface SSHTrustFleetPreview {
  effect_free: boolean;
  job_kind_enabled: boolean;
  plan: SSHTrustFleetPlan;
  plan_digest: string;
  ready_hosts: number;
  skipped_hosts: number;
}

export interface SSHTrustFleetPreviewInput {
  agent_ids: string[];
  name: string;
  public_ca_key: string;
  reason: string;
}

export interface SSHTrustFleetReport {
  agent_id: string;
  ca_fingerprint: string;
  ca_read_back: boolean;
  changed: boolean;
  checked_at: string;
  config_file_sha256?: string;
  effective_config_read_back: boolean;
  healthy: boolean;
  phase: "preflight" | "backup" | "write_trust" | "write_config" | "validate" | "reload" | "health" | "readback" | "complete";
  plan_digest: string;
  readiness_digest: string;
  reason_code?: "local_not_enabled" | "local_unconfirmed" | "other_agent" | "policy_changed" | "ca_pin_changed" | "execution_window_ended" | "canceled" | "local_configuration_invalid" | "host_busy" | "apply_failed" | "readback_failed";
  reloaded: boolean;
  rollback: "not_needed" | "not_available" | "verified" | "failed";
  rollout_id: string;
  state: "verified" | "failed" | "refused";
  trust_file_sha256?: string;
  validated: boolean;
}

export interface SSHTrustFleetRollout {
  approval_request_id: string;
  created_at: string;
  hosts: SSHTrustFleetHost[];
  id: string;
  plan: SSHTrustFleetPlan;
  plan_digest: string;
  requester: string;
  state: "pending" | "verified" | "attention_required" | "execution_window_expired";
  tenant_id: string;
  updated_at: string;
  window_expired: boolean;
}

export interface SSHTrustFleetStartInput {
  approval_intent_digest: string;
  approval_request_id: string;
  plan: SSHTrustFleetPlan;
  plan_digest: string;
}

export interface SSHTrustReadiness {
  ca_fingerprint?: string;
  confirmed: boolean;
  enabled: boolean;
  issue_code?: "local_configuration_invalid" | "report_state_paused";
  policy_digest?: string;
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

export interface ScheduledComplianceArtifact {
  manifest: Record<string, unknown>;
  public_key_der: string;
  signature: string;
}

export interface SecretAccessPreview {
  api_request: { method: "GET"; path: string };
  blockers: string[];
  bulk_import: { available: boolean; reason: string; safe_path: string };
  capability: "F64";
  cli_argv: string[];
  effect_free: boolean;
  env_var: string;
  execute_data_flow: string[];
  execute_reads: string[];
  name: string;
  operation: "read_for_process";
  preview_external_effects: string[];
  preview_reads: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  resolve_references: boolean;
  secret_data_handling: string;
  typescript: string;
  verification_steps: string[];
  version?: number;
}

export interface SecretAccessPreviewRequest {
  env_var: string;
  name: string;
  resolve: boolean;
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

export interface SecretDeliveries {
  consumers: ({ consumer: string; injected_at?: string; injected_version: number; state: "verified" | "injected" | "behind"; verified_at?: string; verified_version: number })[];
  current_version: number;
  name: string;
}

export interface SecretDeliveryReport {
  consumer: string;
  secrets: { name: string; version: number }[];
  state: "injected" | "verified";
}

export interface SecretImportRequest {
  prefix?: string;
  values: Record<string, unknown>;
}

export interface SecretImportResponse {
  batch_id: string;
  count: number;
  items: SecretMeta[];
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

export interface SecretMigration {
  accepted_open: string[];
  consumers: { name: string; pending: string[]; problem?: string; read: string[]; secrets: string[]; subject: string }[];
  created_at: string;
  created_by?: string;
  cut_over_at?: string;
  cut_over_by?: string;
  digest: string;
  id: string;
  objects: ({ name: string; outcome: "migrated" | "reissued"; prior_version: number; rollback?: "restored" | "deleted" | "kept"; rollback_version?: number; version: number; writer: "source" | "store" })[];
  permissions_applied: Record<string, unknown>[];
  plan: Record<string, unknown>;
  project: string;
  rolled_back_at?: string;
  staged_at?: string;
  state: "assessed" | "staged" | "cut-over" | "rolled-back";
}

export interface SecretMigrationCutOverRequest {
  no_consumers?: boolean;
}

export interface SecretMigrationList {
  items: SecretMigration[];
}

export interface SecretMigrationReissueRequest {
  names: string[];
}

export interface SecretMigrationRequest {
  accept_open_environments?: string[];
  consumers?: { environment: string; name: string; secrets?: string[]; subject: string }[];
  migration_id?: string;
  permissions?: ({ access: "read" | "write" | "admin"; environment: string; folder?: string; subject: string })[];
  plan_digest?: string;
  project: string;
  sources: ({ content: string; environment: string; folder?: string; format: "dotenv" | "json" | "yaml" })[];
}

export interface SecretProject {
  can_manage_members?: boolean;
  created_at: string;
  created_by?: string;
  environments?: ({ access: "open" | "member" | "restricted"; name?: string; restricted: boolean; secrets: { key: string; name: string; owner: string; owner_id?: string; version: number }[]; slug: string })[];
  manageable_environments?: string[];
  members?: ({ environments: string[]; granted_at: string; granted_by?: string; role: "viewer" | "developer" | "admin"; subject: string })[];
  name?: string;
  owner: string;
  owner_id?: string;
  owner_resources?: { certificates: number; certificates_needing_work: number; identities: number; soonest_certificates: ({ health: "ok" | "expiring" | "expired"; id: string; kind: string; name: string; not_after?: string; status?: string })[]; soonest_identities: ({ health: "ok" | "expiring" | "expired"; id: string; kind: string; name: string; not_after?: string; status?: string })[] };
  slug: string;
}

export interface SecretProjectCreateRequest {
  environments: { name?: string; restricted?: boolean; slug: string }[];
  name?: string;
  owner_id?: string;
  slug: string;
}

export interface SecretProjectEnvironmentRequest {
  name?: string;
  restricted?: boolean;
  slug: string;
}

export interface SecretProjectList {
  items: SecretProject[];
  next_cursor?: string;
}

export interface SecretProjectMemberRequest {
  environments?: string[];
  role: "viewer" | "developer" | "admin";
}

export interface SecretProjectRenameRequest {
  name: string;
}

export interface SecretPromotionItem {
  action: "create" | "update" | "unchanged" | "blocked";
  key: string;
  owner_id?: string;
  owner_name?: string;
  reason?: string;
  references?: string[];
  rewritten_references?: number;
  source_name: string;
  source_version: number;
  target_name: string;
  target_version: number;
}

export interface SecretPromotionPlan {
  blocked: number;
  changes: number;
  folder?: string;
  from: string;
  items: SecretPromotionItem[];
  kept: string[];
  plan_digest: string;
  project: string;
  to: string;
}

export interface SecretPromotionRequest {
  folder?: string;
  from: string;
  plan_digest?: string;
  to: string;
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

export interface SecretRestoreItem {
  action: "restore" | "unchanged" | "created_since" | "blocked";
  current_version: number;
  name: string;
  reason?: string;
  restore_version?: number;
}

export interface SecretRestorePlan {
  at: string;
  blocked: number;
  changes: number;
  environment: string;
  folder?: string;
  items: SecretRestoreItem[];
  plan_digest: string;
  project: string;
}

export interface SecretRestoreRequest {
  at: string;
  environment: string;
  folder?: string;
  plan_digest?: string;
}

export interface SecretRotateRequest {
  value: string;
}

export interface SecretRotation {
  command_id?: string;
  completed: boolean;
  error?: string;
  failed_phase?: string;
  key: string;
  new_ref: string;
  old_ref: string;
  phase?: string;
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

export interface SecretRotationPreview {
  blockers: string[];
  capability: "F37";
  current_version?: number;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  key: string;
  next_version?: number;
  old_ref: string;
  preview_external_effects: string[];
  preview_writes: string[];
  provider: string;
  ready: boolean;
  recovery_steps: string[];
  remote_key?: string;
  request_fingerprint: string;
  required_permission: string;
  secret_data_handling: string;
  target?: string;
}

export interface SecretRotationRequest {
  acknowledge_single_phase?: boolean;
  consumers?: string[];
  key: string;
  old_ref: string;
  provider: string;
  remote_key?: string;
  retire_after_seconds?: number;
  target?: string;
  ttl_seconds?: number;
}

export interface SecretRotationSchedule {
  consumers?: string[];
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
  retire_after_seconds?: number;
  retired_at?: string;
  single_phase_acknowledged?: boolean;
  tenant_id: string;
  ttl_seconds?: number;
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
  acknowledge_single_phase?: boolean;
  consumers?: string[];
  enabled?: boolean;
  interval_seconds: number;
  key: string;
  name: string;
  next_run_at?: string;
  old_ref: string;
  provider: string;
  retire_after_seconds?: number;
  ttl_seconds?: number;
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

export interface SecretScanPreview {
  blockers: string[];
  capabilities: string[];
  capability: string;
  cli_argv: string[];
  custom_rules: boolean;
  custom_rules_path?: string;
  custom_rules_sha256?: string;
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  mode: string;
  operation: string;
  prerequisites: string[];
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  rules_active: number;
  scanner: string;
  secret_data_handling: string;
  target_path: string;
  verification_steps: string[];
}

export interface SecretScanRequest {
  custom_rules_path?: string;
  mode?: string;
  path: string;
  preview_fingerprint?: string;
}

export interface SecretScopedSync {
  adopt_existing: boolean;
  created_at: string;
  defined_by?: string;
  delete_scope: string;
  destination_prefix?: string;
  id: string;
  key_transform: string;
  keys?: ({ job_id?: string; job_status?: string; key: string; source_name?: string; source_version?: number; state: "synced" | "delete_queued" })[];
  last_applied_at?: string;
  last_plan_digest?: string;
  last_reconcile_at?: string;
  mode: "manual" | "auto";
  name: string;
  reconcile_reason?: string;
  reconcile_status?: "applied" | "unchanged" | "blocked" | "failed";
  source_prefix: string;
  target: string;
  updated_at: string;
}

export interface SecretScopedSyncApplyRequest {
  plan_digest: string;
}

export interface SecretScopedSyncList {
  items: SecretScopedSync[];
  next_cursor?: string;
}

export interface SecretScopedSyncModeRequest {
  mode: "manual" | "auto";
}

export interface SecretScopedSyncPlan {
  blocked: number;
  changes: number;
  items: ({ action: "create" | "update" | "unchanged" | "delete" | "orphaned" | "unmanaged" | "deleting" | "blocked"; key: string; reason?: string; source_name?: string; source_version?: number })[];
  name: string;
  plan_digest: string;
  sync_id: string;
  target: string;
}

export interface SecretScopedSyncReceipt {
  deletes: { delete_id?: string; job_id?: string; key: string }[];
  plan_digest: string;
  sync_id: string;
  writes: { delete_id?: string; job_id?: string; key: string }[];
}

export interface SecretScopedSyncRequest {
  adopt_existing?: boolean;
  delete_scope?: "none" | "managed" | "prefix";
  destination_prefix?: string;
  key_transform?: "path" | "env";
  mode?: "manual" | "auto";
  name: string;
  source_prefix: string;
  target: string;
}

export interface SecretStaticRotation {
  consumer_adoption: "not_requested" | "pending" | "adopted";
  consumer_states?: { adopted: boolean; consumer: string; verified_version: number }[];
  consumers?: string[];
  created_at: string;
  credential_valid: boolean;
  error?: string;
  expected_version: number;
  id: string;
  key: string;
  new_expires_at?: string;
  new_ref: string;
  old_ref: string;
  phase: "queued" | "staged" | "cutover" | "verified" | "completed" | "rolled_back" | "rollback_failed" | "failed" | "retire_pending";
  provider: string;
  provider_type?: string;
  restored_version: number;
  result_version: number;
  retire_after_seconds?: number;
  retire_approved_by?: string;
  retire_not_before?: string;
  rotation_phase?: "two_phase" | "single_phase";
  schedule_id?: string;
  single_phase_acknowledged?: boolean;
  terminal: boolean;
  terminal_at?: string;
  ttl_seconds?: number;
  updated_at: string;
  verify_mode?: string;
}

export interface SecretStaticRotationList {
  items: SecretStaticRotation[];
  next_cursor?: string;
}

export interface SecretStoreCreatePreview {
  blockers: string[];
  capability: "F63";
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  name: string;
  next_version: number;
  operation: "create";
  owner_id?: string;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  required_permission: string;
  secret_data_handling: string;
}

export interface SecretSync {
  delivered: boolean;
  enqueued: boolean;
  job_id: string;
  name: string;
  remote_key: string;
  target: string;
}

export interface SecretSyncJob {
  attempts: number;
  blocked_by_job_id?: string;
  delivered_at?: string;
  job_id: string;
  last_error?: string;
  name: string;
  receiver_effect_state?: "none" | "effect_possible" | "effect_settled" | "failure_authorized" | "failure_reconciled";
  receiver_io_starts: number;
  reconcilable: boolean;
  remote_key: string;
  requested_at: string;
  secret_version: number;
  status: "pending" | "delivered" | "failed";
  target: string;
  updated_at: string;
}

export interface SecretSyncPreview {
  blockers: string[];
  capability: string;
  cli_argv: string[];
  effect_free: boolean;
  execute_external_effects: string[];
  execute_writes: string[];
  name: string;
  operation: string;
  preview_external_effects: string[];
  preview_reads: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  remote_key: string;
  request_fingerprint?: string;
  required_permission: string;
  secret_data_handling: string;
  secret_version: number;
  target: string;
  verification_steps: string[];
}

export interface SecretSyncReconcileRequest {
  observed?: "value_present" | "value_absent";
  operator_verified?: boolean;
}

export interface SecretSyncReconcileResult {
  detail: string;
  job: SecretSyncJob;
  outcome: "delivered" | "failed" | "settled" | "terminal";
}

export interface SecretSyncRequest {
  name: string;
  preview_fingerprint?: string;
  remote_key?: string;
  target: string;
}

export interface SecretSyncTarget {
  auth_mode: string;
  capabilities: string[];
  configured: boolean;
  delivery_mode: string;
  generic: boolean;
  id: string;
  name: string;
  note?: string;
  platform: string;
  proof?: "locally-proven" | "stand-in-only";
  qualification: "discovered" | "implemented" | "served" | "locally-proven" | "vendor-qualified";
  readback?: "value" | "digest" | "receipt-only";
  scoped_sync: boolean;
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

export interface SecretVersionBatchReceipt {
  batch_id?: string;
  items: { name: string; updated_at: string; version: number }[];
  operation: "promotion" | "restore";
  plan_digest: string;
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

export interface SharePreview {
  blockers: string[];
  capability: string;
  cli_argv: string[];
  effect_free: boolean;
  effective_ttl_seconds: number;
  execute_external_effects: string[];
  execute_writes: string[];
  operation: string;
  preview_external_effects: string[];
  preview_writes: string[];
  ready: boolean;
  recovery_steps: string[];
  request_fingerprint: string;
  requested_ttl_seconds: number;
  required_permission: string;
  secret_data_handling: string;
  sensitive_change_approval_configured: boolean;
  verification_steps: string[];
}

export interface SharePreviewRequest {
  ttl_seconds?: number;
}

export interface ShareRedeemRequest {
  token: string;
}

export interface ShareRequest {
  preview_fingerprint?: string;
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

export interface SlackApp {
  approval_channel_id?: string;
  approval_channel_name?: string;
  configured: boolean;
  duplicate_post_check?: boolean;
  installed: boolean;
  installed_at?: string;
  installed_by?: string;
  team_id?: string;
  team_name?: string;
}

export interface SlackApprovalChannel {
  channel_id: string;
}

export interface SlackChannelList {
  items: { id?: string; is_member?: boolean; is_private?: boolean; name?: string }[];
}

export interface SlackInstallStart {
  authorize_url: string;
  expires_at: string;
}

export interface SlackLinkCode {
  code: string;
  expires_at: string;
}

export interface SwitchingImport {
  completed_at?: string;
  counts: Record<string, unknown>;
  created_at: string;
  created_by: string;
  format: string;
  gap_counts: Record<string, unknown>;
  id: string;
  name: string;
  preview_digest: string;
  rows_applied: number;
  rows_recorded: number;
  rows_total: number;
  status: "recording" | "completed";
  watch: { allow_private_endpoint: boolean; counts: Record<string, unknown>; pending: number; private_egress_cidrs: string[]; requested_at?: string; requested_by?: string; round: number };
}

export interface SwitchingImportList {
  items: ({ completed_at?: string; counts: Record<string, unknown>; created_at: string; created_by: string; format: string; gap_counts: Record<string, unknown>; id: string; name: string; preview_digest: string; rows_applied: number; rows_recorded: number; rows_total: number; status: "recording" | "completed"; watch: { allow_private_endpoint: boolean; counts: Record<string, unknown>; pending: number; private_egress_cidrs: string[]; requested_at?: string; requested_by?: string; round: number } })[];
}

export interface SwitchingImportPreview {
  applications: string[];
  counts: Record<string, unknown>;
  digest: string;
  folders: { conflicts?: string[]; folder: string; key_algorithm?: string; profile: string; renewal_window_days?: number; rows: number }[];
  format: string;
  gap_counts: Record<string, unknown>;
  items: ({ application?: string; common_name?: string; duplicate_of?: number; endpoints?: string[]; fingerprint_sha256?: string; folder?: string; gaps?: string[]; has_pem: boolean; issuer?: string; key_algorithm?: string; known_certificate_id?: string; not_after?: string; outcome: "mapped" | "mapped_with_gaps" | "duplicate" | "unparseable" | "expired"; owner_email?: string; owner_id?: string; owner_name?: string; reason?: string; renewal_window_days?: number; row: number; sans?: string[]; serial?: string })[];
  items_truncated: boolean;
  known: number;
  owners: { application?: string; create: boolean; email: string; name?: string; owner_id?: string; rows: number }[];
  rows: number;
}

export interface SwitchingImportRequest {
  column_map?: Record<string, unknown>;
  export: string;
  name?: string;
  preview_digest?: string;
}

export interface SwitchingImportRowList {
  items: ({ application?: string; applied_at?: string; certificate_id?: string; common_name?: string; duplicate_of?: number; endpoints: string[]; fingerprint_sha256?: string; folder?: string; gaps: string[]; has_pem: boolean; issuer?: string; key_algorithm?: string; linked: boolean; not_after?: string; outcome: "mapped" | "mapped_with_gaps" | "duplicate" | "unparseable" | "expired"; owner_email?: string; owner_id?: string; profile?: string; reason?: string; row_number: number; sans: string[]; serial?: string; served_fingerprint_sha256?: string; watch_detail?: string; watch_endpoint?: string; watch_status?: "matched" | "serves_other" | "unreachable" | "no_endpoint" | "serves_trstctl" | "renewed_by_other_product"; watched_at?: string })[];
  next_after: string;
}

export interface SwitchingWatchRequest {
  allow_private_endpoint?: boolean;
  private_egress_cidrs?: string[];
}

export interface SwitchingWave {
  created_at: string;
  created_by: string;
  id: string;
  import_id: string;
  issuer_id?: string;
  name: string;
  preview_digest: string;
  rollback_reason?: string;
  rolled_back_at?: string;
  rolled_back_by?: string;
  rows: { identity_id: string; identity_status: string; imported_fingerprint_sha256: string; live: boolean; renewal_paused: boolean; row_number: number; target_id: string; trstctl_fingerprints_sha256: string[]; watch_status?: string }[];
  status: "cut_over" | "rolled_back";
  withdrawn?: number;
}

export interface SwitchingWaveList {
  items: ({ created_at: string; created_by: string; id: string; import_id: string; issuer_id?: string; name: string; preview_digest: string; rollback_reason?: string; rolled_back_at?: string; rolled_back_by?: string; rows: { identity_id: string; identity_status: string; imported_fingerprint_sha256: string; live: boolean; renewal_paused: boolean; row_number: number; target_id: string; trstctl_fingerprints_sha256: string[]; watch_status?: string }[]; status: "cut_over" | "rolled_back"; withdrawn?: number })[];
}

export interface SwitchingWavePreview {
  digest: string;
  excluded: { reason: string; row_number: number }[];
  import_id: string;
  issuer_id?: string;
  name: string;
  rows: { application?: string; common_name: string; folder?: string; identity_exists: boolean; identity_id: string; imported_fingerprint_sha256: string; issuer_id?: string; owner_id: string; row_number: number; target: { connector: string; id: string; name: string }; watch_status?: string }[];
  stop_renewing: string[];
}

export interface SwitchingWaveRequest {
  assignments: { row_number: number; target_id: string }[];
  issuer_id?: string;
  name: string;
  preview_digest?: string;
}

export interface SwitchingWaveRollbackRequest {
  reason: string;
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

export interface TSACertificate {
  cert_pem: string;
  cert_sha256: string;
  not_after: string;
  not_before: string;
  reason?: string;
  revoked_at?: string;
  serial: string;
  state: "active" | "retired" | "revoked";
}

export interface TSACertificateList {
  crl: string;
  items: TSACertificate[];
  ocsp: string;
}

export interface TSAQualification {
  blockers: string[];
  checked_at: string;
  checks: TSAQualificationCheck[];
  effect_free: boolean;
  endpoint: string;
  policy_oid: string;
  preview_external_effects: string[];
  preview_signer_calls: string[];
  preview_writes: string[];
  proof: string[];
  ready: boolean;
}

export interface TSAQualificationCheck {
  detail: string;
  id: string;
  label: string;
  passed: boolean;
  recovery?: string;
}

export interface TSARevokeRequest {
  reason: string;
}

export interface TSARotateRequest {
  revoke_previous_reason?: string;
}

export interface TSARotation {
  current: TSACertificate;
  previous: TSACertificate;
}

export interface TenantCustomRoleRequest {
  description?: string;
  permissions: string[];
}

export interface TenantKeyDomainMigrateRequest {
  wrapper_id: string;
  wrapper_kind?: "local_file" | "pkcs11";
}

export interface TenantKeyDomainRotateRequest {
  wrapper_id?: string;
  wrapper_kind?: "local_file" | "pkcs11";
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
  next_generation?: number;
  next_wrapper_id?: string;
  next_wrapper_kind?: string;
  operation_id?: string;
  operation_kind?: string;
  operation_status?: string;
  progress_completed: number;
  progress_total: number;
  protection_mode: string;
  recovery: string;
  remote_wrapper_state: string;
  retryable: boolean;
  rotated_at?: string;
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
  annotation?: { allow_private_endpoint?: boolean; auto?: boolean; base_url: string; commit_sha?: string; digest?: string; private_egress_cidrs?: string[]; repo?: string; repository?: string; system?: "github" | "gitlab"; token_ref: string; username_ref?: string };
  artifact_kind?: string;
  artifact_path?: string;
  collect?: { allow_private_endpoint?: boolean; base_url: string; channels?: string[]; jql?: string; max_bytes?: number; max_items?: number; private_egress_cidrs?: string[]; reference?: string; repo?: string; repository?: string; since?: string; system?: "github" | "gitlab"; token_ref?: string; username_ref?: string };
  credential_ref?: string;
  delete_artifact_after_scan?: boolean;
  event?: string;
  require_signature?: boolean;
  signature_path?: string;
  signer_public_key_pem?: string;
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
  name?: string;
  owner_field?: string;
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
  name?: string;
  next_cursor?: string;
  owner_field?: string;
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

export interface TicketIntakeScheduleList {
  items: TicketIntakeSchedule[];
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

export interface TransitKeyVersion {
  current: boolean;
  fact_id?: string;
  recorded: boolean;
  recorded_at?: string;
  version: number;
}

export interface TransitKeyVersionList {
  kind: string;
  name: string;
  versions: TransitKeyVersion[];
}

export interface TransitPlaintext {
  plaintext: string;
}

export interface TransitPosture {
  checked_at: string;
  effect_free: boolean;
  kmip: KMIPPosture;
  proof: string[];
  recovery_steps: string[];
  transit: TransitServicePosture;
}

export interface TransitRewrapRequest {
  aad?: string;
  ciphertext: string;
  key: string;
}

export interface TransitRotateRequest {
  name: string;
}

export interface TransitServicePosture {
  detail: string;
  persistence_configured: boolean;
  recovery?: string;
  recovery_ready: boolean;
  restore_state: string;
  served: boolean;
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
  signature?: string;
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

export interface ValidityReadinessCertificate {
  automation: "scheduled" | "client" | "none";
  certificate_id: string;
  deployment: "verified" | "delivered" | "failed" | "none" | "not_applicable";
  exceeds_maximum_at_issuance: boolean;
  identity_id?: string;
  identity_name?: string;
  issuer: string;
  max_days_at_issuance: number;
  not_after: string;
  not_before: string;
  renewal_lead_days?: number;
  renewal_lifetime_days?: number;
  scope: "public_tls" | "private_tls" | "not_tls_server" | "ca_certificate" | "unknown";
  steps: ValidityReadinessCertificateStep[];
  subject: string;
  validity_days: number;
}

export interface ValidityReadinessCertificateStep {
  effective: string;
  max_days: number;
  reasons: ("scheduler_disabled" | "no_automated_renewal" | "client_renewal_unobserved" | "renewal_failed" | "renewal_paused" | "target_conflict" | "delivery_failed" | "deployment_unverified" | "no_automated_deployment" | "approval_required" | "profile_unavailable" | "renewal_lifetime_exceeds_maximum")[];
  verdict: "renews" | "at_risk" | "manual";
}

export interface ValidityReadinessExport {
  content_type: string;
  csv: string;
  filename: string;
  generated_at: string;
  requirements: ValidityReadinessRequirements;
  truncated: boolean;
}

export interface ValidityReadinessProfile {
  max_validity: string;
  name: string;
  public_tls: boolean;
  requested_days: number;
  server_auth: boolean;
  steps: ValidityReadinessProfileStep[];
  version: number;
}

export interface ValidityReadinessProfileStep {
  effective: string;
  flagged: boolean;
  max_days: number;
  reason?: "no_validity_ceiling" | "requested_validity_exceeds_maximum";
}

export interface ValidityReadinessReport {
  certificates: ValidityReadinessCertificate[];
  generated_at: string;
  limit: number;
  profiles: ValidityReadinessProfile[];
  requirements: ValidityReadinessRequirements;
  scheduler: ValidityReadinessScheduler;
  steps: ValidityReadinessStep[];
  truncated: boolean;
}

export interface ValidityReadinessRequirements {
  name: string;
  published: string;
  section: string;
  url: string;
  version: string;
}

export interface ValidityReadinessScheduler {
  enabled: boolean;
  renew_before: string;
  renew_before_seconds: number;
}

export interface ValidityReadinessStep {
  at_risk: number;
  effective: string;
  flagged_profiles: number;
  in_effect: boolean;
  manual: number;
  manual_renewals_per_year: number;
  max_days: number;
  public_tls: number;
  public_tls_at_risk: number;
  public_tls_manual: number;
  renews: number;
  should_days: number;
}

export interface VerificationAddressConfirmation {
  address: string;
  server_name?: string;
  target_revision: string;
}

export interface VerificationSuggestion {
  address: string;
  evidence: VerificationSuggestionEvidence[];
  last_seen: string;
}

export interface VerificationSuggestionEvidence {
  discovered_at: string;
  finding_id: string;
  fingerprint: string;
  run_id: string;
  source_id: string;
}

export interface VerificationSuggestions {
  note: string;
  suggestions: VerificationSuggestion[];
  target_id: string;
  target_revision: string;
  verify_address?: string;
  verify_server_name?: string;
}

export interface WorkloadAttesterTrustSource {
  allowed_owners: string[];
  audience?: string;
  authority_pending?: boolean;
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
  self_authenticating: boolean;
  tenant_id: string;
  updated_at: string;
}

export interface WorkloadAttesterTrustSourceList {
  items: WorkloadAttesterTrustSource[];
  next_cursor?: string;
}

export interface WorkloadAttesterTrustSourceRequest {
  allowed_owners?: string[];
  audience?: string;
  enabled?: boolean;
  expected_nonce_base64?: string;
  issuer?: string;
  jwks?: Record<string, unknown>;
  method: "aws_iid" | "azure_imds" | "gcp_iit" | "github_oidc" | "k8s_sat" | "tpm";
  name: string;
  root_certs_pem?: string[];
  self_authenticating?: boolean;
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

export interface WorkloadJWTKey {
  activates_at?: string;
  generation: number;
  key_id: string;
  published_at?: string;
  retires_at?: string;
  state: "active" | "next" | "retiring" | "retired";
}

export interface WorkloadJWTKeyRotateRequest {
  publish_ahead_seconds?: number;
  retain_seconds?: number;
}

export interface WorkloadJWTKeys {
  keys: WorkloadJWTKey[];
}
